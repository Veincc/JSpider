package config

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
)

type Config struct {
	URL            string
	URLList        string
	OutDir         string
	Headless       bool // enable headless browser JS discovery
	MaxJS          int
	MaxDepth       int
	MaxSizeMB      int
	Workers        int
	Beautify       bool
	SameOrigin     bool
	AllowCDN       []string
	FetchSourcemap bool
	Timeout        int
	UserAgent      string
	Cookies        string
	Headers        map[string]string
	Verbose        bool
}

func Parse() *Config {
	cfg := &Config{}
	var allowCDNStr string
	var headersStr string

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "JSpider - Frontend JS Asset Discovery Tool\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  jspider -u <URL>                    Static analysis (default)\n")
		fmt.Fprintf(os.Stderr, "  jspider -u <URL> --headless         Static + headless browser discovery\n")
		fmt.Fprintf(os.Stderr, "  jspider -l <file>                   Analyze a URL list file\n")
		fmt.Fprintf(os.Stderr, "  jspider -u <URL> -m -w 10 -o result Full parameter example\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
	}

	flag.StringVar(&cfg.URL, "u", "", "Start URL")
	flag.StringVar(&cfg.URLList, "l", "", "URL list file (one URL per line)")
	flag.StringVar(&cfg.OutDir, "o", "output", "Output directory")
	flag.BoolVar(&cfg.Headless, "headless", false, "Enable headless browser JS discovery (requires Chrome/Chromium)")
	flag.IntVar(&cfg.MaxJS, "n", 0, "Max JS files to analyze (0=unlimited)")
	flag.IntVar(&cfg.MaxDepth, "d", 6, "Max recursion depth")
	flag.IntVar(&cfg.MaxSizeMB, "s", 10, "Max download size per JS in MB")
	flag.IntVar(&cfg.Workers, "w", 5, "Concurrent download workers")
	flag.BoolVar(&cfg.SameOrigin, "same-origin", true, "Only analyze same-origin JS")
	flag.StringVar(&allowCDNStr, "c", "", "Allowed CDN domains (comma-separated)")
	flag.BoolVar(&cfg.FetchSourcemap, "m", false, "Download and parse source maps")
	flag.IntVar(&cfg.Timeout, "t", 15, "HTTP timeout in seconds")
	flag.StringVar(&cfg.UserAgent, "a", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", "Custom User-Agent")
	flag.StringVar(&cfg.Cookies, "k", "", "Optional cookie string")
	flag.StringVar(&headersStr, "H", "", "Extra headers (Header1=Value1;Header2=Value2)")
	flag.BoolVar(&cfg.Beautify, "b", false, "Beautify JS with js-beautify (must be installed)")
	flag.BoolVar(&cfg.Verbose, "v", false, "Print verbose logs")

	flag.Parse()

	if cfg.URL == "" && cfg.URLList == "" {
		fmt.Fprintln(os.Stderr, "Error: provide at least one of -u or -l")
		flag.Usage()
		os.Exit(1)
	}

	if allowCDNStr != "" {
		for _, d := range strings.Split(allowCDNStr, ",") {
			d = strings.TrimSpace(d)
			if d != "" {
				cfg.AllowCDN = append(cfg.AllowCDN, d)
			}
		}
	}

	cfg.Headers = make(map[string]string)
	if headersStr != "" {
		for _, h := range strings.Split(headersStr, ";") {
			parts := strings.SplitN(h, "=", 2)
			if len(parts) == 2 {
				cfg.Headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
	}

	return cfg
}

// URLs returns the list of URLs to analyze (merges -u and -l)
func (c *Config) URLs() []string {
	var urls []string
	seen := make(map[string]bool)

	if c.URL != "" {
		u := normalizeURL(strings.TrimSpace(c.URL))
		if u != "" && !seen[u] {
			seen[u] = true
			urls = append(urls, u)
		}
	}

	if c.URLList != "" {
		for _, u := range readURLList(c.URLList) {
			u = normalizeURL(u)
			if u != "" && !seen[u] {
				seen[u] = true
				urls = append(urls, u)
			}
		}
	}

	return urls
}

// normalizeURL adds a scheme prefix; URLs without http:// or https:// default to https://.
// - //cdn.example.com/lib.js  → ignored
// - mailto:, file:, data: and other non-HTTP(S) schemes → ignored
// - example.com/path  → https://example.com/path
func normalizeURL(u string) string {
	if u == "" {
		return u
	}
	// Already http/https, return as-is
	if strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") {
		return u
	}
	// Protocol-relative URLs (e.g. //cdn.example.com/lib.js) are not used as entry URLs
	if strings.HasPrefix(u, "//") {
		return ""
	}
	// For this tool, non-HTTP(S) entry URLs are ignored.
	if idx := strings.Index(u, ":"); idx > 0 {
		if idx+1 < len(u) && u[idx+1] >= '0' && u[idx+1] <= '9' {
			return "https://" + u
		}
		isScheme := true
		for i := 0; i < idx; i++ {
			c := u[i]
			if c == '.' || !isSchemeChar(c) {
				isScheme = false
				break
			}
		}
		if isScheme && idx > 0 && isAlpha(u[0]) {
			return ""
		}
	}
	return "https://" + u
}

// isAlpha checks whether a byte is an ASCII letter
func isAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// isSchemeChar checks whether a byte is a valid URI scheme character (RFC 3986: ALPHA / DIGIT / "+" / "-" / ".")
func isSchemeChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.'
}

func readURLList(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read URL list file: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	var urls []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			urls = append(urls, line)
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read URL list file: %v\n", err)
		os.Exit(1)
	}
	return urls
}
