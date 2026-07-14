package config

import (
	"bufio"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/Veincc/JSpider/internal/urlutil"
)

const (
	DefaultMaxDepth              = 10
	DefaultMaxSizeMB             = 0
	DefaultProcessTimeoutSeconds = 30
	DefaultHeadlessBodyMB        = 8
)

type Config struct {
	URL                   string
	URLList               string
	OutDir                string
	Headless              bool // enable headless browser JS discovery
	APIDiscovery          bool // enable static/runtime API discovery; implies headless
	MaxJS                 int
	MaxDepth              int
	MaxSizeMB             int
	Workers               int
	SameOrigin            bool
	AllowCDN              []string
	Timeout               int
	ProcessTimeoutSeconds int
	HeadlessBodyMB        int
	UserAgent             string
	Cookies               string
	Headers               map[string]string
	Verbose               bool
	InsecureSkipVerify    bool
	Proxy                 string
}

func Parse() *Config {
	cfg := &Config{}
	var allowCDNStr string
	var headersStr string
	var deprecatedInsecure bool

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "JSpider - Frontend JS Asset Discovery Tool\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  jspider -u <URL>                    Static analysis (default)\n")
		fmt.Fprintf(os.Stderr, "  jspider -u <URL> --headless         Static + headless browser discovery\n")
		fmt.Fprintf(os.Stderr, "  jspider -u <URL> --api-discovery    Static API extraction + browser API observation\n")
		fmt.Fprintf(os.Stderr, "  jspider -l <file>                   Analyze a URL list file\n")
		fmt.Fprintf(os.Stderr, "  jspider -u <URL> -w 10 -o result    Full parameter example\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fmt.Fprintf(os.Stderr, "  -u <url>              Start URL\n")
		fmt.Fprintf(os.Stderr, "  -l <file>             URL list file, one URL per line\n")
		fmt.Fprintf(os.Stderr, "  -o <dir>              Output directory (default: output)\n")
		fmt.Fprintf(os.Stderr, "  --headless            Enable headless browser JS discovery (requires Chrome/Chromium)\n")
		fmt.Fprintf(os.Stderr, "  --api-discovery       Extract static APIs and use Chrome to click safe elements and observe XHR/fetch/EventSource requests (requires CGO and Chrome/Chromium; implies --headless)\n")
		fmt.Fprintf(os.Stderr, "  -n <count>            Max JS files to analyze (0=unlimited)\n")
		fmt.Fprintf(os.Stderr, "  -d <depth>            Max recursion depth (0=no recursion, default: 10)\n")
		fmt.Fprintf(os.Stderr, "  -s <mb>               Max download size per resource in MB (0=unlimited, default: unlimited)\n")
		fmt.Fprintf(os.Stderr, "  -w <workers>          Concurrent download workers (default: 5)\n")
		fmt.Fprintf(os.Stderr, "  --same-origin         Only analyze same-origin JS (default: true)\n")
		fmt.Fprintf(os.Stderr, "  -c <domains>          Allowed CDN domains, comma-separated\n")
		fmt.Fprintf(os.Stderr, "  --proxy <url>         HTTP, HTTPS, or SOCKS5 proxy used by requests and headless Chrome\n")
		fmt.Fprintf(os.Stderr, "  -t <seconds>          HTTP timeout in seconds (default: 15)\n")
		fmt.Fprintf(os.Stderr, "  --process-timeout <seconds>  JavaScript processing timeout (default: 30)\n")
		fmt.Fprintf(os.Stderr, "  --headless-body-mb <mb>      Headless response body limit (default: 8)\n")
		fmt.Fprintf(os.Stderr, "  -a <ua>               Custom User-Agent\n")
		fmt.Fprintf(os.Stderr, "  -k <cookie>           Optional cookie string\n")
		fmt.Fprintf(os.Stderr, "  -H <headers>          Extra headers (Header1=Value1;Header2=Value2)\n")
		fmt.Fprintf(os.Stderr, "  -v                    Print verbose logs\n")
		fmt.Fprintf(os.Stderr, "  --insecure            Skip TLS certificate verification for requests and headless Chrome\n")
	}

	flag.StringVar(&cfg.URL, "u", "", "Start URL")
	flag.StringVar(&cfg.URLList, "l", "", "URL list file (one URL per line)")
	flag.StringVar(&cfg.OutDir, "o", "output", "Output directory")
	flag.BoolVar(&cfg.Headless, "headless", false, "Enable headless browser JS discovery (requires Chrome/Chromium)")
	flag.BoolVar(&cfg.APIDiscovery, "api-discovery", false, "Extract static APIs and observe browser API requests (requires CGO and Chrome/Chromium; implies --headless)")
	flag.IntVar(&cfg.MaxJS, "n", 0, "Max JS files to analyze (0=unlimited)")
	flag.IntVar(&cfg.MaxDepth, "d", DefaultMaxDepth, "Max recursion depth (0=no recursion)")
	flag.IntVar(&cfg.MaxSizeMB, "s", DefaultMaxSizeMB, "Max download size per resource in MB (0=unlimited)")
	flag.IntVar(&cfg.Workers, "w", 5, "Concurrent download workers")
	flag.BoolVar(&cfg.SameOrigin, "same-origin", true, "Only analyze same-origin JS")
	flag.StringVar(&allowCDNStr, "c", "", "Allowed CDN domains (comma-separated)")
	flag.StringVar(&cfg.Proxy, "proxy", "", "HTTP, HTTPS, or SOCKS5 proxy URL")
	flag.IntVar(&cfg.Timeout, "t", 15, "HTTP timeout in seconds")
	flag.IntVar(&cfg.ProcessTimeoutSeconds, "process-timeout", DefaultProcessTimeoutSeconds, "JavaScript processing timeout in seconds")
	flag.IntVar(&cfg.HeadlessBodyMB, "headless-body-mb", DefaultHeadlessBodyMB, "Headless response body limit in MB")
	flag.StringVar(&cfg.UserAgent, "a", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", "Custom User-Agent")
	flag.StringVar(&cfg.Cookies, "k", "", "Optional cookie string")
	flag.StringVar(&headersStr, "H", "", "Extra headers (Header1=Value1;Header2=Value2)")
	flag.BoolVar(&cfg.Verbose, "v", false, "Print verbose logs")
	flag.BoolVar(&cfg.InsecureSkipVerify, "insecure", false, "Skip TLS certificate verification for requests and headless Chrome")
	flag.BoolVar(&deprecatedInsecure, "insecure-skip-verify", false, "Deprecated alias for --insecure")

	flag.Parse()
	ApplyModeImplications(cfg)
	if deprecatedInsecure {
		cfg.InsecureSkipVerify = true
		fmt.Fprintln(os.Stderr, "Warning: --insecure-skip-verify is deprecated; use --insecure")
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

func ApplyModeImplications(cfg *Config) {
	if cfg.APIDiscovery {
		cfg.Headless = true
	}
}

// Validate rejects configuration values that cannot produce a valid run.
func (c *Config) Validate() error {
	if strings.TrimSpace(c.URL) == "" && strings.TrimSpace(c.URLList) == "" {
		return fmt.Errorf("provide at least one URL with -u or -l")
	}
	if strings.TrimSpace(c.OutDir) == "" {
		return fmt.Errorf("output directory must not be empty")
	}
	if c.Workers <= 0 {
		return fmt.Errorf("workers must be greater than zero")
	}
	if c.MaxDepth < 0 {
		return fmt.Errorf("maximum depth must not be negative")
	}
	if c.MaxJS < 0 {
		return fmt.Errorf("maximum JavaScript count must not be negative")
	}
	if c.MaxSizeMB < 0 {
		return fmt.Errorf("maximum download size must not be negative")
	}
	if c.Timeout <= 0 {
		return fmt.Errorf("HTTP timeout must be greater than zero")
	}
	if c.ProcessTimeoutSeconds <= 0 {
		return fmt.Errorf("process timeout must be greater than zero")
	}
	if c.HeadlessBodyMB <= 0 {
		return fmt.Errorf("headless body limit must be greater than zero")
	}
	if _, err := NormalizeProxy(c.Proxy); err != nil {
		return fmt.Errorf("proxy configuration: %w", err)
	}
	return nil
}

// NormalizeProxy validates a proxy value and adds an HTTP scheme when omitted.
func NormalizeProxy(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}

	proxyURL, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid proxy URL: %w", err)
	}
	switch strings.ToLower(proxyURL.Scheme) {
	case "http", "https", "socks5":
	default:
		return "", fmt.Errorf("unsupported proxy scheme %q", proxyURL.Scheme)
	}
	if proxyURL.Host == "" {
		return "", fmt.Errorf("invalid proxy URL: missing host")
	}
	if proxyURL.RawQuery != "" || proxyURL.Fragment != "" {
		return "", fmt.Errorf("invalid proxy URL: query strings and fragments are not supported")
	}
	if proxyURL.Path != "" && proxyURL.Path != "/" {
		return "", fmt.Errorf("invalid proxy URL: paths are not supported")
	}
	proxyURL.Path = ""

	return proxyURL.String(), nil
}

// URLs returns the list of URLs to analyze (merges -u and -l).
func (c *Config) URLs() ([]string, error) {
	var urls []string
	seen := make(map[string]bool)

	if c.URL != "" {
		u, err := normalizeURL(strings.TrimSpace(c.URL))
		if err != nil {
			return nil, fmt.Errorf("parse entry URL %q: %w", c.URL, err)
		}
		if u != "" && !seen[u] {
			seen[u] = true
			urls = append(urls, u)
		}
	}

	if c.URLList != "" {
		rawURLs, err := readURLList(c.URLList)
		if err != nil {
			return nil, err
		}
		for _, raw := range rawURLs {
			u, err := normalizeURL(raw)
			if err != nil {
				return nil, fmt.Errorf("parse URL %q from %s: %w", raw, c.URLList, err)
			}
			if u != "" && !seen[u] {
				seen[u] = true
				urls = append(urls, u)
			}
		}
	}

	if len(urls) == 0 {
		return nil, fmt.Errorf("no HTTP(S) URLs to analyze")
	}
	return urls, nil
}

// normalizeURL adds a scheme prefix; URLs without http:// or https:// default to https://.
// - //cdn.example.com/lib.js  → ignored
// - mailto:, file:, data: and other non-HTTP(S) schemes → ignored
// - example.com/path  → https://example.com/path
func normalizeURL(u string) (string, error) {
	if u == "" {
		return u, nil
	}
	// Protocol-relative URLs (e.g. //cdn.example.com/lib.js) are not used as entry URLs
	if strings.HasPrefix(u, "//") {
		return "", nil
	}

	candidate := "https://" + u
	// For this tool, non-HTTP(S) entry URLs are ignored.
	if idx := strings.Index(u, ":"); idx > 0 {
		if idx+1 < len(u) && u[idx+1] >= '0' && u[idx+1] <= '9' {
			candidate = "https://" + u
		} else {
			isScheme := true
			for i := 0; i < idx; i++ {
				c := u[i]
				if c == '.' || !isSchemeChar(c) {
					isScheme = false
					break
				}
			}
			if isScheme && isAlpha(u[0]) {
				parsed, err := url.Parse(u)
				if err != nil {
					return "", err
				}
				if !strings.EqualFold(parsed.Scheme, "http") && !strings.EqualFold(parsed.Scheme, "https") {
					return "", nil
				}
				candidate = u
			}
		}
	}

	parsed, err := url.Parse(candidate)
	if err != nil {
		return "", err
	}
	if !strings.EqualFold(parsed.Scheme, "http") && !strings.EqualFold(parsed.Scheme, "https") {
		return "", nil
	}
	if _, err := urlutil.CanonicalOrigin(candidate); err != nil {
		return "", err
	}
	return candidate, nil
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

func readURLList(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read URL list file %s: %w", path, err)
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
		return nil, fmt.Errorf("scan URL list file %s: %w", path, err)
	}
	return urls, nil
}
