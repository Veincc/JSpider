package config

import (
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestNormalizeURL(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"empty string", "", ""},
		{"no scheme adds https", "example.com", "https://example.com"},
		{"no scheme with path", "www.example.com/path", "https://www.example.com/path"},
		{"http unchanged", "http://example.com", "http://example.com"},
		{"https unchanged", "https://example.com", "https://example.com"},
		{"protocol-relative URL ignored", "//cdn.example.com/lib.js", ""},
		{"mailto ignored", "mailto:test@example.com", ""},
		{"file ignored", "file:///etc/hosts", ""},
		{"data ignored", "data:text/html,<h1>hi</h1>", ""},
		{"ftp ignored", "ftp://files.example.com/a.txt", ""},
		{"localhost without port adds https", "localhost", "https://localhost"},
		{"localhost with port adds https", "localhost:3000", "https://localhost:3000"},
		{"127.0.0.1 without port adds https", "127.0.0.1", "https://127.0.0.1"},
		{"127.0.0.1 with port adds https", "127.0.0.1:8080", "https://127.0.0.1:8080"},
		{"192.168.1.1 with port adds https", "192.168.1.1:8080/path", "https://192.168.1.1:8080/path"},
		{"IPv6 with port adds https", "[2001:db8::1]:8080/path", "https://[2001:db8::1]:8080/path"},
		{"colon in path adds https", "example.com/path:segment", "https://example.com/path:segment"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeURL(tt.input)
			if err != nil {
				t.Fatalf("normalizeURL(%q) error = %v", tt.input, err)
			}
			if got != tt.want {
				t.Errorf("normalizeURL(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestURLs_Dedup(t *testing.T) {
	cfg := &Config{
		URL: "example.com",
	}
	// example.com normalizes to https://example.com
	urls, err := cfg.URLs()
	if err != nil {
		t.Fatal(err)
	}
	if len(urls) != 1 {
		t.Fatalf("expected 1 URL, got %d: %v", len(urls), urls)
	}
	if urls[0] != "https://example.com" {
		t.Errorf("expected https://example.com, got %s", urls[0])
	}
}

func TestURLs_DedupAcrossSources(t *testing.T) {
	// Write a temp URL list file containing https://example.com
	dir := t.TempDir()
	listFile := filepath.Join(dir, "urls.txt")
	err := os.WriteFile(listFile, []byte("https://example.com\nother.com\n"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		URL:     "example.com", // After normalization == https://example.com
		URLList: listFile,
	}
	urls, err := cfg.URLs()
	if err != nil {
		t.Fatal(err)
	}
	// Expected: https://example.com (deduplicated), https://other.com
	expected := []string{"https://example.com", "https://other.com"}
	if !reflect.DeepEqual(urls, expected) {
		t.Errorf("URLs() = %v, want %v", urls, expected)
	}
}

func TestReadURLList(t *testing.T) {
	dir := t.TempDir()
	listFile := filepath.Join(dir, "urls.txt")
	content := `# comment line
https://a.com

# another comment
example.com
//cdn.example.com/lib.js
mailto:x@y.com
`
	err := os.WriteFile(listFile, []byte(content), 0644)
	if err != nil {
		t.Fatal(err)
	}

	raw, err := readURLList(listFile)
	if err != nil {
		t.Fatal(err)
	}
	// readURLList only filters blank lines/comments, does not normalize schemes
	expected := []string{
		"https://a.com",
		"example.com",
		"//cdn.example.com/lib.js",
		"mailto:x@y.com",
	}
	if !reflect.DeepEqual(raw, expected) {
		t.Errorf("readURLList() = %v, want %v", raw, expected)
	}
}

func TestHeadlessDefaultFalse(t *testing.T) {
	cfg := &Config{}
	if cfg.Headless {
		t.Errorf("zero-value Config.Headless = %v, want false", cfg.Headless)
	}
}

func TestHeadlessCanBeSet(t *testing.T) {
	cfg := &Config{Headless: true}
	if !cfg.Headless {
		t.Error("Config.Headless should be true after setting")
	}
}

func TestAPIDiscoveryImpliesHeadless(t *testing.T) {
	cfg := &Config{APIDiscovery: true}
	ApplyModeImplications(cfg)

	if !cfg.Headless {
		t.Fatal("APIDiscovery should imply Headless")
	}
	if !cfg.APIDiscovery {
		t.Fatal("APIDiscovery should remain enabled")
	}
}

func TestHeadlessAloneDoesNotEnableAPIDiscovery(t *testing.T) {
	cfg := &Config{Headless: true}
	ApplyModeImplications(cfg)

	if cfg.APIDiscovery {
		t.Fatal("Headless alone should not enable APIDiscovery")
	}
}

func TestInsecureSkipVerifyDefaultFalse(t *testing.T) {
	cfg := &Config{}
	if cfg.InsecureSkipVerify {
		t.Errorf("zero-value Config.InsecureSkipVerify = %v, want false", cfg.InsecureSkipVerify)
	}
}

func TestDefaultLimits(t *testing.T) {
	if DefaultMaxDepth != 10 {
		t.Fatalf("DefaultMaxDepth = %d, want 10", DefaultMaxDepth)
	}
	if DefaultMaxSizeMB != 0 {
		t.Fatalf("DefaultMaxSizeMB = %d, want 0", DefaultMaxSizeMB)
	}
	if DefaultProcessTimeoutSeconds != 30 {
		t.Fatalf("DefaultProcessTimeoutSeconds = %d, want 30", DefaultProcessTimeoutSeconds)
	}
	if DefaultHeadlessBodyMB != 8 {
		t.Fatalf("DefaultHeadlessBodyMB = %d, want 8", DefaultHeadlessBodyMB)
	}
}

func TestParseProcessAndHeadlessBodyDefaults(t *testing.T) {
	originalFlags, originalArgs := flag.CommandLine, os.Args
	flag.CommandLine = flag.NewFlagSet("jspider-test", flag.ContinueOnError)
	os.Args = []string{"jspider", "-u", "https://example.com"}
	t.Cleanup(func() {
		flag.CommandLine = originalFlags
		os.Args = originalArgs
	})

	cfg := Parse()
	if cfg.ProcessTimeoutSeconds != 30 {
		t.Fatalf("ProcessTimeoutSeconds = %d, want 30", cfg.ProcessTimeoutSeconds)
	}
	if cfg.HeadlessBodyMB != 8 {
		t.Fatalf("HeadlessBodyMB = %d, want 8", cfg.HeadlessBodyMB)
	}
}

func TestParseProcessAndHeadlessBodyOverrides(t *testing.T) {
	originalFlags, originalArgs := flag.CommandLine, os.Args
	flag.CommandLine = flag.NewFlagSet("jspider-test", flag.ContinueOnError)
	os.Args = []string{"jspider", "-u", "https://example.com", "--process-timeout", "45", "--headless-body-mb", "12"}
	t.Cleanup(func() {
		flag.CommandLine = originalFlags
		os.Args = originalArgs
	})

	cfg := Parse()
	if cfg.ProcessTimeoutSeconds != 45 || cfg.HeadlessBodyMB != 12 {
		t.Fatalf("parsed limits = process %d, headless body %d", cfg.ProcessTimeoutSeconds, cfg.HeadlessBodyMB)
	}
}

func TestDepthFlagDocumentsZeroAsNoRecursion(t *testing.T) {
	originalFlags, originalArgs := flag.CommandLine, os.Args
	flag.CommandLine = flag.NewFlagSet("jspider-test", flag.ContinueOnError)
	os.Args = []string{"jspider", "-u", "https://example.com"}
	t.Cleanup(func() {
		flag.CommandLine = originalFlags
		os.Args = originalArgs
	})

	_ = Parse()
	depthFlag := flag.Lookup("d")
	if depthFlag == nil || !strings.Contains(depthFlag.Usage, "0=no recursion") {
		t.Fatalf("-d usage = %v, want 0=no recursion", depthFlag)
	}
}

func TestValidateRejectsImpossibleValues(t *testing.T) {
	valid := Config{
		URL:                   "https://example.com",
		OutDir:                "output",
		MaxJS:                 0,
		MaxDepth:              0,
		MaxSizeMB:             0,
		Workers:               1,
		Timeout:               1,
		ProcessTimeoutSeconds: 1,
		HeadlessBodyMB:        1,
	}
	tests := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{name: "missing URL input", mutate: func(c *Config) { c.URL = "" }, want: "URL"},
		{name: "empty output directory", mutate: func(c *Config) { c.OutDir = "" }, want: "output"},
		{name: "zero workers", mutate: func(c *Config) { c.Workers = 0 }, want: "workers"},
		{name: "negative workers", mutate: func(c *Config) { c.Workers = -1 }, want: "workers"},
		{name: "negative depth", mutate: func(c *Config) { c.MaxDepth = -1 }, want: "depth"},
		{name: "negative JavaScript limit", mutate: func(c *Config) { c.MaxJS = -1 }, want: "JavaScript"},
		{name: "negative size limit", mutate: func(c *Config) { c.MaxSizeMB = -1 }, want: "size"},
		{name: "zero HTTP timeout", mutate: func(c *Config) { c.Timeout = 0 }, want: "HTTP timeout"},
		{name: "zero process timeout", mutate: func(c *Config) { c.ProcessTimeoutSeconds = 0 }, want: "process timeout"},
		{name: "zero headless body limit", mutate: func(c *Config) { c.HeadlessBodyMB = 0 }, want: "headless body"},
		{name: "invalid proxy", mutate: func(c *Config) { c.Proxy = "ftp://proxy.example" }, want: "proxy"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := valid
			tt.mutate(&cfg)
			err := cfg.Validate()
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tt.want)) {
				t.Fatalf("Validate() error = %v, want containing %q", err, tt.want)
			}
		})
	}

	if err := valid.Validate(); err != nil {
		t.Fatalf("valid Config rejected: %v", err)
	}
}

func TestURLsReturnsFileAndScannerErrors(t *testing.T) {
	t.Run("missing file", func(t *testing.T) {
		cfg := &Config{URLList: filepath.Join(t.TempDir(), "missing.txt")}
		if _, err := cfg.URLs(); err == nil {
			t.Fatal("URLs() returned no error for a missing file")
		}
	})

	t.Run("scanner limit", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "too-long.txt")
		if err := os.WriteFile(path, []byte(strings.Repeat("a", 1024*1024+1)), 0600); err != nil {
			t.Fatal(err)
		}
		cfg := &Config{URLList: path}
		if _, err := cfg.URLs(); err == nil {
			t.Fatal("URLs() returned no scanner error for an oversized line")
		}
	})
}

func TestURLsReturnsHTTPParseErrors(t *testing.T) {
	for _, raw := range []string{
		"http://",
		"https://example.com:invalid",
		"https://\u200d.example",
		"https://\u00ad",
	} {
		t.Run(raw, func(t *testing.T) {
			cfg := &Config{URL: raw}
			if _, err := cfg.URLs(); err == nil {
				t.Fatalf("URLs() returned no error for %q", raw)
			}
		})
	}
}

func TestURLsRejectsAnInputSetWithNoHTTPEntries(t *testing.T) {
	cfg := &Config{URL: "mailto:test@example.com"}
	if _, err := cfg.URLs(); err == nil {
		t.Fatal("URLs() returned no error after filtering every input")
	}
}

func TestNormalizeProxy(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "empty", input: "", want: ""},
		{name: "default HTTP scheme", input: "127.0.0.1:8080", want: "http://127.0.0.1:8080"},
		{name: "HTTP", input: "http://proxy.example:8080", want: "http://proxy.example:8080"},
		{name: "HTTPS", input: "https://proxy.example:8443", want: "https://proxy.example:8443"},
		{name: "SOCKS5", input: "socks5://127.0.0.1:1080", want: "socks5://127.0.0.1:1080"},
		{name: "unsupported scheme", input: "ftp://proxy.example:21", wantErr: true},
		{name: "missing host", input: "http://", wantErr: true},
		{name: "path rejected", input: "http://proxy.example/path", wantErr: true},
		{name: "query rejected", input: "http://proxy.example?x=1", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeProxy(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("NormalizeProxy(%q) returned no error", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeProxy(%q) error = %v", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("NormalizeProxy(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
