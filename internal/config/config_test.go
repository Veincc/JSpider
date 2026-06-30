package config

import (
	"os"
	"path/filepath"
	"reflect"
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeURL(tt.input)
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
	urls := cfg.URLs()
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
	urls := cfg.URLs()
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

	raw := readURLList(listFile)
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
