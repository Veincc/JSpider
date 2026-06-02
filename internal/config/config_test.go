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
