package headless

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Veincc/JSpider/internal/analyzer"
	"github.com/Veincc/JSpider/internal/logging"
	"github.com/Veincc/JSpider/internal/urlutil"
)

func TestCheckBrowserAvailable_NoBrowser(t *testing.T) {
	err := CheckBrowserAvailable()
	if err == nil {
		t.Log("Chrome/Chromium found on system")
		return
	}
	msg := err.Error()
	if !contains(msg, "Chrome/Chromium") {
		t.Errorf("Error message should mention Chrome/Chromium: %s", msg)
	}
}

func TestExtractScriptSrcs(t *testing.T) {
	tests := []struct {
		name string
		html string
		want []string
	}{
		{
			name: "single script src",
			html: `<script src="/assets/main.js"></script>`,
			want: []string{"/assets/main.js"},
		},
		{
			name: "multiple scripts",
			html: `<script src="/a.js"></script><script src="/b.js"></script>`,
			want: []string{"/a.js", "/b.js"},
		},
		{
			name: "no script src",
			html: `<script>console.log("inline")</script>`,
			want: nil,
		},
		{
			name: "script with type attribute",
			html: `<script type="module" src="/app.mjs"></script>`,
			want: []string{"/app.mjs"},
		},
		{
			name: "empty line",
			html: "",
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractScriptSrcs(tt.html)
			if len(got) != len(tt.want) {
				t.Errorf("extractScriptSrcs() = %v, want %v", got, tt.want)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("extractScriptSrcs()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestExtractLinkScripts(t *testing.T) {
	tests := []struct {
		name string
		html string
		want []string
	}{
		{
			name: "modulepreload",
			html: `<link rel="modulepreload" href="/assets/chunk.js">`,
			want: []string{"/assets/chunk.js"},
		},
		{
			name: "preload as script",
			html: `<link rel="preload" as="script" href="/assets/lib.js">`,
			want: []string{"/assets/lib.js"},
		},
		{
			name: "prefetch as script",
			html: `<link rel="prefetch" as="script" href="/assets/future.js">`,
			want: []string{"/assets/future.js"},
		},
		{
			name: "preload as style (not script)",
			html: `<link rel="preload" as="style" href="/assets/style.css">`,
			want: nil,
		},
		{
			name: "stylesheet (not script)",
			html: `<link rel="stylesheet" href="/assets/style.css">`,
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractLinkScripts(tt.html)
			if len(got) != len(tt.want) {
				t.Errorf("extractLinkScripts() = %v, want %v", got, tt.want)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("extractLinkScripts()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestExtractAttr(t *testing.T) {
	tests := []struct {
		tag  string
		attr string
		want string
	}{
		{`<script src="/app.js">`, "src", "/app.js"},
		{`<script src='/app.js'>`, "src", "/app.js"},
		{`<script src=/app.js>`, "src", "/app.js"},
		{`<script src = "/app.js">`, "src", "/app.js"},
		{`<script type="module" src="/app.js">`, "src", "/app.js"},
		{`<script data-src="/lazy.js">`, "src", ""},
		{`<link data-href="/lazy.js" rel="modulepreload">`, "href", ""},
		{`<link rel="modulepreload" href="/chunk.js">`, "href", "/chunk.js"},
		{`<script>`, "src", ""},
		{`<link rel="preload">`, "href", ""},
	}
	for _, tt := range tests {
		t.Run(tt.tag, func(t *testing.T) {
			got := extractAttr(tt.tag, tt.attr)
			if got != tt.want {
				t.Errorf("extractAttr(%q, %q) = %q, want %q", tt.tag, tt.attr, got, tt.want)
			}
		})
	}
}

func TestExtractFromDOM_DoesNotTreatDataSrcAsScriptSrc(t *testing.T) {
	cfg := &Config{
		EntryURL:   "https://example.com/",
		SameOrigin: true,
	}

	assets := extractFromDOM(`<script data-src="/lazy.js"></script><script src="/app.js"></script>`, cfg)

	found := make(map[string]bool)
	for _, a := range assets {
		found[a.URL] = true
	}
	if found["https://example.com/lazy.js"] {
		t.Fatalf("data-src was extracted as a script URL: %+v", assets)
	}
	if !found["https://example.com/app.js"] {
		t.Fatalf("real script src was not extracted: %+v", assets)
	}
}

func TestNetworkCaptureWaitForResponseBodies(t *testing.T) {
	capture := newNetworkCapture()
	capture.beginResponseBody()

	done := make(chan struct{})
	go func() {
		time.Sleep(10 * time.Millisecond)
		capture.endResponseBody()
		close(done)
	}()

	if !capture.waitForResponseBodies(200 * time.Millisecond) {
		t.Fatal("waitForResponseBodies timed out before pending body completed")
	}
	<-done

	capture.beginResponseBody()
	if capture.waitForResponseBodies(1 * time.Millisecond) {
		t.Fatal("waitForResponseBodies returned true while body was still pending")
	}
	capture.endResponseBody()
}

func TestResolveURL(t *testing.T) {
	base := "https://example.com/page/"
	tests := []struct {
		rawURL string
		want   string
	}{
		{"https://cdn.example.com/a.js", "https://cdn.example.com/a.js"},
		{"//cdn.example.com/a.js", "https://cdn.example.com/a.js"},
		{"/assets/main.js", "https://example.com/assets/main.js"},
		{"./chunk.js", "https://example.com/page/chunk.js"},
		{"", ""},
	}
	for _, tt := range tests {
		got := resolveURL(tt.rawURL, base)
		if got != tt.want {
			t.Errorf("resolveURL(%q, %q) = %q, want %q", tt.rawURL, base, got, tt.want)
		}
	}
}

func TestExtractFromDOM(t *testing.T) {
	cfg := &Config{
		EntryURL:   "https://example.com/",
		SameOrigin: true,
	}

	html := `<html>
<head>
<link rel="modulepreload" href="/assets/chunk.js">
<link rel="preload" as="script" href="/assets/lib.js">
</head>
<body>
<script src="/assets/main.js"></script>
<script type="module" src="/assets/app.mjs"></script>
<script>console.log("inline")</script>
</body>
</html>`

	assets := extractFromDOM(html, cfg)

	expectedURLs := map[string]bool{
		"https://example.com/assets/main.js":  false,
		"https://example.com/assets/app.mjs":  false,
		"https://example.com/assets/chunk.js": false,
		"https://example.com/assets/lib.js":   false,
	}

	for _, a := range assets {
		if _, ok := expectedURLs[a.URL]; ok {
			expectedURLs[a.URL] = true
		} else {
			t.Errorf("Unexpected URL: %s", a.URL)
		}
	}

	for url, found := range expectedURLs {
		if !found {
			t.Errorf("Expected URL not found: %s", url)
		}
	}

	// Verify sources
	for _, a := range assets {
		if a.Source != analyzer.SourceHeadlessDOM {
			t.Errorf("Expected source %q, got %q for %s", analyzer.SourceHeadlessDOM, a.Source, a.URL)
		}
	}
}

func TestExtractFromDOM_SameOriginFilter(t *testing.T) {
	cfg := &Config{
		EntryURL:   "https://example.com/",
		SameOrigin: true,
	}

	html := `<script src="/app.js"></script><script src="https://cdn.other.com/lib.js"></script>`

	assets := extractFromDOM(html, cfg)

	if len(assets) != 1 {
		t.Fatalf("Expected 1 asset (same-origin only), got %d: %v", len(assets), assets)
	}
	if assets[0].URL != "https://example.com/app.js" {
		t.Errorf("Expected same-origin URL, got %s", assets[0].URL)
	}
}

func TestExtractURLsFromLogLine(t *testing.T) {
	tests := []struct {
		name string
		line string
		want int
	}{
		{
			name: "url: pattern",
			line: "VERBOSE1:URLRequest::Start url:https://example.com/assets/main.js",
			want: 1,
		},
		{
			name: "raw https URL",
			line: "Fetching https://example.com/chunk.js from network",
			want: 1,
		},
		{
			name: "no URLs",
			line: "Some random log line without URLs",
			want: 0,
		},
		{
			name: "multiple URLs",
			line: "Redirect from https://example.com/a.js to https://cdn.example.com/a.js",
			want: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractURLsFromLogLine(tt.line)
			if len(got) != tt.want {
				t.Errorf("extractURLsFromLogLine(%q) = %v (len=%d), want len=%d", tt.line, got, len(got), tt.want)
			}
		})
	}
}

func TestIsDangerousElement(t *testing.T) {
	tests := []struct {
		text, href string
		want       bool
	}{
		{"Log Out", "", true},
		{"Sign Out", "/logout", true},
		{"Delete Account", "", true},
		{"Submit Form", "", true},
		{"Download Report", "/download/report.pdf", true},
		{"Save Changes", "", true},
		{"Pay Now", "/checkout", true},
		// Safe elements
		{"Home", "/", false},
		{"About", "/about", false},
		{"Learn More", "/docs", false},
		{"View Details", "/details/123", false},
	}
	for _, tt := range tests {
		got := IsDangerousElement(tt.text, tt.href)
		if got != tt.want {
			t.Errorf("IsDangerousElement(%q, %q) = %v, want %v", tt.text, tt.href, got, tt.want)
		}
	}
}

func TestParseJSPathsFromText_JSONResponse(t *testing.T) {
	// Test extracting JS URLs from a JSON config response
	jsonBody := `{
		"scripts": [
			"/assets/main.js",
			"/assets/chunk-abc.js"
		],
		"entrypoint": "/app/entry.js?v=123",
		"styles": ["/assets/style.css"],
		"config": {
			"worker": "./worker.js"
		}
	}`

	urls := ParseJSPathsFromText(jsonBody, "https://example.com/")

	expected := map[string]bool{
		"https://example.com/assets/main.js":      false,
		"https://example.com/assets/chunk-abc.js": false,
		"https://example.com/app/entry.js?v=123":  false,
		"https://example.com/worker.js":           false,
	}

	for _, u := range urls {
		if _, ok := expected[u]; ok {
			expected[u] = true
		} else {
			t.Errorf("Unexpected URL extracted: %s", u)
		}
	}

	for u, found := range expected {
		if !found {
			t.Errorf("Expected URL not found in JSON response: %s", u)
		}
	}
}

func TestParseJSPathsFromText_TextResponse(t *testing.T) {
	// Test extracting JS URLs from a text response (e.g., config file)
	textBody := `// Application configuration
var config = {
  apiEndpoint: "/api/v1",
  scripts: [
    "/assets/vendor.js",
    "/assets/app.js"
  ]
};
// Load additional module
loadScript("/plugins/analytics.js");
`

	urls := ParseJSPathsFromText(textBody, "https://example.com/")

	expected := map[string]bool{
		"https://example.com/assets/vendor.js":     false,
		"https://example.com/assets/app.js":        false,
		"https://example.com/plugins/analytics.js": false,
	}

	for _, u := range urls {
		if _, ok := expected[u]; ok {
			expected[u] = true
		}
	}

	for u, found := range expected {
		if !found {
			t.Errorf("Expected URL not found in text response: %s", u)
		}
	}
}

func TestParseJSPathsFromText_RelativePaths(t *testing.T) {
	// Test extracting relative JS paths from response bodies
	textBody := `{
		"module": "./src/index.js",
		"chunk": "../chunks/worker.js"
	}`

	urls := ParseJSPathsFromText(textBody, "https://example.com/app/config.json")

	// Relative paths should be resolved against the response URL
	found := false
	for _, u := range urls {
		if u == "https://example.com/app/src/index.js" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected ./src/index.js resolved to https://example.com/app/src/index.js, got %v", urls)
	}
}

func TestParseJSPathsFromText_NoJSPaths(t *testing.T) {
	// Test that non-JS content doesn't produce false positives
	textBody := `{
		"name": "My App",
		"version": "1.0.0",
		"author": "test@example.com",
		"homepage": "https://example.com/about"
	}`

	urls := ParseJSPathsFromText(textBody, "https://example.com/")

	if len(urls) != 0 {
		t.Errorf("Expected no JS paths from plain JSON, got %v", urls)
	}
}

func TestIsAllowedByPolicy(t *testing.T) {
	tests := []struct {
		url   string
		sameO bool
		cdns  []string
		entry string
		want  bool
	}{
		{"https://example.com/a.js", true, nil, "https://example.com/", true},
		{"https://cdn.example.com/a.js", true, []string{"cdn.example.com"}, "https://example.com/", true},
		{"https://other.com/a.js", true, nil, "https://example.com/", false},
		{"https://other.com/a.js", false, nil, "https://example.com/", true}, // same-origin disabled
	}
	for _, tt := range tests {
		cfg := &Config{
			EntryURL:   tt.entry,
			SameOrigin: tt.sameO,
			AllowCDN:   tt.cdns,
		}
		got := isAllowedByPolicy(tt.url, cfg)
		if got != tt.want {
			t.Errorf("isAllowedByPolicy(%q, sameOrigin=%v) = %v, want %v", tt.url, tt.sameO, got, tt.want)
		}
	}
}

func TestDiscover_NoBrowser(t *testing.T) {
	if err := CheckBrowserAvailable(); err == nil {
		t.Skip("Chrome available, skipping no-browser test")
	}

	log := logging.New(false, t.TempDir())
	defer log.Close()

	cfg := &Config{
		EntryURL: "https://example.com/",
	}
	_, err := Discover(context.Background(), cfg, log)
	if err == nil {
		t.Error("Expected error when no browser available, got nil")
	}
}

// Integration test: only runs when JSPIDER_HEADLESS_TEST=1
func TestDiscover_Integration(t *testing.T) {
	if os.Getenv("JSPIDER_HEADLESS_TEST") != "1" {
		t.Skip("Set JSPIDER_HEADLESS_TEST=1 to run headless integration tests")
	}

	if err := CheckBrowserAvailable(); err != nil {
		t.Skipf("Chrome not available: %v", err)
	}

	log := logging.New(true, t.TempDir())
	defer log.Close()

	cfg := &Config{
		EntryURL:   "https://example.com/",
		SameOrigin: true,
		MaxClicks:  5,
		Verbose:    true,
	}

	assets, err := Discover(context.Background(), cfg, log)
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}

	t.Logf("Discovered %d assets", len(assets))
	for _, a := range assets {
		t.Logf("  %s (source=%s, confidence=%s)", a.URL, a.Source, a.Confidence)
	}

	for _, a := range assets {
		switch a.Source {
		case analyzer.SourceHeadlessNetwork, analyzer.SourceHeadlessDOM, analyzer.SourceHeadlessResponse:
			// OK
		default:
			t.Errorf("Unexpected source %q for %s", a.Source, a.URL)
		}
	}
}

func TestCleanDiscoveredJSURL(t *testing.T) {
	tests := []struct {
		name      string
		raw       string
		base      string
		wantURL   string
		wantValid bool
	}{
		// The exact bug from vite.dev
		{
			name:      "trailing backslash from JS escape",
			raw:       `https://vite.dev/assets/chunks/footer-background.4sTmNkbe.js\`,
			base:      "",
			wantURL:   "https://vite.dev/assets/chunks/footer-background.4sTmNkbe.js",
			wantValid: true,
		},
		// JSON escaped forward slashes
		{
			name:      "JSON escaped slashes in path",
			raw:       `\/assets\/app.js`,
			base:      "https://example.com/",
			wantURL:   "https://example.com/assets/app.js",
			wantValid: true,
		},
		// Trailing backslash after a quoted .js path
		{
			name:      "quoted path with trailing backslash",
			raw:       `/assets/foo.js\`,
			base:      "https://example.com/",
			wantURL:   "https://example.com/assets/foo.js",
			wantValid: true,
		},
		// Surrounding double quotes
		{
			name:      "surrounding double quotes stripped",
			raw:       `"/assets/main.js"`,
			base:      "https://example.com/",
			wantURL:   "https://example.com/assets/main.js",
			wantValid: true,
		},
		// Surrounding single quotes
		{
			name:      "surrounding single quotes stripped",
			raw:       `'/assets/main.js'`,
			base:      "https://example.com/",
			wantURL:   "https://example.com/assets/main.js",
			wantValid: true,
		},
		// Trailing semicolon
		{
			name:      "trailing semicolon stripped",
			raw:       `/assets/app.js;`,
			base:      "https://example.com/",
			wantURL:   "https://example.com/assets/app.js",
			wantValid: true,
		},
		// Trailing comma
		{
			name:      "trailing comma stripped",
			raw:       `/assets/app.js,`,
			base:      "https://example.com/",
			wantURL:   "https://example.com/assets/app.js",
			wantValid: true,
		},
		// Trailing closing paren
		{
			name:      "trailing paren stripped",
			raw:       `/assets/app.js)`,
			base:      "https://example.com/",
			wantURL:   "https://example.com/assets/app.js",
			wantValid: true,
		},
		// Fragment stripped
		{
			name:      "fragment stripped",
			raw:       `/assets/app.js#section`,
			base:      "https://example.com/",
			wantURL:   "https://example.com/assets/app.js",
			wantValid: true,
		},
		// Absolute URL with scheme — valid
		{
			name:      "full https URL",
			raw:       `https://cdn.example.com/lib.js`,
			base:      "",
			wantURL:   "https://cdn.example.com/lib.js",
			wantValid: true,
		},
		// Non-http scheme rejected
		{
			name:      "ftp scheme rejected",
			raw:       `ftp://example.com/file.js`,
			base:      "",
			wantURL:   "",
			wantValid: false,
		},
		// Empty input
		{
			name:      "empty string",
			raw:       "",
			base:      "",
			wantURL:   "",
			wantValid: false,
		},
		// Whitespace only
		{
			name:      "whitespace only",
			raw:       "   \t  ",
			base:      "",
			wantURL:   "",
			wantValid: false,
		},
		// Windows path — not a URL
		{
			name:      "Windows path rejected",
			raw:       `C:\Users\test\app.js`,
			base:      "",
			wantURL:   "",
			wantValid: false,
		},
		// Plain text — not a URL
		{
			name:      "plain text rejected",
			raw:       "this is not a url at all",
			base:      "",
			wantURL:   "",
			wantValid: false,
		},
		// Relative path without base
		{
			name:      "relative path without base rejected",
			raw:       "./assets/app.js",
			base:      "",
			wantURL:   "",
			wantValid: false,
		},
		// Multiple trailing garbage
		{
			name:      "multiple trailing garbage stripped",
			raw:       `/assets/app.js\");`,
			base:      "https://example.com/",
			wantURL:   "https://example.com/assets/app.js",
			wantValid: true,
		},
		// JSON escaped with escaped quote
		{
			name:      "JSON escaped quote and slash",
			raw:       `\/assets\/chunk.js\"`,
			base:      "https://example.com/",
			wantURL:   "https://example.com/assets/chunk.js",
			wantValid: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotURL, gotValid := CleanDiscoveredJSURL(tt.raw, tt.base)
			if gotValid != tt.wantValid {
				t.Errorf("CleanDiscoveredJSURL(%q, %q) valid = %v, want %v", tt.raw, tt.base, gotValid, tt.wantValid)
			}
			if gotURL != tt.wantURL {
				t.Errorf("CleanDiscoveredJSURL(%q, %q) url = %q, want %q", tt.raw, tt.base, gotURL, tt.wantURL)
			}
		})
	}
}

func TestParseJSPathsFromText_JSONEscapedSlashes(t *testing.T) {
	// Simulate a Vite manifest or similar JSON with \/\/ escape sequences
	jsonBody := `{
		"chunks": [
			"\/assets\/chunks\/footer-background.4sTmNkbe.js",
			"\/assets\/chunks\/theme.abc123.js"
		]
	}`

	urls := ParseJSPathsFromText(jsonBody, "https://vite.dev/")

	for _, u := range urls {
		if strings.HasSuffix(u, `\`) {
			t.Errorf("URL should not end with backslash: %s", u)
		}
	}

	want := map[string]bool{
		"https://vite.dev/assets/chunks/footer-background.4sTmNkbe.js": false,
		"https://vite.dev/assets/chunks/theme.abc123.js":               false,
	}
	for _, u := range urls {
		if _, ok := want[u]; ok {
			want[u] = true
		} else {
			t.Errorf("Unexpected URL: %s", u)
		}
	}
	for u, found := range want {
		if !found {
			t.Errorf("Expected URL not found: %s", u)
		}
	}
}

func TestParseJSPathsFromText_TrailingBackslashNotIncluded(t *testing.T) {
	// Text containing .js paths. The regex char class does not include \,
	// so a trailing \ before a closing " is naturally skipped — the regex
	// captures /assets/foo.js (without \) and " acts as the delimiter.
	// No extracted URL should ever end with a backslash.
	textBody := `loadModule("/assets/foo.js\");
another("/assets/bar.js");
third("/assets/baz.js");
`

	urls := ParseJSPathsFromText(textBody, "https://example.com/")

	for _, u := range urls {
		if strings.HasSuffix(u, `\`) {
			t.Errorf("URL should not end with backslash: %s", u)
		}
	}

	want := map[string]bool{
		"https://example.com/assets/bar.js": false,
		"https://example.com/assets/baz.js": false,
	}
	for _, u := range urls {
		if _, ok := want[u]; ok {
			want[u] = true
		}
	}
	for u, found := range want {
		if !found {
			t.Errorf("Expected URL not found: %s", u)
		}
	}
}

func TestParseJSPathsFromText_WindowsPathNotMisidentified(t *testing.T) {
	// Windows paths and non-JS text should not be extracted
	textBody := `{
		"error": "C:\\Users\\test\\app.js not found",
		"message": "File D:\\projects\\src\\main.js is missing",
		"note": "just some random text with .js extension mentioned"
	}`

	urls := ParseJSPathsFromText(textBody, "https://example.com/")

	for _, u := range urls {
		if strings.Contains(u, "Users") || strings.Contains(u, "projects") {
			t.Errorf("Windows path should not be extracted as JS URL: %s", u)
		}
	}
}

func TestResolveDiscoveredJSURL(t *testing.T) {
	tests := []struct {
		name   string
		base   string
		raw    string
		want   string
		wantOK bool
	}{
		// The original vite.dev bug: bare "assets/chunks/..." resolved against a JS in /assets/chunks/
		{
			name:   "bare assets/chunks path from within assets/chunks",
			base:   "https://vite.dev/assets/chunks/theme.js",
			raw:    "assets/chunks/client.BFYbw6Gq.js",
			want:   "https://vite.dev/assets/chunks/client.BFYbw6Gq.js",
			wantOK: true,
		},
		{
			name:   "bare chunks/ path from within assets/chunks",
			base:   "https://vite.dev/assets/chunks/theme.js",
			raw:    "chunks/client.BFYbw6Gq.js",
			want:   "https://vite.dev/assets/chunks/client.BFYbw6Gq.js",
			wantOK: true,
		},
		{
			name:   "bare chunks/ path from assets/app.js",
			base:   "https://vite.dev/assets/app.js",
			raw:    "chunks/client.js",
			want:   "https://vite.dev/assets/chunks/client.js",
			wantOK: true,
		},
		// Explicit relative paths — standard resolution
		{
			name:   "dot-slash relative",
			base:   "https://example.com/app/main.js",
			raw:    "./chunk.js",
			want:   "https://example.com/app/chunk.js",
			wantOK: true,
		},
		{
			name:   "dot-dot-slash relative",
			base:   "https://example.com/app/main.js",
			raw:    "../lib/utils.js",
			want:   "https://example.com/lib/utils.js",
			wantOK: true,
		},
		// Absolute path from origin
		{
			name:   "absolute path",
			base:   "https://vite.dev/assets/chunks/theme.js",
			raw:    "/assets/main.js",
			want:   "https://vite.dev/assets/main.js",
			wantOK: true,
		},
		// Full absolute URL
		{
			name:   "full URL passthrough",
			base:   "https://vite.dev/",
			raw:    "https://cdn.example.com/lib.js",
			want:   "https://cdn.example.com/lib.js",
			wantOK: true,
		},
		// Protocol-relative
		{
			name:   "protocol-relative",
			base:   "https://vite.dev/",
			raw:    "//cdn.example.com/lib.js",
			want:   "https://cdn.example.com/lib.js",
			wantOK: true,
		},
		// Deduplication: double assets/chunks
		{
			name:   "dedup double assets/chunks",
			base:   "https://vite.dev/assets/chunks/theme.js",
			raw:    "assets/chunks/plugin-vue_export-helper.BDNMzG2s.js",
			want:   "https://vite.dev/assets/chunks/plugin-vue_export-helper.BDNMzG2s.js",
			wantOK: true,
		},
		// _nuxt prefix
		{
			name:   "bare _nuxt path",
			base:   "https://example.com/_nuxt/entry.js",
			raw:    "_nuxt/chunks/app.js",
			want:   "https://example.com/_nuxt/chunks/app.js",
			wantOK: true,
		},
		// _next/static prefix
		{
			name:   "bare _next/static path",
			base:   "https://example.com/_next/static/chunks/app.js",
			raw:    "_next/static/chunks/pages/index.js",
			want:   "https://example.com/_next/static/chunks/pages/index.js",
			wantOK: true,
		},
		// Empty
		{
			name:   "empty raw",
			base:   "https://example.com/",
			raw:    "",
			want:   "",
			wantOK: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ResolveDiscoveredJSURL(tt.base, tt.raw)
			if ok != tt.wantOK {
				t.Errorf("ResolveDiscoveredJSURL(%q, %q) ok = %v, want %v", tt.base, tt.raw, ok, tt.wantOK)
			}
			if got != tt.want {
				t.Errorf("ResolveDiscoveredJSURL(%q, %q) = %q, want %q", tt.base, tt.raw, got, tt.want)
			}
		})
	}
}

func TestDeduplicatePathSegments(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"https://vite.dev/assets/chunks/assets/chunks/client.js", "https://vite.dev/assets/chunks/client.js"},
		{"https://example.com/a/b/a/b/c.js", "https://example.com/a/b/c.js"},
		{"https://example.com/assets/main.js", "https://example.com/assets/main.js"}, // no dup
		{"https://example.com/a/a/b/b/c.js", "https://example.com/a/b/c.js"},         // consecutive dups collapsed
		{"https://example.com/a/b/c.js", "https://example.com/a/b/c.js"},             // short path
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := urlutil.DeduplicatePathSegments(tt.input)
			if got != tt.want {
				t.Errorf("urlutil.DeduplicatePathSegments(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestCleanDiscoveredJSURL_BuildPrefix(t *testing.T) {
	// Test that CleanDiscoveredJSURL uses ResolveDiscoveredJSURL for build-prefix paths
	tests := []struct {
		name string
		raw  string
		base string
		want string
	}{
		{
			name: "bare assets/chunks from within assets/chunks",
			raw:  "assets/chunks/client.js",
			base: "https://vite.dev/assets/chunks/theme.js",
			want: "https://vite.dev/assets/chunks/client.js",
		},
		{
			name: "bare chunks/ from within assets/chunks",
			raw:  "chunks/client.js",
			base: "https://vite.dev/assets/chunks/theme.js",
			want: "https://vite.dev/assets/chunks/client.js",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := CleanDiscoveredJSURL(tt.raw, tt.base)
			if !ok {
				t.Errorf("CleanDiscoveredJSURL(%q, %q) returned false", tt.raw, tt.base)
			}
			if got != tt.want {
				t.Errorf("CleanDiscoveredJSURL(%q, %q) = %q, want %q", tt.raw, tt.base, got, tt.want)
			}
		})
	}
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
