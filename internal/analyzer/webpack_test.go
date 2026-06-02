package analyzer

import (
	"testing"
)

func TestWebpackAnalyzer_Analyze(t *testing.T) {
	w := NewWebpackAnalyzer(NewRegexAnalyzer())

	js := `
(self.webpackChunkmy_app = self.webpackChunkmy_app || []).push([[123], {
  123: function(e, t, n) { /* module code */ }
}]);

__webpack_require__.p = "/static/";
__webpack_require__.u = function(chunkId) {
  return "js/" + chunkId + "." + {"123":"abc123","456":"def456"}[chunkId] + ".chunk.js";
};

__webpack_require__.e(456);
`

	result := w.Analyze(js, "https://example.com/static/js/main.js")

	if result.Framework != "webpack" {
		t.Errorf("framework = %q, want %q", result.Framework, "webpack")
	}

	found := false
	for _, imp := range result.Imports {
		if imp.Raw == "__webpack_require__.e(456)" {
			found = true
			if imp.ResolvedURL != "https://example.com/static/js/456.def456.chunk.js" {
				t.Fatalf("resolved URL = %q, want %q", imp.ResolvedURL, "https://example.com/static/js/456.def456.chunk.js")
			}
		}
	}
	if !found {
		t.Fatal("missing __webpack_require__.e(456) import")
	}

	t.Logf("Found %d imports, %d routes, %d new URLs", len(result.Imports), len(result.Routes), len(result.NewURLs))

	for _, imp := range result.Imports {
		t.Logf("  import: %s -> %s (source=%s, confidence=%s)",
			imp.Raw, imp.ResolvedURL, imp.Source, imp.Confidence)
	}
}

func TestWebpackAnalyzer_ExtractPublicPath(t *testing.T) {
	w := NewWebpackAnalyzer(NewRegexAnalyzer())

	tests := []struct {
		js   string
		want string
	}{
		{`__webpack_require__.p = "/static/"`, "/static/"},
		{`__webpack_require__.p = "https://cdn.example.com/"`, "https://cdn.example.com/"},
		{`var x = 1`, ""},
	}
	for _, tt := range tests {
		got := w.extractPublicPath(tt.js)
		if got != tt.want {
			t.Errorf("extractPublicPath(%q) = %q, want %q", tt.js, got, tt.want)
		}
	}
}

func TestWebpackAnalyzer_ExtractChunkHashes(t *testing.T) {
	w := NewWebpackAnalyzer(NewRegexAnalyzer())

	js := `var chunkHashes = {"0":"abc123","1":"def456","2":"ghi789"};`
	hashes := w.extractChunkHashes(js)

	if len(hashes) != 3 {
		t.Errorf("expected 3 hashes, got %d", len(hashes))
	}

	if hashes["0"] != "abc123" {
		t.Errorf("hashes[0] = %q, want %q", hashes["0"], "abc123")
	}
}

func TestWebpackAnalyzer_ResolveChunkURL(t *testing.T) {
	w := NewWebpackAnalyzer(NewRegexAnalyzer())

	tests := []struct {
		chunkId       string
		publicPath    string
		hashes        map[string]string
		filenameRule  string
		chunkFilename string
		fromJS        string
		want          string
	}{
		{
			chunkId:    "123",
			publicPath: "/static/",
			hashes:     map[string]string{"123": "abc123"},
			fromJS:     "https://example.com/static/js/main.js",
			want:       "https://example.com/static/123.abc123.js",
		},
		{
			chunkId:    "456",
			publicPath: "/static/",
			hashes:     map[string]string{},
			fromJS:     "https://example.com/static/js/main.js",
			want:       "https://example.com/static/456.js",
		},
	}

	for _, tt := range tests {
		got := w.resolveChunkURL(tt.chunkId, tt.publicPath, tt.hashes, tt.filenameRule, tt.chunkFilename, tt.fromJS)
		if got != tt.want {
			t.Errorf("resolveChunkURL(%q, %q, ...) = %q, want %q", tt.chunkId, tt.publicPath, got, tt.want)
		}
	}
}

func TestWebpackAnalyzer_IsWebpackJS(t *testing.T) {
	w := NewWebpackAnalyzer(NewRegexAnalyzer())

	tests := []struct {
		js   string
		want bool
	}{
		{`__webpack_require__("a")`, true},
		{`self.webpackChunk = []`, true},
		{`webpackJsonp.push([])`, true},
		{`console.log("hello")`, false},
	}
	for _, tt := range tests {
		got := w.IsWebpackJS(tt.js)
		if got != tt.want {
			t.Errorf("IsWebpackJS(%q) = %v, want %v", tt.js[:20], got, tt.want)
		}
	}
}
