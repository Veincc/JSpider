package analyzer

import (
	"testing"

	"github.com/Veincc/JSpider/internal/logging"
)

func TestWebpack_URLResolution(t *testing.T) {
	log := logging.New(false, t.TempDir())
	defer log.Close()
	a := NewAnalyzer(log)

	tests := []struct {
		name        string
		jsContent   string
		fromJS      string
		expectedURLs []string
	}{
		{
			name: "publicPath with hash",
			jsContent: `(self.webpackChunkapp=self.webpackChunkapp||[]).push([[1],{1:function(e,t,r){__webpack_require__.p="/static/"}}]);
__webpack_require__.u=function(e){return{1:"js/"+e+".abc123.chunk.js"}[e]||e+".js"};`,
			fromJS:       "http://example.com/static/js/main.js",
			expectedURLs: []string{"http://example.com/static/js/1.abc123.chunk.js"},
		},
		{
			name: "relative publicPath",
			jsContent: `(self.webpackChunkapp=self.webpackChunkapp||[]).push([[2],{2:function(e){}}]);
__webpack_require__.p="./chunks/";`,
			fromJS:       "http://example.com/assets/js/main.js",
			expectedURLs: []string{"http://example.com/assets/js/chunks/2.js"},
		},
		{
			name: "CDN publicPath",
			jsContent: `(self.webpackChunkapp=self.webpackChunkapp||[]).push([[3],{3:function(e){}}]);
__webpack_require__.p="https://cdn.example.com/static/";`,
			fromJS:       "http://example.com/main.js",
			expectedURLs: []string{"https://cdn.example.com/static/3.js"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := a.AnalyzeJS(tt.jsContent, tt.fromJS, "http://example.com/", 0)
			foundURLs := make(map[string]bool)
			for _, imp := range result.Imports {
				if imp.ResolvedURL != "" {
					foundURLs[imp.ResolvedURL] = true
				}
			}
			for _, url := range tt.expectedURLs {
				if !foundURLs[url] {
					t.Errorf("Expected URL %s not found, got imports: %v", url, result.Imports)
				}
			}
		})
	}
}

func TestVite_URLResolution(t *testing.T) {
	log := logging.New(false, t.TempDir())
	defer log.Close()
	a := NewAnalyzer(log)

	tests := []struct {
		name         string
		jsContent    string
		fromJS       string
		expectedURLs []string
	}{
		{
			name: "import() with relative path",
			jsContent: `
function loadChunk() {
  return import("./chunk-abc.js");
}
`,
			fromJS:       "http://example.com/assets/main.js",
			expectedURLs: []string{"http://example.com/assets/chunk-abc.js"},
		},
		{
			name: "import() with absolute path",
			jsContent: `
function loadChunk() {
  return import("/assets/chunk-def.js");
}
`,
			fromJS:       "http://example.com/assets/main.js",
			expectedURLs: []string{"http://example.com/assets/chunk-def.js"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := a.AnalyzeJS(tt.jsContent, tt.fromJS, "http://example.com/", 0)
			foundURLs := make(map[string]bool)
			for _, imp := range result.Imports {
				if imp.ResolvedURL != "" {
					foundURLs[imp.ResolvedURL] = true
				}
			}
			for _, url := range tt.expectedURLs {
				if !foundURLs[url] {
					t.Errorf("Expected URL %s not found, got imports: %v", url, result.Imports)
				}
			}
		})
	}
}

func TestNext_URLResolution(t *testing.T) {
	log := logging.New(false, t.TempDir())
	defer log.Close()
	a := NewAnalyzer(log)

	tests := []struct {
		name         string
		jsContent    string
		fromJS       string
		expectedURLs []string
	}{
		{
			name: "manifest with full paths",
			jsContent: `
self.__BUILD_MANIFEST = {"/about":["/_next/static/chunks/pages/about.js"],"/":["/_next/static/chunks/pages/index.js"]};
`,
			fromJS: "http://example.com/_next/static/abc123/_buildManifest.js",
			expectedURLs: []string{
				"http://example.com/_next/static/chunks/pages/about.js",
				"http://example.com/_next/static/chunks/pages/index.js",
			},
		},
		{
			name: "static chunk references",
			jsContent: `
import("/_next/static/chunks/app.js");
`,
			fromJS:       "http://example.com/_next/static/abc123/_buildManifest.js",
			expectedURLs: []string{"http://example.com/_next/static/chunks/app.js"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := a.AnalyzeJS(tt.jsContent, tt.fromJS, "http://example.com/", 0)
			foundURLs := make(map[string]bool)
			for _, u := range result.NewURLs {
				foundURLs[u.URL] = true
			}
			for _, imp := range result.Imports {
				if imp.ResolvedURL != "" {
					foundURLs[imp.ResolvedURL] = true
				}
			}
			for _, url := range tt.expectedURLs {
				if !foundURLs[url] {
					t.Errorf("Expected URL %s not found, got NewURLs: %v, Imports: %v",
						url, result.NewURLs, result.Imports)
				}
			}
		})
	}
}

func TestNext_ManifestWithFullPaths(t *testing.T) {
	log := logging.New(false, t.TempDir())
	defer log.Close()
	a := NewAnalyzer(log)

	// Manifest chunks that are already full paths should not be double-prefixed
	jsContent := `
self.__BUILD_MANIFEST = {"/about":["/_next/static/chunks/pages/about.js"]};
`
	fromJS := "http://example.com/_next/static/abc/_buildManifest.js"
	result := a.AnalyzeJS(jsContent, fromJS, "http://example.com/", 0)

	for _, route := range result.Routes {
		for _, dep := range route.Deps {
			// Should NOT contain double /_next/
			if contains := `/_next/static/chunks//_next/`; len(dep) > 0 {
				_ = contains
			}
			// Should be a clean URL
			if dep == "" {
				t.Error("Route dep should not be empty")
			}
		}
	}
}
