package analyzer

import (
	"testing"

	"github.com/Veincc/JSpider/internal/logging"
)

func TestAST_ExtractsDynamicImport(t *testing.T) {
	log := logging.New(false, t.TempDir())
	defer log.Close()
	a := NewAnalyzer(log)

	jsContent := `
function loadChunk() {
  return import("./chunk.js");
}
loadChunk();
`
	result := a.AnalyzeJS(jsContent, "http://example.com/app.js", "http://example.com/", 0)

	found := false
	for _, imp := range result.Imports {
		if imp.Raw == "./chunk.js" {
			found = true
			if imp.ResolvedURL != "http://example.com/chunk.js" {
				t.Errorf("Expected resolved URL http://example.com/chunk.js, got %s", imp.ResolvedURL)
			}
			break
		}
	}
	if !found {
		t.Errorf("Expected import('./chunk.js') to be extracted, imports: %v", result.Imports)
	}
}

func TestAST_ExtractsStaticImportsAndReExports(t *testing.T) {
	log := logging.New(false, t.TempDir())
	defer log.Close()
	a := NewAnalyzer(log)

	assets := a.DiscoverJS(`
import "./side-effect.js";
import value from "./dependency.js";
export { value as renamed } from "./re-export.js";
export * from "./all.js";
`, "https://example.com/assets/main.js")

	want := map[string]bool{
		"https://example.com/assets/side-effect.js": false,
		"https://example.com/assets/dependency.js":  false,
		"https://example.com/assets/re-export.js":   false,
		"https://example.com/assets/all.js":         false,
	}
	for _, asset := range assets {
		if _, ok := want[asset.URL]; ok {
			want[asset.URL] = true
		}
	}
	for rawURL, found := range want {
		if !found {
			t.Errorf("static ESM dependency %s not discovered; assets=%+v", rawURL, assets)
		}
	}
}

func TestAST_DoesNotResolveBareDynamicImportSpecifier(t *testing.T) {
	log := logging.New(false, t.TempDir())
	defer log.Close()
	a := NewAnalyzer(log)

	result := a.AnalyzeJS(`import("react");`, "http://example.com/assets/app.js", "http://example.com/", 0)

	found := false
	for _, imp := range result.Imports {
		if imp.Raw == "react" {
			found = true
			if imp.ResolvedURL != "" {
				t.Fatalf("bare import resolved to %q, want empty", imp.ResolvedURL)
			}
			if imp.Confidence != ConfMedium {
				t.Fatalf("bare import confidence = %q, want %q", imp.Confidence, ConfMedium)
			}
		}
	}
	if !found {
		t.Fatalf("bare import not found: %+v", result.Imports)
	}
	if len(result.NewURLs) != 0 {
		t.Fatalf("bare import should not create NewURLs, got %+v", result.NewURLs)
	}
}

func TestAST_ExtractsRoutePath(t *testing.T) {
	log := logging.New(false, t.TempDir())
	defer log.Close()
	a := NewAnalyzer(log)

	jsContent := `
var routes = [
  { path: "/about", component: () => import("./About.js") },
  { path: "/users", component: () => import("./Users.js") }
];
`
	result := a.AnalyzeJS(jsContent, "http://example.com/router.js", "http://example.com/", 0)

	foundPaths := make(map[string]bool)
	for _, r := range result.Routes {
		foundPaths[r.Route] = true
	}

	for _, expected := range []string{"/about", "/users"} {
		if !foundPaths[expected] {
			t.Errorf("Expected route %s, routes: %v", expected, result.Routes)
		}
	}
}

func TestAST_DeduplicatesRepeatedImportsAndRoutesDuringTraversal(t *testing.T) {
	analyzer := NewASTAnalyzer(NewRegexAnalyzer())
	result := analyzer.AnalyzeAST(`
var first = {path: "/items", component: function() { return import("./items.js") }};
var second = {path: "/items", component: function() { return import("./items.js") }};
`, "https://example.com/assets/app.js", "unknown")

	if len(result.Imports) != 1 {
		t.Fatalf("imports = %d, want 1: %+v", len(result.Imports), result.Imports)
	}
	if len(result.Routes) != 1 {
		t.Fatalf("routes = %d, want 1: %+v", len(result.Routes), result.Routes)
	}
	if len(result.NewURLs) != 1 {
		t.Fatalf("new URLs = %d, want 1: %+v", len(result.NewURLs), result.NewURLs)
	}
}

func TestAST_FallbackOnLargeFile(t *testing.T) {
	log := logging.New(false, t.TempDir())
	defer log.Close()
	a := NewAnalyzer(log)

	// Create a >5MB content to trigger regex fallback
	// Use a simple approach: repeat content
	bigContent := make([]byte, 6*1024*1024)
	for i := range bigContent {
		bigContent[i] = 'x'
	}
	// Add an import at the end
	copy(bigContent[len(bigContent)-30:], `import("./chunk.js");`)

	result := a.AnalyzeJS(string(bigContent), "http://example.com/big.js", "http://example.com/", 0)

	// Should still find the import via regex fallback
	found := false
	for _, imp := range result.Imports {
		if imp.Raw == "./chunk.js" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected regex fallback to find import in large file")
	}
}

func TestAST_RegexFallbackOnParseError(t *testing.T) {
	log := logging.New(false, t.TempDir())
	defer log.Close()
	a := NewAnalyzer(log)

	// Invalid JS that will cause AST parse error
	jsContent := `function broken({{{ import("./chunk.js");`

	result := a.AnalyzeJS(jsContent, "http://example.com/app.js", "http://example.com/", 0)

	// Regex should still find the import
	found := false
	for _, imp := range result.Imports {
		if imp.Raw == "./chunk.js" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected regex fallback to find import even with parse error")
	}
}

func TestAST_RegexFallbackFindsStaticESMOnParseError(t *testing.T) {
	log := logging.New(false, t.TempDir())
	defer log.Close()
	a := NewAnalyzer(log)

	assets := a.DiscoverJS(`
function broken({{{
import value from "./dependency.js";
export * from "./re-export.js";
`, "https://example.com/assets/main.js")

	want := map[string]bool{
		"https://example.com/assets/dependency.js": false,
		"https://example.com/assets/re-export.js":  false,
	}
	for _, asset := range assets {
		if _, ok := want[asset.URL]; ok {
			want[asset.URL] = true
		}
	}
	for rawURL, found := range want {
		if !found {
			t.Errorf("fallback static ESM dependency %s not discovered; assets=%+v", rawURL, assets)
		}
	}
}

func TestSecondaryFrameworkDetectionStillSupplementsGenericJSPaths(t *testing.T) {
	log := logging.New(false, t.TempDir())
	defer log.Close()
	a := NewAnalyzer(log)

	assets := a.DiscoverJS(
		`const lazyChunk = "/chunks/lazy.js";`,
		"https://example.com/runtime.polyfills.js",
	)

	for _, asset := range assets {
		if asset.URL == "https://example.com/chunks/lazy.js" {
			return
		}
	}
	t.Fatalf("secondary Angular detection lost generic JavaScript path: %+v", assets)
}
