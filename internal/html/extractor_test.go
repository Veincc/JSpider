package html

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Veincc/JSpider/internal/analyzer"
)

func TestExtractEntryJS_FindsTwentyAdjacentScripts(t *testing.T) {
	var document strings.Builder
	for i := 0; i < 20; i++ {
		fmt.Fprintf(&document, `<script src="/assets/%02d.js"></script>`, i)
	}

	assets := NewExtractor().ExtractEntryJS(document.String(), "https://example.com/index.html")
	if len(assets) != 20 {
		t.Fatalf("adjacent script assets = %d, want 20: %+v", len(assets), assets)
	}
	for i, asset := range assets {
		want := fmt.Sprintf("https://example.com/assets/%02d.js", i)
		if asset.URL != want {
			t.Fatalf("asset[%d].URL = %q, want %q", i, asset.URL, want)
		}
	}
}

func TestExtractEntryJS(t *testing.T) {
	ex := NewExtractor()

	html := `<!DOCTYPE html>
<html>
<head>
  <base href="https://example.com/app/">
  <link rel="modulepreload" href="/assets/vendor.js">
  <link rel="preload" as="script" href="/assets/runtime.js">
</head>
<body>
  <div id="app"></div>
  <script type="module" src="/assets/main.js"></script>
  <script src="/assets/polyfill.js" defer></script>
  <script src="https://cdn.example.com/lib.js"></script>
  <link rel="prefetch" href="/assets/chunk-0.js">
  <script>
    var config = {basePath: "/assets/app.js"};
  </script>
</body>
</html>`

	assets := ex.ExtractEntryJS(html, "https://example.com/index.html")

	if len(assets) == 0 {
		t.Fatal("Expected at least one asset, got 0")
	}

	// Check that the main scripts were extracted
	found := make(map[string]bool)
	for _, a := range assets {
		found[a.URL] = true
		t.Logf("Found: %s (source=%s, confidence=%s)", a.URL, a.Source, a.Confidence)
	}

	// Verify key URLs were extracted
	expectedURLs := []string{
		"https://example.com/assets/main.js",
		"https://example.com/assets/polyfill.js",
		"https://cdn.example.com/lib.js",
	}
	for _, eu := range expectedURLs {
		if !found[eu] {
			t.Errorf("Expected to find %s", eu)
		}
	}

	// Verify modulepreload
	if !found["https://example.com/assets/vendor.js"] {
		t.Error("Expected to find modulepreload vendor.js")
	}

	// Verify preload
	if !found["https://example.com/assets/runtime.js"] {
		t.Error("Expected to find preload runtime.js")
	}
}

func TestExtractEntryJS_Deduplication(t *testing.T) {
	ex := NewExtractor()

	html := `<html>
<body>
  <script src="/app.js"></script>
  <script src="/app.js"></script>
  <link rel="modulepreload" href="/app.js">
</body>
</html>`

	assets := ex.ExtractEntryJS(html, "https://example.com/")

	count := 0
	for _, a := range assets {
		if a.URL == "https://example.com/app.js" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("Expected deduplication, got %d occurrences of app.js", count)
	}
}

func TestExtractBaseHref(t *testing.T) {
	ex := NewExtractor()

	tests := []struct {
		html string
		want string
	}{
		{`<html><head><base href="https://cdn.example.com/"></head></html>`, "https://cdn.example.com/"},
		{`<html><head></head></html>`, ""},
		{`<html><head><base href="/app/"></head></html>`, "/app/"},
	}
	for _, tt := range tests {
		got := ex.ExtractBaseHref(tt.html)
		if got != tt.want {
			t.Errorf("ExtractBaseHref(%q) = %q, want %q", tt.html, got, tt.want)
		}
	}
}

func TestExtractModuleScriptsUsesDocumentBase(t *testing.T) {
	extractor := NewExtractor()
	urls := extractor.ExtractModuleScripts(`
<base href="/nested/assets/">
<script type="module" src="main.js"></script>
`, "https://example.com/pages/index.html")

	if len(urls) != 1 || urls[0] != "https://example.com/nested/assets/main.js" {
		t.Fatalf("module script URLs = %v, want document-base resolution", urls)
	}
}

func TestExtractEntryJSHandlesLinkRelationTokenLists(t *testing.T) {
	assets := NewExtractor().ExtractEntryJS(
		`<link rel="preload MODULEPRELOAD" href="/assets/module.js">`,
		"https://example.com/",
	)
	if len(assets) != 1 || assets[0].URL != "https://example.com/assets/module.js" {
		t.Fatalf("relation-token assets = %+v, want modulepreload URL", assets)
	}
	if assets[0].Source != analyzer.SourceModulepreload {
		t.Fatalf("asset source = %q, want %q", assets[0].Source, analyzer.SourceModulepreload)
	}
}

func TestExtractEntryJSFindsInlineModuleImports(t *testing.T) {
	assets := NewExtractor().ExtractEntryJS(`
<script type="module">
import value from "./entry.js";
export * from "./shared.js";
</script>
`, "https://example.com/app/index.html")

	want := map[string]bool{
		"https://example.com/app/entry.js":  false,
		"https://example.com/app/shared.js": false,
	}
	for _, asset := range assets {
		if _, ok := want[asset.URL]; ok {
			want[asset.URL] = true
		}
	}
	for rawURL, found := range want {
		if !found {
			t.Errorf("inline module dependency %s not found; assets=%+v", rawURL, assets)
		}
	}
}

func TestParseAllTagsDecodesAttributesAndKeepsScriptRawText(t *testing.T) {
	tags := parseAllTags(`<script src="/a&amp;b.js">const marker = "&amp;<tag>";</script>`)
	if len(tags) != 1 {
		t.Fatalf("tags = %d, want 1", len(tags))
	}
	if tags[0].Attrs["src"] != "/a&b.js" {
		t.Fatalf("decoded src = %q, want %q", tags[0].Attrs["src"], "/a&b.js")
	}
	if want := `const marker = "&amp;<tag>";`; tags[0].Body != want {
		t.Fatalf("script body = %q, want raw text %q", tags[0].Body, want)
	}
}

func TestExtractInlineJSPaths(t *testing.T) {
	ex := NewExtractor()

	html := `<html>
<script>
  self.__BUILD_MANIFEST = {"/_next/static/chunks/app.js":true};
  var config = "_buildId":"abc123";
</script>
</html>`

	paths := ex.ExtractInlineJSPaths(html, "https://example.com/")
	if len(paths) == 0 {
		t.Log("No inline paths found (may be expected for this test)")
	}
	for _, p := range paths {
		t.Logf("Inline path: %s", p)
	}
}

func TestExtractEntryJS_UnorderedAttrs(t *testing.T) {
	ex := NewExtractor()

	tests := []struct {
		name     string
		html     string
		expected []string
	}{
		{
			name:     "link href before rel modulepreload",
			html:     `<html><head><link href="/a.js" rel="modulepreload"></head></html>`,
			expected: []string{"https://example.com/a.js"},
		},
		{
			name:     "link rel after href",
			html:     `<html><head><link href="/b.js" rel="modulepreload"></head></html>`,
			expected: []string{"https://example.com/b.js"},
		},
		{
			name:     "preload as before href",
			html:     `<html><head><link as="script" href="/c.js" rel="preload"></head></html>`,
			expected: []string{"https://example.com/c.js"},
		},
		{
			name:     "preload href before as",
			html:     `<html><head><link href="/d.js" rel="preload" as="script"></head></html>`,
			expected: []string{"https://example.com/d.js"},
		},
		{
			name:     "script type before src",
			html:     `<html><body><script type="module" src="/e.js"></script></body></html>`,
			expected: []string{"https://example.com/e.js"},
		},
		{
			name:     "script src before type",
			html:     `<html><body><script src="/f.js" type="module"></script></body></html>`,
			expected: []string{"https://example.com/f.js"},
		},
		{
			name:     "prefetch",
			html:     `<html><head><link rel="prefetch" href="/g.js"></head></html>`,
			expected: []string{"https://example.com/g.js"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assets := ex.ExtractEntryJS(tt.html, "https://example.com/")
			found := make(map[string]bool)
			for _, a := range assets {
				found[a.URL] = true
			}
			for _, url := range tt.expected {
				if !found[url] {
					t.Errorf("Expected to find %s, got: %v", url, assets)
				}
			}
		})
	}
}

func TestExtractEntryJS_CaseInsensitive(t *testing.T) {
	ex := NewExtractor()

	tests := []struct {
		name     string
		html     string
		expected []string
	}{
		{
			name:     "uppercase SCRIPT SRC",
			html:     `<html><body><SCRIPT SRC="/a.js"></SCRIPT></body></html>`,
			expected: []string{"https://example.com/a.js"},
		},
		{
			name:     "mixed case Link Rel",
			html:     `<html><head><Link Href="/b.js" Rel="modulepreload"></head></html>`,
			expected: []string{"https://example.com/b.js"},
		},
		{
			name:     "REL=PRELOAD AS=SCRIPT",
			html:     `<html><head><LINK HREF="/c.js" REL="PRELOAD" AS="SCRIPT"></head></html>`,
			expected: []string{"https://example.com/c.js"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assets := ex.ExtractEntryJS(tt.html, "https://example.com/")
			found := make(map[string]bool)
			for _, a := range assets {
				found[a.URL] = true
			}
			for _, url := range tt.expected {
				if !found[url] {
					t.Errorf("Expected to find %s, got: %v", url, assets)
				}
			}
		})
	}
}

func TestExtractEntryJS_SingleQuotes(t *testing.T) {
	ex := NewExtractor()

	html := `<html>
<head><link href='/a.js' rel='modulepreload'></head>
<body><script src='/b.js' type='module'></script></body>
</html>`

	assets := ex.ExtractEntryJS(html, "https://example.com/")
	found := make(map[string]bool)
	for _, a := range assets {
		found[a.URL] = true
	}
	for _, url := range []string{"https://example.com/a.js", "https://example.com/b.js"} {
		if !found[url] {
			t.Errorf("Expected to find %s, got: %v", url, assets)
		}
	}
}

func TestExtractEntryJS_BaseHref(t *testing.T) {
	ex := NewExtractor()

	tests := []struct {
		name     string
		html     string
		baseURL  string
		expected string
	}{
		{
			name:     "absolute base",
			html:     `<html><head><base href="https://cdn.example.com/"></head><body><script src="app.js"></script></body></html>`,
			baseURL:  "https://example.com/",
			expected: "https://cdn.example.com/app.js",
		},
		{
			name:     "relative base",
			html:     `<html><head><base href="/static/"></head><body><script src="app.js"></script></body></html>`,
			baseURL:  "https://example.com/page/",
			expected: "https://example.com/static/app.js",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assets := ex.ExtractEntryJS(tt.html, tt.baseURL)
			found := false
			for _, a := range assets {
				if a.URL == tt.expected {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Expected %s, got: %v", tt.expected, assets)
			}
		})
	}
}

func TestFirstBaseWithEmptyHrefWins(t *testing.T) {
	ex := NewExtractor()
	const documentURL = "https://example.com/page/index.html"
	const content = `<base href=""><base href="/wrong/"><script type="module" src="app.js"></script>`
	const want = "https://example.com/page/app.js"

	assets := ex.ExtractEntryJS(content, documentURL)
	if len(assets) != 1 || assets[0].URL != want {
		t.Fatalf("ExtractEntryJS() = %+v, want only %q", assets, want)
	}
	modules := ex.ExtractModuleScripts(content, documentURL)
	if len(modules) != 1 || modules[0] != want {
		t.Fatalf("ExtractModuleScripts() = %+v, want only %q", modules, want)
	}
}

func TestExtractEntryJS_GtInsideAttr(t *testing.T) {
	ex := NewExtractor()

	// A > inside an attribute value should not truncate the tag
	html := `<html><body><script data-x="if(a>b)" src="/app.js"></script></body></html>`
	assets := ex.ExtractEntryJS(html, "https://example.com/")

	found := false
	for _, a := range assets {
		if a.URL == "https://example.com/app.js" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected to find /app.js despite > in attr, got: %v", assets)
	}
}

func TestExtractEntryJS_ScriptEndInString(t *testing.T) {
	ex := NewExtractor()

	// A "</script>" string inside script content should be skipped
	html := `<html><body><script>var x = "a>b"; var y = "/assets/app.js";</script></body></html>`
	assets := ex.ExtractEntryJS(html, "https://example.com/")

	found := false
	for _, a := range assets {
		if a.URL == "https://example.com/assets/app.js" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected to find /assets/app.js, got: %v", assets)
	}
}

func TestParseAllTags_AttrOrder(t *testing.T) {
	tests := []struct {
		name     string
		html     string
		tagName  string
		expected map[string]string
	}{
		{
			name:     "link href before rel",
			html:     `<link href="/a.js" rel="modulepreload">`,
			tagName:  "link",
			expected: map[string]string{"href": "/a.js", "rel": "modulepreload"},
		},
		{
			name:     "link rel before href",
			html:     `<link rel="modulepreload" href="/b.js">`,
			tagName:  "link",
			expected: map[string]string{"href": "/b.js", "rel": "modulepreload"},
		},
		{
			name:     "mixed case attrs",
			html:     `<link HREF="/c.js" REL="modulepreload">`,
			tagName:  "link",
			expected: map[string]string{"href": "/c.js", "rel": "modulepreload"},
		},
		{
			name:     "single quotes",
			html:     `<link href='/d.js' rel='modulepreload'>`,
			tagName:  "link",
			expected: map[string]string{"href": "/d.js", "rel": "modulepreload"},
		},
		{
			name:     "unquoted attr value",
			html:     `<script src=/e.js type=module></script>`,
			tagName:  "script",
			expected: map[string]string{"src": "/e.js", "type": "module"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tags := parseAllTags(tt.html)
			if len(tags) == 0 {
				t.Fatal("No tags parsed")
			}
			tag := tags[0]
			if tag.Name != tt.tagName {
				t.Errorf("Tag name: got %q, want %q", tag.Name, tt.tagName)
			}
			for k, want := range tt.expected {
				got := tag.Attrs[k]
				if got != want {
					t.Errorf("Attr %q: got %q, want %q", k, got, want)
				}
			}
		})
	}
}

func TestParseAllTags_ScriptBody(t *testing.T) {
	tests := []struct {
		name     string
		html     string
		wantBody string
	}{
		{
			name:     "simple script",
			html:     `<script>console.log("hello");</script>`,
			wantBody: `console.log("hello");`,
		},
		{
			name:     "script with src (no body)",
			html:     `<script src="/app.js"></script>`,
			wantBody: "",
		},
		{
			name:     "empty script",
			html:     `<script></script>`,
			wantBody: "",
		},
		{
			name:     "script with angle bracket in string",
			html:     `<script>var x = "a>b"; console.log(x);</script>`,
			wantBody: `var x = "a>b"; console.log(x);`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tags := parseAllTags(tt.html)
			var scriptTag *htmlTag
			for i := range tags {
				if tags[i].Name == "script" {
					scriptTag = &tags[i]
					break
				}
			}
			if scriptTag == nil {
				t.Fatal("No script tag found")
			}
			if scriptTag.Body != tt.wantBody {
				t.Errorf("Body:\ngot:  %q\nwant: %q", scriptTag.Body, tt.wantBody)
			}
		})
	}
}
