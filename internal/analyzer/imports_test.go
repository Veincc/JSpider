package analyzer

import (
	"testing"
)

func TestExtractDynamicImports_Static(t *testing.T) {
	r := NewRegexAnalyzer()

	tests := []struct {
		name        string
		raw         string
		fromJS      string
		expectedURL string
		expectedConf string
	}{
		{
			name:        "relative ./ import",
			raw:         `import("./chunk.js")`,
			fromJS:      "http://example.com/assets/app.js",
			expectedURL: "http://example.com/assets/chunk.js",
			expectedConf: ConfHigh,
		},
		{
			name:        "relative ../ import",
			raw:         `import("../lib/utils.js")`,
			fromJS:      "http://example.com/assets/js/app.js",
			expectedURL: "http://example.com/assets/lib/utils.js",
			expectedConf: ConfHigh,
		},
		{
			name:        "absolute URL import",
			raw:         `import("https://cdn.example.com/lib.js")`,
			fromJS:      "http://example.com/app.js",
			expectedURL: "https://cdn.example.com/lib.js",
			expectedConf: ConfHigh,
		},
		{
			name:        "absolute path import",
			raw:         `import("/static/app.js")`,
			fromJS:      "http://example.com/page/index.html",
			expectedURL: "http://example.com/static/app.js",
			expectedConf: ConfHigh,
		},
		{
			name:        "bare specifier (no resolve)",
			raw:         `import("lodash")`,
			fromJS:      "http://example.com/app.js",
			expectedURL: "",
			expectedConf: ConfMedium,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			imports := r.ExtractDynamicImports(tt.raw, tt.fromJS, "")
			if len(imports) == 0 {
				t.Fatal("Expected at least one import")
			}
			imp := imports[0]
			if imp.ResolvedURL != tt.expectedURL {
				t.Errorf("ResolvedURL: got %q, want %q", imp.ResolvedURL, tt.expectedURL)
			}
			if imp.Confidence != tt.expectedConf {
				t.Errorf("Confidence: got %q, want %q", imp.Confidence, tt.expectedConf)
			}
		})
	}
}

func TestExtractDynamicImports_TemplateLiteral(t *testing.T) {
	r := NewRegexAnalyzer()

	tests := []struct {
		name        string
		raw         string
		fromJS      string
		expectedURL string
		expectedConf string
	}{
		{
			name:        "template with variable",
			raw:         "import(`./page-${id}.js`)",
			fromJS:      "http://example.com/app.js",
			expectedURL: "",
			expectedConf: ConfLow,
		},
		{
			name:        "template with expression",
			raw:         "import(`./modules/${name}/index.js`)",
			fromJS:      "http://example.com/app.js",
			expectedURL: "",
			expectedConf: ConfLow,
		},
		{
			name:        "template without expression (static)",
			raw:         "import(`./chunk.js`)",
			fromJS:      "http://example.com/app.js",
			expectedURL: "http://example.com/chunk.js",
			expectedConf: ConfHigh,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			imports := r.ExtractDynamicImports(tt.raw, tt.fromJS, "")
			if len(imports) == 0 {
				t.Fatal("Expected at least one import")
			}
			imp := imports[0]
			if imp.ResolvedURL != tt.expectedURL {
				t.Errorf("ResolvedURL: got %q, want %q", imp.ResolvedURL, tt.expectedURL)
			}
			if imp.Confidence != tt.expectedConf {
				t.Errorf("Confidence: got %q, want %q", imp.Confidence, tt.expectedConf)
			}
		})
	}
}

func TestExtractDynamicImports_MixedContent(t *testing.T) {
	r := NewRegexAnalyzer()

	jsContent := `
import("./static-chunk.js");
import("./page-${route}.js");
import("https://cdn.example.com/vendor.js");
import("./utils.js");
`
	fromJS := "http://example.com/assets/app.js"
	imports := r.ExtractDynamicImports(jsContent, fromJS, "")

	if len(imports) != 4 {
		t.Fatalf("Expected 4 imports, got %d", len(imports))
	}

	// Check each import
	checks := map[string]struct {
		resolvedURL string
		confidence  string
	}{
		"./static-chunk.js":                   {resolvedURL: "http://example.com/assets/static-chunk.js", confidence: ConfHigh},
		"./page-${route}.js":                  {resolvedURL: "", confidence: ConfLow},
		"https://cdn.example.com/vendor.js":   {resolvedURL: "https://cdn.example.com/vendor.js", confidence: ConfHigh},
		"./utils.js":                          {resolvedURL: "http://example.com/assets/utils.js", confidence: ConfHigh},
	}

	for _, imp := range imports {
		expected, ok := checks[imp.Raw]
		if !ok {
			t.Errorf("Unexpected import: %s", imp.Raw)
			continue
		}
		if imp.ResolvedURL != expected.resolvedURL {
			t.Errorf("Import %s: ResolvedURL got %q, want %q", imp.Raw, imp.ResolvedURL, expected.resolvedURL)
		}
		if imp.Confidence != expected.confidence {
			t.Errorf("Import %s: Confidence got %q, want %q", imp.Raw, imp.Confidence, expected.confidence)
		}
	}
}
