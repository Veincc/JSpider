package analyzer

import (
	"testing"
)

func TestSourceMapAnalyzer_ExtractSourceMappingURL(t *testing.T) {
	s := NewSourceMapAnalyzer(NewRegexAnalyzer())

	tests := []struct {
		name   string
		js     string
		fromJS string
		want   string
	}{
		{
			name:   "standard comment",
			js:     `console.log("hello");\n//# sourceMappingURL=app.js.map`,
			fromJS: "https://example.com/assets/app.js",
			want:   "https://example.com/assets/app.js.map",
		},
		{
			name:   "block comment",
			js:     `console.log("hello");\n/*# sourceMappingURL=app.js.map */`,
			fromJS: "https://example.com/assets/app.js",
			want:   "https://example.com/assets/app.js.map",
		},
		{
			name:   "absolute URL",
			js:     `console.log("hello");\n//# sourceMappingURL=https://cdn.example.com/maps/app.js.map`,
			fromJS: "https://example.com/assets/app.js",
			want:   "https://cdn.example.com/maps/app.js.map",
		},
		{
			name:   "data URL ignored",
			js:     `console.log("hello");\n//# sourceMappingURL=data:application/json;base64,abc`,
			fromJS: "https://example.com/assets/app.js",
			want:   "",
		},
		{
			name:   "no sourcemap",
			js:     `console.log("hello")`,
			fromJS: "https://example.com/assets/app.js",
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s.ExtractSourceMappingURL(tt.js, tt.fromJS)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSourceMapAnalyzer_ParseSourceMap(t *testing.T) {
	s := NewSourceMapAnalyzer(NewRegexAnalyzer())

	mapJSON := `{
		"version": 3,
		"file": "app.js",
		"sources": ["src/app.ts", "src/utils.ts"],
		"sourcesContent": ["console.log('hello')", "export function add(a, b) { return a + b; }"]
	}`

	info := s.ParseSourceMap([]byte(mapJSON), "https://example.com/assets/app.js.map", "https://example.com/assets/app.js")

	if info.Status != "parsed" {
		t.Errorf("status = %q, want %q", info.Status, "parsed")
	}

	if info.SourceCount != 2 {
		t.Errorf("sourceCount = %d, want %d", info.SourceCount, 2)
	}

	if !info.HasSourcesContent {
		t.Error("expected HasSourcesContent = true")
	}

	if len(info.Sources) != 2 {
		t.Errorf("sources len = %d, want %d", len(info.Sources), 2)
	}
}

func TestSourceMapAnalyzer_FindSourceMappingURLs(t *testing.T) {
	s := NewSourceMapAnalyzer(NewRegexAnalyzer())

	js := `
console.log("hello");
//# sourceMappingURL=app.js.map
var x = 1;
/*# sourceMappingURL=vendor.js.map */
`

	urls := s.FindSourceMappingURLs(js)

	if len(urls) != 2 {
		t.Errorf("expected 2 URLs, got %d", len(urls))
	}

	t.Logf("Found URLs: %v", urls)
}
