package analyzer

import (
	"testing"
)

func TestExtractDynamicImports(t *testing.T) {
	r := NewRegexAnalyzer()

	tests := []struct {
		name    string
		js      string
		fromJS  string
		wantLen int
		wantRaw []string
	}{
		{
			name:    "double quote import",
			js:      `import("./chunks/0.js")`,
			fromJS:  "https://example.com/assets/main.js",
			wantLen: 1,
			wantRaw: []string{"./chunks/0.js"},
		},
		{
			name:    "single quote import",
			js:      `import('./utils.js')`,
			fromJS:  "https://example.com/assets/main.js",
			wantLen: 1,
			wantRaw: []string{"./utils.js"},
		},
		{
			name:    "template literal import",
			js:      "import(`./dynamic-${id}.js`)",
			fromJS:  "https://example.com/assets/main.js",
			wantLen: 1,
		},
		{
			name:    "multiple imports",
			js:      `const a = import("./a.js"); const b = import('./b.js');`,
			fromJS:  "https://example.com/assets/main.js",
			wantLen: 2,
		},
		{
			name:    "no imports",
			js:      `console.log("hello")`,
			fromJS:  "https://example.com/assets/main.js",
			wantLen: 0,
		},
		{
			name:    "absolute URL import",
			js:      `import("https://cdn.example.com/lib.js")`,
			fromJS:  "https://example.com/assets/main.js",
			wantLen: 1,
			wantRaw: []string{"https://cdn.example.com/lib.js"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			imports := r.ExtractDynamicImports(tt.js, tt.fromJS, "")
			if len(imports) != tt.wantLen {
				t.Errorf("got %d imports, want %d", len(imports), tt.wantLen)
				for _, imp := range imports {
					t.Logf("  found: %s -> %s", imp.Raw, imp.ResolvedURL)
				}
				return
			}
			for i, raw := range tt.wantRaw {
				if i < len(imports) && imports[i].Raw != raw {
					t.Errorf("import[%d].Raw = %q, want %q", i, imports[i].Raw, raw)
				}
			}
		})
	}
}

func TestExtractDynamicImports_Resolution(t *testing.T) {
	r := NewRegexAnalyzer()

	js := `import("./chunks/detail.js")`
	imports := r.ExtractDynamicImports(js, "https://example.com/assets/main.js", "")

	if len(imports) != 1 {
		t.Fatalf("expected 1 import, got %d", len(imports))
	}

	want := "https://example.com/assets/chunks/detail.js"
	if imports[0].ResolvedURL != want {
		t.Errorf("ResolvedURL = %q, want %q", imports[0].ResolvedURL, want)
	}
}

func TestExtractSourceMappingURL(t *testing.T) {
	r := NewRegexAnalyzer()

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
			got := r.ExtractSourceMappingURL(tt.js, tt.fromJS)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractRoutePaths(t *testing.T) {
	r := NewRegexAnalyzer()

	js := `
const routes = [
  { path: "/home", component: () => import("./Home.js") },
  { path: "/about", component: () => import("./About.js") },
  { path: "/user/:id", component: () => import("./User.js") },
];
`
	routes := r.ExtractRoutePaths(js, "https://example.com/assets/router.js")

	if len(routes) < 3 {
		t.Errorf("expected at least 3 routes, got %d", len(routes))
		for _, route := range routes {
			t.Logf("  route: %s -> %s", route.Route, route.Component)
		}
	}
}

func TestExtractViteMapDeps(t *testing.T) {
	r := NewRegexAnalyzer()

	js := `
const __vite__mapDeps = (i, m=__vite__mapDeps, d=(m.f || (m.f=[
  "assets/index-Dt4CpTsX.js",
  "assets/vendor-abc123.js",
  "assets/style.css",
  "assets/chunk-def456.js"
]))) => i.map(i => d[i]);

S(() => import("./index-Dt4CpTsX.js"), __vite__mapDeps([0, 1, 3]), import.meta.url);
`
	imports, _ := r.ExtractViteMapDeps(js, "https://example.com/assets/main.js")

	if len(imports) == 0 {
		t.Fatal("expected at least 1 import from mapDeps")
	}

	// Check dependency resolution
	found := false
	for _, imp := range imports {
		if len(imp.Deps) > 0 {
			found = true
			t.Logf("mapDeps deps: %v", imp.Deps)
			// CSS should be filtered
			for _, dep := range imp.Deps {
				if dep == "assets/style.css" {
					t.Error("CSS should be filtered from deps")
				}
			}
		}
	}
	if !found {
		t.Error("expected mapDeps with deps")
	}
}

func TestExtractWebpackChunks(t *testing.T) {
	r := NewRegexAnalyzer()

	js := `
(self.webpackChunkmy_app = self.webpackChunkmy_app || []).push([[123], {
  123: function(e, t, n) { /* ... */ }
}]);
__webpack_require__.p = "/static/";
__webpack_require__.u = function(chunkId) {
  return "js/" + chunkId + "." + {"123":"abc123","456":"def456"}[chunkId] + ".js";
};
`
	imports, _ := r.ExtractWebpackChunks(js, "https://example.com/assets/main.js")

	if len(imports) == 0 {
		t.Fatal("expected at least 1 webpack chunk")
	}

	t.Logf("Found %d webpack chunks", len(imports))
	for _, imp := range imports {
		t.Logf("  chunk: %s -> %s (confidence: %s)", imp.Raw, imp.ResolvedURL, imp.Confidence)
	}
}

func TestExtractJSPaths(t *testing.T) {
	r := NewRegexAnalyzer()

	js := `
var scripts = ["/assets/vendor.js", "/static/js/app.js", "./chunks/0.js"];
`
	paths := r.ExtractJSPaths(js, "https://example.com/assets/main.js")

	if len(paths) == 0 {
		t.Error("expected at least 1 JS path")
	}

	for _, p := range paths {
		t.Logf("path: %s", p)
	}
}

func TestParseIndices(t *testing.T) {
	tests := []struct {
		input string
		want  []int
	}{
		{"1, 2, 3", []int{1, 2, 3}},
		{"0,1,2", []int{0, 1, 2}},
		{"10, 20, 30", []int{10, 20, 30}},
	}
	for _, tt := range tests {
		got := parseIndices(tt.input)
		if len(got) != len(tt.want) {
			t.Errorf("parseIndices(%q) len = %d, want %d", tt.input, len(got), len(tt.want))
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("parseIndices(%q)[%d] = %d, want %d", tt.input, i, got[i], tt.want[i])
			}
		}
	}
}
