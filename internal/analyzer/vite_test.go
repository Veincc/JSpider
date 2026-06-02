package analyzer

import (
	"testing"
)

func TestViteAnalyzer_Analyze(t *testing.T) {
	v := NewViteAnalyzer(NewRegexAnalyzer())

	js := `
const __vite__mapDeps = (i, m=__vite__mapDeps, d=(m.f || (m.f=[
  "assets/index-Dt4CpTsX.js",
  "assets/vendor-abc123.js",
  "assets/style.css",
  "assets/chunk-def456.js"
]))) => i.map(i => d[i]);

const routes = {
  "/home": () => import("./index-Dt4CpTsX.js"),
  "/about": () => __vitePreload(() => import("./chunk-def456.js"), __vite__mapDeps([0, 3]), import.meta.url),
};

S(() => import("./index-Dt4CpTsX.js"), __vite__mapDeps([0, 1, 3]), import.meta.url);
`

	result := v.Analyze(js, "https://example.com/assets/main.js")

	if result.Framework != "vite" {
		t.Errorf("framework = %q, want %q", result.Framework, "vite")
	}

	t.Logf("Found %d imports, %d routes, %d new URLs", len(result.Imports), len(result.Routes), len(result.NewURLs))

	for _, imp := range result.Imports {
		t.Logf("  import: %s -> %s (source=%s, confidence=%s, deps=%v)",
			imp.Raw, imp.ResolvedURL, imp.Source, imp.Confidence, imp.Deps)
	}

	for _, route := range result.Routes {
		t.Logf("  route: %s -> %s -> %s (confidence=%s)",
			route.Route, route.Component, route.LazyJS, route.Confidence)
	}
}

func TestViteAnalyzer_InferRoute(t *testing.T) {
	v := NewViteAnalyzer(NewRegexAnalyzer())

	tests := []struct {
		component string
		want      string
	}{
		{"../views/user/index.vue", "/user"},
		{"../views/dashboard/settings/index.vue", "/dashboard/settings"},
		{"../pages/about.vue", "/about"},
		{"./App.vue", ""},
		{"../views/user/profile.vue", "/user"},
	}
	for _, tt := range tests {
		got := v.inferRouteFromComponent(tt.component)
		if got != tt.want {
			t.Errorf("inferRouteFromComponent(%q) = %q, want %q", tt.component, got, tt.want)
		}
	}
}

func TestViteAnalyzer_IsViteJS(t *testing.T) {
	v := NewViteAnalyzer(NewRegexAnalyzer())

	tests := []struct {
		js   string
		url  string
		want bool
	}{
		{
			js:   `const __vite__mapDeps = (i) => i; import.meta.url;`,
			url:  "https://example.com/assets/main.js",
			want: true,
		},
		{
			js:   `console.log("hello")`,
			url:  "https://example.com/app.js",
			want: false,
		},
		{
			js:   `__webpack_require__("a")`,
			url:  "https://example.com/app.js",
			want: false,
		},
	}
	for _, tt := range tests {
		got := v.IsViteJS(tt.js, tt.url)
		if got != tt.want {
			t.Errorf("IsViteJS(%q, %q) = %v, want %v", tt.js[:20], tt.url, got, tt.want)
		}
	}
}
