package urlutil

import "testing"

func TestResolve(t *testing.T) {
	tests := []struct {
		base, rel, want string
	}{
		{"https://example.com/index.html", "app.js", "https://example.com/app.js"},
		{"https://example.com/js/main.js", "./utils.js", "https://example.com/js/utils.js"},
		{"https://example.com/js/main.js", "../lib/foo.js", "https://example.com/lib/foo.js"},
		{"https://example.com/page/", "/assets/bundle.js", "https://example.com/assets/bundle.js"},
		{"https://example.com/", "//cdn.example.com/lib.js", "https://cdn.example.com/lib.js"},
		{"https://example.com/", "https://other.com/a.js", "https://other.com/a.js"},
		{"https://example.com/js/app.js", "./chunks/0.js", "https://example.com/js/chunks/0.js"},
	}
	for _, tt := range tests {
		got, err := Resolve(tt.base, tt.rel)
		if err != nil {
			t.Errorf("Resolve(%q, %q) error: %v", tt.base, tt.rel, err)
			continue
		}
		if got != tt.want {
			t.Errorf("Resolve(%q, %q) = %q, want %q", tt.base, tt.rel, got, tt.want)
		}
	}
}

func TestNormalizeURL(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"https://example.com/a.js#section", "https://example.com/a.js"},
		{"https://example.com/a.js?v=1", "https://example.com/a.js?v=1"},
		{"https://example.com/a.js", "https://example.com/a.js"},
	}
	for _, tt := range tests {
		got, err := NormalizeURL(tt.input)
		if err != nil {
			t.Errorf("NormalizeURL(%q) error: %v", tt.input, err)
			continue
		}
		if got != tt.want {
			t.Errorf("NormalizeURL(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestIsSameOrigin(t *testing.T) {
	tests := []struct {
		u1, u2 string
		want   bool
	}{
		{"https://example.com/a.js", "https://example.com/b.js", true},
		{"https://example.com/a.js", "https://other.com/a.js", false},
		{"https://example.com/a.js", "http://example.com/a.js", false},
	}
	for _, tt := range tests {
		got := IsSameOrigin(tt.u1, tt.u2)
		if got != tt.want {
			t.Errorf("IsSameOrigin(%q, %q) = %v, want %v", tt.u1, tt.u2, got, tt.want)
		}
	}
}

func TestIsSameOriginUsesCanonicalHTTPOrigin(t *testing.T) {
	tests := []struct {
		left  string
		right string
		want  bool
	}{
		{"https://EXAMPLE.com:443/a", "https://example.com/b", true},
		{"http://example.com:80/a", "http://example.com/b", true},
		{"https://bücher.example/a", "https://xn--bcher-kva.example/b", true},
		{"http://[2001:0db8::1]:80/a", "http://[2001:db8::1]/b", true},
		{"https://example.com:444/a", "https://example.com/b", false},
		{"http://example.com/a", "https://example.com/a", false},
		{"ftp://example.com/a", "ftp://example.com/b", false},
		{"%zz", "https://example.com/b", false},
	}
	for _, test := range tests {
		if got := IsSameOrigin(test.left, test.right); got != test.want {
			t.Errorf("IsSameOrigin(%q, %q) = %v, want %v", test.left, test.right, got, test.want)
		}
	}
}

func TestGetOriginRequiresSchemeAndHost(t *testing.T) {
	tests := []struct {
		raw  string
		want string
	}{
		{"https://example.com/path", "https://example.com"},
		{"http://example.com:8080/path", "http://example.com:8080"},
		{"https://EXAMPLE.com:443/path", "https://example.com"},
		{"http://EXAMPLE.com:80/path", "http://example.com"},
		{"https://bücher.example/path", "https://xn--bcher-kva.example"},
		{"http://[2001:0db8::1]:80/path", "http://[2001:db8::1]"},
		{"ftp://example.com/path", ""},
		{"%zz", ""},
		{"/relative/path", ""},
		{"", ""},
	}
	for _, tt := range tests {
		if got := GetOrigin(tt.raw); got != tt.want {
			t.Errorf("GetOrigin(%q) = %q, want %q", tt.raw, got, tt.want)
		}
	}
}

func TestIsJSPath(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"https://example.com/app.js", true},
		{"https://example.com/chunk.mjs", true},
		{"https://example.com/assets?id=chunk", true},
		{"https://example.com/style.css", false},
		{"https://example.com/image.png", false},
	}
	for _, tt := range tests {
		got := IsJSPath(tt.input)
		if got != tt.want {
			t.Errorf("IsJSPath(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestIsAllowedDomain(t *testing.T) {
	tests := []struct {
		url, sameOrigin string
		allowed         []string
		want            bool
	}{
		{"https://example.com/a.js", "https://example.com/", nil, true},
		{"https://cdn.example.com/a.js", "https://example.com/", []string{"cdn.example.com"}, true},
		{"https://cdn.example.com/a.js", "https://example.com/", []string{"cdn.example.com:8443"}, true},
		{"https://other.com/a.js", "https://example.com/", nil, false},
		{"https://sub.cdn.com/a.js", "https://example.com/", []string{"cdn.com"}, true},
		{"https://bücher.example/a.js", "https://example.com/", []string{"bücher.example"}, true},
		{"https://xn--bcher-kva.example/a.js", "https://example.com/", []string{"bücher.example"}, true},
		{"https://assets.bücher.example/a.js", "https://example.com/", []string{"bücher.example"}, true},
		{"https://assets.xn--bcher-kva.example/a.js", "https://example.com/", []string{"https://BÜCHER.example:8443/"}, true},
		{"ftp://cdn.example.com/a.js", "https://example.com/", []string{"cdn.example.com"}, false},
		{"https://cdn.example.com:/a.js", "https://example.com/", []string{"cdn.example.com"}, false},
	}
	for _, tt := range tests {
		got := IsAllowedDomain(tt.url, tt.allowed, tt.sameOrigin)
		if got != tt.want {
			t.Errorf("IsAllowedDomain(%q, %v, %q) = %v, want %v", tt.url, tt.allowed, tt.sameOrigin, got, tt.want)
		}
	}
}

func TestShouldAttemptJSFetch_StaticSource(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		// Static sources require .js/.mjs or chunk/module query
		{"https://example.com/app.js", true},
		{"https://example.com/chunk.mjs", true},
		{"https://example.com/assets?id=chunk", true},
		{"https://example.com/assets?id=module", true},
		// Non-JS paths should NOT be attempted from static sources
		{"https://example.com/resource?id=app", false},
		{"https://example.com/api/data", false},
		{"https://example.com/style.css", false},
		{"https://example.com/image.png", false},
		{"https://example.com/page.html", false},
	}
	for _, tt := range tests {
		got := ShouldAttemptJSFetch(tt.url, false)
		if got != tt.want {
			t.Errorf("ShouldAttemptJSFetch(%q, static) = %v, want %v", tt.url, got, tt.want)
		}
	}
}

func TestShouldAttemptJSFetch_DynamicSource(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		// Dynamic sources: allow broader fetch
		{"https://example.com/app.js", true},
		{"https://example.com/resource?id=app", true},
		{"https://example.com/api/config", true},
		{"https://example.com/chunk-abc123", true},
		// But skip obvious non-JS resources
		{"https://example.com/style.css", false},
		{"https://example.com/page.html", false},
		{"https://example.com/image.png", false},
		{"https://example.com/font.woff2", false},
		{"https://example.com/data.json", false}, // plain json without chunk/module
		{"https://example.com/data.xml", false},
		{"https://example.com/icon.svg", false},
	}
	for _, tt := range tests {
		got := ShouldAttemptJSFetch(tt.url, true)
		if got != tt.want {
			t.Errorf("ShouldAttemptJSFetch(%q, dynamic) = %v, want %v", tt.url, got, tt.want)
		}
	}
}

func TestShouldAttemptJSFetch_DynamicJSONWithChunk(t *testing.T) {
	// JSON URLs with chunk/module in query should be allowed even for dynamic
	url := "https://example.com/data.json?chunk=1"
	got := ShouldAttemptJSFetch(url, true)
	if !got {
		t.Errorf("ShouldAttemptJSFetch(%q, dynamic) = false, want true (chunk in query)", url)
	}
}

func TestResolveJS(t *testing.T) {
	tests := []struct {
		name string
		base string
		raw  string
		want string
	}{
		// Bare paths use ordinary directory-relative URL semantics.
		{
			name: "bare assets/chunks from within assets/chunks preserves both prefixes",
			base: "https://vite.dev/assets/chunks/theme.js",
			raw:  "assets/chunks/client.BFYbw6Gq.js",
			want: "https://vite.dev/assets/chunks/assets/chunks/client.BFYbw6Gq.js",
		},
		// Bare "chunks/..." from /assets/app.js
		{
			name: "bare chunks/ from assets/app.js",
			base: "https://vite.dev/assets/app.js",
			raw:  "chunks/client.js",
			want: "https://vite.dev/assets/chunks/client.js",
		},
		// Repeated segments are legal and must not be collapsed.
		{
			name: "bare chunks from assets chunks preserves repeat",
			base: "https://vite.dev/assets/chunks/theme.js",
			raw:  "chunks/client.js",
			want: "https://vite.dev/assets/chunks/chunks/client.js",
		},
		// Absolute path — resolve from origin
		{
			name: "absolute path",
			base: "https://vite.dev/assets/chunks/theme.js",
			raw:  "/assets/main.js",
			want: "https://vite.dev/assets/main.js",
		},
		// Explicit relative ./ — standard resolution
		{
			name: "dot-slash relative",
			base: "https://example.com/app/main.js",
			raw:  "./chunk.js",
			want: "https://example.com/app/chunk.js",
		},
		// Explicit relative ../ — standard resolution
		{
			name: "dot-dot-slash relative",
			base: "https://example.com/app/main.js",
			raw:  "../lib/utils.js",
			want: "https://example.com/lib/utils.js",
		},
		// Absolute URL — passthrough with dedup
		{
			name: "absolute URL passthrough",
			base: "https://vite.dev/",
			raw:  "https://cdn.example.com/lib.js",
			want: "https://cdn.example.com/lib.js",
		},
		// Protocol-relative
		{
			name: "protocol-relative",
			base: "https://vite.dev/",
			raw:  "//cdn.example.com/lib.js",
			want: "https://cdn.example.com/lib.js",
		},
		// Explicit relative references also preserve repeated prefixes.
		{
			name: "preserve double assets chunks in resolved URL",
			base: "https://vite.dev/assets/chunks/theme.js",
			raw:  "./assets/chunks/client.js",
			want: "https://vite.dev/assets/chunks/assets/chunks/client.js",
		},
		// _nuxt prefix
		{
			name: "bare _nuxt path",
			base: "https://example.com/_nuxt/entry.js",
			raw:  "_nuxt/chunks/app.js",
			want: "https://example.com/_nuxt/_nuxt/chunks/app.js",
		},
		// _next/static prefix
		{
			name: "bare _next/static path",
			base: "https://example.com/_next/static/chunks/app.js",
			raw:  "_next/static/chunks/pages/index.js",
			want: "https://example.com/_next/static/chunks/_next/static/chunks/pages/index.js",
		},
		// Empty
		{
			name: "empty raw",
			base: "https://example.com/",
			raw:  "",
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolveJS(tt.base, tt.raw)
			if err != nil {
				t.Errorf("ResolveJS(%q, %q) error: %v", tt.base, tt.raw, err)
				return
			}
			if got != tt.want {
				t.Errorf("ResolveJS(%q, %q) = %q, want %q", tt.base, tt.raw, got, tt.want)
			}
		})
	}
}

func TestResolveJSPreservesLegalAdjacentPathSegments(t *testing.T) {
	got, err := ResolveJS(
		"https://example.com/releases/releases/main.js",
		"./chunks/chunks/app.js",
	)
	if err != nil {
		t.Fatalf("ResolveJS() error = %v", err)
	}
	want := "https://example.com/releases/releases/chunks/chunks/app.js"
	if got != want {
		t.Fatalf("ResolveJS() = %q, want legal path %q", got, want)
	}
}

func TestDeduplicatePathSegmentsPreservesInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"double assets/chunks", "https://vite.dev/assets/chunks/assets/chunks/client.js", "https://vite.dev/assets/chunks/assets/chunks/client.js"},
		{"triple chunk", "https://example.com/a/b/a/b/a/b/c.js", "https://example.com/a/b/a/b/a/b/c.js"},
		{"no dup", "https://example.com/assets/main.js", "https://example.com/assets/main.js"},
		{"adjacent dup", "https://example.com/a/a/b/b/c.js", "https://example.com/a/a/b/b/c.js"},
		{"short path", "https://example.com/a/b/c.js", "https://example.com/a/b/c.js"},
		{"_next/static dup", "https://example.com/_next/static/_next/static/chunks/a.js", "https://example.com/_next/static/_next/static/chunks/a.js"},
		{"chunks/chunks", "https://vite.dev/assets/chunks/chunks/client.js", "https://vite.dev/assets/chunks/chunks/client.js"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DeduplicatePathSegments(tt.input)
			if got != tt.want {
				t.Errorf("DeduplicatePathSegments(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
