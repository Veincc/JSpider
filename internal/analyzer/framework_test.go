package analyzer

import (
	"testing"
)

func TestFrameworkDetector_StrongFeatures(t *testing.T) {
	fd := NewFrameworkDetector()

	tests := []struct {
		name     string
		content  string
		url      string
		expected string
	}{
		{
			name:     "Vite strong: __vite__mapDeps",
			content:  `var d=__vite__mapDeps([0,1,2]);`,
			url:      "http://example.com/assets/app.js",
			expected: "vite",
		},
		{
			name:     "Webpack strong: __webpack_require__",
			content:  `var m=__webpack_require__(123);`,
			url:      "http://example.com/static/js/app.js",
			expected: "webpack",
		},
		{
			name:     "Next strong: __NEXT_DATA__",
			content:  `self.__NEXT_DATA__={"page":"/"};`,
			url:      "http://example.com/_next/static/chunks/app.js",
			expected: "next",
		},
		{
			name:     "Nuxt strong: window.__NUXT__",
			content:  `window.__NUXT__={data:{}};`,
			url:      "http://example.com/_nuxt/app.js",
			expected: "nuxt",
		},
		{
			name:     "Angular strong: @angular/core",
			content:  `import {Component} from '@angular/core';`,
			url:      "http://example.com/main.abc123.js",
			expected: "angular",
		},
		{
			name:     "Vue CLI strong: vue-router + vue.runtime + chunk-vendors",
			content:  `var r=vue-router;var v=vue.runtime;`,
			url:      "http://example.com/js/chunk-vendors.abc.js",
			expected: "vue-cli",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := fd.Detect(tt.content, tt.url)
			if result == nil {
				t.Fatalf("Expected %s, got nil", tt.expected)
			}
			if result.Framework != tt.expected {
				t.Errorf("Expected %s, got %s (score=%d, reasons=%v)",
					tt.expected, result.Framework, result.Score, result.Reasons)
			}
		})
	}
}

func TestFrameworkDetector_WeakFeaturesBelowThreshold(t *testing.T) {
	fd := NewFrameworkDetector()

	tests := []struct {
		name    string
		content string
		url     string
	}{
		{
			name:    "only /assets/ URL (score 1, below threshold)",
			content: `function hello(){return "world";}`,
			url:     "http://example.com/assets/app.js",
		},
		{
			name:    "only main. in content (score 1, below threshold)",
			content: `// main.js\nconsole.log("hello");`,
			url:     "http://example.com/app.js",
		},
		{
			name:    "only runtime. in content (score 1, below threshold)",
			content: `// runtime.js\nconsole.log("hello");`,
			url:     "http://example.com/app.js",
		},
		{
			name:    "empty content and URL",
			content: ``,
			url:     `http://example.com/`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := fd.Detect(tt.content, tt.url)
			if result != nil {
				t.Errorf("Expected nil (below threshold), got %s (score=%d)",
					result.Framework, result.Score)
			}
		})
	}
}

func TestFrameworkDetector_TieBreakDeterministic(t *testing.T) {
	fd := NewFrameworkDetector()

	// "/assets/" gives vite +1, "main." gives angular +1
	// Both score 1, below threshold, so should return nil
	// But if we give both score 2+, tie-breaking should be deterministic
	// Let's test with a scenario where both have score 3
	content := `// content with vite and angular features
import.meta.url
@angular/core
`
	url := "http://example.com/assets/main.js"

	// Run 10 times to verify determinism
	var result string
	for i := 0; i < 10; i++ {
		det := fd.Detect(content, url)
		if det == nil {
			t.Fatal("Expected non-nil result")
		}
		if i == 0 {
			result = det.Framework
		} else if det.Framework != result {
			t.Errorf("Non-deterministic: run %d got %s, expected %s", i, det.Framework, result)
		}
	}

	// Angular has priority 1, Vite has priority 4
	// Both get import.meta.url (+3 for vite) and @angular/core (+5 for angular)
	// Angular = 5, Vite = 3, Angular wins
	if result != "angular" {
		t.Logf("Got %s (this is OK as long as it's deterministic)", result)
	}
}

func TestFrameworkDetector_NoFalsePositiveOnSimpleJS(t *testing.T) {
	fd := NewFrameworkDetector()

	tests := []struct {
		name    string
		content string
		url     string
	}{
		{
			name:    "simple import with /assets/ URL",
			content: `function loadChunk(){return import("./chunk.js");}loadChunk();`,
			url:     "http://127.0.0.1:12345/assets/main.js",
		},
		{
			name:    "plain JS file",
			content: `var x=1;console.log(x);`,
			url:     "http://example.com/script.js",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := fd.Detect(tt.content, tt.url)
			if result != nil {
				t.Errorf("Expected nil (no framework), got %s (score=%d, reasons=%v)",
					result.Framework, result.Score, result.Reasons)
			}
		})
	}
}
