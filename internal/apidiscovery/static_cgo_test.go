//go:build cgo

package apidiscovery

import (
	"strings"
	"testing"
)

func TestAnalyzeJavaScriptWithJsluice(t *testing.T) {
	source := []byte(`
		$.get("/users/list?page=1", {status: "active"});
		$.post("/users/create", {name: "alice", password: "secret", apiKey: "api-secret"});
	`)

	endpoints, err := AnalyzeJavaScript(source, "https://example.com/assets/app.js")
	if err != nil {
		t.Fatalf("AnalyzeJavaScript() error = %v", err)
	}
	if len(endpoints) != 2 {
		t.Fatalf("endpoints = %+v, want 2 deduplicated contextual results", endpoints)
	}

	byURL := make(map[string]StaticEndpoint)
	for _, endpoint := range endpoints {
		byURL[endpoint.RawURL] = endpoint
	}
	get := byURL["/users/list?page=1"]
	if get.Method != "GET" || !equalStrings(parameterNames(get.QueryParams), []string{"page", "status"}) {
		t.Fatalf("GET endpoint = %+v", get)
	}
	post := byURL["/users/create"]
	if post.Method != "POST" || !equalStrings(parameterNames(post.BodyParams), []string{"apiKey", "name", "password"}) {
		t.Fatalf("POST endpoint = %+v", post)
	}
	if post.SourceJSURL != "https://example.com/assets/app.js" || post.Type != "$.post" || post.Source == "" {
		t.Fatalf("POST metadata = %+v", post)
	}
	if containsSecret(post.Source) || strings.Contains(post.Source, "api-secret") {
		t.Fatalf("POST source leaked a sensitive value: %q", post.Source)
	}
}

func TestCGOBuildReportsAPIDiscoveryAvailable(t *testing.T) {
	if err := CheckAvailable(); err != nil {
		t.Fatalf("CheckAvailable() error = %v", err)
	}
}

func TestAnalyzeJavaScriptFiltersStaticAssetsAndInfersWrapperMethods(t *testing.T) {
	source := []byte(`
		import("./chunk.js");
		const stylesheet = "../css/app.css";
		const malformed = "&&n.showStep===2?5:n.serviceHttpType===";
		r.get("/api/users");
		s.postWithMsg("/api/orders", {id: 1});
		const routeOrEndpoint = "/dashboard";
	`)

	endpoints, err := AnalyzeJavaScript(source, "https://example.com/app.js")
	if err != nil {
		t.Fatal(err)
	}

	byURL := make(map[string]StaticEndpoint)
	for _, endpoint := range endpoints {
		byURL[endpoint.RawURL] = endpoint
	}
	if _, ok := byURL["./chunk.js"]; ok {
		t.Fatal("dynamic JavaScript import leaked into static API endpoints")
	}
	if _, ok := byURL["../css/app.css"]; ok {
		t.Fatal("stylesheet leaked into static API endpoints")
	}
	if _, ok := byURL["&&n.showStep===2?5:n.serviceHttpType==="]; ok {
		t.Fatal("malformed expression leaked into static API endpoints")
	}
	if byURL["/api/users"].Method != "GET" {
		t.Fatalf("/api/users method = %q, want GET", byURL["/api/users"].Method)
	}
	if byURL["/api/orders"].Method != "POST" {
		t.Fatalf("/api/orders method = %q, want POST", byURL["/api/orders"].Method)
	}
	if _, ok := byURL["/dashboard"]; !ok {
		t.Fatal("path-like string candidate was dropped")
	}
}

func TestInferHTTPMethodDoesNotTreatPostMessageOrPostmanAsPost(t *testing.T) {
	tests := []struct {
		name      string
		matchType string
		want      string
	}{
		{name: "exact", matchType: "post", want: "POST"},
		{name: "wrapper request", matchType: "api.postRequest", want: "POST"},
		{name: "wrapper fetch", matchType: "client.postFetch", want: "POST"},
		{name: "existing with wrapper", matchType: "s.postWithMsg", want: "POST"},
		{name: "postMessage", matchType: "window.postMessage", want: ""},
		{name: "postman", matchType: "postman", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := inferHTTPMethod("", tt.matchType); got != tt.want {
				t.Fatalf("inferHTTPMethod(%q) = %q, want %q", tt.matchType, got, tt.want)
			}
		})
	}
}

func containsSecret(value string) bool {
	return strings.Contains(value, "secret")
}
