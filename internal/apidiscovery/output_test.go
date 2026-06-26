package apidiscovery

import (
	"bufio"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildReportIncludesRuntimeOnlyStaticOnlyAndResolvedCandidates(t *testing.T) {
	report := BuildReport(
		[]StaticEndpoint{
			{RawURL: "/user/list", Method: "GET", SourceJSURL: "https://example.com/app.js"},
			{RawURL: "/order/list", Method: "GET", SourceJSURL: "https://example.com/app.js"},
			{RawURL: "/admin/list", Method: "GET", SourceJSURL: "https://example.com/admin.js"},
		},
		[]RuntimeRequest{
			{
				RequestID:    "1",
				URL:          "https://example.com/gw/user/list",
				Method:       "GET",
				ResourceType: "Fetch",
				EntryURL:     "https://example.com/",
			},
			{
				RequestID:    "2",
				URL:          "https://example.com/gw/order/list",
				Method:       "GET",
				ResourceType: "XHR",
				EntryURL:     "https://example.com/",
			},
			{
				RequestID:    "3",
				URL:          "https://example.com/gw/runtime-only",
				Method:       "GET",
				ResourceType: "EventSource",
				EntryURL:     "https://example.com/",
			},
		},
	)

	var runtimeOnly, staticOnly *Endpoint
	for i := range report.Endpoints {
		switch report.Endpoints[i].Kind {
		case EndpointRuntimeOnly:
			runtimeOnly = &report.Endpoints[i]
		case EndpointStaticOnly:
			if report.Endpoints[i].RawURL == "/admin/list" {
				staticOnly = &report.Endpoints[i]
			}
		}
	}
	if runtimeOnly == nil || runtimeOnly.ResolvedURL != "https://example.com/gw/runtime-only" {
		t.Fatalf("runtime_only endpoint = %+v", runtimeOnly)
	}
	if staticOnly == nil {
		t.Fatal("missing static_only endpoint")
	}
	if len(staticOnly.ResolvedCandidates) != 1 || staticOnly.ResolvedCandidates[0] != "https://example.com/gw/admin/list" {
		t.Fatalf("resolved candidates = %v", staticOnly.ResolvedCandidates)
	}
}

func TestBuildReportFiltersThirdPartyAndDocumentStaticNoise(t *testing.T) {
	report := BuildReport(
		[]StaticEndpoint{
			{RawURL: "?characterEncoding=utf8&useSSL=false", SourceJSURL: "https://example.com/app.js"},
			{RawURL: "examples/PDF.js/web/viewer.html", SourceJSURL: "https://example.com/vendor.js"},
			{RawURL: "http://jspdf.default.namespaceuri/", SourceJSURL: "https://example.com/vendor.js"},
			{RawURL: "https://api.iconify.design", SourceJSURL: "https://example.com/app.js"},
			{RawURL: "https://github.com/zloirock/core-js", SourceJSURL: "https://example.com/vendor.js"},
			{RawURL: "https://example.com/api/local", Method: "GET", SourceJSURL: "https://example.com/app.js"},
			{RawURL: "/api/users", Method: "GET", SourceJSURL: "https://example.com/app.js"},
		},
		[]RuntimeRequest{
			{
				RequestID:    "runtime",
				URL:          "https://example.com/api/runtime",
				Method:       "GET",
				ResourceType: "Fetch",
				EntryURL:     "https://example.com/",
			},
		},
	)

	staticOnly := make(map[string]bool)
	for _, endpoint := range report.Endpoints {
		if endpoint.Kind == EndpointStaticOnly {
			staticOnly[endpoint.RawURL] = true
		}
	}
	for _, unwanted := range []string{
		"?characterEncoding=utf8&useSSL=false",
		"examples/PDF.js/web/viewer.html",
		"http://jspdf.default.namespaceuri/",
		"https://api.iconify.design",
		"https://github.com/zloirock/core-js",
	} {
		if staticOnly[unwanted] {
			t.Fatalf("static noise %q leaked into endpoints", unwanted)
		}
	}
	for _, wanted := range []string{"https://example.com/api/local", "/api/users"} {
		if !staticOnly[wanted] {
			t.Fatalf("local API %q missing from endpoints", wanted)
		}
	}
}

func TestSessionFiltersThirdPartyStaticNoiseWithoutRuntimeRequests(t *testing.T) {
	session := NewSession()
	session.AddEntryURL("https://example.com/")
	session.AddStatic([]StaticEndpoint{
		{RawURL: "https://example.com/api/local", Method: "GET", SourceJSURL: "https://cdn.example.net/app.js"},
		{RawURL: "https://api.example.net/v1/users", Method: "GET", SourceJSURL: "https://example.com/app.js"},
		{RawURL: "https://api.iconify.design/icons", SourceJSURL: "https://cdn.example.net/app.js"},
		{RawURL: "https://docs.example.net/guide", SourceJSURL: "https://example.com/app.js"},
	})

	report := session.Report()
	if len(report.Endpoints) != 2 {
		t.Fatalf("endpoints without runtime requests = %+v", report.Endpoints)
	}
	got := make(map[string]bool)
	for _, endpoint := range report.Endpoints {
		got[endpoint.RawURL] = true
	}
	for _, wanted := range []string{
		"https://example.com/api/local",
		"https://api.example.net/v1/users",
	} {
		if !got[wanted] {
			t.Fatalf("method-bearing API %q was filtered: %+v", wanted, report.Endpoints)
		}
	}
	if got["https://api.iconify.design/icons"] || got["https://docs.example.net/guide"] {
		t.Fatalf("untyped third-party URL leaked into endpoints: %+v", report.Endpoints)
	}
}

func TestWriteArtifactsIsSortedVersionedAtomicAndPrivate(t *testing.T) {
	siteDir := t.TempDir()
	report := BuildReport(
		[]StaticEndpoint{
			{RawURL: "/z/list", Method: "GET", SourceJSURL: "https://example.com/z.js"},
			{RawURL: "/a/list", Method: "GET", SourceJSURL: "https://example.com/a.js"},
			{RawURL: "/only/static", Method: "POST", SourceJSURL: "https://example.com/static.js"},
		},
		[]RuntimeRequest{
			{RequestID: "z", URL: "https://example.com/z/list", Method: "GET", ResourceType: "XHR"},
			{RequestID: "a", URL: "https://example.com/a/list", Method: "GET", ResourceType: "Fetch"},
			{RequestID: "runtime", URL: "https://example.com/only/runtime", Method: "GET", ResourceType: "Fetch"},
		},
	)

	if err := WriteArtifacts(siteDir, report); err != nil {
		t.Fatalf("WriteArtifacts() error = %v", err)
	}

	for _, dir := range []string{filepath.Join(siteDir, "runtime"), filepath.Join(siteDir, "analysis")} {
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatalf("stat %s: %v", dir, err)
		}
		if info.Mode().Perm() != 0700 {
			t.Fatalf("%s mode = %o, want 700", dir, info.Mode().Perm())
		}
	}

	paths := []string{
		filepath.Join(siteDir, "runtime", "requests.jsonl"),
		filepath.Join(siteDir, "analysis", "static-endpoints.jsonl"),
		filepath.Join(siteDir, "analysis", "endpoints.jsonl"),
		filepath.Join(siteDir, "analysis", "runtime-bases.json"),
	}
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("%s mode = %o, want 600", path, info.Mode().Perm())
		}
		assertVersionOne(t, path)
	}

	staticLines := readLines(t, paths[1])
	if len(staticLines) != 3 || !strings.Contains(staticLines[0], `"/a/list"`) ||
		!strings.Contains(staticLines[1], `"/only/static"`) || !strings.Contains(staticLines[2], `"/z/list"`) {
		t.Fatalf("static endpoint order = %v", staticLines)
	}

	tempMatches, err := filepath.Glob(filepath.Join(siteDir, "analysis", ".*.tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(tempMatches) != 0 {
		t.Fatalf("temporary files remain: %v", tempMatches)
	}

	for _, line := range readLines(t, paths[2]) {
		var value map[string]json.RawMessage
		if err := json.Unmarshal([]byte(line), &value); err != nil {
			t.Fatal(err)
		}
		for _, field := range []string{"resolved_candidates", "source_js_urls", "query_params", "body_params", "evidence"} {
			if string(value[field]) == "null" {
				t.Fatalf("endpoints field %q serialized as null: %s", field, line)
			}
		}
	}
}

func TestWriteArtifactsReturnsJSONMarshalErrors(t *testing.T) {
	siteDir := t.TempDir()
	report := Report{
		RuntimeRequests: []RuntimeRequest{
			{
				Version:           Version,
				RequestID:         "nan",
				URL:               "https://example.com/api",
				Method:            "GET",
				ResourceType:      "Fetch",
				EncodedDataLength: math.NaN(),
			},
		},
	}

	if err := WriteArtifacts(siteDir, report); err == nil {
		t.Fatal("WriteArtifacts() error = nil, want JSON marshal error")
	}
}

func assertVersionOne(t *testing.T, path string) {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		t.Fatalf("%s is empty", path)
	}
	var value map[string]any
	if err := json.Unmarshal(scanner.Bytes(), &value); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	if value["version"] != float64(1) {
		t.Fatalf("%s version = %#v, want 1", path, value["version"])
	}
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.TrimSpace(string(data))
	if text == "" {
		return nil
	}
	return strings.Split(text, "\n")
}
