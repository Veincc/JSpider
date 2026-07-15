package apidiscovery

import (
	"bufio"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestEndpointURLsUsesPriorityAndResolvesRelativeRawURLs(t *testing.T) {
	report := Report{Endpoints: []Endpoint{
		{ResolvedURL: "https://api.example.com/matched#fragment", RawURL: "/ignored"},
		{ResolvedCandidates: []string{"https://example.com/candidate?x=1#drop"}, RawURL: "/ignored-too"},
		{RawURL: "https://example.com/absolute?q=1#drop"},
		{RawURL: "/api/users"},
		{RawURL: "./api/orders"},
		{RawURL: "../api/admin"},
		{RawURL: "//api.example.net/users"},
	}}
	got := EndpointURLs(report, []string{"https://example.com/base/page"})
	want := []string{
		"https://api.example.com/matched",
		"https://api.example.net/users",
		"https://example.com/absolute?q=1",
		"https://example.com/api/admin",
		"https://example.com/api/users",
		"https://example.com/base/api/orders",
		"https://example.com/candidate?x=1",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("EndpointURLs() = %v, want %v", got, want)
	}
}

func TestEndpointURLsFiltersInvalidAndDeduplicatesAcrossEntries(t *testing.T) {
	report := Report{Endpoints: []Endpoint{
		{RawURL: ""}, {RawURL: "?page=1"}, {RawURL: "#section"},
		{RawURL: "mailto:test@example.com"}, {RawURL: "file:///tmp/a"},
		{RawURL: "javascript:alert(1)"}, {RawURL: "http://[::1"},
		{RawURL: "/api/EXPR/users"}, {RawURL: "/shared"}, {RawURL: "/shared"},
		{ResolvedCandidates: []string{"ftp://example.com/ignored"}, RawURL: "/must-not-fallback"},
		{ResolvedCandidates: []string{" "}, RawURL: "https://example.com/fallback"},
	}}
	got := EndpointURLs(report, []string{"https://example.com/a", "https://example.com/b"})
	want := []string{"https://example.com/fallback", "https://example.com/shared"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("EndpointURLs() = %v, want %v", got, want)
	}
}

func TestEndpointURLsResolvesRelativeStaticOnlyWithinOwnSourceEntry(t *testing.T) {
	firstEntry := "https://first.example/app/page"
	secondEntry := "https://second.example/root/page"
	session := NewSession()
	session.AddStatic([]StaticEndpoint{
		{RawURL: "./api/first", Method: "GET", SourceIdentity: SourceIdentity{EntryURL: firstEntry}},
		{RawURL: "./api/second", Method: "GET", SourceIdentity: SourceIdentity{EntryURL: secondEntry}},
	})
	got := EndpointURLs(session.Report(), []string{firstEntry, secondEntry})
	want := []string{
		"https://first.example/app/api/first",
		"https://second.example/root/api/second",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("EndpointURLs() = %v, want provenance-isolated %v", got, want)
	}
}

func TestEndpointURLsUsesOwnEntrySchemeForProtocolRelativeStatic(t *testing.T) {
	entry := "http://first.example/app/"
	session := NewSession()
	session.AddStatic([]StaticEndpoint{{
		RawURL: "//api.example/users", Method: "GET",
		SourceIdentity: SourceIdentity{EntryURL: entry},
	}})
	got := EndpointURLs(session.Report(), []string{entry, "https://second.example/"})
	want := []string{"http://api.example/users"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("EndpointURLs() = %v, want own-entry scheme %v", got, want)
	}
}

func TestReportAndEndpointFilePreserveRawFullQueryValues(t *testing.T) {
	longValue := strings.Repeat("x", MaxParameterValueBytes+73)
	rawURL := "https://example.com/api/users?access_token=top-secret&query=" + longValue
	report := BuildReport(nil, []RuntimeRequest{{
		RequestID: "runtime", URL: rawURL, Method: "GET", ResourceType: "Fetch",
		QueryParams: []Parameter{
			{Name: "access_token", Value: "top-secret"},
			{Name: "query", Value: longValue},
		},
	}})
	if report.RuntimeRequests[0].URL != rawURL || report.Endpoints[0].ResolvedURL != rawURL {
		t.Fatalf("report URLs = %q / %q, want %q", report.RuntimeRequests[0].URL, report.Endpoints[0].ResolvedURL, rawURL)
	}
	if valueFor(report.RuntimeRequests[0].QueryParams, "query") != longValue {
		t.Fatalf("report query params = %+v, want full value", report.RuntimeRequests[0].QueryParams)
	}
	urls := EndpointURLs(report, nil)
	if !reflect.DeepEqual(urls, []string{rawURL}) {
		t.Fatalf("EndpointURLs() = %v, want raw URL", urls)
	}
	dir := t.TempDir()
	if err := WriteEndpointURLs(dir, urls); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "endpoints.txt"))
	if err != nil || string(data) != rawURL+"\n" {
		t.Fatalf("endpoints.txt = %q, error = %v", data, err)
	}
}

func TestEndpointURLsDoesNotReintroduceFilteredReportNoise(t *testing.T) {
	report := BuildReport([]StaticEndpoint{
		{RawURL: "examples/PDF.js/web/viewer.html", SourceJSURL: "https://example.com/vendor.js"},
		{RawURL: "https://api.iconify.design", SourceJSURL: "https://example.com/app.js"},
		{RawURL: "https://example.com/api/local", Method: "GET", SourceJSURL: "https://example.com/app.js"},
		{RawURL: "/api/users", Method: "GET", SourceJSURL: "https://example.com/app.js"},
	}, nil)
	got := EndpointURLs(report, []string{"https://example.com/"})
	want := []string{"https://example.com/api/local", "https://example.com/api/users"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("EndpointURLs(filtered report) = %v, want %v", got, want)
	}
}

func TestWriteEndpointURLsIsAtomicPrivateAndSupportsEmptyOutput(t *testing.T) {
	siteDir := t.TempDir()
	if err := WriteEndpointURLs(siteDir, []string{"https://example.com/z", "https://example.com/a", "https://example.com/a"}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(siteDir, "endpoints.txt")
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "https://example.com/a\nhttps://example.com/z\n" {
		t.Fatalf("endpoints = %q, error = %v", data, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatalf("endpoint mode = %o, want 600", info.Mode().Perm())
	}
	if err := WriteEndpointURLs(siteDir, nil); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(path)
	if err != nil || len(data) != 0 {
		t.Fatalf("empty endpoints = %q, error = %v", data, err)
	}
	temps, err := filepath.Glob(filepath.Join(siteDir, ".endpoints.txt.tmp-*"))
	if err != nil || len(temps) != 0 {
		t.Fatalf("temporary endpoint files = %v, error = %v", temps, err)
	}
}

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
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0700 {
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
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
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
