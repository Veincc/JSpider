//go:build cgo

package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Veincc/JSpider/internal/analyzer"
	"github.com/Veincc/JSpider/internal/apidiscovery"
	"github.com/Veincc/JSpider/internal/fetcher"
	"github.com/Veincc/JSpider/internal/headless"
	"github.com/Veincc/JSpider/internal/html"
	"github.com/Veincc/JSpider/internal/logging"
	"github.com/Veincc/JSpider/internal/preprocess"
	"github.com/Veincc/JSpider/internal/store"
	"github.com/Veincc/JSpider/internal/urlutil"
)

func TestRunReportsCheapPerEntryAPIStatsAndWritesOneFinalEndpointSet(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/first" && r.URL.Path != "/second" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html></html>`))
	}))
	defer server.Close()

	originalCheck, originalDiscover := checkBrowserAvailable, discoverBrowser
	checkBrowserAvailable = func() error { return nil }
	discoverBrowser = func(_ context.Context, cfg *headless.Config, _ *logging.Logger) (headless.DiscoveryResult, error) {
		name := strings.TrimPrefix(cfg.EntryURL, server.URL+"/")
		return headless.DiscoveryResult{Requests: []apidiscovery.RuntimeRequest{{
			RequestID: name, URL: server.URL + "/api/" + name + "?keep=" + name,
			Method: "GET", ResourceType: "Fetch",
		}}}, nil
	}
	t.Cleanup(func() { checkBrowserAvailable, discoverBrowser = originalCheck, originalDiscover })

	listPath := filepath.Join(t.TempDir(), "urls.txt")
	if err := os.WriteFile(listPath, []byte(server.URL+"/second\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := testConfig(server.URL+"/first", t.TempDir())
	cfg.URLList = listPath
	cfg.APIDiscovery, cfg.Headless = true, true

	result, err := run(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Success) != 2 {
		t.Fatalf("success results = %+v", result.Success)
	}
	for _, entry := range result.Success {
		if entry.API.Sources != 0 || entry.API.Runtime != 1 {
			t.Fatalf("API stats for %s = %+v", entry.EntryURL, entry.API)
		}
	}
	origin, canonicalErr := urlutil.CanonicalOrigin(server.URL)
	if canonicalErr != nil {
		t.Fatal(canonicalErr)
	}
	stats := result.Sites[origin]
	if stats.API.Sources != 0 || stats.API.Runtime != 2 {
		t.Fatalf("site API stats = %+v", stats.API)
	}
	data, readErr := os.ReadFile(filepath.Join(cfg.OutDir, stats.Directory, "endpoints.txt"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	want := server.URL + "/api/first?keep=first\n" + server.URL + "/api/second?keep=second\n"
	if string(data) != want {
		t.Fatalf("endpoints.txt = %q, want %q", data, want)
	}
}

func TestRunSameOriginEntriesRetainAPIProvenance(t *testing.T) {
	var appHits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/first", "/second", "/third":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<script src="/app.js"></script>`))
		case "/app.js":
			appHits.Add(1)
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte(`fetch("/api/users");`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	firstURL := server.URL + "/first"
	secondURL := server.URL + "/second"
	thirdURL := server.URL + "/third"
	originalCheck, originalDiscover := checkBrowserAvailable, discoverBrowser
	checkBrowserAvailable = func() error { return nil }
	discoverBrowser = func(_ context.Context, cfg *headless.Config, _ *logging.Logger) (headless.DiscoveryResult, error) {
		if cfg.EntryURL != secondURL {
			return headless.DiscoveryResult{}, nil
		}
		return headless.DiscoveryResult{Requests: []apidiscovery.RuntimeRequest{{
			RequestID: "second-entry-runtime", URL: server.URL + "/api/users",
			Method: "GET", ResourceType: "XHR",
		}}}, nil
	}
	t.Cleanup(func() { checkBrowserAvailable, discoverBrowser = originalCheck, originalDiscover })

	session := apidiscovery.NewSession()
	originalNewSession := newAPISession
	newAPISession = func() apiDiscoverySession { return session }
	t.Cleanup(func() { newAPISession = originalNewSession })

	listPath := filepath.Join(t.TempDir(), "urls.txt")
	if err := os.WriteFile(listPath, []byte(secondURL+"\n"+thirdURL+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := testConfig(firstURL, t.TempDir())
	cfg.URLList = listPath
	cfg.APIDiscovery, cfg.Headless = true, true
	cfg.MaxJS = 2

	result, err := run(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Success) != 3 {
		t.Fatalf("success results = %+v", result.Success)
	}
	if got := session.Stats(firstURL); got.Sources != 1 || got.Runtime != 0 {
		t.Fatalf("first stats = %+v, want sources/runtime 1/0", got)
	}
	if got := session.Stats(secondURL); got.Sources != 1 || got.Runtime != 1 {
		t.Fatalf("second stats = %+v, want sources/runtime 1/1", got)
	}
	if got := session.Stats(thirdURL); got.Sources != 0 || got.Runtime != 0 {
		t.Fatalf("third stats = %+v, want shared-budget exhaustion before source collection", got)
	}
	report := session.Report()
	identities := make(map[string]apidiscovery.SourceIdentity)
	for _, endpoint := range report.StaticEndpoints {
		if endpoint.RawURL == "/api/users" {
			identities[endpoint.SourceIdentity.EntryURL] = endpoint.SourceIdentity
		}
	}
	if len(identities) != 2 {
		t.Fatalf("source identities = %+v, want one for each exact entry URL", identities)
	}
	sharedJS := server.URL + "/app.js"
	for _, entryURL := range []string{firstURL, secondURL} {
		identity := identities[entryURL]
		if identity.EntryURL != entryURL || identity.RequestedURL != sharedJS || identity.FinalURL != sharedJS || identity.ContentHash == "" {
			t.Fatalf("source identity for %s = %+v, want exact entry and shared script provenance", entryURL, identity)
		}
	}
	if len(report.Associations) != 1 {
		t.Fatalf("associations = %d, want 1: %+v", len(report.Associations), report.Associations)
	}
	association := report.Associations[0]
	if association.EntryURL != secondURL {
		t.Fatalf("association entry = %q, want %q", association.EntryURL, secondURL)
	}
	if association.SourceIdentity.EntryURL != secondURL ||
		association.SourceIdentity.RequestedURL != sharedJS ||
		association.SourceIdentity.FinalURL != sharedJS {
		t.Fatalf("association source identity = %+v, want exact second-entry provenance for %s", association.SourceIdentity, sharedJS)
	}
	if len(report.Bases) != 1 || report.Bases[0].RuntimeBase != server.URL ||
		len(report.Bases[0].EntryURLs) != 1 || report.Bases[0].EntryURLs[0] != secondURL {
		t.Fatalf("runtime bases = %+v, want one base inferred only for the second entry", report.Bases)
	}
	if got := appHits.Load(); got != 2 {
		t.Fatalf("app.js requests = %d, want 2 in API mode", got)
	}
	if result.Success[0].FetchAttempts != 1 || result.Success[1].FetchAttempts != 1 ||
		result.Success[2].EntryURL != thirdURL || result.Success[2].FetchAttempts != 0 {
		t.Fatalf("entry fetch attempts = %s:%d / %s:%d / %s:%d, want exact first/second/third attempts 1/1/0",
			result.Success[0].EntryURL, result.Success[0].FetchAttempts,
			result.Success[1].EntryURL, result.Success[1].FetchAttempts,
			result.Success[2].EntryURL, result.Success[2].FetchAttempts)
	}
	origin, canonicalErr := urlutil.CanonicalOrigin(server.URL)
	if canonicalErr != nil {
		t.Fatal(canonicalErr)
	}
	if got := result.Sites[origin].FetchAttempts; got != 2 {
		t.Fatalf("site fetch attempts = %d, want shared API-mode budget count 2", got)
	}
}

func TestAnalyzeEntryKeepsStaticAPIsWhenHeadlessFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<script src="/app.js"></script>`))
		case "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte(`$.get("/user/list", {page: 1});`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	original := discoverBrowser
	discoverBrowser = func(context.Context, *headless.Config, *logging.Logger) (headless.DiscoveryResult, error) {
		return headless.DiscoveryResult{
			Requests: []apidiscovery.RuntimeRequest{{
				URL:          server.URL + "/api/partial",
				Method:       "GET",
				ResourceType: "Fetch",
				EntryURL:     server.URL + "/",
			}},
		}, errors.New("browser target failed")
	}
	t.Cleanup(func() { discoverBrowser = original })

	outDir := t.TempDir()
	cfg := testConfig(server.URL+"/", outDir)
	cfg.Headless = true
	cfg.APIDiscovery = true
	log := logging.New(false, outDir)
	defer log.Close()
	f, err := fetcher.New(cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	processor, err := preprocess.New(filepath.Join(outDir, urlutil.SanitizeDomain(server.URL)), func(ctx context.Context, entryURL, rawURL string) ([]byte, error) {
		result := f.FetchForEntryContext(ctx, rawURL, entryURL)
		if result.Err != nil {
			return nil, result.Err
		}
		if result.StatusCode != http.StatusOK {
			return nil, errors.New(http.StatusText(result.StatusCode))
		}
		return result.Body, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = processor.Close() })
	session := apidiscovery.NewSession()
	analyzed := 0
	attempts := 0

	got, err := analyzeEntry(
		cfg,
		store.New(outDir),
		f,
		analyzer.NewAnalyzer(log),
		html.NewExtractor(),
		log,
		processor,
		session,
		server.URL+"/",
		urlutil.SanitizeDomain(server.URL),
		map[string]bool{},
		map[string]bool{},
		&analyzed,
		&attempts,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got != 1 {
		t.Fatalf("analyzed JS = %d, want 1", got)
	}
	if err := session.AnalyzeSources(); err != nil {
		t.Fatal(err)
	}
	report := session.Report()
	if report.Summary.Static == 0 {
		t.Fatalf("static API results were lost after headless failure: %+v", report)
	}
	if report.Summary.Runtime != 0 {
		t.Fatalf("runtime requests = %d, want 0", report.Summary.Runtime)
	}
}

func TestRunChecksBrowserBeforeCreatingOutput(t *testing.T) {
	original := checkBrowserAvailable
	checkBrowserAvailable = func() error { return errors.New("browser unavailable for test") }
	t.Cleanup(func() { checkBrowserAvailable = original })

	outDir := t.TempDir() + "/not-created"
	cfg := testConfig("https://example.com/", outDir)
	cfg.APIDiscovery = true
	cfg.Headless = true

	err := runTest(cfg)
	if err == nil || err.Error() != "browser unavailable for test" {
		t.Fatalf("runTest() error = %v", err)
	}
	if _, statErr := os.Stat(outDir); !os.IsNotExist(statErr) {
		t.Fatalf("output directory was created before browser validation: %v", statErr)
	}
}

func TestRunAppliesAPIModeImplicationWithoutMutatingCaller(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html></html>`))
	}))
	defer server.Close()

	var browserChecks, browserDiscoveries int
	originalCheck, originalDiscover := checkBrowserAvailable, discoverBrowser
	checkBrowserAvailable = func() error {
		browserChecks++
		return nil
	}
	discoverBrowser = func(_ context.Context, browserCfg *headless.Config, _ *logging.Logger) (headless.DiscoveryResult, error) {
		browserDiscoveries++
		browserCfg.AllowCDN[0] = "mutated.example"
		browserCfg.Headers["X-Test"] = "mutated"
		return headless.DiscoveryResult{}, nil
	}
	t.Cleanup(func() { checkBrowserAvailable, discoverBrowser = originalCheck, originalDiscover })

	cfg := testConfig(server.URL+"/", t.TempDir())
	cfg.APIDiscovery = true
	cfg.Headless = false
	cfg.AllowCDN = []string{"cdn.example"}
	cfg.Headers = map[string]string{"X-Test": "original"}

	if _, err := run(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if browserChecks != 1 || browserDiscoveries != 1 {
		t.Fatalf("browser calls = check %d discovery %d, want 1/1", browserChecks, browserDiscoveries)
	}
	if cfg.Headless {
		t.Fatal("run mutated caller configuration")
	}
	if cfg.AllowCDN[0] != "cdn.example" || cfg.Headers["X-Test"] != "original" {
		t.Fatalf("run mutated caller slice/map fields: AllowCDN=%v Headers=%v", cfg.AllowCDN, cfg.Headers)
	}
}

func TestAnalyzeResultUsesInMemoryAnalysisDataForStaticAPI(t *testing.T) {
	cfg, s, a, log, prep := analysisHarness(t)
	cfg.APIDiscovery = true
	session := apidiscovery.NewSession()
	queued := make(map[string]bool)
	processed := make(map[string]bool)
	var queue []fetchReq
	analyzed := 0
	total := 0

	analyzeResultWithPreprocess(
		cfg,
		s,
		a,
		log,
		prep,
		session,
		successfulFetch("app.js", `$.post("/users/create", {name: "alice"});`),
		"https://example.com/",
		"example_com",
		queued,
		processed,
		&queue,
		&analyzed,
		&total,
	)

	before := session.Report()
	if before.Summary.Static != 0 {
		t.Fatalf("static API analysis ran before discovery completed: %+v", before.StaticEndpoints)
	}
	if session.SourceCount() != 1 {
		t.Fatalf("collected JS sources = %d, want 1", session.SourceCount())
	}
	if err := session.AnalyzeSources(); err != nil {
		t.Fatal(err)
	}

	report := session.Report()
	if report.Summary.Static == 0 || report.StaticEndpoints[0].RawURL != "/users/create" {
		t.Fatalf("static endpoints = %+v", report.StaticEndpoints)
	}
}

func TestAPIDiscoveryWritesOnlyFinalEndpoints(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<script src="/app.js"></script>`))
		case "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte(`console.log("app")`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	originalCheck, originalDiscover := checkBrowserAvailable, discoverBrowser
	checkBrowserAvailable = func() error { return nil }
	discoverBrowser = func(context.Context, *headless.Config, *logging.Logger) (headless.DiscoveryResult, error) {
		return headless.DiscoveryResult{Requests: []apidiscovery.RuntimeRequest{{
			RequestID: "runtime", URL: server.URL + "/api/runtime", Method: "GET",
			ResourceType: "Fetch", EntryURL: server.URL + "/",
		}}}, nil
	}
	t.Cleanup(func() { checkBrowserAvailable, discoverBrowser = originalCheck, originalDiscover })

	outDir := t.TempDir()
	cfg := testConfig(server.URL+"/", outDir)
	cfg.APIDiscovery, cfg.Headless = true, true
	if err := runTest(cfg); err != nil {
		t.Fatal(err)
	}
	siteDir := filepath.Join(outDir, urlutil.SanitizeDomain(server.URL))
	data, err := os.ReadFile(filepath.Join(siteDir, "endpoints.txt"))
	if err != nil || string(data) != server.URL+"/api/runtime\n" {
		t.Fatalf("endpoints = %q, error = %v", data, err)
	}
	assertMapTargetsExist(t, siteDir)
	assertPathMissing(t, filepath.Join(siteDir, "entry.html"))
	assertPathMissing(t, filepath.Join(siteDir, "runtime"))
	assertPathMissing(t, filepath.Join(siteDir, "analysis"))
}

func TestAPIDiscoveryWritesEmptyEndpointsFile(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html></html>`))
	}))
	defer server.Close()

	originalCheck, originalDiscover := checkBrowserAvailable, discoverBrowser
	checkBrowserAvailable = func() error { return nil }
	discoverBrowser = func(context.Context, *headless.Config, *logging.Logger) (headless.DiscoveryResult, error) {
		return headless.DiscoveryResult{}, nil
	}
	t.Cleanup(func() { checkBrowserAvailable, discoverBrowser = originalCheck, originalDiscover })

	outDir := t.TempDir()
	cfg := testConfig(server.URL+"/", outDir)
	cfg.APIDiscovery, cfg.Headless = true, true
	if err := runTest(cfg); err != nil {
		t.Fatal(err)
	}
	siteDir := filepath.Join(outDir, urlutil.SanitizeDomain(server.URL))
	data, err := os.ReadFile(filepath.Join(siteDir, "endpoints.txt"))
	if err != nil || len(data) != 0 {
		t.Fatalf("empty endpoints = %q, error = %v", data, err)
	}
}
