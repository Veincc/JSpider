//go:build cgo

package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
	processor, err := preprocess.New(filepath.Join(outDir, urlutil.SanitizeDomain(server.URL)), func(entryURL, rawURL string) ([]byte, error) {
		result := f.FetchForEntry(rawURL, entryURL)
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

	err := run(cfg)
	if err == nil || err.Error() != "browser unavailable for test" {
		t.Fatalf("run() error = %v", err)
	}
	if _, statErr := os.Stat(outDir); !os.IsNotExist(statErr) {
		t.Fatalf("output directory was created before browser validation: %v", statErr)
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
	if err := run(cfg); err != nil {
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
	if err := run(cfg); err != nil {
		t.Fatal(err)
	}
	siteDir := filepath.Join(outDir, urlutil.SanitizeDomain(server.URL))
	data, err := os.ReadFile(filepath.Join(siteDir, "endpoints.txt"))
	if err != nil || len(data) != 0 {
		t.Fatalf("empty endpoints = %q, error = %v", data, err)
	}
}
