package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Veincc/JSpider/internal/analyzer"
	"github.com/Veincc/JSpider/internal/config"
	"github.com/Veincc/JSpider/internal/fetcher"
	"github.com/Veincc/JSpider/internal/headless"
	"github.com/Veincc/JSpider/internal/logging"
	"github.com/Veincc/JSpider/internal/preprocess"
	"github.com/Veincc/JSpider/internal/store"
	"github.com/Veincc/JSpider/internal/urlutil"
)

func TestNormalModeWritesProcessedJavaScriptAndMapOnly(t *testing.T) {
	server := newSiteServer(t, map[string]string{
		"/":                `<script src="/assets/app.js"></script>`,
		"/assets/app.js":   `import("./chunk.js");`,
		"/assets/chunk.js": `console.log("chunk");`,
	})
	defer server.Close()

	outDir := t.TempDir()
	cfg := testConfig(server.URL+"/", outDir)
	if err := run(cfg); err != nil {
		t.Fatalf("run() error = %v", err)
	}

	siteDir := filepath.Join(outDir, urlutil.SanitizeDomain(server.URL))
	if count := countFiles(t, filepath.Join(siteDir, "js")); count != 2 {
		t.Fatalf("processed JavaScript files = %d, want 2", count)
	}
	assertMapTargetsExist(t, siteDir)
	assertPathMissing(t, filepath.Join(siteDir, "entry.html"))
	assertPathMissing(t, filepath.Join(siteDir, "endpoints.txt"))
	assertPathMissing(t, filepath.Join(siteDir, "audit"))
	assertPathMissing(t, filepath.Join(siteDir, "runtime"))
	assertPathMissing(t, filepath.Join(siteDir, "analysis"))
	assertNoLegacyReports(t, outDir)
}

func TestRunRequiresNodeBeforeCreatingOutput(t *testing.T) {
	server := newSiteServer(t, map[string]string{"/": `<html></html>`})
	defer server.Close()

	t.Setenv("PATH", "")
	outDir := filepath.Join(t.TempDir(), "not-created")
	err := run(testConfig(server.URL+"/", outDir))
	if err == nil || err.Error() != preprocess.NodeRuntimeError {
		t.Fatalf("run() error = %v", err)
	}
	assertPathMissing(t, outDir)
}

func TestRunRejectsInvalidConfigBeforeCreatingOutput(t *testing.T) {
	outDir := filepath.Join(t.TempDir(), "not-created")
	cfg := testConfig("https://example.com/", outDir)
	cfg.Workers = 0

	err := run(cfg)
	if err == nil || !strings.Contains(err.Error(), "workers") {
		t.Fatalf("run() error = %v, want worker validation error", err)
	}
	assertPathMissing(t, outDir)
}

func TestRunReturnsURLFileErrorBeforeCreatingOutput(t *testing.T) {
	outDir := filepath.Join(t.TempDir(), "not-created")
	cfg := testConfig("", outDir)
	cfg.URLList = filepath.Join(t.TempDir(), "missing.txt")

	err := run(cfg)
	if err == nil || !strings.Contains(err.Error(), "URL list") {
		t.Fatalf("run() error = %v, want URL list error", err)
	}
	assertPathMissing(t, outDir)
}

func TestNormalModeUsesSourceMapsThenFallsBackToReadableBundle(t *testing.T) {
	if err := preprocess.CheckNodeRuntime(); err != nil {
		t.Skip(err)
	}

	server := newSiteServer(t, map[string]string{
		"/": `<script src="/app.js"></script>`,
		"/app.js": `import("./chunk.js");
//# sourceMappingURL=app.js.map`,
		"/app.js.map": `{
			"version":3,
			"sources":["src/main.ts","webpack:///node_modules/lib/index.js"],
			"sourcesContent":["export const main = true;","vendor"]
		}`,
		"/chunk.js": `const value=atob("L2FwaS9jaHVuaw==");console.log(value);`,
	})
	defer server.Close()

	outDir := t.TempDir()
	cfg := testConfig(server.URL+"/", outDir)
	if err := run(cfg); err != nil {
		t.Fatalf("run() error = %v", err)
	}

	siteDir := filepath.Join(outDir, urlutil.SanitizeDomain(server.URL))
	assertPathExists(t, filepath.Join(siteDir, "js", "src", "main.ts"))
	if count := countFiles(t, filepath.Join(siteDir, "js")); count != 2 {
		t.Fatalf("processed outputs = %d, want 2", count)
	}
	rows := readTabMap(t, filepath.Join(siteDir, "js-map.txt"))
	if len(rows) != 2 || rows[0][0] != server.URL+"/app.js" || rows[1][0] != server.URL+"/chunk.js" {
		t.Fatalf("JavaScript map = %+v", rows)
	}
	assertMapTargetsExist(t, siteDir)
	assertPathMissing(t, filepath.Join(siteDir, "entry.html"))
	assertPathMissing(t, filepath.Join(siteDir, "audit"))
	assertNoLegacyReports(t, outDir)
}

func TestNormalModeParseFailureSavesOriginalAsOnlyArtifact(t *testing.T) {
	if err := preprocess.CheckNodeRuntime(); err != nil {
		t.Skip(err)
	}

	server := newSiteServer(t, map[string]string{
		"/":          `<script src="/broken.js"></script>`,
		"/broken.js": `function broken(`,
	})
	defer server.Close()

	outDir := t.TempDir()
	cfg := testConfig(server.URL+"/", outDir)
	if err := run(cfg); err != nil {
		t.Fatalf("run() error = %v", err)
	}

	siteDir := filepath.Join(outDir, urlutil.SanitizeDomain(server.URL))
	if count := countFiles(t, filepath.Join(siteDir, "js")); count != 1 {
		t.Fatalf("fallback files = %d, want 1", count)
	}
	rows := readTabMap(t, filepath.Join(siteDir, "js-map.txt"))
	if len(rows) != 1 || rows[0][0] != server.URL+"/broken.js" {
		t.Fatalf("JavaScript map = %+v", rows)
	}
	data, err := os.ReadFile(filepath.Join(siteDir, filepath.FromSlash(rows[0][1])))
	if err != nil || string(data) != "function broken(" {
		t.Fatalf("fallback = %q, error = %v", data, err)
	}
	assertPathMissing(t, filepath.Join(siteDir, "audit"))
}

func TestAllowedCDNJavaScriptBelongsToEntrySite(t *testing.T) {
	assetServer := newSiteServer(t, map[string]string{
		"/cdn.js": `console.log("cdn");`,
	})
	defer assetServer.Close()

	entryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<script src="%s/cdn.js"></script>`, assetServer.URL)
	}))
	defer entryServer.Close()

	entryURL := strings.Replace(entryServer.URL, "127.0.0.1", "localhost", 1) + "/"
	outDir := t.TempDir()
	cfg := testConfig(entryURL, outDir)
	cfg.AllowCDN = []string{"127.0.0.1"}
	if err := run(cfg); err != nil {
		t.Fatalf("run() error = %v", err)
	}

	entrySite := filepath.Join(outDir, urlutil.SanitizeDomain(entryURL))
	if count := countFiles(t, filepath.Join(entrySite, "js")); count != 1 {
		t.Fatalf("entry-site JavaScript files = %d, want 1", count)
	}
	rows := readTabMap(t, filepath.Join(entrySite, "js-map.txt"))
	if len(rows) != 1 || rows[0][0] != assetServer.URL+"/cdn.js" {
		t.Fatalf("CDN map = %+v", rows)
	}
	assertMapTargetsExist(t, entrySite)
	assertPathMissing(t, filepath.Join(outDir, urlutil.SanitizeDomain(assetServer.URL)))
}

func TestRedirectTargetMustRemainAllowedForEntry(t *testing.T) {
	var internalHits int32
	internalServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&internalHits, 1)
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte(`console.log("metadata");`))
	}))
	defer internalServer.Close()

	entryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<script src="/redirect.js"></script>`))
		case "/redirect.js":
			http.Redirect(w, r, internalServer.URL+"/metadata.js", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer entryServer.Close()

	outDir := t.TempDir()
	cfg := testConfig(entryServer.URL+"/", outDir)
	if err := run(cfg); err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if got := atomic.LoadInt32(&internalHits); got != 0 {
		t.Fatalf("redirect target was fetched %d time(s), want 0", got)
	}
}

func TestCookiesAreNotForwardedToCDNOrigins(t *testing.T) {
	var cdnCookie atomic.Value
	cdnServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cdnCookie.Store(r.Header.Get("Cookie"))
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte(`console.log("cdn");`))
	}))
	defer cdnServer.Close()

	entryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<script src="%s/cdn.js"></script>`, cdnServer.URL)
	}))
	defer entryServer.Close()

	outDir := t.TempDir()
	entryURL := strings.Replace(entryServer.URL, "127.0.0.1", "localhost", 1) + "/"
	cfg := testConfig(entryURL, outDir)
	cfg.AllowCDN = []string{"127.0.0.1"}
	cfg.Cookies = "session=secret"
	if err := run(cfg); err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if got, _ := cdnCookie.Load().(string); got != "" {
		t.Fatalf("CDN Cookie header = %q, want empty", got)
	}
}

func TestMultipleEntrySitesAreIsolated(t *testing.T) {
	first := newSiteServer(t, map[string]string{
		"/":         `<script src="/first.js"></script>`,
		"/first.js": `console.log("same");`,
	})
	defer first.Close()
	second := newSiteServer(t, map[string]string{
		"/":          `<script src="/second.js"></script>`,
		"/second.js": `console.log("same");`,
	})
	defer second.Close()

	listPath := filepath.Join(t.TempDir(), "urls.txt")
	secondURL := strings.Replace(second.URL, "127.0.0.1", "localhost", 1) + "/"
	if err := os.WriteFile(listPath, []byte(secondURL+"\n"), 0644); err != nil {
		t.Fatalf("write URL list: %v", err)
	}

	outDir := t.TempDir()
	cfg := testConfig(first.URL+"/", outDir)
	cfg.URLList = listPath
	if err := run(cfg); err != nil {
		t.Fatalf("run() error = %v", err)
	}

	firstSite := filepath.Join(outDir, urlutil.SanitizeDomain(first.URL))
	secondSite := filepath.Join(outDir, urlutil.SanitizeDomain(secondURL))
	if count := countFiles(t, filepath.Join(firstSite, "js")); count != 1 {
		t.Fatalf("first site JavaScript files = %d, want 1", count)
	}
	if count := countFiles(t, filepath.Join(secondSite, "js")); count != 1 {
		t.Fatalf("second site JavaScript files = %d, want 1", count)
	}
	firstRows := readTabMap(t, filepath.Join(firstSite, "js-map.txt"))
	secondRows := readTabMap(t, filepath.Join(secondSite, "js-map.txt"))
	if len(firstRows) != 1 || firstRows[0][0] != first.URL+"/first.js" {
		t.Fatalf("first-site map = %+v", firstRows)
	}
	if len(secondRows) != 1 || secondRows[0][0] != secondURL+"second.js" {
		t.Fatalf("second-site map = %+v", secondRows)
	}
	assertMapTargetsExist(t, firstSite)
	assertMapTargetsExist(t, secondSite)
}

func TestNormalModeWritesEmptyJSMapWhenNoJavaScriptSucceeds(t *testing.T) {
	server := newSiteServer(t, map[string]string{"/": `<html></html>`})
	defer server.Close()

	outDir := t.TempDir()
	if err := run(testConfig(server.URL+"/", outDir)); err != nil {
		t.Fatal(err)
	}
	siteDir := filepath.Join(outDir, urlutil.SanitizeDomain(server.URL))
	data, err := os.ReadFile(filepath.Join(siteDir, "js-map.txt"))
	if err != nil || len(data) != 0 {
		t.Fatalf("empty map = %q, error = %v", data, err)
	}
}

func TestSameContentFromDifferentURLsMapsToOneArtifact(t *testing.T) {
	server := newSiteServer(t, map[string]string{
		"/":     "<script src=\"/a.js\"></script>\n<script src=\"/b.js\"></script>",
		"/a.js": `console.log("same");`,
		"/b.js": `console.log("same");`,
	})
	defer server.Close()

	outDir := t.TempDir()
	if err := run(testConfig(server.URL+"/", outDir)); err != nil {
		t.Fatal(err)
	}
	siteDir := filepath.Join(outDir, urlutil.SanitizeDomain(server.URL))
	rows := readTabMap(t, filepath.Join(siteDir, "js-map.txt"))
	if len(rows) != 2 || rows[0][1] != rows[1][1] {
		t.Fatalf("deduplicated map rows = %+v", rows)
	}
	if count := countFiles(t, filepath.Join(siteDir, "js")); count != 1 {
		t.Fatalf("deduplicated JavaScript files = %d, want 1", count)
	}
}

func TestSameSiteMultipleEntriesAccumulateJavaScriptMap(t *testing.T) {
	server := newSiteServer(t, map[string]string{
		"/first":     `<script src="/first.js"></script>`,
		"/second":    `<script src="/second.js"></script>`,
		"/first.js":  `console.log("first");`,
		"/second.js": `console.log("second");`,
	})
	defer server.Close()

	listPath := filepath.Join(t.TempDir(), "urls.txt")
	if err := os.WriteFile(listPath, []byte(server.URL+"/second\n"), 0644); err != nil {
		t.Fatal(err)
	}
	outDir := t.TempDir()
	cfg := testConfig(server.URL+"/first", outDir)
	cfg.URLList = listPath
	if err := run(cfg); err != nil {
		t.Fatal(err)
	}
	siteDir := filepath.Join(outDir, urlutil.SanitizeDomain(server.URL))
	rows := readTabMap(t, filepath.Join(siteDir, "js-map.txt"))
	wantURLs := []string{server.URL + "/first.js", server.URL + "/second.js"}
	if len(rows) != 2 || rows[0][0] != wantURLs[0] || rows[1][0] != wantURLs[1] {
		t.Fatalf("same-site accumulated map = %+v", rows)
	}
	assertMapTargetsExist(t, siteDir)
}

func TestHeadlessOnlyWritesJavaScriptMapWithoutAPIArtifacts(t *testing.T) {
	server := newSiteServer(t, map[string]string{
		"/":            `<html></html>`,
		"/headless.js": `console.log("headless");`,
	})
	defer server.Close()

	originalCheck, originalDiscover := checkBrowserAvailable, discoverBrowser
	checkBrowserAvailable = func() error { return nil }
	discoverBrowser = func(context.Context, *headless.Config, *logging.Logger) (headless.DiscoveryResult, error) {
		return headless.DiscoveryResult{Assets: []analyzer.JSAsset{{
			URL: server.URL + "/headless.js", Source: analyzer.SourceHeadlessNetwork,
			Confidence: analyzer.ConfHigh, Status: analyzer.StatusCandidate,
		}}}, nil
	}
	t.Cleanup(func() { checkBrowserAvailable, discoverBrowser = originalCheck, originalDiscover })

	outDir := t.TempDir()
	cfg := testConfig(server.URL+"/", outDir)
	cfg.Headless = true
	if err := run(cfg); err != nil {
		t.Fatal(err)
	}
	siteDir := filepath.Join(outDir, urlutil.SanitizeDomain(server.URL))
	assertMapTargetsExist(t, siteDir)
	assertPathMissing(t, filepath.Join(siteDir, "endpoints.txt"))
	assertPathMissing(t, filepath.Join(siteDir, "runtime"))
	assertPathMissing(t, filepath.Join(siteDir, "analysis"))
}

func TestFailedJavaScriptDownloadDoesNotCreateMapRow(t *testing.T) {
	server := newSiteServer(t, map[string]string{"/": `<script src="/missing.js"></script>`})
	defer server.Close()

	outDir := t.TempDir()
	if err := run(testConfig(server.URL+"/", outDir)); err != nil {
		t.Fatal(err)
	}
	siteDir := filepath.Join(outDir, urlutil.SanitizeDomain(server.URL))
	data, err := os.ReadFile(filepath.Join(siteDir, "js-map.txt"))
	if err != nil || len(data) != 0 {
		t.Fatalf("failed-download map = %q, error = %v", data, err)
	}
	if count := countFiles(t, filepath.Join(siteDir, "js")); count != 0 {
		t.Fatalf("failed-download outputs = %d, want 0", count)
	}
}

func TestRunRemovesLegacyAndPreviousModeOutputs(t *testing.T) {
	server := newSiteServer(t, map[string]string{
		"/":       `<script src="/app.js"></script>`,
		"/app.js": `console.log("app");`,
	})
	defer server.Close()

	outDir := t.TempDir()
	site := urlutil.SanitizeDomain(server.URL)
	for _, stale := range []string{
		"js.txt",
		"dynamic_imports.json",
		"route_chunk_map.json",
		"sourcemaps.txt",
		"framework_detect.json",
		"analysis_errors.log",
		"audit_bundle/manifest.json",
		filepath.Join(site, "entry.html"),
		filepath.Join(site, "audit", "manifest.json"),
		filepath.Join(site, "runtime", "requests.jsonl"),
		filepath.Join(site, "analysis", "endpoints.jsonl"),
		filepath.Join(site, "js-map.txt"),
		filepath.Join(site, "endpoints.txt"),
		filepath.Join(site, "js", "old.js"),
	} {
		path := filepath.Join(outDir, stale)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatalf("MkdirAll stale path: %v", err)
		}
		if err := os.WriteFile(path, []byte("stale"), 0644); err != nil {
			t.Fatalf("write stale path: %v", err)
		}
	}
	for rel, content := range map[string]string{
		"user-notes.txt":     "keep top-level",
		"other_com/keep.txt": "keep other site",
	} {
		path := filepath.Join(outDir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}

	if err := run(testConfig(server.URL+"/", outDir)); err != nil {
		t.Fatalf("run() error = %v", err)
	}
	assertNoLegacyReports(t, outDir)
	assertPathMissing(t, filepath.Join(outDir, site, "entry.html"))
	assertPathMissing(t, filepath.Join(outDir, site, "audit"))
	assertPathMissing(t, filepath.Join(outDir, site, "runtime"))
	assertPathMissing(t, filepath.Join(outDir, site, "analysis"))
	assertPathMissing(t, filepath.Join(outDir, site, "endpoints.txt"))
	assertPathMissing(t, filepath.Join(outDir, site, "js", "old.js"))
	assertMapTargetsExist(t, filepath.Join(outDir, site))
	assertFileContent(t, filepath.Join(outDir, "user-notes.txt"), "keep top-level")
	assertFileContent(t, filepath.Join(outDir, "other_com", "keep.txt"), "keep other site")
}

func TestMaxJSPrecisionLimit(t *testing.T) {
	cfg, s, a, log, prep := analysisHarness(t)
	cfg.MaxJS = 2
	queued := make(map[string]bool)
	processed := make(map[string]bool)
	var queue []fetchReq
	analyzed := 0
	total := 0

	for _, name := range []string{"a.js", "b.js", "c.js"} {
		analyzeResultForTest(cfg, s, a, log, prep, successfulFetch(name, `console.log("ok");`), "https://example.com/", queued, processed, &queue, &analyzed, &total)
	}

	if total != 2 {
		t.Fatalf("total analyzed = %d, want 2", total)
	}
	if got := len(s.GetConfirmedURLs()); got != 2 {
		t.Fatalf("confirmed JavaScript = %d, want 2", got)
	}
}

func TestMaxDepthLimit(t *testing.T) {
	cfg, s, a, log, prep := analysisHarness(t)
	cfg.MaxDepth = 1
	queued := map[string]bool{"https://example.com/a.js": true}
	processed := make(map[string]bool)
	var queue []fetchReq
	analyzed := 0
	total := 0

	result := successfulFetch("a.js", `import("./b.js");`)
	result.req.depth = 1
	analyzeResultForTest(cfg, s, a, log, prep, result, "https://example.com/", queued, processed, &queue, &analyzed, &total)

	if len(queue) != 0 {
		t.Fatalf("queued items = %d, want 0 beyond depth limit", len(queue))
	}
	if total != 1 {
		t.Fatalf("total analyzed = %d, want 1", total)
	}
}

func TestZeroDepthStopsRecursiveDiscovery(t *testing.T) {
	cfg, s, a, log, prep := analysisHarness(t)
	cfg.MaxDepth = 0
	queued := map[string]bool{"https://example.com/a.js": true}
	processed := make(map[string]bool)
	var queue []fetchReq
	analyzed := 0
	total := 0

	analyzeResultForTest(cfg, s, a, log, prep, successfulFetch("a.js", `import("./b.js");`), "https://example.com/", queued, processed, &queue, &analyzed, &total)

	if len(queue) != 0 {
		t.Fatalf("queued items = %d, want 0 when depth is zero", len(queue))
	}
	if total != 1 {
		t.Fatalf("total analyzed = %d, want the entry JavaScript only", total)
	}
}

func TestCircularImportIsProcessedOnce(t *testing.T) {
	cfg, s, a, log, prep := analysisHarness(t)
	cfg.MaxDepth = 5
	queued := map[string]bool{"https://example.com/a.js": true}
	processed := make(map[string]bool)
	var queue []fetchReq
	analyzed := 0
	total := 0

	analyzeResultForTest(cfg, s, a, log, prep, successfulFetch("a.js", `import("./b.js");`), "https://example.com/", queued, processed, &queue, &analyzed, &total)
	if len(queue) != 1 || queue[0].url != "https://example.com/b.js" {
		t.Fatalf("queue after a.js = %+v", queue)
	}

	next := queue[0]
	queue = nil
	result := successfulFetch("b.js", `import("./a.js");`)
	result.req = next
	analyzeResultForTest(cfg, s, a, log, prep, result, "https://example.com/", queued, processed, &queue, &analyzed, &total)

	if len(queue) != 0 {
		t.Fatalf("queue after circular import = %+v, want empty", queue)
	}
	if total != 2 {
		t.Fatalf("total analyzed = %d, want 2", total)
	}
}

func TestCrawlStateIsSharedWithinSiteOnly(t *testing.T) {
	states := make(map[string]*crawlState)
	first := crawlStateForSite(states, "example_com")
	first.processed["https://cdn.example/app.js"] = true

	sameSite := crawlStateForSite(states, "example_com")
	if !sameSite.processed["https://cdn.example/app.js"] {
		t.Fatal("same-site entries did not share processed state")
	}

	otherSite := crawlStateForSite(states, "other_com")
	if otherSite.processed["https://cdn.example/app.js"] {
		t.Fatal("different sites unexpectedly shared processed state")
	}
}

func TestCLIAndDocumentationRemoveLegacyFlagsAndReports(t *testing.T) {
	configSource, err := os.ReadFile(filepath.Join("..", "..", "internal", "config", "config.go"))
	if err != nil {
		t.Fatalf("read config.go: %v", err)
	}
	configText := string(configSource)
	for _, removed := range []string{
		`"m"`,
		`"b"`,
		`"audit-prep"`,
		"FetchSourcemap",
		"AuditPrep",
		"AuditPrepAlias",
	} {
		if strings.Contains(configText, removed) {
			t.Fatalf("config still contains removed CLI behavior %q", removed)
		}
	}

	readme, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	readmeText := string(readme)
	for _, removed := range []string{
		"js.txt",
		"dynamic_imports.json",
		"route_chunk_map.json",
		"framework_detect.json",
		"runtime/requests.jsonl",
		"analysis/static-endpoints.jsonl",
		"analysis/endpoints.jsonl",
		"analysis/runtime-bases.json",
		"--audit-prep",
		"audit/manifest.json",
		"indexes/",
		"slices/",
		"transform_log.json",
		"`-m`",
		"`-b`",
	} {
		if strings.Contains(readmeText, removed) {
			t.Fatalf("README still contains removed output or flag %q", removed)
		}
	}
	for _, required := range []string{
		"`--api-discovery`",
		"`--insecure`",
		"`--insecure-skip-verify`",
		"`--proxy <url>`",
		"Node.js 18 or newer",
		"js-map.txt",
		"endpoints.txt",
		"Tab",
		"one absolute HTTP(S) URL per line",
		"API intermediate JSON",
		"does not persist entry.html",
		"| `-d <depth>` | `10`",
		"| `-s <mb>` | unlimited",
	} {
		if !strings.Contains(readmeText, required) {
			t.Fatalf("README is missing %q", required)
		}
	}
}

func TestBuildHeadlessConfigIncludesNetworkOptions(t *testing.T) {
	cfg := &config.Config{
		Timeout:            21,
		SameOrigin:         true,
		AllowCDN:           []string{"cdn.example.com"},
		Verbose:            true,
		InsecureSkipVerify: true,
		Proxy:              "socks5://127.0.0.1:1080",
		APIDiscovery:       true,
		UserAgent:          "JSpider-Test-UA",
		Cookies:            "session=test",
		Headers:            map[string]string{"X-Test": "yes"},
	}

	got := buildHeadlessConfig(cfg, "https://example.com")
	if got.Timeout.String() != "21s" {
		t.Fatalf("Timeout = %s, want 21s", got.Timeout)
	}
	if !got.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify = false, want true")
	}
	if got.Proxy != cfg.Proxy {
		t.Fatalf("Proxy = %q, want %q", got.Proxy, cfg.Proxy)
	}
	if !got.CaptureAPI {
		t.Fatal("CaptureAPI = false, want true")
	}
	if got.UserAgent != cfg.UserAgent || got.Cookies != cfg.Cookies || got.Headers["X-Test"] != "yes" {
		t.Fatalf("browser request config = %+v", got)
	}
}

func analysisHarness(t *testing.T) (*config.Config, *store.Store, *analyzer.Analyzer, *logging.Logger, *preprocess.Processor) {
	t.Helper()
	outDir := t.TempDir()
	cfg := testConfig("https://example.com/", outDir)
	log := logging.New(false, outDir)
	processor, err := preprocess.New(filepath.Join(outDir, "example_com"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = processor.Close()
		log.Close()
	})
	return cfg, store.New(outDir), analyzer.NewAnalyzer(log), log, processor
}

func successfulFetch(name, body string) fetchRes {
	rawURL := "https://example.com/" + name
	return fetchRes{
		req: fetchReq{url: rawURL, depth: 0, from: "https://example.com/"},
		result: &fetcher.Result{
			URL:         rawURL,
			StatusCode:  200,
			ContentType: "application/javascript",
			Body:        []byte(body),
			IsJS:        true,
		},
	}
}

func analyzeResultForTest(cfg *config.Config, s *store.Store, a *analyzer.Analyzer, log *logging.Logger, prep *preprocess.Processor, res fetchRes, entryURL string, queued, processed map[string]bool, queue *[]fetchReq, analyzed, totalAnalyzed *int) {
	analyzeResultWithPreprocess(cfg, s, a, log, prep, nil, res, entryURL, urlutil.SanitizeDomain(entryURL), queued, processed, queue, analyzed, totalAnalyzed)
}

func testConfig(entryURL, outDir string) *config.Config {
	return &config.Config{
		URL:                   entryURL,
		OutDir:                outDir,
		MaxJS:                 100,
		MaxDepth:              config.DefaultMaxDepth,
		MaxSizeMB:             config.DefaultMaxSizeMB,
		Workers:               2,
		SameOrigin:            true,
		Timeout:               5,
		ProcessTimeoutSeconds: config.DefaultProcessTimeoutSeconds,
		HeadlessBodyMB:        config.DefaultHeadlessBodyMB,
		UserAgent:             "JSpider-Test/1.0",
	}
}

func newSiteServer(t *testing.T, routes map[string]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := routes[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if strings.HasSuffix(r.URL.Path, ".map") {
			w.Header().Set("Content-Type", "application/json")
		} else if strings.HasSuffix(r.URL.Path, ".js") {
			w.Header().Set("Content-Type", "application/javascript")
		} else {
			w.Header().Set("Content-Type", "text/html")
		}
		_, _ = w.Write([]byte(body))
	}))
}

func readTabMap(t *testing.T, path string) [][2]string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rows [][2]string
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) != 2 {
			t.Fatalf("invalid map row %q", line)
		}
		rows = append(rows, [2]string{parts[0], parts[1]})
	}
	return rows
}

func assertMapTargetsExist(t *testing.T, siteDir string) {
	t.Helper()
	for _, row := range readTabMap(t, filepath.Join(siteDir, "js-map.txt")) {
		assertPathExists(t, filepath.Join(siteDir, filepath.FromSlash(row[1])))
	}
}

func countFiles(t *testing.T, root string) int {
	t.Helper()
	count := 0
	err := filepath.WalkDir(root, func(_ string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			count++
		}
		return nil
	})
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		t.Fatalf("WalkDir %s: %v", root, err)
	}
	return count
}

func assertNoLegacyReports(t *testing.T, outDir string) {
	t.Helper()
	for _, name := range []string{
		"analysis_errors.log",
		"js.txt",
		"dynamic_imports.json",
		"route_chunk_map.json",
		"sourcemaps.txt",
		"framework_detect.json",
		"audit_bundle",
	} {
		assertPathMissing(t, filepath.Join(outDir, name))
	}
}

func assertPathExists(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected %s: %v", path, err)
	}
}

func assertPathMissing(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected %s to be absent, stat error = %v", path, err)
	}
}

func assertFileContent(t *testing.T, path, want string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil || string(data) != want {
		t.Fatalf("%s = %q, error = %v; want %q", path, data, err, want)
	}
}
