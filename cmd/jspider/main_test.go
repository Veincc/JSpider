package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Veincc/JSpider/internal/analyzer"
	"github.com/Veincc/JSpider/internal/config"
	"github.com/Veincc/JSpider/internal/fetcher"
	"github.com/Veincc/JSpider/internal/html"
	"github.com/Veincc/JSpider/internal/logging"
	"github.com/Veincc/JSpider/internal/store"
	"github.com/Veincc/JSpider/internal/urlutil"
)

func setupTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	// index.html includes /assets/main.js
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
<script src="/assets/main.js"></script>
</body>
</html>`))
	})

	// main.js contains import() and sourceMappingURL
	mux.HandleFunc("/assets/main.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte(`// main.js
function loadChunk() {
  return import("./chunk.js");
}
loadChunk();
//# sourceMappingURL=main.js.map
`))
	})

	// chunk.js is downloadable
	mux.HandleFunc("/assets/chunk.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte(`// chunk.js
export function hello() {
  return "world";
}
`))
	})

	// main.js.map source map
	mux.HandleFunc("/assets/main.js.map", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		sourceMap := map[string]interface{}{
			"version":        3,
			"file":           "main.js",
			"sources":        []string{"src/main.ts"},
			"sourcesContent": []string{"function loadChunk() {\n  return import('./chunk.js');\n}\nloadChunk();\n"},
			"mappings":       "AAAA",
		}
		data, _ := json.Marshal(sourceMap)
		w.Write(data)
	})

	return httptest.NewServer(mux)
}

func TestEndToEnd(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	// Create temp output directory
	outDir := t.TempDir()

	cfg := &config.Config{
		URL:            ts.URL + "/",
		OutDir:         outDir,
		MaxJS:          100,
		MaxDepth:       3,
		MaxSizeMB:      10,
		Workers:        2,
		SameOrigin:     true,
		FetchSourcemap: true,
		Timeout:        5,
		UserAgent:      "JSpider-Test/1.0",
		Verbose:        true,
	}

	log := logging.New(cfg.Verbose, cfg.OutDir)
	defer log.Close()

	f := fetcher.New(cfg, log)
	s := store.New(cfg.OutDir)
	a := analyzer.NewAnalyzer(log)
	htmlEx := html.NewExtractor()

	// Simulate main flow
	entryURL := cfg.URL

	// 1. Download entry HTML
	htmlResult := f.Fetch(entryURL)
	if htmlResult.Err != nil {
		t.Fatalf("Failed to download entry HTML: %v", htmlResult.Err)
	}

	htmlContent := string(htmlResult.Body)
	entryDomain := "127_0_0_1"
	s.SaveRaw(entryDomain, "entry.html", htmlResult.Body)

	// 2. Extract entry JS
	entryAssets := htmlEx.ExtractEntryJS(htmlContent, entryURL)
	if len(entryAssets) == 0 {
		t.Fatal("No entry JS found")
	}
	t.Logf("Found %d entry JS files", len(entryAssets))

	// 3. Download and analyze entry JS (full crawl loop)
	queued := make(map[string]bool)
	processed := make(map[string]bool)
	var queue []fetchReq

	for _, asset := range entryAssets {
		addToQueue(asset.URL, 0, entryURL, queued, processed, &queue)
	}

	totalAnalyzed := 0
	for len(queue) > 0 {
		if cfg.MaxJS > 0 && totalAnalyzed >= cfg.MaxJS {
			break
		}
		results := fetchBatch(cfg, f, log, queue)
		queue = nil
		analyzed := 0
		for res := range results {
			analyzeResult(cfg, s, a, log, res, entryURL, queued, processed, &queue, &analyzed, &totalAnalyzed)
		}
	}

	// 4. Process source maps
	fetchSourceMaps(cfg, s, f, a, log)

	// 5. Save results
	if err := s.SaveAll(); err != nil {
		t.Fatalf("Failed to save results: %v", err)
	}

	// Verify output files
	assertFileExists(t, outDir+"/js.txt")
	assertFileExists(t, outDir+"/dynamic_imports.json")
	assertFileExists(t, outDir+"/sourcemaps.txt")
	assertFileExists(t, outDir+"/framework_detect.json")

	// Verify js.txt contains all confirmed URLs
	jsTxtData, err := os.ReadFile(filepath.Join(outDir, "js.txt"))
	if err != nil {
		t.Fatalf("Failed to read js.txt: %v", err)
	}
	jsTxtContent := string(jsTxtData)
	if len(jsTxtContent) == 0 {
		t.Error("js.txt should not be empty")
	}

	// Verify confirmed JS contains main.js
	confirmed := s.GetConfirmedURLs()
	found := false
	for _, u := range confirmed {
		if u == ts.URL+"/assets/main.js" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("main.js missing from confirmed, got: %v", confirmed)
	}

	// Verify dynamic_imports contains chunk.js
	imports := s.GetDynamicImports()
	hasChunkImport := false
	for _, imp := range imports {
		if imp.ResolvedURL == ts.URL+"/assets/chunk.js" {
			hasChunkImport = true
			break
		}
	}
	if !hasChunkImport {
		t.Errorf("chunk.js import missing from dynamic_imports, got: %v", imports)
	}

	// Verify sourcemaps
	sourcemaps := s.GetSourcemaps()
	hasParsedMap := false
	for _, sm := range sourcemaps {
		if sm.Status == "parsed" && sm.HasSourcesContent {
			hasParsedMap = true
			break
		}
	}
	if !hasParsedMap {
		t.Errorf("Parsed source map missing from sourcemaps, got: %v", sourcemaps)
	}

	// Verify JS files exist in output directory
	jsDir := filepath.Join(outDir, entryDomain)
	entries, _ := os.ReadDir(jsDir)
	jsCount := 0
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".js" {
			jsCount++
		}
	}
	if jsCount < 2 { // main.js + chunk.js
		t.Errorf("Not enough JS files, got %d", jsCount)
	}

	t.Logf("Test passed: analyzed %d JS files, confirmed=%d, imports=%d, sourcemaps=%d",
		totalAnalyzed, len(confirmed), len(imports), len(sourcemaps))
}

func TestMaxDepthLimit(t *testing.T) {
	// Test MaxDepth limit
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<script src="/a.js"></script>`))
		case "/a.js":
			w.Header().Set("Content-Type", "application/javascript")
			w.Write([]byte(`import("./b.js");`))
		case "/b.js":
			w.Header().Set("Content-Type", "application/javascript")
			w.Write([]byte(`import("./c.js");`))
		case "/c.js":
			w.Header().Set("Content-Type", "application/javascript")
			w.Write([]byte(`console.log("c");`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	outDir := t.TempDir()
	cfg := &config.Config{
		URL:        ts.URL + "/",
		OutDir:     outDir,
		MaxJS:      100,
		MaxDepth:   1, // Only allow depth 0 and 1
		MaxSizeMB:  10,
		Workers:    1,
		SameOrigin: true,
		Timeout:    5,
		UserAgent:  "Test/1.0",
		Verbose:    false,
	}

	log := logging.New(false, outDir)
	defer log.Close()
	f := fetcher.New(cfg, log)
	s := store.New(outDir)
	a := analyzer.NewAnalyzer(log)
	htmlEx := html.NewExtractor()

	entryURL := cfg.URL
	htmlResult := f.Fetch(entryURL)
	if htmlResult.Err != nil {
		t.Fatalf("HTML fetch error: %v", htmlResult.Err)
	}
	htmlContent := string(htmlResult.Body)
	entryAssets := htmlEx.ExtractEntryJS(htmlContent, entryURL)

	queued := make(map[string]bool)
	processed := make(map[string]bool)
	var queue []fetchReq
	for _, asset := range entryAssets {
		addToQueue(asset.URL, 0, entryURL, queued, processed, &queue)
	}

	totalAnalyzed := 0
	for len(queue) > 0 {
		if cfg.MaxJS > 0 && totalAnalyzed >= cfg.MaxJS {
			break
		}
		results := fetchBatch(cfg, f, log, queue)
		queue = nil
		analyzed := 0
		for res := range results {
			analyzeResult(cfg, s, a, log, res, entryURL, queued, processed, &queue, &analyzed, &totalAnalyzed)
		}
	}

	// a.js depth 0, b.js depth 1, c.js depth 2 (should be skipped)
	confirmed := s.GetConfirmedURLs()
	confirmedSet := make(map[string]bool)
	for _, u := range confirmed {
		confirmedSet[u] = true
	}

	if !confirmedSet[ts.URL+"/a.js"] {
		t.Error("a.js should be analyzed (depth 0)")
	}
	// b.js depth 1, MaxDepth=1, should be analyzed
	if !confirmedSet[ts.URL+"/b.js"] {
		t.Error("b.js should be analyzed (depth 1 <= MaxDepth=1)")
	}
	if confirmedSet[ts.URL+"/c.js"] {
		t.Error("c.js should not be analyzed (depth 2 > MaxDepth=1)")
	}

	t.Logf("MaxDepth test: confirmed=%d, totalAnalyzed=%d", len(confirmed), totalAnalyzed)
}

func TestStoreSaveAllCreatesDir(t *testing.T) {
	// Test SaveAll auto-creates output directory
	outDir := filepath.Join(t.TempDir(), "nonexistent", "deep", "path")
	s := store.New(outDir)

	// Add some data
	s.AddJS(&analyzer.JSAsset{
		URL:    "https://example.com/test.js",
		Status: analyzer.StatusConfirmed,
	})

	if err := s.SaveAll(); err != nil {
		t.Fatalf("SaveAll should auto-create the directory, got error: %v", err)
	}

	// Verify file exists
	assertFileExists(t, outDir+"/js.txt")
}

func assertFileExists(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Errorf("File does not exist: %s", path)
	}
}

func TestMaxJS_PrecisionLimit(t *testing.T) {
	// Test that MaxJS is a hard limit, not a soft one
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<script src="/a.js"></script><script src="/b.js"></script><script src="/c.js"></script>`))
		case "/a.js", "/b.js", "/c.js":
			w.Header().Set("Content-Type", "application/javascript")
			w.Write([]byte(`console.log("ok");`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	outDir := t.TempDir()
	cfg := &config.Config{
		URL:        ts.URL + "/",
		OutDir:     outDir,
		MaxJS:      2, // Only allow 2
		MaxDepth:   3,
		MaxSizeMB:  10,
		Workers:    3,
		SameOrigin: true,
		Timeout:    5,
		UserAgent:  "Test/1.0",
		Verbose:    false,
	}

	log := logging.New(false, outDir)
	defer log.Close()
	f := fetcher.New(cfg, log)
	s := store.New(outDir)
	a := analyzer.NewAnalyzer(log)
	htmlEx := html.NewExtractor()

	queued := make(map[string]bool)
	processed := make(map[string]bool)
	entryAssets := htmlEx.ExtractEntryJS(`<script src="/a.js"></script><script src="/b.js"></script><script src="/c.js"></script>`, ts.URL+"/")

	var queue []fetchReq
	for _, asset := range entryAssets {
		addToQueue(asset.URL, 0, ts.URL+"/", queued, processed, &queue)
	}

	totalAnalyzed := 0
	for len(queue) > 0 {
		if cfg.MaxJS > 0 && totalAnalyzed >= cfg.MaxJS {
			break
		}
		results := fetchBatch(cfg, f, log, queue)
		queue = nil
		analyzed := 0
		for res := range results {
			analyzeResult(cfg, s, a, log, res, ts.URL+"/", queued, processed, &queue, &analyzed, &totalAnalyzed)
		}
	}

	if totalAnalyzed > 2 {
		t.Errorf("MaxJS=2 but analyzed %d", totalAnalyzed)
	}
}

func TestCircularImport(t *testing.T) {
	// A imports B, B imports A - should not loop forever
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<script src="/a.js"></script>`))
		case "/a.js":
			w.Header().Set("Content-Type", "application/javascript")
			w.Write([]byte(`import("./b.js");`))
		case "/b.js":
			w.Header().Set("Content-Type", "application/javascript")
			w.Write([]byte(`import("./a.js");`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	outDir := t.TempDir()
	cfg := &config.Config{
		URL:        ts.URL + "/",
		OutDir:     outDir,
		MaxJS:      100,
		MaxDepth:   5,
		MaxSizeMB:  10,
		Workers:    1,
		SameOrigin: true,
		Timeout:    5,
		UserAgent:  "Test/1.0",
		Verbose:    false,
	}

	log := logging.New(false, outDir)
	defer log.Close()
	f := fetcher.New(cfg, log)
	s := store.New(outDir)
	a := analyzer.NewAnalyzer(log)
	htmlEx := html.NewExtractor()

	entryURL := cfg.URL
	htmlResult := f.Fetch(entryURL)
	htmlContent := string(htmlResult.Body)
	entryAssets := htmlEx.ExtractEntryJS(htmlContent, entryURL)

	queued := make(map[string]bool)
	processed := make(map[string]bool)
	var queue []fetchReq
	for _, asset := range entryAssets {
		addToQueue(asset.URL, 0, entryURL, queued, processed, &queue)
	}

	totalAnalyzed := 0
	for len(queue) > 0 {
		if cfg.MaxJS > 0 && totalAnalyzed >= cfg.MaxJS {
			break
		}
		results := fetchBatch(cfg, f, log, queue)
		queue = nil
		analyzed := 0
		for res := range results {
			analyzeResult(cfg, s, a, log, res, entryURL, queued, processed, &queue, &analyzed, &totalAnalyzed)
		}
	}

	// Should process a.js and b.js exactly once each
	if totalAnalyzed != 2 {
		t.Errorf("Expected 2 analyzed (circular), got %d", totalAnalyzed)
	}

	confirmed := s.GetConfirmedURLs()
	if len(confirmed) != 2 {
		t.Errorf("Expected 2 confirmed, got %d: %v", len(confirmed), confirmed)
	}
}

func TestEntryJS_SameOriginFilter(t *testing.T) {
	outDir := t.TempDir()
	cfg := &config.Config{
		OutDir:     outDir,
		MaxJS:      10,
		MaxDepth:   2,
		MaxSizeMB:  10,
		Workers:    1,
		SameOrigin: true,
		Timeout:    5,
		UserAgent:  "Test/1.0",
	}

	log := logging.New(false, outDir)
	defer log.Close()

	s := store.New(outDir)
	htmlEx := html.NewExtractor()
	entryURL := "https://example.com/"
	htmlContent := `<script src="/app.js"></script><script src="https://cdn.example.com/lib.js"></script>`

	entryAssets := htmlEx.ExtractEntryJS(htmlContent, entryURL)
	queued := make(map[string]bool)
	processed := make(map[string]bool)
	var queue []fetchReq

	for i := range entryAssets {
		if cfg.SameOrigin && !urlutil.IsAllowedDomain(entryAssets[i].URL, cfg.AllowCDN, entryURL) {
			continue
		}
		entryAssets[i].Depth = 0
		entryAssets[i].FromURL = entryURL
		s.AddJS(&entryAssets[i])
		addToQueue(entryAssets[i].URL, 0, entryURL, queued, processed, &queue)
	}

	confirmed := s.GetCandidateURLs()
	if len(confirmed) != 1 || confirmed[0] != "https://example.com/app.js" {
		t.Fatalf("same-origin filter mismatch, got %v", confirmed)
	}
}

func TestHeadlessDefaultFalse(t *testing.T) {
	cfg := &config.Config{}
	if cfg.Headless {
		t.Errorf("default Config.Headless = %v, want false", cfg.Headless)
	}
}

func TestHeadlessFlagTrue(t *testing.T) {
	cfg := &config.Config{Headless: true}
	if !cfg.Headless {
		t.Error("Config.Headless should be true when set")
	}
}

func TestHybridMergeDedup(t *testing.T) {
	// Test that static + headless assets are properly deduplicated
	outDir := t.TempDir()
	s := store.New(outDir)

	// Simulate static finding a.js and b.js
	s.AddJS(&analyzer.JSAsset{
		URL: "https://example.com/a.js", Status: analyzer.StatusCandidate,
		Source: analyzer.SourceHTMLScript, Confidence: analyzer.ConfHigh,
	})
	s.AddJS(&analyzer.JSAsset{
		URL: "https://example.com/b.js", Status: analyzer.StatusCandidate,
		Source: analyzer.SourceHTMLScript, Confidence: analyzer.ConfHigh,
	})

	// Simulate headless finding b.js (overlap) and c.js (new)
	s.AddJS(&analyzer.JSAsset{
		URL: "https://example.com/b.js", Status: analyzer.StatusCandidate,
		Source: analyzer.SourceHeadlessNetwork, Confidence: analyzer.ConfHigh,
	})
	s.AddJS(&analyzer.JSAsset{
		URL: "https://example.com/c.js", Status: analyzer.StatusCandidate,
		Source: analyzer.SourceHeadlessNetwork, Confidence: analyzer.ConfHigh,
	})

	if err := s.SaveAll(); err != nil {
		t.Fatalf("SaveAll failed: %v", err)
	}

	// js.txt should have 3 unique URLs (a, b, c), not 4
	data, err := os.ReadFile(filepath.Join(outDir, "js.txt"))
	if err != nil {
		t.Fatalf("ReadFile js.txt: %v", err)
	}

	lines := splitLines(string(data))
	if len(lines) != 3 {
		t.Errorf("Expected 3 deduped URLs in js.txt, got %d: %v", len(lines), lines)
	}

	// b.js should still be present (merged, not lost)
	found := false
	for _, line := range lines {
		if line == "https://example.com/b.js" {
			found = true
			break
		}
	}
	if !found {
		t.Error("b.js should be in js.txt (merged from static + headless)")
	}
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			line := s[start:i]
			if line != "" {
				lines = append(lines, line)
			}
			start = i + 1
		}
	}
	if start < len(s) {
		line := s[start:]
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func TestMultiEntry_DoesNotDowngradeConfirmed(t *testing.T) {
	outDir := t.TempDir()
	s := store.New(outDir)

	s.AddJS(&analyzer.JSAsset{
		URL:        "https://example.com/app.js",
		Status:     analyzer.StatusConfirmed,
		Confidence: analyzer.ConfHigh,
		Type:       analyzer.TypeEntryJS,
		Source:     analyzer.SourceHTMLScript,
	})

	s.AddJS(&analyzer.JSAsset{
		URL:        "https://example.com/app.js",
		Status:     analyzer.StatusCandidate,
		Confidence: analyzer.ConfMedium,
		Type:       analyzer.TypeEntryJS,
		Source:     analyzer.SourceHTMLScript,
	})

	confirmed := s.GetConfirmedURLs()
	if len(confirmed) != 1 || confirmed[0] != "https://example.com/app.js" {
		t.Fatalf("confirmed asset was downgraded, got %v", confirmed)
	}
}
