package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Veincc/JSpider/internal/analyzer"
	"github.com/Veincc/JSpider/internal/beautify"
	"github.com/Veincc/JSpider/internal/config"
	"github.com/Veincc/JSpider/internal/fetcher"
	"github.com/Veincc/JSpider/internal/headless"
	"github.com/Veincc/JSpider/internal/html"
	"github.com/Veincc/JSpider/internal/logging"
	"github.com/Veincc/JSpider/internal/store"
	"github.com/Veincc/JSpider/internal/urlutil"
)

// fetchReq represents a pending JS download request
type fetchReq struct {
	url   string
	depth int
	from  string
}

// fetchRes represents a download result
type fetchRes struct {
	req    fetchReq
	result *fetcher.Result
}

func buildHeadlessConfig(cfg *config.Config, entryURL string) *headless.Config {
	return &headless.Config{
		EntryURL:           entryURL,
		Timeout:            time.Duration(cfg.Timeout) * time.Second,
		SameOrigin:         cfg.SameOrigin,
		AllowCDN:           cfg.AllowCDN,
		MaxClicks:          20,
		Verbose:            cfg.Verbose,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
	}
}

func main() {
	cfg := config.Parse()

	if err := os.MkdirAll(cfg.OutDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create output directory: %v\n", err)
		os.Exit(1)
	}

	log := logging.New(cfg.Verbose, cfg.OutDir)
	defer log.Close()

	f := fetcher.New(cfg, log)
	s := store.New(cfg.OutDir)
	a := analyzer.NewAnalyzer(log)
	htmlEx := html.NewExtractor()

	// Check for js-beautify
	if cfg.Beautify {
		if !beautify.IsAvailable() {
			log.Warn("js-beautify not installed, beautify disabled (npm install -g js-beautify)")
			cfg.Beautify = false
		} else {
			log.Info("js-beautify enabled, JS files will be beautified")
		}
	}

	// Check browser availability when headless mode is requested
	if cfg.Headless {
		if err := headless.CheckBrowserAvailable(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		log.Info("Headless discovery enabled: Chrome/Chromium found")
	}

	urls := cfg.URLs()
	if len(urls) == 0 {
		log.Error("No URLs to analyze")
		os.Exit(1)
	}

	log.Info("JSpider started: %d entry URLs, workers %d, output dir %s", len(urls), cfg.Workers, cfg.OutDir)

	// Global deduplication state
	queued := make(map[string]bool)
	processed := make(map[string]bool)
	totalAnalyzed := 0

	for i, entryURL := range urls {
		log.Info("[%d/%d] Analyzing: %s", i+1, len(urls), entryURL)
		analyzed := analyzeEntry(cfg, s, f, a, htmlEx, log, entryURL, queued, processed, &totalAnalyzed)
		log.Info("[%d/%d] Done: %s (analyzed %d JS)", i+1, len(urls), entryURL, analyzed)
	}

	// Source map processing
	if cfg.FetchSourcemap {
		fetchSourceMaps(cfg, s, f, a, log)
	}

	// Save results
	log.Info("Saving analysis results...")
	if err := s.SaveAll(); err != nil {
		log.Error("Failed to save results: %v", err)
		os.Exit(1)
	}

	printSummary(s, totalAnalyzed, cfg.OutDir, log)
}

// analyzeEntry analyzes a single entry URL and returns the number of JS files analyzed.
// It always runs static HTML extraction, and additionally runs headless browser
// discovery if cfg.Headless is enabled, merging and deduplicating the results.
func analyzeEntry(cfg *config.Config, s *store.Store, f *fetcher.Fetcher, a *analyzer.Analyzer, htmlEx *html.Extractor, log *logging.Logger, entryURL string, queued, processed map[string]bool, totalAnalyzed *int) int {
	entryDomain := urlutil.SanitizeDomain(entryURL)

	// 1. Static HTML extraction (always)
	log.Info("Downloading entry HTML: %s", entryURL)
	htmlResult := f.Fetch(entryURL)
	if htmlResult.Err != nil {
		log.LogError("download entry HTML", "URL=%s error=%v", entryURL, htmlResult.Err)
		return 0
	}

	htmlContent := string(htmlResult.Body)
	log.Info("Entry HTML size: %d bytes", len(htmlContent))
	s.SaveRaw(entryDomain, "entry.html", htmlResult.Body)

	staticAssets := htmlEx.ExtractEntryJS(htmlContent, entryURL)
	log.Info("Static extraction found %d JS assets", len(staticAssets))

	entryAssets := staticAssets

	// 2. Headless discovery (optional)
	if cfg.Headless {
		log.Info("Running headless discovery: %s", entryURL)
		hlAssets, err := headless.Discover(context.Background(), buildHeadlessConfig(cfg, entryURL), log)
		if err != nil {
			log.Warn("Headless discovery failed (continuing with static results): %v", err)
		} else {
			log.Info("Headless discovery found %d JS assets", len(hlAssets))
		}

		// Merge: deduplicate by URL, prefer static source info
		merged := make(map[string]*analyzer.JSAsset)
		for i := range staticAssets {
			if cfg.SameOrigin && !urlutil.IsAllowedDomain(staticAssets[i].URL, cfg.AllowCDN, entryURL) {
				continue
			}
			cp := staticAssets[i]
			merged[cp.URL] = &cp
		}
		for i := range hlAssets {
			if _, exists := merged[hlAssets[i].URL]; !exists {
				cp := hlAssets[i]
				merged[cp.URL] = &cp
			}
		}
		entryAssets = nil
		for _, v := range merged {
			entryAssets = append(entryAssets, *v)
		}
		log.Info("Merged: %d unique JS assets", len(entryAssets))
	}

	// Add entry JS assets to store
	for i := range entryAssets {
		if cfg.SameOrigin && !urlutil.IsAllowedDomain(entryAssets[i].URL, cfg.AllowCDN, entryURL) {
			log.Verbose("Skipping entry JS (not same-origin): %s", entryAssets[i].URL)
			continue
		}
		entryAssets[i].Depth = 0
		entryAssets[i].FromURL = entryURL
		s.AddJS(&entryAssets[i])
	}

	// Initialize queue
	var queue []fetchReq
	for _, asset := range entryAssets {
		if cfg.SameOrigin && !urlutil.IsAllowedDomain(asset.URL, cfg.AllowCDN, entryURL) {
			continue
		}
		addToQueue(asset.URL, 0, entryURL, queued, processed, &queue)
	}

	// Concurrent download + serial analysis
	analyzed := 0

	for len(queue) > 0 {
		// Check limits
		if cfg.MaxJS > 0 && *totalAnalyzed >= cfg.MaxJS {
			log.Info("Reached max analysis count (%d), stopping", cfg.MaxJS)
			break
		}

		// Concurrent download this batch
		results := fetchBatch(cfg, f, log, queue)
		queue = nil

		// Serially analyze each result
		for res := range results {
			analyzeResult(cfg, s, a, log, res, entryURL, queued, processed, &queue, &analyzed, totalAnalyzed)
		}
	}

	// Mark undownloaded entry JS as candidate
	for _, asset := range entryAssets {
		if !processed[asset.URL] {
			s.AddJS(&analyzer.JSAsset{
				URL:        asset.URL,
				FromURL:    entryURL,
				Type:       asset.Type,
				Source:     asset.Source,
				Confidence: asset.Confidence,
				Status:     analyzer.StatusCandidate,
				Depth:      0,
			})
		}
	}

	return analyzed
}

// fetchBatch concurrently downloads a batch of URLs
func fetchBatch(cfg *config.Config, f *fetcher.Fetcher, log *logging.Logger, queue []fetchReq) <-chan fetchRes {
	results := make(chan fetchRes, len(queue))
	workers := cfg.Workers
	if workers <= 0 {
		workers = 1
	}
	if workers > len(queue) {
		workers = len(queue)
	}

	var wg sync.WaitGroup
	reqCh := make(chan fetchReq, len(queue))
	for _, req := range queue {
		reqCh <- req
	}
	close(reqCh)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for req := range reqCh {
				log.Verbose("Downloading: %s (depth=%d)", req.url, req.depth)
				results <- fetchRes{req: req, result: f.FetchJS(req.url)}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	return results
}

// analyzeResult analyzes a single download result
func analyzeResult(cfg *config.Config, s *store.Store, a *analyzer.Analyzer, log *logging.Logger, res fetchRes, entryURL string, queued, processed map[string]bool, queue *[]fetchReq, analyzed, totalAnalyzed *int) {
	item := res.req

	if processed[item.url] {
		return
	}
	processed[item.url] = true

	// Exact MaxJS limit (serial analysis, no race condition)
	if cfg.MaxJS > 0 && *totalAnalyzed >= cfg.MaxJS {
		return
	}

	if res.result.Err != nil {
		log.LogError("Download failed", "URL=%s error=%v", item.url, res.result.Err)
		s.AddJS(&analyzer.JSAsset{
			URL: item.url, FromURL: item.from,
			Type: analyzer.TypeUnknownJS, Source: analyzer.SourceRegexCandidate,
			Confidence: analyzer.ConfLow, Status: analyzer.StatusFailed, Depth: item.depth,
		})
		return
	}

	// Beautify processing
	saveData := res.result.Body
	if cfg.Beautify {
		if beautified, err := beautify.Beautify(res.result.Body); err == nil {
			saveData = beautified
		} else {
			log.Verbose("Beautify failed %s: %v, saving original version", item.url, err)
		}
	}

	// Save to domain directory
	filename := urlutil.SanitizeFilename(item.url)
	domain := urlutil.SanitizeDomain(item.url)
	s.SaveRaw(domain, filename+".js", saveData)

	*analyzed++
	*totalAnalyzed++

	// Mark as confirmed
	s.AddJS(&analyzer.JSAsset{
		URL: item.url, FromURL: item.from,
		Type: analyzer.TypeUnknownJS, Source: analyzer.SourceRegexCandidate,
		Confidence: analyzer.ConfHigh, Status: analyzer.StatusConfirmed,
		Depth: item.depth, ContentType: res.result.ContentType,
		Size: res.result.Size, Hash: res.result.Hash,
	})

	// Analyze JS
	result := a.AnalyzeJS(string(res.result.Body), item.url, item.from, item.depth)

	// Write analysis results to store
	for _, imp := range result.Imports {
		s.AddDynamicImport(imp)
	}
	for _, route := range result.Routes {
		s.AddRoute(route)
	}
	for _, sm := range result.Sourcemaps {
		s.AddSourcemap(sm)
	}
	if result.FrameworkInfo != nil {
		s.AddFramework(*result.FrameworkInfo)
	}

	// Also add resolved URLs from dynamic imports to NewURLs (supplementing framework analyzer gaps)
	newURLSet := make(map[string]bool)
	for _, u := range result.NewURLs {
		newURLSet[u.URL] = true
	}
	for _, imp := range result.Imports {
		if imp.ResolvedURL != "" && !newURLSet[imp.ResolvedURL] {
			newURLSet[imp.ResolvedURL] = true
			result.NewURLs = append(result.NewURLs, analyzer.JSAsset{
				URL:        imp.ResolvedURL,
				FromURL:    item.url,
				Type:       analyzer.TypeLazyChunkJS,
				Framework:  result.Framework,
				Source:     imp.Source,
				Confidence: imp.Confidence,
				Status:     analyzer.StatusCandidate,
			})
		}
	}

	// Add newly discovered JS URLs to the next batch queue
	for _, newAsset := range result.NewURLs {
		// For static analysis, require IsJSPath. For dynamic sources, allow broader fetch.
		fromDynamic := newAsset.Source == analyzer.SourceHeadlessNetwork ||
			newAsset.Source == analyzer.SourceHeadlessDOM ||
			newAsset.Source == analyzer.SourceHeadlessResponse
		if queued[newAsset.URL] || !urlutil.ShouldAttemptJSFetch(newAsset.URL, fromDynamic) {
			continue
		}
		if cfg.SameOrigin && !urlutil.IsAllowedDomain(newAsset.URL, cfg.AllowCDN, entryURL) {
			log.Verbose("Skipping (not same-origin): %s", newAsset.URL)
			continue
		}
		if shouldEnqueue(newAsset.Confidence, newAsset.Status) {
			newAsset.FromURL = item.url
			newAsset.Depth = item.depth + 1
			if cfg.MaxDepth > 0 && newAsset.Depth > cfg.MaxDepth {
				log.Verbose("Skipping (exceeds depth limit %d): %s", cfg.MaxDepth, newAsset.URL)
				continue
			}
			s.AddJS(&newAsset)
			addToQueue(newAsset.URL, newAsset.Depth, newAsset.FromURL, queued, processed, queue)
			log.Verbose("  New discovery: %s (confidence=%s)", newAsset.URL, newAsset.Confidence)
		} else {
			s.AddJS(&newAsset)
		}
	}
}

// fetchSourceMaps downloads and parses discovered source maps
func fetchSourceMaps(cfg *config.Config, s *store.Store, f *fetcher.Fetcher, a *analyzer.Analyzer, log *logging.Logger) {
	sms := s.GetSourcemaps()
	if len(sms) == 0 {
		return
	}
	log.Info("Processing %d source maps...", len(sms))

	smAnalyzer := analyzer.NewSourceMapAnalyzer(nil)
	// Get regex analyzer from analyzer for ExtractFromSourcesContent
	regex := analyzer.NewRegexAnalyzer()
	smAnalyzer = analyzer.NewSourceMapAnalyzer(regex)

	for _, sm := range sms {
		if sm.Status != "found" {
			continue
		}

		// Parse map URL (may be relative)
		mapURL := sm.MapURL
		if mapURL == "" {
			continue
		}

		log.Verbose("Downloading source map: %s", mapURL)
		mapResult := f.Fetch(mapURL)
		if mapResult.Err != nil {
			log.LogError("download sourcemap", "URL=%s error=%v", mapURL, mapResult.Err)
			s.UpdateSourcemapStatus(mapURL, "fetch_error", 0, false)
			continue
		}

		// Save source map file
		filename := urlutil.SanitizeFilename(mapURL)
		domain := urlutil.SanitizeDomain(mapURL)
		s.SaveRaw(domain, filename+".map", mapResult.Body)

		// Parse source map
		parsed := smAnalyzer.ParseSourceMap(mapResult.Body, mapURL, sm.FromJS)
		s.UpdateSourcemapStatus(mapURL, parsed.Status, parsed.SourceCount, parsed.HasSourcesContent)

		// If sourcesContent exists, extract additional information
		if parsed.HasSourcesContent {
			var rawMap struct {
				SourcesContent []string `json:"sourcesContent"`
			}
			if err := json.Unmarshal(mapResult.Body, &rawMap); err == nil && len(rawMap.SourcesContent) > 0 {
				extraImports, extraRoutes := smAnalyzer.ExtractFromSourcesContent(rawMap.SourcesContent, sm.FromJS)
				for _, imp := range extraImports {
					s.AddDynamicImport(imp)
				}
				for _, route := range extraRoutes {
					s.AddRoute(route)
				}
				log.Verbose("  Extracted from sourcesContent: %d imports, %d routes", len(extraImports), len(extraRoutes))
			}
		}

		// Update source map info with full information
		info := analyzer.SourceMapInfo{
			FromJS:            sm.FromJS,
			MapURL:            mapURL,
			Status:            parsed.Status,
			HasSourcesContent: parsed.HasSourcesContent,
			SourceCount:       parsed.SourceCount,
			Sources:           parsed.Sources,
		}
		s.AddSourcemap(info)
	}
}

func addToQueue(url string, depth int, from string, queued, processed map[string]bool, queue *[]fetchReq) {
	if queued[url] || processed[url] {
		return
	}
	queued[url] = true
	*queue = append(*queue, fetchReq{url: url, depth: depth, from: from})
}

func shouldEnqueue(confidence, status string) bool {
	return confidence == analyzer.ConfHigh || confidence == analyzer.ConfMedium
}

func printSummary(s *store.Store, totalAnalyzed int, outDir string, log *logging.Logger) {
	confirmed := s.GetConfirmedURLs()
	candidates := s.GetCandidateURLs()
	log.Info("Analysis complete!")
	log.Info("  Confirmed JS: %d", len(confirmed))
	log.Info("  Candidate JS: %d", len(candidates))
	log.Info("  Total analyzed: %d", totalAnalyzed)
	log.Info("JS list saved to: %s", filepath.Join(outDir, "js.txt"))
}
