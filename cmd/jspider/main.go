package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Veincc/JSpider/internal/analyzer"
	"github.com/Veincc/JSpider/internal/config"
	"github.com/Veincc/JSpider/internal/fetcher"
	"github.com/Veincc/JSpider/internal/headless"
	"github.com/Veincc/JSpider/internal/html"
	"github.com/Veincc/JSpider/internal/logging"
	"github.com/Veincc/JSpider/internal/preprocess"
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
		Proxy:              cfg.Proxy,
	}
}

func main() {
	cfg := config.Parse()
	if err := run(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run(cfg *config.Config) error {
	proxy, err := config.NormalizeProxy(cfg.Proxy)
	if err != nil {
		return err
	}
	cfg.Proxy = proxy

	if err := os.MkdirAll(cfg.OutDir, 0755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	cleanupLegacyOutputs(cfg.OutDir)

	log := logging.New(cfg.Verbose, cfg.OutDir)
	defer log.Close()

	f, err := fetcher.New(cfg, log)
	if err != nil {
		return fmt.Errorf("configure HTTP client: %w", err)
	}
	s := store.New(cfg.OutDir)
	a := analyzer.NewAnalyzer(log)
	htmlEx := html.NewExtractor()

	// Check browser availability when headless mode is requested
	if cfg.Headless {
		if err := headless.CheckBrowserAvailable(); err != nil {
			return err
		}
		log.Info("Headless discovery enabled: Chrome/Chromium found")
	}

	urls := cfg.URLs()
	if len(urls) == 0 {
		return errors.New("no URLs to analyze")
	}

	log.Info("JSpider started: %d entry URLs, workers %d, output dir %s", len(urls), cfg.Workers, cfg.OutDir)

	initializedSites := make(map[string]bool)
	processors := make(map[string]*preprocess.Processor)
	defer func() {
		for _, processor := range processors {
			_ = processor.Close()
		}
	}()
	totalAnalyzed := 0

	for i, entryURL := range urls {
		site := urlutil.SanitizeDomain(entryURL)
		siteDir := filepath.Join(cfg.OutDir, site)
		if !initializedSites[site] {
			if err := os.RemoveAll(siteDir); err != nil {
				return fmt.Errorf("reset site output %s: %w", site, err)
			}
			if err := os.MkdirAll(siteDir, 0755); err != nil {
				return fmt.Errorf("create site output %s: %w", site, err)
			}
			initializedSites[site] = true
		}

		var prep *preprocess.Processor
		if cfg.AuditPrep {
			prep = processors[site]
			if prep == nil {
				var err error
				prep, err = preprocess.New(siteDir, func(rawURL string) ([]byte, error) {
					result := f.Fetch(rawURL)
					if result.Err != nil {
						return nil, result.Err
					}
					if result.StatusCode != 200 {
						return nil, fmt.Errorf("HTTP %d", result.StatusCode)
					}
					return result.Body, nil
				})
				if err != nil {
					return err
				}
				processors[site] = prep
				log.Info("Audit preparation enabled: output will be written to %s", filepath.Join(siteDir, "audit"))
			}
		}

		queued := make(map[string]bool)
		processed := make(map[string]bool)
		log.Info("[%d/%d] Analyzing: %s", i+1, len(urls), entryURL)
		analyzed := analyzeEntry(cfg, s, f, a, htmlEx, log, prep, entryURL, queued, processed, &totalAnalyzed)
		log.Info("[%d/%d] Done: %s (analyzed %d JS)", i+1, len(urls), entryURL, analyzed)
	}

	for _, prep := range processors {
		if err := prep.Save(); err != nil {
			return fmt.Errorf("save audit manifest: %w", err)
		}
		if err := prep.Close(); err != nil {
			return fmt.Errorf("close audit-prep worker: %w", err)
		}
	}

	printSummary(s, totalAnalyzed, log)
	return nil
}

// analyzeEntry analyzes a single entry URL and returns the number of JS files analyzed.
// It always runs static HTML extraction, and additionally runs headless browser
// discovery if cfg.Headless is enabled, merging and deduplicating the results.
func analyzeEntry(cfg *config.Config, s *store.Store, f *fetcher.Fetcher, a *analyzer.Analyzer, htmlEx *html.Extractor, log *logging.Logger, prep *preprocess.Processor, entryURL string, queued, processed map[string]bool, totalAnalyzed *int) int {
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
	if err := s.SaveEntry(entryDomain, htmlResult.Body); err != nil {
		log.LogError("save entry HTML", "URL=%s error=%v", entryURL, err)
		return 0
	}

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
			analyzeResultWithPreprocess(cfg, s, a, log, prep, res, entryURL, queued, processed, &queue, &analyzed, totalAnalyzed)
		}
	}

	// Mark undownloaded entry JS as candidate
	for _, asset := range entryAssets {
		if cfg.SameOrigin && !urlutil.IsAllowedDomain(asset.URL, cfg.AllowCDN, entryURL) {
			continue
		}
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
	analyzeResultWithPreprocess(cfg, s, a, log, nil, res, entryURL, queued, processed, queue, analyzed, totalAnalyzed)
}

// analyzeResultWithPreprocess analyzes a single download result with optional audit-prep preprocessing.
func analyzeResultWithPreprocess(cfg *config.Config, s *store.Store, a *analyzer.Analyzer, log *logging.Logger, prep *preprocess.Processor, res fetchRes, entryURL string, queued, processed map[string]bool, queue *[]fetchReq, analyzed, totalAnalyzed *int) {
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

	analysisData := res.result.Body
	entrySite := urlutil.SanitizeDomain(entryURL)

	if cfg.AuditPrep && prep != nil {
		prepResult := prep.Process(entryURL, item.url, res.result.Body)
		analysisData = prepResult.AnalysisBody
		if prepResult.Failed {
			log.Warn("Audit preparation failed for %s: %s", item.url, prepResult.Error)
		}
	} else {
		if _, _, err := s.SaveJS(entrySite, item.url, res.result.Body); err != nil {
			log.LogError("save JavaScript", "URL=%s error=%v", item.url, err)
		}
	}

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

	discovered := a.DiscoverJS(string(analysisData), item.url)

	// Add newly discovered JS URLs to the next batch queue
	for _, newAsset := range discovered {
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

func printSummary(s *store.Store, totalAnalyzed int, log *logging.Logger) {
	confirmed := s.GetConfirmedURLs()
	candidates := s.GetCandidateURLs()
	log.Info("Analysis complete!")
	log.Info("  Confirmed JS: %d", len(confirmed))
	log.Info("  Candidate JS: %d", len(candidates))
	log.Info("  Total analyzed: %d", totalAnalyzed)
}

func cleanupLegacyOutputs(outDir string) {
	for _, name := range []string{
		"analysis_errors.log",
		"js.txt",
		"dynamic_imports.json",
		"route_chunk_map.json",
		"sourcemaps.txt",
		"framework_detect.json",
		"audit_bundle",
	} {
		_ = os.RemoveAll(filepath.Join(outDir, name))
	}
}
