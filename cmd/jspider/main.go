package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Veincc/JSpider/internal/analyzer"
	"github.com/Veincc/JSpider/internal/apidiscovery"
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

type crawlState struct {
	queued    map[string]bool
	processed map[string]bool
}

var discoverBrowser = headless.DiscoverWithRuntime
var checkBrowserAvailable = headless.CheckBrowserAvailable

func crawlStateForSite(states map[string]*crawlState, site string) *crawlState {
	state := states[site]
	if state == nil {
		state = &crawlState{
			queued:    make(map[string]bool),
			processed: make(map[string]bool),
		}
		states[site] = state
	}
	return state
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
		CaptureAPI:         cfg.APIDiscovery,
		UserAgent:          cfg.UserAgent,
		Cookies:            cfg.Cookies,
		Headers:            cfg.Headers,
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
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	urls, err := cfg.URLs()
	if err != nil {
		return err
	}
	originDirectories, err := urlutil.OriginDirectoryNames(urls)
	if err != nil {
		return fmt.Errorf("plan origin directories: %w", err)
	}

	if cfg.APIDiscovery {
		if err := apidiscovery.CheckAvailable(); err != nil {
			return err
		}
	}
	if err := preprocess.CheckNodeRuntime(); err != nil {
		return err
	}
	if cfg.Headless {
		if err := checkBrowserAvailable(); err != nil {
			return err
		}
	}

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

	if cfg.APIDiscovery {
		log.Info("API discovery enabled (headless implied)")
	} else if cfg.Headless {
		log.Info("Headless discovery enabled: Chrome/Chromium found")
	}

	log.Info("JSpider started: %d entry URLs, workers %d, output dir %s", len(urls), cfg.Workers, cfg.OutDir)

	initializedSites := make(map[string]bool)
	processors := make(map[string]*preprocess.Processor)
	apiSessions := make(map[string]*apidiscovery.Session)
	siteEntryURLs := make(map[string][]string)
	states := make(map[string]*crawlState)
	defer func() {
		for _, processor := range processors {
			_ = processor.Close()
		}
	}()
	totalAnalyzed := 0
	totalAttempts := 0

	for i, entryURL := range urls {
		origin, err := urlutil.CanonicalOrigin(entryURL)
		if err != nil {
			return fmt.Errorf("canonicalize entry URL %s: %w", entryURL, err)
		}
		site := originDirectories[origin]
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

		prep := processors[site]
		if prep == nil {
			var err error
			prep, err = preprocess.New(siteDir, func(entryURL, rawURL string) ([]byte, error) {
				result := f.FetchForEntry(rawURL, entryURL)
				if result.Err != nil {
					return nil, result.Err
				}
				if result.StatusCode < 200 || result.StatusCode >= 300 {
					return nil, fmt.Errorf("HTTP %d", result.StatusCode)
				}
				return result.Body, nil
			})
			if err != nil {
				return err
			}
			processors[site] = prep
			log.Info("Processed JavaScript will be written to %s", filepath.Join(siteDir, "js"))
		}
		siteEntryURLs[site] = append(siteEntryURLs[site], entryURL)

		state := crawlStateForSite(states, site)
		var apiSession *apidiscovery.Session
		if cfg.APIDiscovery {
			apiSession = apiSessions[site]
			if apiSession == nil {
				apiSession = apidiscovery.NewSession()
				apiSessions[site] = apiSession
			}
			apiSession.AddEntryURL(entryURL)
		}
		log.Info("[%d/%d] Analyzing: %s", i+1, len(urls), entryURL)
		analyzed, err := analyzeEntry(cfg, s, f, a, htmlEx, log, prep, apiSession, entryURL, site, state.queued, state.processed, &totalAnalyzed, &totalAttempts)
		if err != nil {
			return fmt.Errorf("analyze entry %s: %w", entryURL, err)
		}
		if apiSession != nil {
			if err := apiSession.AnalyzeSources(); err != nil {
				return fmt.Errorf("analyze discovered JavaScript APIs for %s: %w", entryURL, err)
			}
			report := apiSession.Report()
			log.Info("[%d/%d] API discovery: static=%d runtime=%d matched=%d confirmed=%d bases=%d",
				i+1, len(urls), report.Summary.Static, report.Summary.Runtime,
				report.Summary.Matched, report.Summary.Confirmed, report.Summary.Bases)
			for _, association := range report.Associations {
				log.Verbose("  [api] match static=%s runtime=%s score=%d confidence=%s evidence=%v",
					association.StaticRawURL, association.RuntimeURL, association.Score,
					association.Confidence, association.Evidence)
			}
			for _, base := range report.Bases {
				if base.Confidence == apidiscovery.ConfidenceConfirmed {
					log.Info("Runtime base confirmed: %s (evidence=%d)", base.RuntimeBase, base.EvidenceCount)
				}
			}
		}
		log.Info("[%d/%d] Done: %s (analyzed %d JS)", i+1, len(urls), entryURL, analyzed)
	}

	if err := finalizeOutputs(cfg.OutDir, s, initializedSites, processors, apiSessions, siteEntryURLs, cfg.APIDiscovery); err != nil {
		return err
	}

	printSummary(s, totalAnalyzed, log)
	return nil
}

// analyzeEntry analyzes a single entry URL and returns the number of JS files analyzed.
// It always runs static HTML extraction, and additionally runs headless browser
// discovery if cfg.Headless is enabled, merging and deduplicating the results.
func analyzeEntry(cfg *config.Config, s *store.Store, f *fetcher.Fetcher, a *analyzer.Analyzer, htmlEx *html.Extractor, log *logging.Logger, prep *preprocess.Processor, apiSession *apidiscovery.Session, entryURL, site string, queued, processed map[string]bool, totalAnalyzed, totalAttempts *int) (int, error) {
	// 1. Static HTML extraction (always)
	log.Info("Downloading entry HTML: %s", entryURL)
	htmlResult := f.FetchForEntry(entryURL, entryURL)
	if htmlResult.Err != nil {
		return 0, fmt.Errorf("download entry HTML: %w", htmlResult.Err)
	}
	if htmlResult.StatusCode < 200 || htmlResult.StatusCode >= 300 {
		return 0, fmt.Errorf("download entry HTML: HTTP %d", htmlResult.StatusCode)
	}

	htmlContent := string(htmlResult.Body)
	log.Info("Entry HTML size: %d bytes", len(htmlContent))

	htmlBaseURL := htmlResult.FinalURL
	if htmlBaseURL == "" {
		htmlBaseURL = entryURL
	}
	staticAssets := htmlEx.ExtractEntryJS(htmlContent, htmlBaseURL)
	log.Info("Static extraction found %d JS assets", len(staticAssets))

	entryAssets := staticAssets

	// 2. Headless discovery (optional)
	if cfg.Headless {
		log.Info("Running headless discovery: %s", entryURL)
		discovery, err := discoverBrowser(context.Background(), buildHeadlessConfig(cfg, entryURL), log)
		var hlAssets []analyzer.JSAsset
		if err != nil {
			log.Warn("Headless discovery failed (continuing with static results): %v", err)
		} else {
			hlAssets = discovery.Assets
			if apiSession != nil {
				apiSession.AddRuntime(discovery.Requests)
			}
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
		if cfg.MaxJS > 0 && *totalAttempts >= cfg.MaxJS {
			log.Info("Reached max JavaScript fetch attempts (%d), stopping", cfg.MaxJS)
			break
		}

		batch := queue
		if cfg.MaxJS > 0 {
			remaining := cfg.MaxJS - *totalAttempts
			if len(batch) > remaining {
				batch = batch[:remaining]
			}
		}
		queue = nil
		// Reserve the complete batch before any worker can schedule a request.
		// Failed requests consume the same budget as successful requests.
		*totalAttempts += len(batch)
		results := fetchBatch(cfg, f, log, batch, entryURL)

		// Serially analyze each result
		for res := range results {
			analyzeResultWithPreprocess(cfg, s, a, log, prep, apiSession, res, entryURL, site, queued, processed, &queue, &analyzed, totalAnalyzed)
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

	return analyzed, nil
}

// fetchBatch concurrently downloads a batch of URLs
func fetchBatch(cfg *config.Config, f *fetcher.Fetcher, log *logging.Logger, queue []fetchReq, entryURL string) <-chan fetchRes {
	workers := cfg.Workers
	if workers <= 0 {
		workers = 1
	}
	results := make(chan fetchRes, workers)

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
				results <- fetchRes{req: req, result: f.FetchJSForEntry(req.url, entryURL)}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	return results
}

// analyzeResultWithPreprocess analyzes a single downloaded JavaScript response.
func analyzeResultWithPreprocess(cfg *config.Config, s *store.Store, a *analyzer.Analyzer, log *logging.Logger, prep *preprocess.Processor, apiSession *apidiscovery.Session, res fetchRes, entryURL, site string, queued, processed map[string]bool, queue *[]fetchReq, analyzed, totalAnalyzed *int) {
	item := res.req

	if processed[item.url] {
		return
	}
	processed[item.url] = true

	if res.result.Err != nil {
		log.LogError("Download failed", "URL=%s error=%v", item.url, res.result.Err)
		s.AddJS(&analyzer.JSAsset{
			URL: item.url, FromURL: item.from,
			Type: analyzer.TypeUnknownJS, Source: analyzer.SourceRegexCandidate,
			Confidence: analyzer.ConfLow, Status: analyzer.StatusFailed, Depth: item.depth,
		})
		return
	}

	requestedURL := res.result.RequestedURL
	if requestedURL == "" {
		requestedURL = item.url
	}
	finalURL := res.result.FinalURL
	if finalURL == "" {
		finalURL = requestedURL
	}
	processed[requestedURL] = true
	processed[finalURL] = true

	prepResult := prep.Process(entryURL, finalURL, res.result.Body)
	analysisData := prepResult.AnalysisBody
	if prepResult.Failed {
		log.Warn("JavaScript processing fell back for %s: %s", item.url, prepResult.Error)
	}
	s.RecordJSOutputs(site, requestedURL, prepResult.Outputs)
	if finalURL != requestedURL {
		s.RecordJSOutputs(site, finalURL, prepResult.Outputs)
	}

	if cfg.APIDiscovery && apiSession != nil {
		apiSession.AddSource(finalURL, analysisData)
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

	discovered := a.DiscoverJS(string(analysisData), finalURL)

	// Add newly discovered JS URLs to the next batch queue
	for _, newAsset := range discovered {
		// For static analysis, require IsJSPath. For dynamic sources, allow broader fetch.
		fromDynamic := newAsset.Source == analyzer.SourceHeadlessNetwork ||
			newAsset.Source == analyzer.SourceHeadlessDOM ||
			newAsset.Source == analyzer.SourceHeadlessResponse ||
			newAsset.Source == analyzer.SourceImportExpr
		if queued[newAsset.URL] || !urlutil.ShouldAttemptJSFetch(newAsset.URL, fromDynamic) {
			continue
		}
		if cfg.SameOrigin && !urlutil.IsAllowedDomain(newAsset.URL, cfg.AllowCDN, entryURL) {
			log.Verbose("Skipping (not same-origin): %s", newAsset.URL)
			continue
		}
		if shouldEnqueue(newAsset.Confidence, newAsset.Status) {
			newAsset.FromURL = finalURL
			newAsset.Depth = item.depth + 1
			if newAsset.Depth > cfg.MaxDepth {
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
