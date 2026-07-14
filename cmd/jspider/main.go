package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
	ordinal int
	req     fetchReq
	result  *fetcher.Result
	// acknowledge releases one sliding-window slot after the consumer has
	// finished with this response body.
	acknowledge func()
}

func (r fetchRes) acknowledgeConsumption() {
	if r.acknowledge != nil {
		r.acknowledge()
	}
}

type fetchTask struct {
	ordinal int
	req     fetchReq
}

type crawlState struct {
	queued    map[string]bool
	processed map[string]bool
}

type javaScriptProcessor interface {
	Process(entryURL, jsURL string, body []byte) preprocess.FileResult
	Close() error
}

// EntryResult describes one configured entry without conflating a failed
// crawl with a process-wide initialization or finalization error.
type EntryResult struct {
	EntryURL        string
	CanonicalOrigin string
	Directory       string
	Analyzed        int
	FetchAttempts   int
	API             apidiscovery.SessionStats
	Err             error
	Reason          string
}

// SiteStats is an origin-scoped snapshot. Directory is included because two
// origins can intentionally share the same legacy directory base and must be
// disambiguated before any output is written.
type SiteStats struct {
	Origin            string
	Directory         string
	Success           int
	Failure           int
	Skipped           int
	FetchAttempts     int
	Analyzed          int
	Confirmed         int
	Candidate         int
	API               apidiscovery.SessionStats
	FinalizationError string
}

type RunResult struct {
	Success []EntryResult
	Failure []EntryResult
	Skipped []EntryResult
	Sites   map[string]SiteStats
}

type apiDiscoverySession interface {
	AddEntryURL(string)
	AddRuntimeForEntry(string, []apidiscovery.RuntimeRequest)
	AddSourceWithIdentity(apidiscovery.SourceIdentity, string, []byte)
	Stats(string) apidiscovery.SessionStats
	AnalyzeSources() error
	Report() apidiscovery.Report
}

// OrderedSites returns a deterministic view for logs and other derived output.
func (r RunResult) OrderedSites() []SiteStats {
	origins := make([]string, 0, len(r.Sites))
	for origin := range r.Sites {
		origins = append(origins, origin)
	}
	sort.Strings(origins)
	ordered := make([]SiteStats, 0, len(origins))
	for _, origin := range origins {
		ordered = append(ordered, r.Sites[origin])
	}
	return ordered
}

type siteRuntime struct {
	origin      string
	directory   string
	entryURLs   []string
	state       *crawlState
	store       *store.Store
	fetcher     *fetcher.Fetcher
	analyzer    *analyzer.Analyzer
	html        *html.Extractor
	processor   javaScriptProcessor
	apiSession  apiDiscoverySession
	attempts    int
	analyzed    int
	finalizeErr error
}

type fatalOutputError struct {
	err error
}

func (e *fatalOutputError) Error() string { return e.err.Error() }
func (e *fatalOutputError) Unwrap() error { return e.err }

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
		HeadlessBodyMB:     cfg.HeadlessBodyMB,
	}
}

func main() {
	cfg := config.Parse()
	_, err := run(context.Background(), cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cfg *config.Config) (RunResult, error) {
	result := RunResult{Sites: make(map[string]SiteStats)}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := cfg.Validate(); err != nil {
		return result, fmt.Errorf("invalid configuration: %w", err)
	}
	urls, err := cfg.URLs()
	if err != nil {
		return result, err
	}
	originDirectories, err := urlutil.OriginDirectoryNames(urls)
	if err != nil {
		return result, fmt.Errorf("plan origin directories: %w", err)
	}
	type plannedEntry struct {
		url       string
		origin    string
		directory string
	}
	planned := make([]plannedEntry, 0, len(urls))
	for _, entryURL := range urls {
		origin, canonicalErr := urlutil.CanonicalOrigin(entryURL)
		if canonicalErr != nil {
			return result, fmt.Errorf("canonicalize entry URL %s: %w", entryURL, canonicalErr)
		}
		directory := originDirectories[origin]
		planned = append(planned, plannedEntry{url: entryURL, origin: origin, directory: directory})
		result.Sites[origin] = SiteStats{Origin: origin, Directory: directory}
	}
	if err := ctx.Err(); err != nil {
		for _, entry := range planned {
			skipped := EntryResult{
				EntryURL: entry.url, CanonicalOrigin: entry.origin, Directory: entry.directory,
				Err: err, Reason: err.Error(),
			}
			result.Skipped = append(result.Skipped, skipped)
			stats := result.Sites[entry.origin]
			stats.Skipped++
			result.Sites[entry.origin] = stats
		}
		return result, err
	}

	if cfg.APIDiscovery {
		if err := apidiscovery.CheckAvailable(); err != nil {
			return result, err
		}
	}
	if err := preprocess.CheckNodeRuntime(); err != nil {
		return result, err
	}
	if cfg.Headless {
		if err := checkBrowserAvailable(); err != nil {
			return result, err
		}
	}

	if err := os.MkdirAll(cfg.OutDir, 0755); err != nil {
		return result, fmt.Errorf("create output directory: %w", err)
	}
	cleanupLegacyOutputs(cfg.OutDir)

	log := logging.New(cfg.Verbose, cfg.OutDir)
	defer log.Close()

	if cfg.APIDiscovery {
		log.Info("API discovery enabled (headless implied)")
	} else if cfg.Headless {
		log.Info("Headless discovery enabled: Chrome/Chromium found")
	}

	log.Info("JSpider started: %d entry URLs, workers %d, output dir %s", len(urls), cfg.Workers, cfg.OutDir)

	sites := make(map[string]*siteRuntime)
	var runErrors []error
	stopReason := error(nil)
	for i, entry := range planned {
		if stopReason == nil {
			if contextErr := ctx.Err(); contextErr != nil {
				stopReason = contextErr
				runErrors = append(runErrors, contextErr)
			}
		}
		if stopReason != nil {
			skipped := EntryResult{
				EntryURL: entry.url, CanonicalOrigin: entry.origin, Directory: entry.directory,
				Err: stopReason, Reason: stopReason.Error(),
			}
			result.Skipped = append(result.Skipped, skipped)
			stats := result.Sites[entry.origin]
			stats.Skipped++
			result.Sites[entry.origin] = stats
			continue
		}

		site := sites[entry.origin]
		if site == nil {
			site, err = newSiteRuntime(cfg, log, entry.origin, entry.directory)
			if site != nil {
				sites[entry.origin] = site
			}
			if err != nil {
				entryErr := fmt.Errorf("initialize origin %s: %w", entry.origin, err)
				failure := EntryResult{EntryURL: entry.url, CanonicalOrigin: entry.origin, Directory: entry.directory, Err: entryErr, Reason: entryErr.Error()}
				result.Failure = append(result.Failure, failure)
				stats := result.Sites[entry.origin]
				stats.Failure++
				result.Sites[entry.origin] = stats
				runErrors = append(runErrors, entryErr)
				stopReason = entryErr
				continue
			}
		}

		site.entryURLs = append(site.entryURLs, entry.url)
		if site.apiSession != nil {
			site.apiSession.AddEntryURL(entry.url)
		}
		attemptsBefore := site.attempts
		log.Info("[%d/%d] Analyzing: %s", i+1, len(planned), entry.url)
		analyzed, entryErr := analyzeEntryContext(
			ctx, cfg, site.store, site.fetcher, site.analyzer, site.html, log, site.processor, site.apiSession,
			entry.url, site.directory, site.state.queued, site.state.processed, &site.analyzed, &site.attempts,
		)
		apiStats := apidiscovery.SessionStats{}
		if site.apiSession != nil {
			apiStats = site.apiSession.Stats(entry.url)
		}
		entryResult := EntryResult{
			EntryURL: entry.url, CanonicalOrigin: entry.origin, Directory: entry.directory,
			Analyzed: analyzed, FetchAttempts: site.attempts - attemptsBefore, API: apiStats,
		}
		stats := result.Sites[entry.origin]
		stats.FetchAttempts = site.attempts
		stats.Analyzed = site.analyzed
		stats.API.Sources += apiStats.Sources
		stats.API.Runtime += apiStats.Runtime
		if entryErr != nil {
			entryErr = fmt.Errorf("analyze entry %s: %w", entry.url, entryErr)
			entryResult.Err = entryErr
			entryResult.Reason = entryErr.Error()
			result.Failure = append(result.Failure, entryResult)
			stats.Failure++
			runErrors = append(runErrors, entryErr)
			var fatal *fatalOutputError
			if errors.As(entryErr, &fatal) || errors.Is(entryErr, context.Canceled) || errors.Is(entryErr, context.DeadlineExceeded) {
				stopReason = entryErr
			}
		} else {
			result.Success = append(result.Success, entryResult)
			stats.Success++
			log.Info("[%d/%d] Done: %s (analyzed %d JS)", i+1, len(planned), entry.url, analyzed)
		}
		result.Sites[entry.origin] = stats
	}

	finalizeErr := finalizeOutputs(cfg.OutDir, sites, cfg.APIDiscovery, log)
	if finalizeErr != nil {
		runErrors = append(runErrors, finalizeErr)
	}
	for origin, site := range sites {
		stats := result.Sites[origin]
		stats.FetchAttempts = site.attempts
		stats.Analyzed = site.analyzed
		stats.Confirmed = len(site.store.GetConfirmedURLs())
		stats.Candidate = len(site.store.GetCandidateURLs())
		if site.finalizeErr != nil {
			stats.FinalizationError = site.finalizeErr.Error()
		}
		result.Sites[origin] = stats
	}

	printSummary(result, log)
	return result, errors.Join(runErrors...)
}

func newSiteRuntime(cfg *config.Config, log *logging.Logger, origin, directory string) (*siteRuntime, error) {
	site := &siteRuntime{
		origin: origin, directory: directory,
		state: &crawlState{queued: make(map[string]bool), processed: make(map[string]bool)},
		store: store.New(cfg.OutDir), analyzer: analyzer.NewAnalyzer(log), html: html.NewExtractor(),
	}
	siteDir := filepath.Join(cfg.OutDir, directory)
	if err := os.RemoveAll(siteDir); err != nil {
		return site, fmt.Errorf("reset site output %s: %w", directory, err)
	}
	if err := os.MkdirAll(siteDir, 0755); err != nil {
		return site, fmt.Errorf("create site output %s: %w", directory, err)
	}
	f, err := fetcher.New(cfg, log)
	if err != nil {
		return site, fmt.Errorf("configure HTTP client: %w", err)
	}
	site.fetcher = f
	processor, err := preprocess.NewWithTimeout(siteDir, func(ctx context.Context, entryURL, rawURL string) ([]byte, error) {
		fetchResult := f.FetchForEntryContext(ctx, rawURL, entryURL)
		if fetchResult.Err != nil {
			return nil, fetchResult.Err
		}
		if fetchResult.StatusCode < 200 || fetchResult.StatusCode >= 300 {
			return nil, fmt.Errorf("HTTP %d", fetchResult.StatusCode)
		}
		return fetchResult.Body, nil
	}, time.Duration(cfg.ProcessTimeoutSeconds)*time.Second)
	if err != nil {
		return site, err
	}
	site.processor = processor
	if cfg.APIDiscovery {
		site.apiSession = apidiscovery.NewSession()
	}
	log.Info("Processed JavaScript will be written to %s", filepath.Join(siteDir, "js"))
	return site, nil
}

// analyzeEntry analyzes a single entry URL and returns the number of JS files analyzed.
// It always runs static HTML extraction, and additionally runs headless browser
// discovery if cfg.Headless is enabled, merging and deduplicating the results.
func analyzeEntry(cfg *config.Config, s *store.Store, f *fetcher.Fetcher, a *analyzer.Analyzer, htmlEx *html.Extractor, log *logging.Logger, prep javaScriptProcessor, apiSession apiDiscoverySession, entryURL, site string, queued, processed map[string]bool, totalAnalyzed, totalAttempts *int) (int, error) {
	return analyzeEntryContext(context.Background(), cfg, s, f, a, htmlEx, log, prep, apiSession, entryURL, site, queued, processed, totalAnalyzed, totalAttempts)
}

func analyzeEntryContext(ctx context.Context, cfg *config.Config, s *store.Store, f *fetcher.Fetcher, a *analyzer.Analyzer, htmlEx *html.Extractor, log *logging.Logger, prep javaScriptProcessor, apiSession apiDiscoverySession, entryURL, site string, queued, processed map[string]bool, totalAnalyzed, totalAttempts *int) (int, error) {
	// 1. Static HTML extraction (always)
	log.Info("Downloading entry HTML: %s", entryURL)
	htmlResult := f.FetchForEntryContext(ctx, entryURL, entryURL)
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
		discovery, err := discoverBrowser(ctx, buildHeadlessConfig(cfg, entryURL), log)
		var hlAssets []analyzer.JSAsset
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return 0, err
			}
			log.Warn("Headless discovery failed (continuing with static results): %v", err)
		} else {
			hlAssets = discovery.Assets
			if apiSession != nil {
				apiSession.AddRuntimeForEntry(entryURL, discovery.Requests)
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
	sort.SliceStable(entryAssets, func(i, j int) bool {
		if entryAssets[i].URL != entryAssets[j].URL {
			return entryAssets[i].URL < entryAssets[j].URL
		}
		if entryAssets[i].Source != entryAssets[j].Source {
			return entryAssets[i].Source < entryAssets[j].Source
		}
		return entryAssets[i].Type < entryAssets[j].Type
	})

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
		batchContext, cancelBatch := context.WithCancel(ctx)
		results := fetchBatchContext(batchContext, cfg, f, log, batch, entryURL)

		// Serially analyze each result
		completedAttempts := 0
		for res := range results {
			completedAttempts++
			if err := analyzeResultWithPreprocess(cfg, s, a, log, prep, apiSession, res, entryURL, site, queued, processed, &queue, &analyzed, totalAnalyzed); err != nil {
				// Cancel before acknowledging the failed ordinal. Acknowledgement
				// normally advances the sliding launch window.
				cancelBatch()
				res.acknowledgeConsumption()
				for remaining := range results {
					completedAttempts++
					remaining.acknowledgeConsumption()
				}
				*totalAttempts -= len(batch) - completedAttempts
				return analyzed, err
			}
			res.acknowledgeConsumption()
		}
		cancelBatch()
		*totalAttempts -= len(batch) - completedAttempts
		if err := ctx.Err(); err != nil {
			return analyzed, err
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

	if err := ctx.Err(); err != nil {
		return analyzed, err
	}
	return analyzed, nil
}

// fetchBatch concurrently downloads a batch of URLs
func fetchBatch(cfg *config.Config, f *fetcher.Fetcher, log *logging.Logger, queue []fetchReq, entryURL string) <-chan fetchRes {
	return fetchBatchContext(context.Background(), cfg, f, log, queue, entryURL)
}

func fetchBatchContext(ctx context.Context, cfg *config.Config, f *fetcher.Fetcher, log *logging.Logger, queue []fetchReq, entryURL string) <-chan fetchRes {
	if ctx == nil {
		ctx = context.Background()
	}
	workers := cfg.Workers
	if workers <= 0 {
		workers = 1
	}
	results := make(chan fetchRes, workers)
	effectiveWorkers := workers
	if effectiveWorkers > len(queue) {
		effectiveWorkers = len(queue)
	}
	if effectiveWorkers == 0 {
		close(results)
		return results
	}
	completed := make(chan fetchRes, effectiveWorkers)
	acknowledged := make(chan int, 1)

	var wg sync.WaitGroup
	reqCh := make(chan fetchTask)

	for i := 0; i < effectiveWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for task := range reqCh {
				log.Verbose("Downloading: %s (depth=%d)", task.req.url, task.req.depth)
				completed <- fetchRes{
					ordinal: task.ordinal,
					req:     task.req,
					result:  f.FetchJSForEntryContext(ctx, task.req.url, entryURL),
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(completed)
	}()

	go func() {
		defer close(results)

		nextLaunch := 0
		requestsClosed := false
		launchNext := func() {
			reqCh <- fetchTask{ordinal: nextLaunch, req: queue[nextLaunch]}
			nextLaunch++
			if nextLaunch == len(queue) {
				close(reqCh)
				requestsClosed = true
			}
		}
		for i := 0; i < effectiveWorkers; i++ {
			launchNext()
		}

		pending := make(map[int]fetchRes, effectiveWorkers)
		nextOrdinal := 0
		target := len(queue)
		contextDone := ctx.Done()
		stopping := false
		waitingForAcknowledgement := false
		for nextOrdinal < target {
			if !waitingForAcknowledgement {
				if result, ok := pending[nextOrdinal]; ok {
					delete(pending, nextOrdinal)
					ordinal := result.ordinal
					var once sync.Once
					result.acknowledge = func() {
						once.Do(func() { acknowledged <- ordinal })
					}
					results <- result
					waitingForAcknowledgement = true
					continue
				}
			}

			select {
			case <-contextDone:
				contextDone = nil
				stopping = true
				target = nextLaunch
				if !requestsClosed {
					close(reqCh)
					requestsClosed = true
				}
			case result, ok := <-completed:
				if !ok {
					completed = nil
					continue
				}
				pending[result.ordinal] = result
			case ordinal := <-acknowledged:
				if ordinal != nextOrdinal {
					continue
				}
				waitingForAcknowledgement = false
				nextOrdinal++
				if !stopping && nextLaunch < len(queue) {
					launchNext()
				}
			}
		}
	}()

	return results
}

// analyzeResultWithPreprocess analyzes a single downloaded JavaScript response.
func analyzeResultWithPreprocess(cfg *config.Config, s *store.Store, a *analyzer.Analyzer, log *logging.Logger, prep javaScriptProcessor, apiSession apiDiscoverySession, res fetchRes, entryURL, site string, queued, processed map[string]bool, queue *[]fetchReq, analyzed, totalAnalyzed *int) error {
	item := res.req

	if processed[item.url] {
		return nil
	}
	processed[item.url] = true

	if res.result.Err != nil {
		log.LogError("Download failed", "URL=%s error=%v", item.url, res.result.Err)
		s.AddJS(&analyzer.JSAsset{
			URL: item.url, FromURL: item.from,
			Type: analyzer.TypeUnknownJS, Source: analyzer.SourceRegexCandidate,
			Confidence: analyzer.ConfLow, Status: analyzer.StatusFailed, Depth: item.depth,
		})
		return nil
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
	if prepResult.Failed {
		log.Warn("JavaScript processing fell back for %s: %s", item.url, prepResult.Error)
	}
	if len(prepResult.Outputs) > 0 {
		s.RecordJSOutputs(site, requestedURL, prepResult.Outputs)
		if finalURL != requestedURL {
			s.RecordJSOutputs(site, finalURL, prepResult.Outputs)
		}
	}
	if len(prepResult.Outputs) == 0 || prepResult.FallbackWriteFailed {
		detail := prepResult.Error
		if detail == "" {
			detail = "processor returned no persisted output"
		}
		return &fatalOutputError{err: fmt.Errorf("persist JavaScript %s: %s", finalURL, detail)}
	}

	analysisUnits := prepResult.Analysis
	if len(analysisUnits) == 0 {
		analysisUnits = []preprocess.AnalysisUnit{{SourceName: finalURL, BaseURL: finalURL, Body: res.result.Body}}
	}
	if cfg.APIDiscovery && apiSession != nil {
		identity := apidiscovery.SourceIdentity{
			EntryURL: entryURL, RequestedURL: requestedURL, FinalURL: finalURL, ContentHash: res.result.Hash,
		}
		for _, unit := range analysisUnits {
			apiSession.AddSourceWithIdentity(identity, unit.SourceName, unit.Body)
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

	discovered := make([]analyzer.JSAsset, 0)
	for _, unit := range analysisUnits {
		discovered = append(discovered, a.DiscoverJS(string(unit.Body), unit.BaseURL)...)
	}

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
	return nil
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

func printSummary(result RunResult, log *logging.Logger) {
	confirmed := 0
	candidates := 0
	totalAnalyzed := 0
	for _, site := range result.OrderedSites() {
		confirmed += site.Confirmed
		candidates += site.Candidate
		totalAnalyzed += site.Analyzed
	}
	log.Info("Analysis complete!")
	log.Info("  Confirmed JS: %d", confirmed)
	log.Info("  Candidate JS: %d", candidates)
	log.Info("  Total analyzed: %d", totalAnalyzed)
	log.Info("  Entries: success=%d failure=%d skipped=%d", len(result.Success), len(result.Failure), len(result.Skipped))
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
