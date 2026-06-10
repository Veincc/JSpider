// Package headless provides headless Chrome-based JS discovery using chromedp.
// It uses Chrome DevTools Protocol (CDP) for proper network monitoring,
// DOM extraction, page scrolling, and safe element clicking.
package headless

import (
	"bufio"
	"context"
	"fmt"
	"net/url"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"

	"github.com/Veincc/JSpider/internal/analyzer"
	"github.com/Veincc/JSpider/internal/logging"
	"github.com/Veincc/JSpider/internal/urlutil"
)

// Browser candidates in priority order
var browserCandidates = []string{
	"google-chrome",
	"google-chrome-stable",
	"chromium",
	"chromium-browser",
	"chrome",
}

// dangerousPatterns are substrings in link/button text or href that indicate
// state-changing actions we should NOT click during discovery.
var dangerousPatterns = []string{
	"log out", "logout", "sign out", "signout",
	"delete", "remove", "destroy",
	"submit", "save", "pay", "purchase", "buy",
	"download", "install",
	"unsubscribe", "deactivate", "disable",
	"cancel", "reject", "block", "ban",
	"approve", "accept", "confirm",
}

// jsPathInResponse matches JS-like paths in XHR/fetch response bodies.
// Callers must preprocess lines with unescapeJSONSlashes before matching.
// The char class [a-zA-Z0-9_./-] includes dots for filenames like
// footer-background.4sTmNkbe.js. Backslash (\) is excluded so that
// trailing \" from JSON escapes acts as a natural delimiter.
var jsPathInResponse = regexp.MustCompile(`(?:^|["'\s])(/[a-zA-Z0-9_./-]*\.js(?:\?[^\s"'\)]*)?)(?:["'\s\)]|$)`)

// relativeJSPath matches relative JS paths in response bodies.
var relativeJSPath = regexp.MustCompile(`(?:^|["'\s])(\./[a-zA-Z0-9_./-]*\.js(?:\?[^\s"'\)]*)?|(?:\.\./[a-zA-Z0-9_./-]*\.js(?:\?[^\s"'\)]*)?))(?:["'\s\)]|$)`)

// unescapeJSONSlashes replaces JSON-escaped forward slashes (\/) with plain /.
// This is applied to each line before regex matching so that paths like
// \/assets\/app.js are correctly captured as /assets/app.js.
func unescapeJSONSlashes(s string) string {
	return strings.ReplaceAll(s, `\/`, `/`)
}

// Config holds headless discovery configuration.
type Config struct {
	// EntryURL is the page to discover JS from.
	EntryURL string
	// Timeout for the entire discovery operation.
	Timeout time.Duration
	// SameOrigin filters discovered URLs to same-origin only.
	SameOrigin bool
	// AllowCDN is the list of allowed CDN domains.
	AllowCDN []string
	// MaxClicks limits the number of safe clicks (default 20).
	MaxClicks int
	// Verbose enables verbose logging.
	Verbose bool
	// InsecureSkipVerify skips TLS certificate verification in Chrome.
	InsecureSkipVerify bool
	// Proxy is the proxy server used by Chrome.
	Proxy string
}

// networkCapture holds JS URLs captured from network events.
type networkCapture struct {
	mu         sync.Mutex
	scriptURLs map[string]bool // URLs with ResourceType=Script
	jsCTURLs   map[string]bool // URLs with JS Content-Type
	xhrURLs    map[string]bool // JS URLs found in XHR/fetch responses

	bodyMu        sync.Mutex
	pendingBodies int
	bodyIdle      chan struct{}
}

func newNetworkCapture() *networkCapture {
	idle := make(chan struct{})
	close(idle)
	return &networkCapture{
		scriptURLs: make(map[string]bool),
		jsCTURLs:   make(map[string]bool),
		xhrURLs:    make(map[string]bool),
		bodyIdle:   idle,
	}
}

func (c *networkCapture) beginResponseBody() {
	c.bodyMu.Lock()
	if c.pendingBodies == 0 {
		c.bodyIdle = make(chan struct{})
	}
	c.pendingBodies++
	c.bodyMu.Unlock()
}

func (c *networkCapture) endResponseBody() {
	c.bodyMu.Lock()
	if c.pendingBodies > 0 {
		c.pendingBodies--
		if c.pendingBodies == 0 {
			close(c.bodyIdle)
		}
	}
	c.bodyMu.Unlock()
}

func (c *networkCapture) waitForResponseBodies(timeout time.Duration) bool {
	c.bodyMu.Lock()
	if c.pendingBodies == 0 {
		c.bodyMu.Unlock()
		return true
	}
	idle := c.bodyIdle
	c.bodyMu.Unlock()

	if timeout <= 0 {
		select {
		case <-idle:
			return true
		default:
			return false
		}
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-idle:
		return true
	case <-timer.C:
		return false
	}
}

// CheckBrowserAvailable checks whether Chrome or Chromium is available on the system.
// Returns nil if a browser is found, or an error describing what was searched for.
func CheckBrowserAvailable() error {
	_, err := findBrowser()
	return err
}

// findBrowser locates a Chrome/Chromium binary.
func findBrowser() (string, error) {
	// Try chromedp's built-in detection first
	if path := chromedp.DefaultExecAllocatorOptions[0]; path != nil {
		// chromedp uses findExecPath internally, try common names
	}
	for _, name := range browserCandidates {
		if path, err := exec.LookPath(name); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("no Chrome/Chromium browser found; searched for: %s\n"+
		"Install Chrome or Chromium and ensure it is in PATH.\n"+
		"Required for --headless mode.", strings.Join(browserCandidates, ", "))
}

// Discover runs headless Chrome on entryURL and returns discovered JS assets.
// It uses CDP network monitoring to capture:
//   - Network requests with ResourceType=Script
//   - Responses with JS Content-Type
//   - XHR/fetch response bodies containing JS paths
//
// It also scrolls the page, clicks safe elements, and extracts DOM scripts.
//
// The total timeout budget is partitioned across phases so that a slow phase
// does not silently starve later phases. When the budget is exhausted the
// remaining phases are skipped and a single summary message is logged.
//
// All chromedp.Run calls receive contexts derived from browserCtx (the
// chromedp-managed context) so that the CDP session stays valid across phases.
func Discover(ctx context.Context, cfg *Config, log *logging.Logger) ([]analyzer.JSAsset, error) {
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.MaxClicks == 0 {
		cfg.MaxClicks = 20
	}

	totalBudget := cfg.Timeout
	deadline := time.Now().Add(totalBudget)

	browserPath, err := findBrowser()
	if err != nil {
		return nil, err
	}

	capture := newNetworkCapture()

	// Create allocator — uses the caller-supplied ctx for cancellation,
	// not the deadline, so that browserCtx lifetime is not cut short.
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(browserPath),
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
	)
	if cfg.InsecureSkipVerify {
		opts = append(opts, chromedp.Flag("ignore-certificate-errors", true))
	}
	if cfg.Proxy != "" {
		opts = append(opts, chromedp.ProxyServer(cfg.Proxy))
	}

	allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, opts...)
	defer allocCancel()

	// Create browser context — this is the root of the chromedp context tree.
	// Every chromedp.Run must receive a descendant of browserCtx.
	browserCtx, browserCancel := chromedp.NewContext(allocCtx)
	defer browserCancel()

	// Set up network event listener BEFORE navigating
	chromedp.ListenTarget(browserCtx, func(ev any) {
		switch e := ev.(type) {
		case *network.EventRequestWillBeSent:
			if e.Type == network.ResourceTypeScript {
				capture.mu.Lock()
				capture.scriptURLs[e.Request.URL] = true
				capture.mu.Unlock()
				log.Verbose("  [network] Script request: %s", e.Request.URL)
			}
		case *network.EventResponseReceived:
			ct := e.Response.MimeType
			if isJSContentType(ct) || isJSResourceType(e.Type) {
				capture.mu.Lock()
				capture.jsCTURLs[e.Response.URL] = true
				capture.mu.Unlock()
				log.Verbose("  [network] JS response: %s (type=%s, mime=%s)", e.Response.URL, e.Type, ct)
			}
			if e.Type == network.ResourceTypeXHR || e.Type == network.ResourceTypeFetch {
				capture.beginResponseBody()
				go func(reqID network.RequestID, respURL string) {
					defer capture.endResponseBody()
					body, err := network.GetResponseBody(reqID).Do(browserCtx)
					if err != nil {
						return
					}
					jsURLs := extractJSPathsFromResponse(string(body), respURL, cfg.EntryURL)
					if len(jsURLs) > 0 {
						capture.mu.Lock()
						for _, u := range jsURLs {
							capture.xhrURLs[u] = true
						}
						capture.mu.Unlock()
						log.Verbose("  [network] XHR/fetch JS paths in %s: %v", respURL, jsURLs)
					}
				}(e.RequestID, e.Response.URL)
			}
		}
	})

	budgetExhausted := false

	// Phase 1: Navigate + wait for page load (~40% of budget)
	if time.Now().Before(deadline) {
		phaseTimeout := totalBudget * 40 / 100
		if phaseTimeout < 2*time.Second {
			phaseTimeout = 2 * time.Second
		}
		phaseCtx, phaseCancel := phaseContext(browserCtx, phaseTimeout)

		log.Verbose("Headless: navigating to %s", cfg.EntryURL)
		if err := chromedp.Run(phaseCtx, chromedp.Navigate(cfg.EntryURL)); err != nil {
			phaseCancel()
			if isDeadlineExceeded(err) {
				budgetExhausted = true
				log.Verbose("Headless: navigate timed out: %v", err)
			} else {
				return nil, fmt.Errorf("navigate failed: %w", err)
			}
		} else {
			log.Verbose("Headless: waiting for page load...")
			if err := chromedp.Run(phaseCtx,
				chromedp.WaitReady("body", chromedp.ByQuery),
				chromedp.Sleep(2*time.Second),
			); err != nil && isDeadlineExceeded(err) {
				log.Verbose("Headless: page load wait timed out: %v", err)
			}
			phaseCancel()
		}
	} else {
		budgetExhausted = true
	}

	// Phase 2: Scroll to trigger lazy loading (~20% of budget)
	if !budgetExhausted && time.Now().Before(deadline) {
		phaseCtx, phaseCancel := phaseContext(browserCtx, remaining(deadline))

		log.Verbose("Headless: scrolling page...")
		if err := chromedp.Run(phaseCtx, chromedp.ActionFunc(func(ctx context.Context) error {
			return scrollPage(ctx, log)
		})); err != nil {
			if isDeadlineExceeded(err) {
				budgetExhausted = true
				log.Verbose("Headless: scroll timed out: %v", err)
			} else {
				log.Verbose("Headless: scroll error (non-fatal): %v", err)
			}
		}
		phaseCancel()
	}

	// Phase 3: Click safe elements + settle (~25% of budget)
	if !budgetExhausted && time.Now().Before(deadline) {
		phaseCtx, phaseCancel := phaseContext(browserCtx, remaining(deadline))

		log.Verbose("Headless: clicking safe elements (max %d)...", cfg.MaxClicks)
		if err := chromedp.Run(phaseCtx, chromedp.ActionFunc(func(ctx context.Context) error {
			return clickSafeElements(ctx, cfg.EntryURL, cfg.MaxClicks, log)
		})); err != nil {
			if isDeadlineExceeded(err) {
				budgetExhausted = true
				log.Verbose("Headless: click pass timed out: %v", err)
			} else {
				log.Verbose("Headless: click pass error (non-fatal): %v", err)
			}
		}

		if !budgetExhausted {
			if err := chromedp.Run(phaseCtx, chromedp.Sleep(2*time.Second)); err != nil && isDeadlineExceeded(err) {
				log.Verbose("Headless: post-click settle timed out")
			}
		}
		phaseCancel()
	}

	// Phase 4: Extract DOM scripts (~15% of budget)
	var domHTML string
	if !budgetExhausted && time.Now().Before(deadline) {
		phaseCtx, phaseCancel := phaseContext(browserCtx, remaining(deadline))

		if err := chromedp.Run(phaseCtx, chromedp.OuterHTML("html", &domHTML, chromedp.ByQuery)); err != nil {
			if isDeadlineExceeded(err) {
				log.Verbose("Headless: DOM extraction timed out: %v", err)
			} else {
				log.Verbose("Headless: DOM extraction error (non-fatal): %v", err)
			}
		}
		phaseCancel()
	}

	if budgetExhausted {
		log.Info("Headless discovery reached time budget; using captured network assets")
	}

	waitBudget := remaining(deadline)
	if waitBudget > 2*time.Second {
		waitBudget = 2 * time.Second
	}
	if !capture.waitForResponseBodies(waitBudget) {
		log.Verbose("Headless: timed out waiting for pending XHR/fetch response bodies")
	}

	// Combine all discovered assets (from whatever phases succeeded)
	assets := buildAssets(capture, domHTML, cfg, log)

	return assets, nil
}

// phaseContext creates a child context of browserCtx with a timeout.
// Every chromedp.Run call must receive a context derived from browserCtx;
// this helper enforces that pattern.
func phaseContext(browserCtx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(browserCtx, timeout)
}

// isDeadlineExceeded checks whether an error is a context deadline exceeded.
func isDeadlineExceeded(err error) bool {
	return err != nil && (err == context.DeadlineExceeded || strings.Contains(err.Error(), "context deadline exceeded"))
}

// remaining returns the time until the deadline, clamped to >= 0.
func remaining(deadline time.Time) time.Duration {
	d := time.Until(deadline)
	if d < 0 {
		return 0
	}
	return d
}

// scrollPage scrolls the page to trigger lazy-loaded content.
func scrollPage(ctx context.Context, log *logging.Logger) error {
	// Get page height
	var pageHeight float64
	if err := chromedp.Evaluate(`document.documentElement.scrollHeight`, &pageHeight).Do(ctx); err != nil {
		return err
	}

	// Scroll down in steps
	step := 500.0
	current := 0.0
	for current < pageHeight {
		current += step
		if err := chromedp.Evaluate(fmt.Sprintf(`window.scrollTo(0, %f)`, current), nil).Do(ctx); err != nil {
			return err
		}
		time.Sleep(300 * time.Millisecond)

		// Re-check height (may have changed due to lazy loading)
		if err := chromedp.Evaluate(`document.documentElement.scrollHeight`, &pageHeight).Do(ctx); err != nil {
			return err
		}
	}

	// Scroll back to top
	if err := chromedp.Evaluate(`window.scrollTo(0, 0)`, nil).Do(ctx); err != nil {
		return err
	}

	log.Verbose("  Scrolled page (height: %.0f)", pageHeight)
	return nil
}

// clickSafeElements clicks up to maxClicks safe interactive elements on the page.
// It skips elements with dangerous text/href patterns.
func clickSafeElements(ctx context.Context, entryURL string, maxClicks int, log *logging.Logger) error {
	// Find clickable elements: links, buttons, and elements with click handlers
	var elementCount int
	if err := chromedp.Evaluate(`(function() {
		var els = document.querySelectorAll('a[href], button, [role="button"], [onclick], [role="tab"], [role="menuitem"], nav a, .nav a, .menu a');
		return els.length;
	})()`, &elementCount).Do(ctx); err != nil {
		return err
	}

	if elementCount == 0 {
		log.Verbose("  No clickable elements found")
		return nil
	}

	clicked := 0
	for i := 0; i < elementCount && clicked < maxClicks; i++ {
		// Get element info (text, href, tag)
		var info struct {
			Text  string `json:"text"`
			Href  string `json:"href"`
			Tag   string `json:"tag"`
			Index int    `json:"index"`
		}

		err := chromedp.Evaluate(fmt.Sprintf(`(function() {
			var els = document.querySelectorAll('a[href], button, [role="button"], [onclick], [role="tab"], [role="menuitem"], nav a, .nav a, .menu a');
			var el = els[%d];
			if (!el) return null;
			return {
				text: (el.innerText || el.textContent || '').substring(0, 100),
				href: el.getAttribute('href') || '',
				tag: el.tagName.toLowerCase(),
				index: %d
			};
		})()`, i, i), &info).Do(ctx)

		if err != nil || info.Tag == "" {
			continue
		}

		// Check if element is dangerous
		if IsDangerousElement(info.Text, info.Href) {
			log.Verbose("  Skipping dangerous element: %q href=%q", info.Text, info.Href)
			continue
		}

		if shouldSkipClickableHref(info.Href, entryURL) {
			continue
		}

		// Click the element using JavaScript (more reliable than chromedp.Click for dynamic elements)
		clickedJS := fmt.Sprintf(`(function() {
			var els = document.querySelectorAll('a[href], button, [role="button"], [onclick], [role="tab"], [role="menuitem"], nav a, .nav a, .menu a');
			var el = els[%d];
			if (el) { el.click(); return true; }
			return false;
		})()`, i)

		var clickResult bool
		if err := chromedp.Evaluate(clickedJS, &clickResult).Do(ctx); err != nil {
			continue
		}

		if clickResult {
			clicked++
			log.Verbose("  Clicked element %d: %q href=%q", i, info.Text, info.Href)
			// Wait for any triggered network activity
			time.Sleep(500 * time.Millisecond)
		}
	}

	log.Verbose("  Clicked %d elements", clicked)
	return nil
}

func shouldSkipClickableHref(href, entryURL string) bool {
	href = strings.TrimSpace(href)
	if href == "" {
		return false
	}
	if strings.HasPrefix(href, "#") {
		return true
	}

	parsed, err := url.Parse(href)
	if err != nil {
		return true
	}
	if parsed.Scheme != "" && parsed.Scheme != "http" && parsed.Scheme != "https" {
		return true
	}

	base, err := url.Parse(entryURL)
	if err != nil || base.Scheme == "" || base.Host == "" {
		return true
	}
	resolved := base.ResolveReference(parsed)
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return true
	}

	return !urlutil.IsSameOrigin(resolved.String(), entryURL)
}

// buildAssets combines all captured JS URLs into a deduplicated asset list.
func buildAssets(capture *networkCapture, domHTML string, cfg *Config, log *logging.Logger) []analyzer.JSAsset {
	assets := make(map[string]*analyzer.JSAsset)

	// 1. Network Script requests (highest confidence)
	capture.mu.Lock()
	for u := range capture.scriptURLs {
		cleaned, ok := CleanDiscoveredJSURL(u, "")
		if !ok {
			cleaned = u // CDP URLs are already well-formed, keep as-is
		}
		if !isAllowedByPolicy(cleaned, cfg) {
			continue
		}
		assets[cleaned] = &analyzer.JSAsset{
			URL:        cleaned,
			FromURL:    cfg.EntryURL,
			Type:       analyzer.TypeUnknownJS,
			Source:     analyzer.SourceHeadlessNetwork,
			Confidence: analyzer.ConfHigh,
			Status:     analyzer.StatusCandidate,
		}
	}

	// 2. Network responses with JS Content-Type
	for u := range capture.jsCTURLs {
		cleaned, ok := CleanDiscoveredJSURL(u, "")
		if !ok {
			cleaned = u
		}
		if _, exists := assets[cleaned]; exists {
			continue
		}
		if !isAllowedByPolicy(cleaned, cfg) {
			continue
		}
		assets[cleaned] = &analyzer.JSAsset{
			URL:        cleaned,
			FromURL:    cfg.EntryURL,
			Type:       analyzer.TypeUnknownJS,
			Source:     analyzer.SourceHeadlessResponse,
			Confidence: analyzer.ConfHigh,
			Status:     analyzer.StatusCandidate,
		}
	}

	// 3. XHR/fetch response JS paths
	for u := range capture.xhrURLs {
		if _, exists := assets[u]; exists {
			continue
		}
		if !isAllowedByPolicy(u, cfg) {
			continue
		}
		assets[u] = &analyzer.JSAsset{
			URL:        u,
			FromURL:    cfg.EntryURL,
			Type:       analyzer.TypeUnknownJS,
			Source:     analyzer.SourceHeadlessResponse,
			Confidence: analyzer.ConfMedium,
			Status:     analyzer.StatusCandidate,
		}
	}
	capture.mu.Unlock()

	// 4. DOM extraction
	domAssets := extractFromDOM(domHTML, cfg)
	for _, a := range domAssets {
		if _, exists := assets[a.URL]; !exists {
			cp := a
			assets[cp.URL] = &cp
		}
	}

	// Convert to slice
	var result []analyzer.JSAsset
	for _, a := range assets {
		result = append(result, *a)
	}
	return result
}

// extractFromDOM extracts JS assets from rendered HTML content.
func extractFromDOM(html string, cfg *Config) []analyzer.JSAsset {
	var assets []analyzer.JSAsset
	seen := make(map[string]bool)

	lines := strings.Split(html, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Extract <script src="..."> tags
		for _, src := range extractScriptSrcs(line) {
			cleaned, ok := CleanDiscoveredJSURL(src, cfg.EntryURL)
			if !ok || seen[cleaned] {
				continue
			}
			if !isAllowedByPolicy(cleaned, cfg) {
				continue
			}
			seen[cleaned] = true
			assets = append(assets, analyzer.JSAsset{
				URL:        cleaned,
				FromURL:    cfg.EntryURL,
				Type:       analyzer.TypeUnknownJS,
				Source:     analyzer.SourceHeadlessDOM,
				Confidence: analyzer.ConfHigh,
				Status:     analyzer.StatusCandidate,
			})
		}

		// Extract <link rel="modulepreload/preload/prefetch" as="script" href="...">
		for _, href := range extractLinkScripts(line) {
			cleaned, ok := CleanDiscoveredJSURL(href, cfg.EntryURL)
			if !ok || seen[cleaned] {
				continue
			}
			if !isAllowedByPolicy(cleaned, cfg) {
				continue
			}
			seen[cleaned] = true
			assets = append(assets, analyzer.JSAsset{
				URL:        cleaned,
				FromURL:    cfg.EntryURL,
				Type:       analyzer.TypeUnknownJS,
				Source:     analyzer.SourceHeadlessDOM,
				Confidence: analyzer.ConfMedium,
				Status:     analyzer.StatusCandidate,
			})
		}
	}

	return assets
}

// extractJSPathsFromResponse extracts JS URLs from XHR/fetch response bodies.
func extractJSPathsFromResponse(body, respURL, entryURL string) []string {
	var urls []string
	seen := make(map[string]bool)

	// Try to parse as JSON and look for JS paths
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		// Preprocess: unescape \/ to / so regex can match JSON-escaped paths
		unescaped := unescapeJSONSlashes(line)

		// Match absolute paths like /assets/main.js
		for _, match := range jsPathInResponse.FindAllStringSubmatch(unescaped, -1) {
			if len(match) > 1 {
				u := match[1]
				if cleaned, ok := CleanDiscoveredJSURL(u, entryURL); ok && !seen[cleaned] {
					seen[cleaned] = true
					urls = append(urls, cleaned)
				}
			}
		}

		// Match relative paths like ./chunk.js or ../lib/utils.js
		for _, match := range relativeJSPath.FindAllStringSubmatch(unescaped, -1) {
			if len(match) > 1 {
				u := match[1]
				if cleaned, ok := CleanDiscoveredJSURL(u, respURL); ok && !seen[cleaned] {
					seen[cleaned] = true
					urls = append(urls, cleaned)
				}
			}
		}
	}

	return urls
}

// isAllowedByPolicy checks if a URL passes same-origin/CDN policy.
func isAllowedByPolicy(rawURL string, cfg *Config) bool {
	if !cfg.SameOrigin {
		return true
	}
	return urlutil.IsAllowedDomain(rawURL, cfg.AllowCDN, cfg.EntryURL)
}

// isJSContentType checks if a MIME type indicates JavaScript.
func isJSContentType(ct string) bool {
	ct = strings.ToLower(ct)
	return strings.Contains(ct, "javascript") ||
		strings.Contains(ct, "ecmascript") ||
		strings.Contains(ct, "application/js") ||
		strings.Contains(ct, "text/js")
}

// isJSResourceType checks if a CDP resource type is Script.
func isJSResourceType(rt network.ResourceType) bool {
	return rt == network.ResourceTypeScript
}

// extractScriptSrcs extracts src attributes from <script> tags in a single line.
func extractScriptSrcs(line string) []string {
	var results []string
	lower := strings.ToLower(line)

	idx := 0
	for {
		start := strings.Index(lower[idx:], "<script")
		if start == -1 {
			break
		}
		start += idx
		end := strings.Index(lower[start:], ">")
		if end == -1 {
			break
		}
		end += start
		tag := line[start : end+1]

		if src := extractAttr(tag, "src"); src != "" {
			results = append(results, src)
		}
		idx = end + 1
	}

	return results
}

// extractLinkScripts extracts href from <link rel="modulepreload/preload/prefetch" as="script"> tags.
func extractLinkScripts(line string) []string {
	var results []string
	lower := strings.ToLower(line)

	idx := 0
	for {
		start := strings.Index(lower[idx:], "<link")
		if start == -1 {
			break
		}
		start += idx
		end := strings.Index(lower[start:], ">")
		if end == -1 {
			break
		}
		end += start
		tag := line[start : end+1]
		tagLower := lower[start : end+1]

		rel := extractAttr(tag, "rel")
		relLower := strings.ToLower(rel)

		isScriptLink := false
		switch relLower {
		case "modulepreload":
			isScriptLink = true
		case "preload", "prefetch":
			as := extractAttr(tag, "as")
			if strings.ToLower(as) == "script" {
				isScriptLink = true
			}
		}

		if isScriptLink {
			if href := extractAttr(tag, "href"); href != "" {
				results = append(results, href)
			}
		}
		idx = end + 1
		_ = tagLower
	}

	return results
}

// extractAttr extracts an attribute value from an HTML tag string.
func extractAttr(tag, attrName string) string {
	target := strings.ToLower(attrName)
	i := 0
	n := len(tag)

	if i < n && tag[i] == '<' {
		i++
		for i < n && !isAttrSpace(tag[i]) && tag[i] != '>' && tag[i] != '/' {
			i++
		}
	}

	for i < n {
		for i < n && isAttrSpace(tag[i]) {
			i++
		}
		if i >= n || tag[i] == '>' {
			break
		}
		if tag[i] == '/' {
			i++
			continue
		}

		nameStart := i
		for i < n && tag[i] != '=' && !isAttrSpace(tag[i]) && tag[i] != '>' && tag[i] != '/' {
			i++
		}
		name := strings.ToLower(strings.TrimSpace(tag[nameStart:i]))
		if name == "" {
			i++
			continue
		}

		for i < n && isAttrSpace(tag[i]) {
			i++
		}

		value := ""
		if i < n && tag[i] == '=' {
			i++
			for i < n && isAttrSpace(tag[i]) {
				i++
			}
			if i < n {
				switch tag[i] {
				case '"', '\'':
					quote := tag[i]
					i++
					valueStart := i
					for i < n && tag[i] != quote {
						i++
					}
					value = tag[valueStart:i]
					if i < n {
						i++
					}
				default:
					valueStart := i
					for i < n && !isAttrSpace(tag[i]) && tag[i] != '>' {
						i++
					}
					value = tag[valueStart:i]
				}
			}
		}

		if name == target {
			return value
		}
	}
	return ""
}

func isAttrSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f'
}

// resolveURL resolves a potentially relative URL against the entry URL.
func resolveURL(rawURL, baseURL string) string {
	if rawURL == "" {
		return ""
	}

	if strings.HasPrefix(rawURL, "http://") || strings.HasPrefix(rawURL, "https://") {
		return rawURL
	}

	if strings.HasPrefix(rawURL, "//") {
		u, err := url.Parse(baseURL)
		if err != nil {
			return ""
		}
		return u.Scheme + ":" + rawURL
	}

	resolved, err := urlutil.ResolveJS(baseURL, rawURL)
	if err != nil {
		return ""
	}
	return resolved
}

// ResolveDiscoveredJSURL resolves a raw JS URL string discovered by headless
// against a base URL. Delegates to urlutil.ResolveJS which handles bare relative
// paths and deduplicates consecutive repeated path segments.
func ResolveDiscoveredJSURL(baseURL, raw string) (string, bool) {
	if raw == "" {
		return "", false
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}

	resolved, err := urlutil.ResolveJS(baseURL, raw)
	if err != nil || resolved == "" {
		return "", false
	}

	// Validate
	parsed, err := url.Parse(resolved)
	if err != nil {
		return "", false
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", false
	}

	return resolved, true
}

// CleanDiscoveredJSURL sanitizes a raw URL string extracted from dynamic sources
// (XHR/fetch bodies, DOM, network logs). It handles JSON/JS escape sequences and
// strips trailing characters that are not part of a valid URL.
// Returns the cleaned URL and true if it's valid, or ("", false) if rejected.
func CleanDiscoveredJSURL(raw string, resolveBase string) (string, bool) {
	if raw == "" {
		return "", false
	}

	// 1. Trim whitespace
	s := strings.TrimSpace(raw)

	// 2. Strip surrounding quotes / backticks
	if len(s) >= 2 {
		first := s[0]
		last := s[len(s)-1]
		if (first == '"' && last == '"') || (first == '\'' && last == '\'') || (first == '`' && last == '`') {
			s = s[1 : len(s)-1]
		}
	}

	// 3. Unescape common JSON/JS escape sequences
	//    \/" -> /,  \" -> ",  \\ -> \,  \n -> skip, \t -> skip
	s = strings.ReplaceAll(s, `\/`, `/`)
	s = strings.ReplaceAll(s, `\"`, `"`)
	s = strings.ReplaceAll(s, `\\`, `\`)

	// 4. Strip trailing characters that cannot end a URL path/query
	//    These are artifacts of surrounding syntax: \ " ' ` ) ] } ; ,
	trailers := `\` + "`" + `")];},`
	for len(s) > 0 {
		last := s[len(s)-1]
		if strings.ContainsRune(trailers, rune(last)) {
			s = s[:len(s)-1]
		} else {
			break
		}
	}

	// 5. Also strip trailing backslash that may remain after unescaping
	s = strings.TrimRight(s, `\`)

	// 6. Trim again after stripping
	s = strings.TrimSpace(s)

	if s == "" {
		return "", false
	}

	// 7. Strip fragment (#...) — fragments are not useful for JS discovery
	if idx := strings.Index(s, "#"); idx != -1 {
		s = s[:idx]
	}

	if s == "" {
		return "", false
	}

	// 8. Validate with url.Parse
	parsed, err := url.Parse(s)
	if err != nil {
		return "", false
	}

	// If it has a scheme, must be http/https
	if parsed.Scheme != "" && parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", false
	}

	// If it's a relative path, resolve it
	if parsed.Scheme == "" {
		if resolveBase == "" {
			return "", false
		}
		resolved, ok := ResolveDiscoveredJSURL(resolveBase, s)
		if !ok {
			return "", false
		}
		return resolved, true
	}

	// Absolute URL — still deduplicate path segments
	resolved := urlutil.DeduplicatePathSegments(parsed.String())
	return resolved, true
}

// IsDangerousElement checks if an element's text or href suggests a dangerous action.
func IsDangerousElement(text, href string) bool {
	lower := strings.ToLower(text + " " + href)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

// extractURLsFromLogLine extracts HTTP(S) URLs from a Chrome log line.
// Used for fallback log parsing if needed.
func extractURLsFromLogLine(line string) []string {
	var urls []string

	idx := 0
	for {
		pos := strings.Index(line[idx:], "url:")
		if pos == -1 {
			break
		}
		pos += idx + 4
		end := pos
		for end < len(line) && line[end] != ' ' && line[end] != '\t' && line[end] != ')' && line[end] != ',' {
			end++
		}
		if end > pos {
			u := line[pos:end]
			if strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") {
				urls = append(urls, u)
			}
		}
		idx = end
	}

	idx = 0
	for {
		pos := strings.Index(line[idx:], "https://")
		if pos == -1 {
			pos = strings.Index(line[idx:], "http://")
		}
		if pos == -1 {
			break
		}
		pos += idx
		end := pos
		for end < len(line) && line[end] != ' ' && line[end] != '\t' && line[end] != '"' && line[end] != '\'' && line[end] != ')' && line[end] != ',' && line[end] != '>' {
			end++
		}
		if end > pos {
			u := line[pos:end]
			found := false
			for _, existing := range urls {
				if existing == u {
					found = true
					break
				}
			}
			if !found {
				urls = append(urls, u)
			}
		}
		idx = end
	}

	return urls
}

// ParseJSPathsFromText extracts JS URLs from arbitrary text content (JSON, config, etc.).
// This is exported for use in testing and external callers.
func ParseJSPathsFromText(text, baseURL string) []string {
	var urls []string
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := scanner.Text()
		// Preprocess: unescape \/ to / so regex can match JSON-escaped paths
		unescaped := unescapeJSONSlashes(line)

		// Absolute paths
		for _, match := range jsPathInResponse.FindAllStringSubmatch(unescaped, -1) {
			if len(match) > 1 {
				u := match[1]
				if cleaned, ok := CleanDiscoveredJSURL(u, baseURL); ok && !seen[cleaned] {
					seen[cleaned] = true
					urls = append(urls, cleaned)
				}
			}
		}

		// Relative paths
		for _, match := range relativeJSPath.FindAllStringSubmatch(unescaped, -1) {
			if len(match) > 1 {
				u := match[1]
				if cleaned, ok := CleanDiscoveredJSURL(u, baseURL); ok && !seen[cleaned] {
					seen[cleaned] = true
					urls = append(urls, cleaned)
				}
			}
		}
	}

	return urls
}
