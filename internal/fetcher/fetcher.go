package fetcher

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Veincc/JSpider/internal/config"
	"github.com/Veincc/JSpider/internal/logging"
	"github.com/Veincc/JSpider/internal/urlutil"
	"github.com/andybalholm/brotli"
	"github.com/tdewolff/parse/v2"
	"github.com/tdewolff/parse/v2/js"
)

// ErrDecompressTooLarge indicates decompressed content exceeded size limit
type ErrDecompressTooLarge struct {
	Size  int64
	Limit int64
}

func (e *ErrDecompressTooLarge) Error() string {
	return fmt.Sprintf("Decompressed content too large: %d bytes exceeds limit of %d bytes", e.Size, e.Limit)
}

// Result represents a download result (immutable, safe to share)
type Result struct {
	URL          string // Deprecated: use RequestedURL or FinalURL.
	RequestedURL string
	FinalURL     string
	StatusCode   int
	ContentType  string
	Size         int64
	Hash         string
	Body         []byte
	IsJS         bool
	Err          error
}

// clone returns a copy of the Result so validation does not mutate a shared
// active-request result.
func (r *Result) clone() *Result {
	c := *r
	return &c
}

// inflight represents an in-progress request
type inflight struct {
	done    chan struct{}
	res     *Result
	cancel  context.CancelFunc
	waiters int
}

type Fetcher struct {
	cfg     *config.Config
	log     *logging.Logger
	client  *http.Client
	mu      sync.Mutex
	pending map[string]*inflight // In-flight requests (singleflight)
}

type redirectPolicyKey struct{}

func New(cfg *config.Config, log *logging.Logger) (*Fetcher, error) {
	client := &http.Client{
		Timeout:       time.Duration(cfg.Timeout) * time.Second,
		CheckRedirect: redirectChecker(cfg),
	}
	if cfg.InsecureSkipVerify || cfg.Proxy != "" {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		if cfg.InsecureSkipVerify {
			transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		}
		if cfg.Proxy != "" {
			normalized, err := config.NormalizeProxy(cfg.Proxy)
			if err != nil {
				return nil, err
			}
			cfg.Proxy = normalized
			proxyURL, err := url.Parse(normalized)
			if err != nil {
				return nil, fmt.Errorf("parse proxy URL: %w", err)
			}
			transport.Proxy = http.ProxyURL(proxyURL)
		}
		client.Transport = transport
	}

	return &Fetcher{
		cfg:     cfg,
		log:     log,
		client:  client,
		pending: make(map[string]*inflight),
	}, nil
}

// Fetch downloads URL content with active-request singleflight deduplication.
func (f *Fetcher) Fetch(rawURL string) *Result {
	return f.FetchContext(context.Background(), rawURL)
}

// FetchContext downloads URL content and cancels the request when ctx ends.
func (f *Fetcher) FetchContext(ctx context.Context, rawURL string) *Result {
	return f.fetch(ctx, rawURL, rawURL)
}

// FetchForEntry downloads URL content using entryURL as the same-origin policy
// anchor for redirects and credential scoping.
func (f *Fetcher) FetchForEntry(rawURL, entryURL string) *Result {
	return f.FetchForEntryContext(context.Background(), rawURL, entryURL)
}

// FetchForEntryContext downloads URL content with a caller-controlled context
// and entryURL as the same-origin policy anchor.
func (f *Fetcher) FetchForEntryContext(ctx context.Context, rawURL, entryURL string) *Result {
	if entryURL == "" {
		entryURL = rawURL
	}
	return f.fetch(ctx, rawURL, entryURL)
}

func (f *Fetcher) fetch(ctx context.Context, rawURL, entryURL string) *Result {
	if ctx == nil {
		ctx = context.Background()
	}
	cacheKey := fetchCacheKey(rawURL, entryURL)

	f.mu.Lock()

	// Join an in-flight request for the same URL and entry policy.
	if inf, ok := f.pending[cacheKey]; ok {
		inf.waiters++
		f.mu.Unlock()
		return f.waitForInflight(ctx, cacheKey, rawURL, inf)
	}

	// Create a new in-flight request. Completed bodies are not retained.
	requestContext, cancel := context.WithCancel(context.Background())
	inf := &inflight{done: make(chan struct{}), cancel: cancel, waiters: 1}
	f.pending[cacheKey] = inf
	f.mu.Unlock()

	go f.runInflight(requestContext, cacheKey, rawURL, entryURL, inf)
	return f.waitForInflight(ctx, cacheKey, rawURL, inf)
}

func (f *Fetcher) runInflight(ctx context.Context, cacheKey, rawURL, entryURL string, inf *inflight) {
	result := f.doFetch(ctx, rawURL, entryURL)

	// Publish to current waiters, then release the request from the active set.
	f.mu.Lock()
	inf.res = result
	if f.pending[cacheKey] == inf {
		delete(f.pending, cacheKey)
	}
	f.mu.Unlock()
	close(inf.done)
	inf.cancel()
}

func (f *Fetcher) waitForInflight(ctx context.Context, cacheKey, rawURL string, inf *inflight) *Result {
	select {
	case <-inf.done:
		return inf.res
	case <-ctx.Done():
		f.mu.Lock()
		if f.pending[cacheKey] == inf {
			inf.waiters--
			if inf.waiters == 0 {
				delete(f.pending, cacheKey)
				inf.cancel()
			}
		}
		f.mu.Unlock()
		return &Result{URL: rawURL, RequestedURL: rawURL, Err: ctx.Err()}
	}
}

func (f *Fetcher) doFetch(ctx context.Context, rawURL, entryURL string) *Result {
	result := &Result{URL: rawURL, RequestedURL: rawURL}
	requestContext := context.WithValue(ctx, redirectPolicyKey{}, entryURL)
	req, err := http.NewRequestWithContext(requestContext, "GET", rawURL, nil)
	if err != nil {
		result.Err = err
		return result
	}
	req.Header.Set("User-Agent", f.cfg.UserAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")

	sendCookies := shouldSendCookies(rawURL, entryURL)
	if f.cfg.Cookies != "" && sendCookies {
		req.Header.Set("Cookie", f.cfg.Cookies)
	}
	for k, v := range f.cfg.Headers {
		if strings.EqualFold(k, "Cookie") && !sendCookies {
			continue
		}
		req.Header.Set(k, v)
	}

	f.log.Verbose("Downloading: %s", rawURL)

	resp, err := f.client.Do(req)
	if err != nil {
		result.Err = err
		return result
	}
	defer resp.Body.Close()
	result.FinalURL = resp.Request.URL.String()
	result.StatusCode = resp.StatusCode
	result.ContentType = resp.Header.Get("Content-Type")

	maxSize := maxSizeBytes(f.cfg.MaxSizeMB)
	compressedBody, err := readBounded(resp.Body, maxSize)
	if err != nil {
		result.Err = err
		return result
	}

	if maxSize > 0 && int64(len(compressedBody)) > maxSize {
		result.Err = fmt.Errorf("File too large: %d bytes exceeds limit of %d bytes", len(compressedBody), maxSize)
		return result
	}

	// Decompress (with post-decompression size limit)
	body, err := decompressBounded(compressedBody, resp.Header.Get("Content-Encoding"), maxSize)
	if err != nil {
		if _, ok := err.(*ErrDecompressTooLarge); ok {
			// Decompressed content exceeds limit, return error
			result.Err = err
			return result
		}
		// Other decompression errors (e.g. corrupted format), fall back to raw content
		f.log.Verbose("Decompression failed %s: %v, using raw content", rawURL, err)
		body = compressedBody
	}

	hash := sha256.Sum256(body)

	result.Size = int64(len(body))
	result.Hash = fmt.Sprintf("%x", hash[:8])
	result.Body = body
	result.IsJS = result.ContentType != "" && urlutil.IsJSContentType(result.ContentType)
	return result
}

// decompressBounded decompresses content with a size limit
func decompressBounded(data []byte, encoding string, maxSize int64) ([]byte, error) {
	encoding = strings.ToLower(strings.TrimSpace(encoding))

	var reader io.Reader
	switch encoding {
	case "gzip":
		r, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return data, err
		}
		defer r.Close()
		reader = r
	case "deflate":
		r, err := zlib.NewReader(bytes.NewReader(data))
		if err != nil {
			return data, err
		}
		defer r.Close()
		reader = r
	case "br":
		reader = brotli.NewReader(bytes.NewReader(data))
	default:
		return data, nil
	}

	result, err := readBounded(reader, maxSize)
	if err != nil {
		return data, err
	}
	if maxSize > 0 && int64(len(result)) > maxSize {
		return data, &ErrDecompressTooLarge{Size: int64(len(result)), Limit: maxSize}
	}
	return result, nil
}

func maxSizeBytes(maxSizeMB int) int64 {
	if maxSizeMB <= 0 {
		return 0
	}
	return int64(maxSizeMB) * 1024 * 1024
}

func readBounded(reader io.Reader, maxSize int64) ([]byte, error) {
	if maxSize <= 0 {
		return io.ReadAll(reader)
	}
	return io.ReadAll(io.LimitReader(reader, maxSize+1))
}

// FetchJS downloads a JS resource with status and media-type validation.
// It returns a copy because active singleflight callers can share the raw result.
func (f *Fetcher) FetchJS(rawURL string) *Result {
	result := f.Fetch(rawURL)
	return validateJSResult(result, rawURL)
}

// FetchJSForEntry downloads a JS resource using entryURL as the same-origin
// policy anchor for redirects and credential scoping.
func (f *Fetcher) FetchJSForEntry(rawURL, entryURL string) *Result {
	return f.FetchJSForEntryContext(context.Background(), rawURL, entryURL)
}

// FetchJSForEntryContext validates a JavaScript response while honoring the
// caller's crawl or batch cancellation.
func (f *Fetcher) FetchJSForEntryContext(ctx context.Context, rawURL, entryURL string) *Result {
	result := f.FetchForEntryContext(ctx, rawURL, entryURL)
	return validateJSResult(result, rawURL)
}

func validateJSResult(result *Result, rawURL string) *Result {
	if result.Err != nil {
		return result.clone()
	}

	// Return a copy to avoid mutating a result shared with active waiters.
	clone := result.clone()

	if clone.StatusCode < http.StatusOK || clone.StatusCode >= http.StatusMultipleChoices {
		clone.Err = fmt.Errorf("HTTP %d", clone.StatusCode)
		return clone
	}

	// An explicit Content-Type is authoritative. URL suffixes never override a
	// server that says the response is HTML, JSON, an image, or another type.
	if strings.TrimSpace(clone.ContentType) != "" {
		if !clone.IsJS {
			clone.Err = fmt.Errorf("Not a JS resource: content-type=%s", clone.ContentType)
		}
		return clone
	}

	// Some servers omit Content-Type. Only accept those responses when a small
	// body sample has clear JavaScript syntax; the URL suffix alone is not proof.
	if looksLikeJS(clone.Body) {
		clone.IsJS = true
	} else {
		clone.Err = fmt.Errorf("Not a JS resource: content-type missing")
	}

	return clone
}

func fetchCacheKey(rawURL, entryURL string) string {
	if entryURL == "" || entryURL == rawURL {
		return rawURL
	}
	return entryURL + "\x00" + rawURL
}

func redirectChecker(cfg *config.Config) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return fmt.Errorf("stopped after 10 redirects")
		}
		entryURL := redirectEntryURL(req)
		if entryURL == "" && len(via) > 0 {
			entryURL = redirectEntryURL(via[0])
			if entryURL == "" {
				entryURL = via[0].URL.String()
			}
		}
		if cfg.SameOrigin && !urlutil.IsAllowedDomain(req.URL.String(), cfg.AllowCDN, entryURL) {
			return fmt.Errorf("redirect target not allowed by same-origin policy: %s", req.URL.Host)
		}
		return nil
	}
}

func redirectEntryURL(req *http.Request) string {
	if req == nil {
		return ""
	}
	entryURL, _ := req.Context().Value(redirectPolicyKey{}).(string)
	return entryURL
}

func shouldSendCookies(rawURL, entryURL string) bool {
	if entryURL == "" {
		return true
	}
	return urlutil.IsSameOrigin(rawURL, entryURL)
}

// looksLikeJS checks if content looks like JS
func looksLikeJS(data []byte) bool {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) < 10 {
		return false
	}

	lower := strings.ToLower(string(trimmed[:min(500, len(trimmed))]))
	for _, prefix := range []string{"<!doctype", "<html", "<script", "<?xml", "<svg"} {
		if strings.HasPrefix(lower, prefix) {
			return false
		}
	}
	if json.Valid(trimmed) || hasKnownBinaryMagic(trimmed) {
		return false
	}
	program, err := js.Parse(parse.NewInputBytes(trimmed), js.Options{})
	if err != nil {
		return false
	}
	moduleEvidence := &moduleSyntaxEvidenceVisitor{}
	js.Walk(moduleEvidence, program)
	if moduleEvidence.found {
		return true
	}

	indicators := []string{
		"__webpack_require__", "__vite__", "import(", "export ",
		"function(", "function ", "var ", "let ", "const ",
		"self.", "window.", "document.", "(()=>{", "(function(",
	}
	hasIndicator := false
	for _, ind := range indicators {
		if strings.Contains(lower, ind) {
			hasIndicator = true
			break
		}
	}
	if !hasIndicator {
		return false
	}
	return true
}

type moduleSyntaxEvidenceVisitor struct {
	found bool
}

func (v *moduleSyntaxEvidenceVisitor) Enter(n js.INode) js.IVisitor {
	switch n.(type) {
	case *js.ImportStmt, *js.ExportStmt:
		v.found = true
	}
	return v
}

func (v *moduleSyntaxEvidenceVisitor) Exit(js.INode) {}

func hasKnownBinaryMagic(data []byte) bool {
	return bytes.HasPrefix(data, []byte("\x89PNG\r\n\x1a\n")) ||
		bytes.HasPrefix(data, []byte("\xff\xd8\xff")) ||
		bytes.HasPrefix(data, []byte("GIF87a")) ||
		bytes.HasPrefix(data, []byte("GIF89a")) ||
		(len(data) >= 12 && bytes.Equal(data[:4], []byte("RIFF")) && bytes.Equal(data[8:12], []byte("WEBP")))
}
