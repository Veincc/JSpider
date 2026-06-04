package fetcher

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Veincc/JSpider/internal/config"
	"github.com/Veincc/JSpider/internal/logging"
	"github.com/Veincc/JSpider/internal/urlutil"
	"github.com/andybalholm/brotli"
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
	URL         string
	StatusCode  int
	ContentType string
	Size        int64
	Hash        string
	Body        []byte
	IsJS        bool
	Err         error
}

// clone returns a copy of the Result so FetchJS mutations do not pollute the cache
func (r *Result) clone() *Result {
	c := *r
	return &c
}

// inflight represents an in-progress request
type inflight struct {
	done chan struct{}
	res  *Result
}

type Fetcher struct {
	cfg     *config.Config
	log     *logging.Logger
	client  *http.Client
	mu      sync.Mutex
	cache   map[string]*Result   // Completed results cache
	pending map[string]*inflight // In-flight requests (singleflight)
}

func New(cfg *config.Config, log *logging.Logger) *Fetcher {
	client := &http.Client{
		Timeout: time.Duration(cfg.Timeout) * time.Second,
	}
	if cfg.InsecureSkipVerify {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		client.Transport = transport
	}

	return &Fetcher{
		cfg:     cfg,
		log:     log,
		client:  client,
		cache:   make(map[string]*Result),
		pending: make(map[string]*inflight),
	}
}

// Fetch downloads URL content with caching and singleflight deduplication
func (f *Fetcher) Fetch(rawURL string) *Result {
	f.mu.Lock()

	// 1. Check completed cache
	if cached, ok := f.cache[rawURL]; ok {
		f.mu.Unlock()
		return cached
	}

	// 2. Check for in-flight request
	if inf, ok := f.pending[rawURL]; ok {
		f.mu.Unlock()
		// Wait for the request to complete
		<-inf.done
		return inf.res
	}

	// 3. Create new in-flight request
	inf := &inflight{done: make(chan struct{})}
	f.pending[rawURL] = inf
	f.mu.Unlock()

	// 4. Perform download
	result := f.doFetch(rawURL)

	// 5. Store in cache and notify waiters
	f.mu.Lock()
	f.cache[rawURL] = result
	inf.res = result
	delete(f.pending, rawURL)
	f.mu.Unlock()
	close(inf.done)

	return result
}

func (f *Fetcher) doFetch(rawURL string) *Result {
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return &Result{URL: rawURL, Err: err}
	}

	req.Header.Set("User-Agent", f.cfg.UserAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")

	if f.cfg.Cookies != "" {
		req.Header.Set("Cookie", f.cfg.Cookies)
	}
	for k, v := range f.cfg.Headers {
		req.Header.Set(k, v)
	}

	f.log.Verbose("Downloading: %s", rawURL)

	resp, err := f.client.Do(req)
	if err != nil {
		return &Result{URL: rawURL, Err: err}
	}
	defer resp.Body.Close()

	// Limit compressed body read size
	maxSize := int64(f.cfg.MaxSizeMB) * 1024 * 1024
	limitedReader := io.LimitReader(resp.Body, maxSize+1)

	compressedBody, err := io.ReadAll(limitedReader)
	if err != nil {
		return &Result{URL: rawURL, StatusCode: resp.StatusCode, Err: err}
	}

	if int64(len(compressedBody)) > maxSize {
		return &Result{
			URL:        rawURL,
			StatusCode: resp.StatusCode,
			Err:        fmt.Errorf("File too large: %d bytes exceeds limit of %d bytes", len(compressedBody), maxSize),
		}
	}

	// Decompress (with post-decompression size limit)
	body, err := decompressBounded(compressedBody, resp.Header.Get("Content-Encoding"), maxSize)
	if err != nil {
		if _, ok := err.(*ErrDecompressTooLarge); ok {
			// Decompressed content exceeds limit, return error
			return &Result{URL: rawURL, StatusCode: resp.StatusCode, Err: err}
		}
		// Other decompression errors (e.g. corrupted format), fall back to raw content
		f.log.Verbose("Decompression failed %s: %v, using raw content", rawURL, err)
		body = compressedBody
	}

	ct := resp.Header.Get("Content-Type")
	hash := sha256.Sum256(body)

	isJS := urlutil.IsJSPath(rawURL) || urlutil.IsJSContentType(ct)

	return &Result{
		URL:         rawURL,
		StatusCode:  resp.StatusCode,
		ContentType: ct,
		Size:        int64(len(body)),
		Hash:        fmt.Sprintf("%x", hash[:8]),
		Body:        body,
		IsJS:        isJS,
	}
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

	// Limit decompressed size
	limited := io.LimitReader(reader, maxSize+1)
	result, err := io.ReadAll(limited)
	if err != nil {
		return data, err
	}
	if int64(len(result)) > maxSize {
		return data, &ErrDecompressTooLarge{Size: int64(len(result)), Limit: maxSize}
	}
	return result, nil
}

// FetchJS downloads a JS resource with status validation.
// Returns a copy of the Result so mutations do not pollute the cache.
func (f *Fetcher) FetchJS(rawURL string) *Result {
	result := f.Fetch(rawURL)
	if result.Err != nil {
		return result.clone()
	}

	// Return a copy to avoid mutating the cache
	clone := result.clone()

	if clone.StatusCode != 200 {
		clone.Err = fmt.Errorf("HTTP %d", clone.StatusCode)
		return clone
	}

	// Check if JS: by URL path or Content-Type
	if !clone.IsJS {
		// Try to check if content looks like JS
		if looksLikeJS(clone.Body) {
			clone.IsJS = true
		} else {
			clone.Err = fmt.Errorf("Not a JS resource: content-type=%s", clone.ContentType)
		}
	}

	return clone
}

// looksLikeJS checks if content looks like JS
func looksLikeJS(data []byte) bool {
	if len(data) < 10 {
		return false
	}
	snippet := string(data[:min(500, len(data))])
	indicators := []string{
		"__webpack_require__", "__vite__", "import(", "export ",
		"function(", "function ", "var ", "let ", "const ",
		"self.", "window.", "document.", "(()=>{", "(function(",
	}
	for _, ind := range indicators {
		if strings.Contains(snippet, ind) {
			return true
		}
	}
	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
