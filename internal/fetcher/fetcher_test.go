package fetcher

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Veincc/JSpider/internal/config"
	"github.com/Veincc/JSpider/internal/logging"
)

func newTestFetcher(t *testing.T, ts *httptest.Server) *Fetcher {
	t.Helper()
	cfg := &config.Config{
		Timeout:   5,
		MaxSizeMB: 1,
		UserAgent: "Test/1.0",
		Verbose:   false,
	}
	log := logging.New(false, t.TempDir())
	t.Cleanup(func() { log.Close() })
	f, err := New(cfg, log)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return f
}

func TestShouldSendCookiesUsesCanonicalOrigin(t *testing.T) {
	if !shouldSendCookies("https://EXAMPLE.com:443/app.js", "https://example.com/") {
		t.Fatal("canonical same-origin request lost cookies")
	}
	if shouldSendCookies("https://example.com:444/app.js", "https://example.com/") {
		t.Fatal("non-default port received same-origin cookies")
	}
	if shouldSendCookies("https://[::ffff:192.0.2.1]/app.js", "https://192.0.2.1/") {
		t.Fatal("IPv4-mapped IPv6 request received IPv4-origin cookies")
	}
	if !shouldSendCookies("https://[::ffff:c000:201]/app.js", "https://[::ffff:192.0.2.1]/") {
		t.Fatal("equivalent IPv4-mapped IPv6 request lost cookies")
	}
}

func TestRedirectPolicyUsesCanonicalOrigin(t *testing.T) {
	checker := redirectChecker(&config.Config{SameOrigin: true})
	entryURL := "https://example.com/start"

	canonicalTarget, err := http.NewRequestWithContext(
		context.WithValue(context.Background(), redirectPolicyKey{}, entryURL),
		http.MethodGet,
		"https://EXAMPLE.com:443/next",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := checker(canonicalTarget, nil); err != nil {
		t.Fatalf("canonical same-origin redirect rejected: %v", err)
	}

	nonDefaultTarget, err := http.NewRequestWithContext(
		context.WithValue(context.Background(), redirectPolicyKey{}, entryURL),
		http.MethodGet,
		"https://example.com:444/next",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := checker(nonDefaultTarget, nil); err == nil {
		t.Fatal("non-default-port redirect accepted as same-origin")
	}

	mappedTarget, err := http.NewRequestWithContext(
		context.WithValue(context.Background(), redirectPolicyKey{}, "https://192.0.2.1/start"),
		http.MethodGet,
		"https://[::ffff:192.0.2.1]/next",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := checker(mappedTarget, nil); err == nil {
		t.Fatal("IPv4-mapped IPv6 redirect accepted for IPv4 entry origin")
	}

	equivalentMappedTarget, err := http.NewRequestWithContext(
		context.WithValue(context.Background(), redirectPolicyKey{}, "https://[::ffff:192.0.2.1]/start"),
		http.MethodGet,
		"https://[::ffff:c000:201]/next",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := checker(equivalentMappedTarget, nil); err != nil {
		t.Fatalf("equivalent IPv4-mapped IPv6 redirect rejected: %v", err)
	}
}

func TestRedirectCanonicalPolicyRejectsInvalidAllowedCDNOrigin(t *testing.T) {
	checker := redirectChecker(&config.Config{SameOrigin: true, AllowCDN: []string{"cdn.example"}})
	entryContext := context.WithValue(context.Background(), redirectPolicyKey{}, "https://example.com/start")

	ftpTarget, err := http.NewRequestWithContext(entryContext, http.MethodGet, "ftp://cdn.example/next", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := checker(ftpTarget, nil); err == nil {
		t.Fatal("non-HTTP CDN redirect accepted")
	}

	invalidPortTarget := (&http.Request{
		Method: http.MethodGet,
		URL:    &url.URL{Scheme: "https", Host: "cdn.example:", Path: "/next"},
	}).WithContext(entryContext)
	if err := checker(invalidPortTarget, nil); err == nil {
		t.Fatal("invalid-port CDN redirect accepted")
	}
}

func TestFetchRecordsRequestedAndRedirectFinalURLs(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/requested/app.js":
			http.Redirect(w, r, "/final/nested/app.js", http.StatusFound)
		case "/final/nested/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = io.WriteString(w, `import("./chunk.js");`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	f := newTestFetcher(t, ts)
	requested := ts.URL + "/requested/app.js"
	result := f.Fetch(requested)

	if result.Err != nil {
		t.Fatalf("Fetch() error = %v", result.Err)
	}
	if result.RequestedURL != requested {
		t.Fatalf("RequestedURL = %q, want %q", result.RequestedURL, requested)
	}
	if want := ts.URL + "/final/nested/app.js"; result.FinalURL != want {
		t.Fatalf("FinalURL = %q, want %q", result.FinalURL, want)
	}
}

func TestFetchForEntryContextCancelsRequest(t *testing.T) {
	requestCanceled := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
		close(requestCanceled)
	}))
	defer ts.Close()

	f := newTestFetcher(t, ts)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	result := f.FetchForEntryContext(ctx, ts.URL+"/map", ts.URL+"/")
	if !errors.Is(result.Err, context.DeadlineExceeded) {
		t.Fatalf("FetchForEntryContext() error = %v", result.Err)
	}
	select {
	case <-requestCanceled:
	case <-time.After(time.Second):
		t.Fatal("HTTP request context was not canceled")
	}
}

func TestShortSingleflightCallerDoesNotCancelLongCaller(t *testing.T) {
	requestStarted := make(chan struct{})
	releaseRequest := make(chan struct{})
	requestCanceled := make(chan struct{}, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(requestStarted)
		select {
		case <-releaseRequest:
			_, _ = w.Write([]byte("ok"))
		case <-r.Context().Done():
			requestCanceled <- struct{}{}
		}
	}))
	defer ts.Close()

	f := newTestFetcher(t, ts)
	shortCtx, shortCancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer shortCancel()
	shortResult := make(chan *Result, 1)
	go func() {
		shortResult <- f.FetchForEntryContext(shortCtx, ts.URL+"/map", ts.URL+"/")
	}()
	<-requestStarted

	longCtx, longCancel := context.WithTimeout(context.Background(), time.Second)
	defer longCancel()
	longResult := make(chan *Result, 1)
	go func() {
		longResult <- f.FetchForEntryContext(longCtx, ts.URL+"/map", ts.URL+"/")
	}()

	short := <-shortResult
	if !errors.Is(short.Err, context.DeadlineExceeded) {
		t.Fatalf("short caller error = %v", short.Err)
	}
	close(releaseRequest)
	long := <-longResult
	if long.Err != nil || string(long.Body) != "ok" {
		t.Fatalf("long caller result = %+v", long)
	}
	select {
	case <-requestCanceled:
		t.Fatal("short caller canceled the shared HTTP request")
	default:
	}
}

func TestFetchRecordsRequestedURLWhenRequestCannotBeBuilt(t *testing.T) {
	f := newTestFetcher(t, nil)
	const requested = "://invalid"
	result := f.Fetch(requested)

	if result.Err == nil {
		t.Fatal("Fetch() error = nil, want malformed URL error")
	}
	if result.RequestedURL != requested {
		t.Fatalf("RequestedURL = %q, want %q", result.RequestedURL, requested)
	}
	if result.FinalURL != "" {
		t.Fatalf("FinalURL = %q, want empty without an HTTP request", result.FinalURL)
	}
}

func TestFetch_DoesNotCacheCompletedBodies(t *testing.T) {
	var count int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&count, 1)
		w.Write([]byte("hello"))
	}))
	defer ts.Close()

	f := newTestFetcher(t, ts)

	r1 := f.Fetch(ts.URL + "/test")
	r2 := f.Fetch(ts.URL + "/test")

	if r1.Err != nil {
		t.Fatalf("Fetch 1 error: %v", r1.Err)
	}
	if r2.Err != nil {
		t.Fatalf("Fetch 2 error: %v", r2.Err)
	}
	if atomic.LoadInt32(&count) != 2 {
		t.Errorf("HTTP requests = %d, want 2 after the first request completed", count)
	}
	if string(r1.Body) != "hello" {
		t.Errorf("Body: got %q, want %q", r1.Body, "hello")
	}
}

func TestFetch_Singleflight(t *testing.T) {
	var httpCount int32

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&httpCount, 1)
		w.Write([]byte("data"))
	}))
	defer ts.Close()

	f := newTestFetcher(t, ts)

	// Launch 10 concurrent fetches for the same URL
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := f.Fetch(ts.URL + "/same")
			if r == nil {
				t.Error("Got nil result")
			}
		}()
	}
	wg.Wait()

	// Only 1 HTTP request should have been made (singleflight)
	if c := atomic.LoadInt32(&httpCount); c != 1 {
		t.Errorf("Expected 1 HTTP request, got %d", c)
	}
}

func TestFetchJS_NoCachePollution(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html>not js</html>"))
	}))
	defer ts.Close()

	f := newTestFetcher(t, ts)

	// FetchJS should set Err for non-JS content
	r1 := f.FetchJS(ts.URL + "/page")
	if r1.Err == nil {
		t.Fatal("Expected error for non-JS content")
	}

	// Fetch should return the cached result WITHOUT the Err
	r2 := f.Fetch(ts.URL + "/page")
	if r2.Err != nil {
		t.Errorf("Fetch should not have Err (cache pollution): %v", r2.Err)
	}
	if string(r2.Body) != "<html>not js</html>" {
		t.Errorf("Body mismatch: %q", r2.Body)
	}
}

func TestFetchJS_CacheNotModified(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte("var x=1;"))
	}))
	defer ts.Close()

	f := newTestFetcher(t, ts)

	r1 := f.FetchJS(ts.URL + "/app.js")
	if r1.Err != nil {
		t.Fatalf("FetchJS error: %v", r1.Err)
	}

	// Modify the result (should not affect cache)
	r1.Body = []byte("modified")
	r1.Err = fmt.Errorf("injected error")

	// Fetch again should get original
	r2 := f.Fetch(ts.URL + "/app.js")
	if string(r2.Body) != "var x=1;" {
		t.Errorf("Cache was modified: %q", r2.Body)
	}
	if r2.Err != nil {
		t.Errorf("Cache Err was modified: %v", r2.Err)
	}
}

func TestFetch_DecompressionSizeLimit(t *testing.T) {
	// Create gzip that decompresses to > 1MB
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "application/javascript")
		// Build gzip in buffer first to ensure all data is flushed
		var buf strings.Builder
		gz := gzip.NewWriter(&buf)
		data := strings.Repeat("x", 2*1024*1024) // 2MB
		gz.Write([]byte(data))
		gz.Close()
		w.Write([]byte(buf.String()))
	}))
	defer ts.Close()

	cfg := &config.Config{
		Timeout:   5,
		MaxSizeMB: 1, // 1MB limit
		UserAgent: "Test/1.0",
		Verbose:   false,
	}
	log := logging.New(false, t.TempDir())
	defer log.Close()
	f, err := New(cfg, log)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	r := f.Fetch(ts.URL + "/big.js")
	if r.Err == nil {
		t.Fatal("Expected error for oversized decompressed content")
	}
	if _, ok := r.Err.(*ErrDecompressTooLarge); !ok {
		t.Errorf("Expected ErrDecompressTooLarge, got: %v (%T)", r.Err, r.Err)
	}
}

func TestFetch_Non200Status(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			w.WriteHeader(200)
			w.Write([]byte("ok"))
		case "/notfound":
			w.WriteHeader(404)
			w.Write([]byte("not found"))
		case "/nocontent":
			w.WriteHeader(204)
		}
	}))
	defer ts.Close()

	f := newTestFetcher(t, ts)

	// Fetch preserves body for non-200
	r404 := f.Fetch(ts.URL + "/notfound")
	if r404.StatusCode != 404 {
		t.Errorf("StatusCode: got %d, want 404", r404.StatusCode)
	}
	if r404.Err != nil {
		t.Errorf("Fetch should not set Err for non-200: %v", r404.Err)
	}

	// FetchJS sets Err for non-200
	r404js := f.FetchJS(ts.URL + "/notfound")
	if r404js.Err == nil {
		t.Error("FetchJS should set Err for 404")
	}

	// FetchJS sets Err for 204
	r204js := f.FetchJS(ts.URL + "/nocontent")
	if r204js.Err == nil {
		t.Error("FetchJS should set Err for 204")
	}
}

func TestFetchJS_AcceptsAnyTwoHundredStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.WriteHeader(http.StatusPartialContent)
		_, _ = io.WriteString(w, `const partial = true;`)
	}))
	defer ts.Close()

	f := newTestFetcher(t, ts)
	if result := f.FetchJS(ts.URL + "/partial.js"); result.Err != nil {
		t.Fatalf("FetchJS() rejected 206 response: %v", result.Err)
	}
}

func TestFetchJS_RejectsExplicitNonJavaScriptContentType(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("function hello() { return 'world'; }"))
	}))
	defer ts.Close()

	f := newTestFetcher(t, ts)

	r := f.FetchJS(ts.URL + "/script")
	if r.Err == nil {
		t.Fatal("FetchJS() accepted explicit text/plain content")
	}
}

func TestFetchJS_RejectsHTMLAtJavaScriptPath(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, `<script>const looksLikeJavaScript = true;</script>`)
	}))
	defer ts.Close()

	f := newTestFetcher(t, ts)
	result := f.FetchJS(ts.URL + "/app.js")

	if result.Err == nil {
		t.Fatal("FetchJS() accepted HTML because the URL ended in .js")
	}
}

func TestFetchJS_RejectsJSONWhoseParameterMentionsJavaScript(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", `application/json; profile="javascript"`)
		_, _ = io.WriteString(w, `{"const value":"looks like source"}`)
	}))
	defer ts.Close()

	f := newTestFetcher(t, ts)
	if result := f.FetchJS(ts.URL + "/data.js"); result.Err == nil {
		t.Fatal("FetchJS() accepted application/json because a parameter mentioned javascript")
	}
}

func TestFetchJSWithoutContentTypeAcceptsStaticESM(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "static import", body: `import "./dep.js";`},
		{name: "compact re-export", body: `export{value}from"./dep.js";`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header()["Content-Type"] = nil
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, tt.body)
			}))
			defer ts.Close()

			result := newTestFetcher(t, ts).FetchJS(ts.URL + "/module")
			if result.ContentType != "" {
				t.Fatalf("response Content-Type = %q, want absent", result.ContentType)
			}
			if result.Err != nil || !result.IsJS {
				t.Fatalf("FetchJS() rejected static ESM without Content-Type: %+v", result)
			}
		})
	}
}

func TestFetchJSWithoutContentTypeRejectsHTMLJSONAndBinary(t *testing.T) {
	tests := []struct {
		name string
		body []byte
	}{
		{name: "HTML", body: []byte(`<!doctype html><script>const value = true;</script>`)},
		{name: "JSON", body: []byte(`{"source":"const value = true;"}`)},
		{name: "binary", body: append([]byte("\x89PNG\r\n\x1a\n"), []byte("const value = true;")...)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header()["Content-Type"] = nil
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(tt.body)
			}))
			defer ts.Close()

			result := newTestFetcher(t, ts).FetchJS(ts.URL + "/app.js")
			if result.ContentType != "" {
				t.Fatalf("response Content-Type = %q, want absent", result.ContentType)
			}
			if result.Err == nil {
				t.Fatalf("FetchJS fallback accepted %s without Content-Type", tt.name)
			}
		})
	}
}

func TestFetch_PlainTextNotJS(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("Hello, this is just plain text content."))
	}))
	defer ts.Close()

	f := newTestFetcher(t, ts)

	r := f.FetchJS(ts.URL + "/text")
	if r.Err == nil {
		t.Error("Expected error for non-JS text/plain content")
	}
}

func TestFetch_TLSVerificationDefault(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte("const ok = true;"))
	}))
	defer ts.Close()

	f := newTestFetcher(t, nil)

	r := f.Fetch(ts.URL + "/app.js")
	if r.Err == nil {
		t.Fatal("Expected TLS verification error for self-signed certificate")
	}
}

func TestFetch_InsecureSkipVerifyAllowsSelfSigned(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte("const ok = true;"))
	}))
	defer ts.Close()

	cfg := &config.Config{
		Timeout:            5,
		MaxSizeMB:          1,
		UserAgent:          "Test/1.0",
		InsecureSkipVerify: true,
	}
	log := logging.New(false, t.TempDir())
	defer log.Close()
	f, err := New(cfg, log)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	r := f.Fetch(ts.URL + "/app.js")
	if r.Err != nil {
		t.Fatalf("Fetch error with InsecureSkipVerify enabled: %v", r.Err)
	}
	if string(r.Body) != "const ok = true;" {
		t.Errorf("Body: got %q", r.Body)
	}
}

func TestFetch_UnlimitedSize(t *testing.T) {
	body := strings.Repeat("x", 2*1024*1024)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = io.WriteString(w, body)
	}))
	defer ts.Close()

	cfg := &config.Config{
		Timeout:   5,
		MaxSizeMB: 0,
		UserAgent: "Test/1.0",
	}
	log := logging.New(false, t.TempDir())
	defer log.Close()
	f, err := New(cfg, log)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	result := f.Fetch(ts.URL + "/large.js")
	if result.Err != nil {
		t.Fatalf("Fetch() error = %v", result.Err)
	}
	if len(result.Body) != len(body) {
		t.Fatalf("body length = %d, want %d", len(result.Body), len(body))
	}
}

func TestFetch_UsesConfiguredProxy(t *testing.T) {
	var proxyRequests int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&proxyRequests, 1)
		if !r.URL.IsAbs() {
			t.Errorf("proxy request URL is not absolute: %s", r.URL)
		}
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = io.WriteString(w, "const proxied = true;")
	}))
	defer proxy.Close()

	cfg := &config.Config{
		Timeout:   5,
		MaxSizeMB: 0,
		UserAgent: "Test/1.0",
		Proxy:     proxy.URL,
	}
	log := logging.New(false, t.TempDir())
	defer log.Close()
	f, err := New(cfg, log)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	result := f.Fetch("http://target.invalid/app.js")
	if result.Err != nil {
		t.Fatalf("Fetch() error = %v", result.Err)
	}
	if got := atomic.LoadInt32(&proxyRequests); got != 1 {
		t.Fatalf("proxy request count = %d, want 1", got)
	}
	if string(result.Body) != "const proxied = true;" {
		t.Fatalf("body = %q", result.Body)
	}
}

func TestNewRejectsInvalidProxy(t *testing.T) {
	cfg := &config.Config{
		Timeout:   5,
		UserAgent: "Test/1.0",
		Proxy:     "ftp://proxy.example:21",
	}
	log := logging.New(false, t.TempDir())
	defer log.Close()

	if _, err := New(cfg, log); err == nil {
		t.Fatal("New() returned no error for an unsupported proxy scheme")
	}
}

func TestMaxSizeBytesNeverWrapsToUnlimited(t *testing.T) {
	if got := maxSizeBytes(math.MaxInt); got <= 0 {
		t.Fatalf("maxSizeBytes(math.MaxInt) = %d, want a positive bounded value", got)
	}
}
