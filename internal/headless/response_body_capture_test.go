package headless

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"
)

func TestResponseBodyFetchStartsOnlyAfterLoadingFinished(t *testing.T) {
	capture := newNetworkCapture()
	var fetches atomic.Int32
	capture.startBodyWorkers(context.Background(), 1024, "https://example.com/", nil, func(context.Context, network.RequestID) ([]byte, error) {
		fetches.Add(1)
		return []byte(`{"chunk":"/assets/late.js"}`), nil
	})
	defer capture.stopBodyWorkers()

	capture.handleResponseReceived(&network.EventResponseReceived{
		RequestID: "chunked",
		Type:      network.ResourceTypeFetch,
		Response: &network.Response{
			URL:      "https://example.com/api/config",
			MimeType: "application/json",
		},
	})
	if got := fetches.Load(); got != 0 {
		t.Fatalf("body fetches after responseReceived = %d, want 0", got)
	}

	capture.handleLoadingFinished(&network.EventLoadingFinished{RequestID: "chunked", EncodedDataLength: 64})
	waitCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if !capture.waitForResponseBodies(waitCtx) {
		t.Fatal("timed out waiting for finished response body")
	}
	if got := fetches.Load(); got != 1 {
		t.Fatalf("body fetches after loadingFinished = %d, want 1", got)
	}
	if !captureHasXHRURL(capture, "https://example.com/assets/late.js") {
		t.Fatalf("captured XHR URLs = %#v", capture.xhrURLs)
	}
}

func TestResponseBodyRejectsNonTextAndKnownOversizeBeforeFetch(t *testing.T) {
	capture := newNetworkCapture()
	var fetches atomic.Int32
	capture.startBodyWorkers(context.Background(), 32, "https://example.com/", nil, func(context.Context, network.RequestID) ([]byte, error) {
		fetches.Add(1)
		return []byte(`{"chunk":"/should-not-run.js"}`), nil
	})
	defer capture.stopBodyWorkers()

	capture.handleResponseReceived(&network.EventResponseReceived{
		RequestID: "binary", Type: network.ResourceTypeXHR,
		Response: &network.Response{URL: "https://example.com/blob", MimeType: "application/octet-stream"},
	})
	capture.handleLoadingFinished(&network.EventLoadingFinished{RequestID: "binary", EncodedDataLength: 8})
	capture.handleResponseReceived(&network.EventResponseReceived{
		RequestID: "oversize", Type: network.ResourceTypeFetch,
		Response: &network.Response{URL: "https://example.com/config", MimeType: "text/plain", EncodedDataLength: 64},
	})
	capture.handleLoadingFinished(&network.EventLoadingFinished{RequestID: "oversize", EncodedDataLength: 64})

	waitCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if !capture.waitForResponseBodies(waitCtx) {
		t.Fatal("rejected bodies left pending work")
	}
	if got := fetches.Load(); got != 0 {
		t.Fatalf("body fetches = %d, want 0", got)
	}
}

func TestResponseBodyUsesFinishedEncodedLengthForPreFetchCap(t *testing.T) {
	capture := newNetworkCapture()
	var fetches atomic.Int32
	capture.startBodyWorkers(context.Background(), 32, "https://example.com/", nil, func(context.Context, network.RequestID) ([]byte, error) {
		fetches.Add(1)
		return []byte(`{"chunk":"/should-not-run.js"}`), nil
	})
	defer capture.stopBodyWorkers()

	capture.handleResponseReceived(&network.EventResponseReceived{
		RequestID: "grew", Type: network.ResourceTypeFetch,
		Response: &network.Response{URL: "https://example.com/config", MimeType: "application/problem+json"},
	})
	capture.handleLoadingFinished(&network.EventLoadingFinished{RequestID: "grew", EncodedDataLength: 33})

	waitCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if !capture.waitForResponseBodies(waitCtx) || fetches.Load() != 0 {
		t.Fatalf("oversized finished body fetched=%d", fetches.Load())
	}
}

func TestResponseBodyTruncatesOnlyAfterCDPReturnsFullBody(t *testing.T) {
	capture := newNetworkCapture()
	const limit = 32
	// GetResponseBody has no streaming/capped form. This fake deliberately
	// returns a fully allocated body; the collector can only truncate it after
	// transport return and must not parse the suffix past limit.
	fullBody := []byte(strings.Repeat("x", limit) + ` "/assets/past-cap.js"`)
	var returnedBytes atomic.Int64
	capture.startBodyWorkers(context.Background(), limit, "https://example.com/", nil, func(context.Context, network.RequestID) ([]byte, error) {
		returnedBytes.Store(int64(len(fullBody)))
		return fullBody, nil
	})
	defer capture.stopBodyWorkers()

	capture.handleResponseReceived(&network.EventResponseReceived{
		RequestID: "compressed", Type: network.ResourceTypeFetch,
		Response: &network.Response{URL: "https://example.com/config", MimeType: "text/plain"},
	})
	capture.handleLoadingFinished(&network.EventLoadingFinished{RequestID: "compressed", EncodedDataLength: 16})
	waitCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if !capture.waitForResponseBodies(waitCtx) {
		t.Fatal("timed out waiting for compressed body")
	}
	if returnedBytes.Load() <= limit {
		t.Fatalf("fake transport returned %d bytes, want evidence of full allocation beyond cap", returnedBytes.Load())
	}
	if captureHasXHRURL(capture, "https://example.com/assets/past-cap.js") {
		t.Fatal("collector parsed bytes beyond the post-transport cap")
	}
}

func TestLoadingFailedDropsPendingResponseMetadata(t *testing.T) {
	capture := newNetworkCapture()
	var fetches atomic.Int32
	capture.startBodyWorkers(context.Background(), 1024, "https://example.com/", nil, func(context.Context, network.RequestID) ([]byte, error) {
		fetches.Add(1)
		return nil, nil
	})
	defer capture.stopBodyWorkers()

	capture.handleResponseReceived(&network.EventResponseReceived{
		RequestID: "failed", Type: network.ResourceTypeXHR,
		Response: &network.Response{URL: "https://example.com/api", MimeType: "application/json"},
	})
	capture.handleLoadingFailed(&network.EventLoadingFailed{RequestID: "failed", ErrorText: "net::ERR_FAILED"})
	capture.bodyMu.Lock()
	pending := len(capture.pendingResponses)
	capture.bodyMu.Unlock()
	if pending != 0 || fetches.Load() != 0 {
		t.Fatalf("pending metadata=%d fetches=%d, want 0/0", pending, fetches.Load())
	}
}

func TestResponseBodyPoolUsesAtMostFourWorkers(t *testing.T) {
	capture := newNetworkCapture()
	started := make(chan struct{}, 8)
	release := make(chan struct{})
	var active atomic.Int32
	var maximum atomic.Int32
	capture.startBodyWorkers(context.Background(), 1024, "https://example.com/", nil, func(ctx context.Context, _ network.RequestID) ([]byte, error) {
		current := active.Add(1)
		for {
			old := maximum.Load()
			if current <= old || maximum.CompareAndSwap(old, current) {
				break
			}
		}
		started <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
		}
		active.Add(-1)
		return []byte(`{}`), nil
	})
	defer capture.stopBodyWorkers()

	for i := 0; i < 8; i++ {
		id := network.RequestID(string(rune('a' + i)))
		capture.handleResponseReceived(&network.EventResponseReceived{
			RequestID: id, Type: network.ResourceTypeFetch,
			Response: &network.Response{URL: "https://example.com/config", MimeType: "application/json"},
		})
		capture.handleLoadingFinished(&network.EventLoadingFinished{RequestID: id, EncodedDataLength: 2})
	}
	for i := 0; i < 4; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("four body workers did not start")
		}
	}
	select {
	case <-started:
		t.Fatal("more than four body fetches ran concurrently")
	case <-time.After(20 * time.Millisecond):
	}
	if got := maximum.Load(); got != 4 {
		t.Fatalf("maximum body fetch concurrency = %d, want 4", got)
	}
	close(release)
	waitCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if !capture.waitForResponseBodies(waitCtx) {
		t.Fatal("body pool did not drain")
	}
}

func captureHasXHRURL(capture *networkCapture, rawURL string) bool {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return capture.xhrURLs[rawURL]
}
