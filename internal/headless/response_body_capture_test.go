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

func TestResponseBodyDrainWaitsForDelayedLoadingFinished(t *testing.T) {
	capture := newNetworkCapture()
	capture.startBodyWorkers(context.Background(), 1024, "https://example.com/", nil, func(context.Context, network.RequestID) ([]byte, error) {
		return []byte(`{"chunk":"/assets/delayed.js"}`), nil
	})
	defer capture.stopBodyWorkers()

	capture.handleResponseReceived(&network.EventResponseReceived{
		RequestID: "delayed", Type: network.ResourceTypeFetch,
		Response: &network.Response{URL: "https://example.com/api/config", MimeType: "application/json"},
	})
	waitCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	drained := make(chan bool, 1)
	waitStarted := make(chan struct{})
	go func() {
		close(waitStarted)
		drained <- capture.waitForResponseBodies(waitCtx)
	}()
	<-waitStarted

	select {
	case result := <-drained:
		t.Fatalf("drain returned %v before loadingFinished", result)
	case <-time.After(20 * time.Millisecond):
	}
	capture.handleLoadingFinished(&network.EventLoadingFinished{RequestID: "delayed", EncodedDataLength: 64})
	select {
	case result := <-drained:
		if !result {
			t.Fatal("drain did not complete after loadingFinished and body processing")
		}
	case <-time.After(time.Second):
		t.Fatal("drain remained blocked after loadingFinished")
	}
	if !captureHasXHRURL(capture, "https://example.com/assets/delayed.js") {
		t.Fatal("delayed response body was not captured")
	}
}

func TestResponseBodyDrainWaitsUntilLoadingFailedReleasesMetadata(t *testing.T) {
	capture := newNetworkCapture()
	capture.startBodyWorkers(context.Background(), 1024, "https://example.com/", nil, func(context.Context, network.RequestID) ([]byte, error) {
		t.Fatal("failed response must not fetch a body")
		return nil, nil
	})
	defer capture.stopBodyWorkers()
	capture.handleResponseReceived(&network.EventResponseReceived{
		RequestID: "failed-drain", Type: network.ResourceTypeXHR,
		Response: &network.Response{URL: "https://example.com/api", MimeType: "text/plain"},
	})

	waitCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	drained := make(chan bool, 1)
	waitStarted := make(chan struct{})
	go func() {
		close(waitStarted)
		drained <- capture.waitForResponseBodies(waitCtx)
	}()
	<-waitStarted
	select {
	case result := <-drained:
		t.Fatalf("drain returned %v before loadingFailed", result)
	case <-time.After(20 * time.Millisecond):
	}
	capture.handleLoadingFailed(&network.EventLoadingFailed{RequestID: "failed-drain", ErrorText: "net::ERR_FAILED"})
	select {
	case result := <-drained:
		if !result {
			t.Fatal("drain did not complete after loadingFailed")
		}
	case <-time.After(time.Second):
		t.Fatal("loadingFailed did not release drain state")
	}
}

func TestResponseBodyContextCancelReleasesPendingMetadata(t *testing.T) {
	poolCtx, poolCancel := context.WithCancel(context.Background())
	capture := newNetworkCapture()
	capture.startBodyWorkers(poolCtx, 1024, "https://example.com/", nil, func(context.Context, network.RequestID) ([]byte, error) {
		return nil, nil
	})
	capture.handleResponseReceived(&network.EventResponseReceived{
		RequestID: "canceled-metadata", Type: network.ResourceTypeFetch,
		Response: &network.Response{URL: "https://example.com/api", MimeType: "application/json"},
	})
	poolCancel()
	releaseCtx, releaseCancel := context.WithTimeout(context.Background(), time.Second)
	defer releaseCancel()
	if !capture.waitForResponseBodies(releaseCtx) {
		t.Fatal("pool context cancellation did not release pending metadata")
	}

	capture.bodyMu.Lock()
	pendingMetadata, pendingBodies := len(capture.pendingResponses), capture.pendingBodies
	capture.bodyMu.Unlock()
	if pendingMetadata != 0 || pendingBodies != 0 {
		t.Fatalf("state after context cancellation: metadata=%d bodies=%d, want 0/0", pendingMetadata, pendingBodies)
	}
	capture.stopBodyWorkers()
}

func TestResponseBodyMIMERejectsNonApplicationJSONSuffix(t *testing.T) {
	for _, mimeType := range []string{"image/vendor+json", "model/example+json", "audio/problem+json"} {
		if isTextResponseMIME(mimeType) {
			t.Fatalf("isTextResponseMIME(%q) = true, want false", mimeType)
		}
	}
	for _, mimeType := range []string{"text/plain", "application/json", "application/problem+json"} {
		if !isTextResponseMIME(mimeType) {
			t.Fatalf("isTextResponseMIME(%q) = false, want true", mimeType)
		}
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

func TestResponseBodyQueueIsBoundedAndDropsFullAdmissionWithoutBlocking(t *testing.T) {
	capture := newNetworkCapture()
	started := make(chan struct{}, 16)
	release := make(chan struct{})
	var fetches atomic.Int32
	capture.startBodyWorkers(context.Background(), 1024, "https://example.com/", nil, func(ctx context.Context, _ network.RequestID) ([]byte, error) {
		fetches.Add(1)
		started <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
		}
		return []byte(`{}`), nil
	})
	defer capture.stopBodyWorkers()

	for i := 0; i < 4; i++ {
		enqueueFinishedTextResponse(capture, network.RequestID(string(rune('a'+i))))
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("body worker did not become active")
		}
	}
	for i := 4; i < 8; i++ {
		enqueueFinishedTextResponse(capture, network.RequestID(string(rune('a'+i))))
	}

	admissionStarted := time.Now()
	enqueueFinishedTextResponse(capture, "full-drop")
	if elapsed := time.Since(admissionStarted); elapsed > 100*time.Millisecond {
		t.Fatalf("full body queue blocked CDP event handling for %s", elapsed)
	}
	capture.bodyMu.Lock()
	queued, pending, metadata := len(capture.bodyQueue), capture.pendingBodies, len(capture.pendingResponses)
	capture.bodyMu.Unlock()
	if queued != 4 || pending != 8 || metadata != 0 {
		t.Fatalf("bounded body state: queued=%d pending=%d metadata=%d, want 4/8/0", queued, pending, metadata)
	}

	close(release)
	waitCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if !capture.waitForResponseBodies(waitCtx) {
		t.Fatal("bounded body pool did not drain")
	}
	if got := fetches.Load(); got != 8 {
		t.Fatalf("body fetches = %d, want 8 (full admission must be dropped)", got)
	}
}

func TestResponseBodyPendingMetadataAdmissionIsBounded(t *testing.T) {
	capture := newNetworkCapture()
	capture.startBodyWorkers(context.Background(), 1024, "https://example.com/", nil, func(context.Context, network.RequestID) ([]byte, error) {
		t.Fatal("metadata-only responses must not fetch before loadingFinished")
		return nil, nil
	})
	defer capture.stopBodyWorkers()

	for i := 0; i < 9; i++ {
		capture.handleResponseReceived(&network.EventResponseReceived{
			RequestID: network.RequestID(string(rune('a' + i))), Type: network.ResourceTypeFetch,
			Response: &network.Response{URL: "https://example.com/config", MimeType: "application/json"},
		})
	}
	capture.bodyMu.Lock()
	metadata := len(capture.pendingResponses)
	capture.bodyMu.Unlock()
	if metadata != 8 {
		t.Fatalf("pending response metadata = %d, want bounded admission of 8", metadata)
	}
}

func TestResponseBodyStrictTotalDeadlineDropsQueuedBacklogDuringTeardown(t *testing.T) {
	const totalBudget = 100 * time.Millisecond
	origin := time.Now()
	operationCtx, operationCancel := context.WithDeadline(context.Background(), origin.Add(totalBudget))
	defer operationCancel()
	capture := newNetworkCapture()
	started := make(chan struct{}, 16)
	var fetches atomic.Int32
	capture.startBodyWorkers(operationCtx, 1024, "https://example.com/", nil, func(ctx context.Context, _ network.RequestID) ([]byte, error) {
		fetches.Add(1)
		started <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	})

	for i := 0; i < 4; i++ {
		enqueueFinishedTextResponse(capture, network.RequestID(string(rune('a'+i))))
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("body worker did not become active")
		}
	}
	for i := 4; i < 8; i++ {
		enqueueFinishedTextResponse(capture, network.RequestID(string(rune('a'+i))))
	}

	if capture.waitForResponseBodies(operationCtx) {
		t.Fatal("body drain reported success with active and queued jobs at total deadline")
	}
	teardownStarted := time.Now()
	capture.stopBodyWorkers()
	if teardownElapsed := time.Since(teardownStarted); teardownElapsed > 150*time.Millisecond {
		t.Fatalf("worker teardown after total deadline took %s", teardownElapsed)
	}
	if elapsed := time.Since(origin); elapsed > totalBudget+200*time.Millisecond {
		t.Fatalf("operation plus worker teardown exceeded strict total bound: %s", elapsed)
	}
	if got := fetches.Load(); got != 4 {
		t.Fatalf("workers fetched %d bodies, want only 4 active jobs and no post-deadline backlog traversal", got)
	}
	capture.bodyMu.Lock()
	queued, pending, metadata := len(capture.bodyQueue), capture.pendingBodies, len(capture.pendingResponses)
	capture.bodyMu.Unlock()
	if queued != 0 || pending != 0 || metadata != 0 {
		t.Fatalf("teardown state: queued=%d pending=%d metadata=%d, want 0/0/0", queued, pending, metadata)
	}
	enqueueFinishedTextResponse(capture, "after-stop")
	capture.bodyMu.Lock()
	queued, pending, metadata = len(capture.bodyQueue), capture.pendingBodies, len(capture.pendingResponses)
	capture.bodyMu.Unlock()
	if queued != 0 || pending != 0 || metadata != 0 || fetches.Load() != 4 {
		t.Fatalf("post-stop admission changed state: queued=%d pending=%d metadata=%d fetches=%d", queued, pending, metadata, fetches.Load())
	}
}

func enqueueFinishedTextResponse(capture *networkCapture, requestID network.RequestID) {
	capture.handleResponseReceived(&network.EventResponseReceived{
		RequestID: requestID, Type: network.ResourceTypeFetch,
		Response: &network.Response{URL: "https://example.com/config", MimeType: "application/json"},
	})
	capture.handleLoadingFinished(&network.EventLoadingFinished{RequestID: requestID, EncodedDataLength: 2})
}

func captureHasXHRURL(capture *networkCapture, rawURL string) bool {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return capture.xhrURLs[rawURL]
}
