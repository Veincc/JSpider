package headless

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"
	cdpRuntime "github.com/chromedp/cdproto/runtime"

	"github.com/Veincc/JSpider/internal/apidiscovery"
)

func TestRuntimeCaptureMergesRequestResponseAndFinished(t *testing.T) {
	capture := newRuntimeCapture("https://example.com/")
	capture.setStage("click")
	capture.handleRequest(&network.EventRequestWillBeSent{
		RequestID:   "request-1",
		DocumentURL: "https://example.com/",
		Type:        network.ResourceTypeFetch,
		Request: &network.Request{
			URL:         "https://example.com/gw/user/list?page=1&token=url-secret",
			Method:      "POST",
			Headers:     network.Headers{"Content-Type": "application/json", "Authorization": "secret"},
			HasPostData: true,
		},
		Initiator: &network.Initiator{
			Type: network.InitiatorTypeScript,
			Stack: &cdpRuntime.StackTrace{CallFrames: []*cdpRuntime.CallFrame{{
				URL: "https://example.com/app.js",
			}}},
		},
	})
	capture.setPostData("request-1", "https://example.com/gw/user/list?page=1&token=url-secret", []byte(`{"filters":{"status":"active"},"token":"secret"}`))
	capture.handleResponse(&network.EventResponseReceived{
		RequestID: "request-1",
		Type:      network.ResourceTypeFetch,
		Response: &network.Response{
			URL:      "https://example.com/gw/user/list?page=1&token=url-secret",
			Status:   200,
			MimeType: "application/json",
		},
	})
	capture.handleFinished(&network.EventLoadingFinished{
		RequestID:         "request-1",
		EncodedDataLength: 123,
	})

	requests := capture.snapshot()
	if len(requests) != 1 {
		t.Fatalf("requests = %+v", requests)
	}
	got := requests[0]
	if got.Stage != "click" || got.StatusCode != 200 || !got.Completed || got.EncodedDataLength != 123 {
		t.Fatalf("merged request = %+v", got)
	}
	if got.Headers["Authorization"] != "secret" {
		t.Fatalf("Authorization header = %#v, want original value", got.Headers)
	}
	if valueForRuntime(got.BodyParams, "token") != "secret" {
		t.Fatalf("token body param = %q", valueForRuntime(got.BodyParams, "token"))
	}
	if !strings.Contains(got.URL, "url-secret") {
		t.Fatalf("runtime URL did not preserve query value: %q", got.URL)
	}
	if len(got.Initiator.StackURLs) != 1 || got.Initiator.StackURLs[0] != "https://example.com/app.js" {
		t.Fatalf("initiator = %+v", got.Initiator)
	}
}

func TestRuntimeCaptureAppliesPostDataAfterRequestCompletes(t *testing.T) {
	capture := newRuntimeCapture("https://example.com/")
	capture.handleRequest(&network.EventRequestWillBeSent{
		RequestID: "fast-post",
		Type:      network.ResourceTypeFetch,
		Request: &network.Request{
			URL:         "https://example.com/api/update",
			Method:      "POST",
			Headers:     network.Headers{"Content-Type": "application/json"},
			HasPostData: true,
		},
	})
	capture.handleFinished(&network.EventLoadingFinished{RequestID: "fast-post"})

	capture.setPostData(
		"fast-post",
		"https://example.com/api/update",
		[]byte(`{"filters":{"status":"active"},"api_key":"secret"}`),
	)

	requests := capture.snapshot()
	if len(requests) != 1 {
		t.Fatalf("requests = %+v", requests)
	}
	if valueForRuntime(requests[0].BodyParams, "filters.status") != "active" {
		t.Fatalf("body params after completion = %+v", requests[0].BodyParams)
	}
	if valueForRuntime(requests[0].BodyParams, "api_key") != "secret" {
		t.Fatalf("api_key after completion = %+v", requests[0].BodyParams)
	}
}

func TestRuntimeCaptureCarriesBodyTruncationAndParseError(t *testing.T) {
	capture := newRuntimeCapture("https://example.com/")
	capture.handleRequest(&network.EventRequestWillBeSent{
		RequestID: "large-post", Type: network.ResourceTypeFetch,
		Request: &network.Request{
			URL: "https://example.com/api", Method: "POST",
			Headers: network.Headers{"Content-Type": "application/json"}, HasPostData: true,
		},
	})
	capture.setPostData(
		"large-post",
		"https://example.com/api",
		[]byte(`{"padding":"`+strings.Repeat("x", apidiscovery.MaxRequestBodyBytes+1)+`"}`),
	)
	requests := capture.snapshot()
	if len(requests) != 1 {
		t.Fatalf("requests = %+v", requests)
	}
	if !requests[0].BodyTruncated || requests[0].BodyParseError == "" {
		t.Fatalf("runtime body flags = truncated %v parse error %q", requests[0].BodyTruncated, requests[0].BodyParseError)
	}
}

func TestRuntimeCaptureReleasesPostDataLookupAfterParsing(t *testing.T) {
	capture := newRuntimeCapture("https://example.com/")
	capture.handleRequest(&network.EventRequestWillBeSent{
		RequestID: "post", Type: network.ResourceTypeFetch,
		Request: &network.Request{
			URL: "https://example.com/api", Method: "POST",
			Headers: network.Headers{"Content-Type": "application/json"}, HasPostData: true,
		},
	})
	capture.setPostData("post", "https://example.com/api", []byte(`{"name":"alice"}`))

	capture.mu.Lock()
	lookups := len(capture.trackedByKey)
	capture.mu.Unlock()
	if lookups != 0 {
		t.Fatalf("post-data lookup entries=%d, want 0 (body must not be retained)", lookups)
	}
}

func TestRuntimeCaptureReleasesPostDataLookupWhenFetchFails(t *testing.T) {
	capture := newRuntimeCapture("https://example.com/")
	capture.handleRequest(&network.EventRequestWillBeSent{
		RequestID: "post-error", Type: network.ResourceTypeFetch,
		Request: &network.Request{URL: "https://example.com/api", Method: "POST", HasPostData: true},
	})
	capture.releasePostDataLookup("post-error", "https://example.com/api")

	capture.mu.Lock()
	lookups := len(capture.trackedByKey)
	capture.mu.Unlock()
	if lookups != 0 {
		t.Fatalf("post-data lookup entries after fetch failure = %d, want 0", lookups)
	}
}

func TestRuntimeCaptureDefersJSONBodyParsingUntilPostDataIsRetrieved(t *testing.T) {
	unavailable := newRuntimeCapture("https://example.com/")
	unavailable.handleRequest(&network.EventRequestWillBeSent{
		RequestID: "unavailable", Type: network.ResourceTypeFetch,
		Request: &network.Request{
			URL: "https://example.com/api", Method: "POST",
			Headers: network.Headers{"Content-Type": "application/json"}, HasPostData: true,
		},
	})
	unavailable.releasePostDataLookup("unavailable", "https://example.com/api")
	requests := unavailable.snapshot()
	if len(requests) != 1 || !requests[0].HasBody || requests[0].BodyParseError != "" {
		t.Fatalf("unavailable post data = %+v, want HasBody with no fabricated parse error", requests)
	}

	empty := newRuntimeCapture("https://example.com/")
	empty.handleRequest(&network.EventRequestWillBeSent{
		RequestID: "empty", Type: network.ResourceTypeFetch,
		Request: &network.Request{
			URL: "https://example.com/api", Method: "POST",
			Headers: network.Headers{"Content-Type": "application/json"}, HasPostData: true,
		},
	})
	empty.setPostData("empty", "https://example.com/api", []byte{})
	requests = empty.snapshot()
	if len(requests) != 1 || !requests[0].HasBody || requests[0].BodyParseError == "" {
		t.Fatalf("retrieved empty JSON = %+v, want a real parse error", requests)
	}
}

func TestRuntimeCaptureRecordsFailureAndRedirectChain(t *testing.T) {
	capture := newRuntimeCapture("https://example.com/")
	capture.setStage("navigate")
	capture.handleRequest(&network.EventRequestWillBeSent{
		RequestID: "redirect",
		Type:      network.ResourceTypeXHR,
		Request:   &network.Request{URL: "https://example.com/old", Method: "GET"},
	})
	capture.handleRequest(&network.EventRequestWillBeSent{
		RequestID:        "redirect",
		Type:             network.ResourceTypeXHR,
		RedirectResponse: &network.Response{URL: "https://example.com/old", Status: 302, MimeType: "text/html"},
		Request:          &network.Request{URL: "https://example.com/new", Method: "GET"},
	})
	capture.handleFailed(&network.EventLoadingFailed{
		RequestID: "redirect",
		Type:      network.ResourceTypeXHR,
		ErrorText: "net::ERR_FAILED",
	})

	requests := capture.snapshot()
	if len(requests) != 2 {
		t.Fatalf("redirect requests = %+v, want 2 hops", requests)
	}
	if requests[0].StatusCode != 302 || !requests[0].Completed || requests[0].RedirectTo != "https://example.com/new" {
		t.Fatalf("redirect first hop = %+v", requests[0])
	}
	if !requests[1].Failed || requests[1].ErrorText != "net::ERR_FAILED" || requests[1].RedirectFrom != "https://example.com/old" {
		t.Fatalf("redirect final hop = %+v", requests[1])
	}
}

func TestRuntimeCaptureRedirectToNonIdleResourceReleasesIdleCounter(t *testing.T) {
	capture := newRuntimeCapture("https://example.com/")
	capture.handleRequest(&network.EventRequestWillBeSent{
		RequestID: "redirect",
		Type:      network.ResourceTypeXHR,
		Request:   &network.Request{URL: "https://example.com/poll", Method: "GET"},
	})
	if capture.inFlight != 1 {
		t.Fatalf("inFlight after XHR = %d, want 1", capture.inFlight)
	}

	capture.handleRequest(&network.EventRequestWillBeSent{
		RequestID:        "redirect",
		Type:             network.ResourceTypeEventSource,
		RedirectResponse: &network.Response{URL: "https://example.com/poll", Status: 302},
		Request:          &network.Request{URL: "https://example.com/events", Method: "GET"},
	})

	if capture.inFlight != 0 {
		t.Fatalf("inFlight after XHR redirects to EventSource = %d, want 0", capture.inFlight)
	}
}

func TestRuntimeCaptureOldLongPollDoesNotBlockNetworkQuiet(t *testing.T) {
	capture := newRuntimeCapture("https://example.com/")
	capture.handleRequest(&network.EventRequestWillBeSent{
		RequestID: "poll", Type: network.ResourceTypeFetch,
		Request: &network.Request{URL: "https://example.com/poll", Method: "GET"},
	})
	capture.mu.Lock()
	capture.active["poll"].startedAt = time.Now().Add(-6 * time.Second)
	capture.lastActivity = time.Now().Add(-6 * time.Second)
	capture.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if !capture.waitForAPIIdle(ctx, 20*time.Millisecond) {
		t.Fatal("request older than five seconds prevented network quiet")
	}
}

func TestRuntimeCaptureSnapshotKeepsRequestArrivalOrderAcrossConcurrentFinishes(t *testing.T) {
	capture := newRuntimeCapture("https://example.com/")
	const count = 32
	for i := 0; i < count; i++ {
		id := network.RequestID(string(rune('A' + i)))
		capture.handleRequest(&network.EventRequestWillBeSent{
			RequestID: id, Type: network.ResourceTypeFetch,
			Request: &network.Request{URL: "https://example.com/" + string(id), Method: "GET"},
		})
	}

	var wg sync.WaitGroup
	for i := count - 1; i >= 0; i-- {
		id := network.RequestID(string(rune('A' + i)))
		wg.Add(1)
		go func() {
			defer wg.Done()
			capture.handleFinished(&network.EventLoadingFinished{RequestID: id})
		}()
	}
	wg.Wait()

	requests := capture.snapshot()
	if len(requests) != count {
		t.Fatalf("snapshot count = %d, want %d", len(requests), count)
	}
	for i, request := range requests {
		want := string(rune('A' + i))
		if request.RequestID != want {
			t.Fatalf("snapshot[%d].RequestID = %q, want arrival-order %q", i, request.RequestID, want)
		}
	}
}

func TestRuntimeCaptureKeepsWebSocketsSeparateAndPreflightExcludedFromMatching(t *testing.T) {
	capture := newRuntimeCapture("https://example.com/")
	capture.handleWebSocketCreated(&network.EventWebSocketCreated{
		RequestID: "ws-1",
		URL:       "wss://example.com/socket",
	})
	capture.handleRequest(&network.EventRequestWillBeSent{
		RequestID: "preflight",
		Type:      network.ResourceTypeFetch,
		Request:   &network.Request{URL: "https://api.example.com/users", Method: "OPTIONS"},
	})
	capture.handleFinished(&network.EventLoadingFinished{RequestID: "preflight"})

	requests := capture.snapshot()
	if len(requests) != 2 {
		t.Fatalf("requests = %+v", requests)
	}
	if !requests[0].Preflight && !requests[1].Preflight {
		t.Fatal("OPTIONS preflight was not marked")
	}
	if !requests[0].WebSocket && !requests[1].WebSocket {
		t.Fatal("WebSocket was not recorded separately")
	}
	for _, request := range requests {
		if request.WebSocket && request.Completed {
			t.Fatalf("WebSocket was completed before handshake response: %+v", request)
		}
	}
}

func TestRuntimeCaptureMarksWebSocketHandshakeResult(t *testing.T) {
	capture := newRuntimeCapture("https://example.com/")
	capture.handleWebSocketCreated(&network.EventWebSocketCreated{
		RequestID: "ws-ok",
		URL:       "wss://example.com/socket",
	})
	capture.handleWebSocketHandshakeResponse(&network.EventWebSocketHandshakeResponseReceived{
		RequestID: "ws-ok",
		Response:  &network.WebSocketResponse{Status: 101},
	})
	capture.handleWebSocketCreated(&network.EventWebSocketCreated{
		RequestID: "ws-denied",
		URL:       "wss://example.com/denied",
	})
	capture.handleWebSocketHandshakeResponse(&network.EventWebSocketHandshakeResponseReceived{
		RequestID: "ws-denied",
		Response:  &network.WebSocketResponse{Status: 403, StatusText: "Forbidden"},
	})

	requests := capture.snapshot()
	if len(requests) != 2 {
		t.Fatalf("requests = %+v", requests)
	}
	byID := make(map[string]apidiscovery.RuntimeRequest)
	for _, request := range requests {
		byID[request.RequestID] = request
	}
	if got := byID["ws-ok"]; !got.Completed || got.Failed || got.StatusCode != 101 {
		t.Fatalf("successful websocket handshake = %+v", got)
	}
	if got := byID["ws-denied"]; !got.Completed || !got.Failed || got.StatusCode != 403 {
		t.Fatalf("failed websocket handshake = %+v", got)
	}
}

func valueForRuntime(params []apidiscovery.Parameter, name string) string {
	for _, param := range params {
		if param.Name == name {
			return param.Value
		}
	}
	return ""
}
