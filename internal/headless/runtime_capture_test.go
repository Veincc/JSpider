package headless

import (
	"strings"
	"testing"

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
	if _, ok := got.Headers["Authorization"]; ok {
		t.Fatalf("Authorization header was retained: %#v", got.Headers)
	}
	if valueForRuntime(got.BodyParams, "token") != "[REDACTED]" {
		t.Fatalf("token body param = %q", valueForRuntime(got.BodyParams, "token"))
	}
	if strings.Contains(got.URL, "url-secret") {
		t.Fatalf("runtime URL leaked a sensitive query value: %q", got.URL)
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
	if valueForRuntime(requests[0].BodyParams, "api_key") != apidiscovery.RedactedValue {
		t.Fatalf("api_key after completion = %+v", requests[0].BodyParams)
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
