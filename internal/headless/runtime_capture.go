package headless

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
	cdpRuntime "github.com/chromedp/cdproto/runtime"

	"github.com/Veincc/JSpider/internal/apidiscovery"
)

type trackedRuntimeRequest struct {
	request    apidiscovery.RuntimeRequest
	requestURL string
	body       []byte
}

type runtimeCapture struct {
	mu sync.Mutex

	entryURL  string
	stage     string
	active    map[network.RequestID]*trackedRuntimeRequest
	completed []*trackedRuntimeRequest
	// trackedByKey keeps completed redirects addressable for async
	// Network.getRequestPostData responses. RequestID alone is not enough when
	// Chrome reuses it across redirect hops.
	trackedByKey    map[string]*trackedRuntimeRequest
	redirectCounts  map[network.RequestID]int
	webSockets      map[network.RequestID]*trackedRuntimeRequest
	inFlight        int
	lastActivity    time.Time
	activity        chan struct{}
	postDataPending int
	postDataIdle    chan struct{}
}

func newRuntimeCapture(entryURL string) *runtimeCapture {
	return &runtimeCapture{
		entryURL:       apidiscovery.SanitizeURL(entryURL),
		stage:          "navigate",
		active:         make(map[network.RequestID]*trackedRuntimeRequest),
		trackedByKey:   make(map[string]*trackedRuntimeRequest),
		redirectCounts: make(map[network.RequestID]int),
		webSockets:     make(map[network.RequestID]*trackedRuntimeRequest),
		lastActivity:   time.Now(),
		activity:       make(chan struct{}, 1),
		postDataIdle:   closedChannel(),
	}
}

func (c *runtimeCapture) setStage(stage string) {
	c.mu.Lock()
	c.stage = stage
	c.mu.Unlock()
}

func (c *runtimeCapture) handleRequest(event *network.EventRequestWillBeSent) bool {
	if event == nil || event.Request == nil || !isCapturedAPIType(event.Type) {
		return false
	}

	headers := networkHeaders(event.Request.Headers)
	data := apidiscovery.ParseRequestData(event.Request.URL, headers, nil, event.Request.HasPostData)

	c.mu.Lock()
	defer c.mu.Unlock()

	previous := c.active[event.RequestID]
	redirectFrom := ""
	redirectIndex := c.redirectCounts[event.RequestID]
	if event.RedirectResponse != nil && previous != nil {
		previous.request.StatusCode = event.RedirectResponse.Status
		previous.request.MimeType = event.RedirectResponse.MimeType
		previous.request.Completed = true
		previous.request.RedirectTo = apidiscovery.SanitizeURL(event.Request.URL)
		redirectFrom = previous.request.URL
		c.completed = append(c.completed, previous)
		if countsForIdleString(previous.request.ResourceType) && c.inFlight > 0 {
			c.inFlight--
		}
		redirectIndex++
		c.redirectCounts[event.RequestID] = redirectIndex
	}
	if (previous == nil || event.RedirectResponse != nil) && countsForIdle(event.Type) {
		c.inFlight++
	}

	request := apidiscovery.RuntimeRequest{
		Version:       apidiscovery.Version,
		RequestID:     string(event.RequestID),
		RedirectIndex: redirectIndex,
		URL:           apidiscovery.SanitizeURL(event.Request.URL),
		Method:        strings.ToUpper(event.Request.Method),
		ResourceType:  string(event.Type),
		Stage:         c.stage,
		EntryURL:      c.entryURL,
		DocumentURL:   apidiscovery.SanitizeURL(event.DocumentURL),
		Headers:       data.Headers,
		QueryParams:   data.QueryParams,
		BodyParams:    data.Body.Params,
		ContentType:   data.Body.ContentType,
		HasBody:       data.Body.HasBody,
		BodySample:    data.Body.Sample,
		GraphQL:       data.Body.GraphQL,
		Initiator:     convertInitiator(event.Initiator),
		RedirectFrom:  redirectFrom,
		Preflight:     strings.EqualFold(event.Request.Method, "OPTIONS"),
	}
	tracked := &trackedRuntimeRequest{request: request, requestURL: event.Request.URL}
	c.active[event.RequestID] = tracked
	c.trackedByKey[runtimeRequestKey(event.RequestID, event.Request.URL)] = tracked
	c.markActivityLocked()
	return true
}

func (c *runtimeCapture) setPostData(requestID network.RequestID, requestURL string, body []byte) {
	if len(body) > apidiscovery.MaxRequestBodyBytes {
		body = body[:apidiscovery.MaxRequestBodyBytes]
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	tracked := c.trackedByKey[runtimeRequestKey(requestID, requestURL)]
	if tracked == nil {
		return
	}
	// RequestWillBeSent can arrive before post data is retrievable. Re-parse the
	// request after the async body fetch finishes, even if the request already
	// moved from active to completed.
	tracked.body = append([]byte(nil), body...)
	data := apidiscovery.ParseRequestData(tracked.request.URL, tracked.request.Headers, tracked.body, true)
	tracked.request.QueryParams = data.QueryParams
	tracked.request.BodyParams = data.Body.Params
	tracked.request.ContentType = data.Body.ContentType
	tracked.request.HasBody = data.Body.HasBody
	tracked.request.BodySample = data.Body.Sample
	tracked.request.GraphQL = data.Body.GraphQL
}

func (c *runtimeCapture) stageName() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stage
}

func (c *runtimeCapture) handleResponse(event *network.EventResponseReceived) {
	if event == nil || event.Response == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	tracked := c.active[event.RequestID]
	if tracked == nil {
		return
	}
	tracked.request.URL = apidiscovery.SanitizeURL(event.Response.URL)
	tracked.request.StatusCode = event.Response.Status
	tracked.request.MimeType = event.Response.MimeType
	data := apidiscovery.ParseRequestData(tracked.request.URL, tracked.request.Headers, tracked.body, tracked.request.HasBody)
	tracked.request.QueryParams = data.QueryParams
	c.markActivityLocked()
}

func (c *runtimeCapture) handleFinished(event *network.EventLoadingFinished) {
	if event == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	tracked := c.active[event.RequestID]
	if tracked == nil {
		return
	}
	tracked.request.Completed = true
	tracked.request.EncodedDataLength = event.EncodedDataLength
	c.completed = append(c.completed, tracked)
	delete(c.active, event.RequestID)
	if countsForIdleString(tracked.request.ResourceType) && c.inFlight > 0 {
		c.inFlight--
	}
	c.markActivityLocked()
}

func (c *runtimeCapture) handleFailed(event *network.EventLoadingFailed) {
	if event == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	tracked := c.active[event.RequestID]
	if tracked == nil {
		return
	}
	tracked.request.Completed = true
	tracked.request.Failed = true
	tracked.request.ErrorText = event.ErrorText
	c.completed = append(c.completed, tracked)
	delete(c.active, event.RequestID)
	if countsForIdleString(tracked.request.ResourceType) && c.inFlight > 0 {
		c.inFlight--
	}
	c.markActivityLocked()
}

func (c *runtimeCapture) handleWebSocketCreated(event *network.EventWebSocketCreated) {
	if event == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	tracked := &trackedRuntimeRequest{request: apidiscovery.RuntimeRequest{
		Version:      apidiscovery.Version,
		RequestID:    string(event.RequestID),
		URL:          apidiscovery.SanitizeURL(event.URL),
		Method:       "GET",
		ResourceType: "WebSocket",
		Stage:        c.stage,
		EntryURL:     c.entryURL,
		QueryParams:  []apidiscovery.Parameter{},
		BodyParams:   []apidiscovery.Parameter{},
		Initiator:    convertInitiator(event.Initiator),
		WebSocket:    true,
	}}
	c.webSockets[event.RequestID] = tracked
	c.completed = append(c.completed, tracked)
	c.markActivityLocked()
}

func (c *runtimeCapture) handleWebSocketHandshakeResponse(event *network.EventWebSocketHandshakeResponseReceived) {
	if event == nil || event.Response == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	tracked := c.webSockets[event.RequestID]
	if tracked == nil {
		return
	}
	tracked.request.StatusCode = event.Response.Status
	tracked.request.Completed = true
	if event.Response.Status != http.StatusSwitchingProtocols {
		tracked.request.Failed = true
		tracked.request.ErrorText = strings.TrimSpace(event.Response.StatusText)
	}
	c.markActivityLocked()
}

func (c *runtimeCapture) snapshot() []apidiscovery.RuntimeRequest {
	c.mu.Lock()
	defer c.mu.Unlock()

	requests := make([]apidiscovery.RuntimeRequest, 0, len(c.completed)+len(c.active))
	for _, tracked := range c.completed {
		requests = append(requests, tracked.request)
	}
	activeIDs := make([]string, 0, len(c.active))
	byID := make(map[string]apidiscovery.RuntimeRequest)
	for requestID, tracked := range c.active {
		id := string(requestID)
		activeIDs = append(activeIDs, id)
		byID[id] = tracked.request
	}
	sort.Strings(activeIDs)
	for _, id := range activeIDs {
		requests = append(requests, byID[id])
	}
	return requests
}

func (c *runtimeCapture) beginPostDataFetch() {
	c.mu.Lock()
	if c.postDataPending == 0 {
		c.postDataIdle = make(chan struct{})
	}
	c.postDataPending++
	c.mu.Unlock()
}

func (c *runtimeCapture) endPostDataFetch() {
	c.mu.Lock()
	if c.postDataPending > 0 {
		c.postDataPending--
		if c.postDataPending == 0 {
			close(c.postDataIdle)
		}
	}
	c.mu.Unlock()
}

func (c *runtimeCapture) waitForPostData(timeout time.Duration) bool {
	c.mu.Lock()
	if c.postDataPending == 0 {
		c.mu.Unlock()
		return true
	}
	idle := c.postDataIdle
	c.mu.Unlock()

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

func (c *runtimeCapture) waitForAPIIdle(ctx context.Context, quiet time.Duration) bool {
	if quiet <= 0 {
		return true
	}
	start := time.Now()
	timer := time.NewTimer(quiet)
	defer timer.Stop()

	for {
		c.mu.Lock()
		inFlight := c.inFlight
		lastActivity := c.lastActivity
		c.mu.Unlock()

		idleSince := lastActivity
		if idleSince.Before(start) {
			idleSince = start
		}
		if inFlight == 0 {
			remaining := quiet - time.Since(idleSince)
			if remaining <= 0 {
				return true
			}
			resetTimer(timer, remaining)
		} else {
			resetTimer(timer, quiet)
		}

		select {
		case <-ctx.Done():
			return false
		case <-c.activity:
		case <-timer.C:
		}
	}
}

func (c *runtimeCapture) markActivityLocked() {
	c.lastActivity = time.Now()
	select {
	case c.activity <- struct{}{}:
	default:
	}
}

func runtimeRequestKey(requestID network.RequestID, requestURL string) string {
	return string(requestID) + "\x00" + requestURL
}

func closedChannel() chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}

func resetTimer(timer *time.Timer, duration time.Duration) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(duration)
}

func isCapturedAPIType(resourceType network.ResourceType) bool {
	switch resourceType {
	case network.ResourceTypeXHR, network.ResourceTypeFetch, network.ResourceTypeEventSource:
		return true
	default:
		return false
	}
}

func countsForIdle(resourceType network.ResourceType) bool {
	return resourceType == network.ResourceTypeXHR || resourceType == network.ResourceTypeFetch
}

func countsForIdleString(resourceType string) bool {
	return strings.EqualFold(resourceType, string(network.ResourceTypeXHR)) ||
		strings.EqualFold(resourceType, string(network.ResourceTypeFetch))
}

func networkHeaders(headers network.Headers) map[string]string {
	if len(headers) == 0 {
		return nil
	}
	out := make(map[string]string, len(headers))
	for name, value := range headers {
		out[name] = fmt.Sprint(value)
	}
	return out
}

func convertInitiator(initiator *network.Initiator) apidiscovery.Initiator {
	if initiator == nil {
		return apidiscovery.Initiator{StackURLs: []string{}}
	}
	stackURLs := make([]string, 0)
	collectStackURLs(initiator.Stack, &stackURLs)
	stackURLs = uniqueStrings(stackURLs)
	return apidiscovery.Initiator{
		Type:      string(initiator.Type),
		URL:       apidiscovery.SanitizeURL(initiator.URL),
		StackURLs: stackURLs,
	}
}

func collectStackURLs(stack *cdpRuntime.StackTrace, urls *[]string) {
	if stack == nil {
		return
	}
	for _, frame := range stack.CallFrames {
		if frame != nil && frame.URL != "" {
			*urls = append(*urls, apidiscovery.SanitizeURL(frame.URL))
		}
	}
	collectStackURLs(stack.Parent, urls)
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	out := make([]string, 0, len(values))
	seen := make(map[string]bool)
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}
