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
	order      uint64
	startedAt  time.Time
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
	trackedByKey      map[string]*trackedRuntimeRequest
	latestByRequestID map[network.RequestID]*trackedRuntimeRequest
	redirectCounts    map[network.RequestID]int
	webSockets        map[network.RequestID]*trackedRuntimeRequest
	inFlight          int
	lastActivity      time.Time
	activity          chan struct{}
	postDataPending   int
	postDataIdle      chan struct{}
	postDataQueue     []postDataJob
	postDataWake      chan struct{}
	postDataCtx       context.Context
	postDataCancel    context.CancelFunc
	postDataWorkers   sync.WaitGroup
	postDataWatcher   sync.WaitGroup
	postDataAccepting bool
	postDataFetcher   requestPostDataFetcher
	postDataError     func(string, error)
	nextOrder         uint64
}

type postDataJob struct {
	requestID  network.RequestID
	requestURL string
	tracked    *trackedRuntimeRequest
}

type requestPostDataFetcher func(context.Context, network.RequestID) ([]byte, error)

const (
	networkQuietRequestMaxAge   = 5 * time.Second
	postDataWorkerCount         = 4
	postDataQueueCapacity       = 4
	postDataOutstandingCapacity = postDataWorkerCount + postDataQueueCapacity
)

func newRuntimeCapture(entryURL string) *runtimeCapture {
	return &runtimeCapture{
		entryURL:          apidiscovery.SanitizeURL(entryURL),
		stage:             "navigate",
		active:            make(map[network.RequestID]*trackedRuntimeRequest),
		trackedByKey:      make(map[string]*trackedRuntimeRequest),
		latestByRequestID: make(map[network.RequestID]*trackedRuntimeRequest),
		redirectCounts:    make(map[network.RequestID]int),
		webSockets:        make(map[network.RequestID]*trackedRuntimeRequest),
		lastActivity:      time.Now(),
		activity:          make(chan struct{}, 1),
		postDataIdle:      closedChannel(),
		postDataWake:      make(chan struct{}, postDataWorkerCount),
	}
}

func (c *runtimeCapture) setStage(stage string) {
	c.mu.Lock()
	c.stage = stage
	c.mu.Unlock()
}

func (c *runtimeCapture) handleRequest(event *network.EventRequestWillBeSent) *trackedRuntimeRequest {
	if event == nil || event.Request == nil || !isCapturedAPIType(event.Type) {
		return nil
	}

	headers := networkHeaders(event.Request.Headers)
	// The request event only tells us that post data exists; its bytes arrive
	// asynchronously through Network.getRequestPostData. Parsing a nil body as
	// JSON here would fabricate an EOF error when Chrome cannot return the data.
	data := apidiscovery.ParseRequestData(event.Request.URL, headers, nil, false)

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
		Version:        apidiscovery.Version,
		RequestID:      string(event.RequestID),
		RedirectIndex:  redirectIndex,
		URL:            apidiscovery.SanitizeURL(event.Request.URL),
		Method:         strings.ToUpper(event.Request.Method),
		ResourceType:   string(event.Type),
		Stage:          c.stage,
		EntryURL:       c.entryURL,
		DocumentURL:    apidiscovery.SanitizeURL(event.DocumentURL),
		Headers:        data.Headers,
		QueryParams:    data.QueryParams,
		BodyParams:     data.Body.Params,
		ContentType:    data.Body.ContentType,
		HasBody:        event.Request.HasPostData,
		BodyTruncated:  data.Body.Truncated,
		BodyParseError: data.Body.ParseError,
		BodySample:     data.Body.Sample,
		GraphQL:        data.Body.GraphQL,
		Initiator:      convertInitiator(event.Initiator),
		RedirectFrom:   redirectFrom,
		Preflight:      strings.EqualFold(event.Request.Method, "OPTIONS"),
	}
	tracked := &trackedRuntimeRequest{
		request:    request,
		requestURL: event.Request.URL,
		order:      c.nextOrder,
		startedAt:  time.Now(),
	}
	c.nextOrder++
	c.active[event.RequestID] = tracked
	if event.Request.HasPostData {
		c.latestByRequestID[event.RequestID] = tracked
		c.trackedByKey[runtimeRequestKey(event.RequestID, event.Request.URL)] = tracked
	} else {
		// A bodyless redirect hop invalidates any older post-data token that
		// reused this CDP request ID without retaining a useless generation.
		delete(c.latestByRequestID, event.RequestID)
	}
	c.markActivityLocked()
	return tracked
}

func (c *runtimeCapture) setPostData(requestID network.RequestID, requestURL string, body []byte) {
	c.mu.Lock()
	key := runtimeRequestKey(requestID, requestURL)
	tracked := c.trackedByKey[key]
	c.mu.Unlock()
	defer c.releasePostDataLookupForTracked(requestID, requestURL, tracked)
	c.setPostDataForTracked(requestID, requestURL, tracked, body)
}

func (c *runtimeCapture) setPostDataForTracked(requestID network.RequestID, requestURL string, tracked *trackedRuntimeRequest, body []byte) {
	if tracked == nil {
		return
	}
	c.mu.Lock()
	key := runtimeRequestKey(requestID, requestURL)
	if c.trackedByKey[key] != tracked || c.latestByRequestID[requestID] != tracked {
		c.mu.Unlock()
		return
	}
	request := tracked.request
	request.Headers = cloneHeaders(tracked.request.Headers)
	c.mu.Unlock()

	// RequestWillBeSent can arrive before post data is retrievable. Re-parse the
	// request after the async body fetch finishes, even if the request already
	// moved from active to completed.
	data := apidiscovery.ParseRequestData(request.URL, request.Headers, body, true)

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.trackedByKey[key] != tracked || c.latestByRequestID[requestID] != tracked {
		return
	}
	tracked.request.BodyParams = data.Body.Params
	tracked.request.ContentType = data.Body.ContentType
	tracked.request.HasBody = data.Body.HasBody
	tracked.request.BodyTruncated = data.Body.Truncated
	tracked.request.BodyParseError = data.Body.ParseError
	tracked.request.BodySample = data.Body.Sample
	tracked.request.GraphQL = data.Body.GraphQL
	c.releasePostDataLookupLocked(requestID, requestURL, tracked)
}

func (c *runtimeCapture) releasePostDataLookup(requestID network.RequestID, requestURL string) {
	c.mu.Lock()
	key := runtimeRequestKey(requestID, requestURL)
	tracked := c.trackedByKey[key]
	c.releasePostDataLookupLocked(requestID, requestURL, tracked)
	c.mu.Unlock()
}

func (c *runtimeCapture) releasePostDataLookupForTracked(requestID network.RequestID, requestURL string, tracked *trackedRuntimeRequest) {
	c.mu.Lock()
	c.releasePostDataLookupLocked(requestID, requestURL, tracked)
	c.mu.Unlock()
}

func (c *runtimeCapture) releasePostDataLookupLocked(requestID network.RequestID, requestURL string, tracked *trackedRuntimeRequest) {
	if tracked == nil {
		return
	}
	key := runtimeRequestKey(requestID, requestURL)
	if c.trackedByKey[key] == tracked {
		delete(c.trackedByKey, key)
	}
	if c.latestByRequestID[requestID] == tracked {
		delete(c.latestByRequestID, requestID)
	}
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
	sanitizedURL := apidiscovery.SanitizeURL(event.Response.URL)
	queryParams := apidiscovery.ParseRequestData(sanitizedURL, nil, nil, false).QueryParams
	c.mu.Lock()
	defer c.mu.Unlock()
	tracked := c.active[event.RequestID]
	if tracked == nil {
		return
	}
	tracked.request.URL = sanitizedURL
	tracked.request.StatusCode = event.Response.Status
	tracked.request.MimeType = event.Response.MimeType
	tracked.request.QueryParams = queryParams
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
	}, order: c.nextOrder, startedAt: time.Now()}
	c.nextOrder++
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

	trackedRequests := make([]*trackedRuntimeRequest, 0, len(c.completed)+len(c.active))
	trackedRequests = append(trackedRequests, c.completed...)
	for _, tracked := range c.active {
		trackedRequests = append(trackedRequests, tracked)
	}
	sort.Slice(trackedRequests, func(i, j int) bool {
		if trackedRequests[i].order != trackedRequests[j].order {
			return trackedRequests[i].order < trackedRequests[j].order
		}
		if trackedRequests[i].request.RequestID != trackedRequests[j].request.RequestID {
			return trackedRequests[i].request.RequestID < trackedRequests[j].request.RequestID
		}
		return trackedRequests[i].request.RedirectIndex < trackedRequests[j].request.RedirectIndex
	})
	requests := make([]apidiscovery.RuntimeRequest, 0, len(trackedRequests))
	for _, tracked := range trackedRequests {
		requests = append(requests, tracked.request)
	}
	return requests
}

func (c *runtimeCapture) startPostDataWorkers(ctx context.Context, fetcher requestPostDataFetcher, reportError func(string, error)) {
	c.mu.Lock()
	c.postDataCtx, c.postDataCancel = context.WithCancel(ctx)
	c.postDataFetcher = fetcher
	c.postDataError = reportError
	c.postDataAccepting = true
	c.postDataQueue = make([]postDataJob, 0, postDataQueueCapacity)
	c.mu.Unlock()

	for range postDataWorkerCount {
		c.postDataWorkers.Add(1)
		go c.runPostDataWorker()
	}
	c.postDataWatcher.Add(1)
	go func() {
		defer c.postDataWatcher.Done()
		<-c.postDataCtx.Done()
		c.shutdownPostDataAdmission()
	}()
}

func (c *runtimeCapture) stopPostDataWorkers() {
	c.mu.Lock()
	cancel := c.postDataCancel
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	c.shutdownPostDataAdmission()
	c.postDataWatcher.Wait()
	c.postDataWorkers.Wait()
}

func (c *runtimeCapture) shutdownPostDataAdmission() {
	c.mu.Lock()
	c.postDataAccepting = false
	for _, job := range c.postDataQueue {
		c.releasePostDataLookupLocked(job.requestID, job.requestURL, job.tracked)
	}
	dropped := len(c.postDataQueue)
	clear(c.postDataQueue)
	c.postDataQueue = nil
	if dropped >= c.postDataPending {
		c.postDataPending = 0
	} else {
		c.postDataPending -= dropped
	}
	c.signalPostDataIdleLocked()
	c.mu.Unlock()
	for range postDataWorkerCount {
		c.wakePostDataWorker()
	}
}

func (c *runtimeCapture) enqueuePostDataFetch(requestID network.RequestID, requestURL string, tracked *trackedRuntimeRequest) bool {
	c.mu.Lock()
	key := runtimeRequestKey(requestID, requestURL)
	ctx := c.postDataCtx
	if tracked == nil || c.trackedByKey[key] != tracked || c.latestByRequestID[requestID] != tracked ||
		!c.postDataAccepting || ctx == nil || ctx.Err() != nil ||
		len(c.postDataQueue) >= postDataQueueCapacity || c.postDataPending >= postDataOutstandingCapacity {
		c.releasePostDataLookupLocked(requestID, requestURL, tracked)
		c.mu.Unlock()
		return false
	}
	if c.postDataPending == 0 {
		c.postDataIdle = make(chan struct{})
	}
	c.postDataPending++
	c.postDataQueue = append(c.postDataQueue, postDataJob{requestID: requestID, requestURL: requestURL, tracked: tracked})
	c.mu.Unlock()
	c.wakePostDataWorker()
	return true
}

func (c *runtimeCapture) wakePostDataWorker() {
	select {
	case c.postDataWake <- struct{}{}:
	default:
	}
}

func (c *runtimeCapture) runPostDataWorker() {
	defer c.postDataWorkers.Done()
	for {
		job, ok := c.nextPostDataJob()
		if !ok {
			return
		}
		c.processPostDataJob(job)
	}
}

func (c *runtimeCapture) nextPostDataJob() (postDataJob, bool) {
	for {
		c.mu.Lock()
		ctx := c.postDataCtx
		if ctx == nil || ctx.Err() != nil || !c.postDataAccepting {
			c.mu.Unlock()
			return postDataJob{}, false
		}
		if len(c.postDataQueue) > 0 {
			job := c.postDataQueue[0]
			c.postDataQueue[0] = postDataJob{}
			c.postDataQueue = c.postDataQueue[1:]
			c.mu.Unlock()
			return job, true
		}
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return postDataJob{}, false
		case <-c.postDataWake:
		}
	}
}

func (c *runtimeCapture) processPostDataJob(job postDataJob) {
	defer c.endPostDataFetch()
	defer c.releasePostDataLookupForTracked(job.requestID, job.requestURL, job.tracked)
	c.mu.Lock()
	ctx, fetcher, reportError := c.postDataCtx, c.postDataFetcher, c.postDataError
	c.mu.Unlock()
	if ctx == nil || fetcher == nil {
		return
	}
	body, err := fetcher(ctx, job.requestID)
	if err != nil || ctx.Err() != nil {
		if err != nil && reportError != nil && ctx.Err() == nil {
			reportError(job.requestURL, err)
		}
		return
	}
	if len(body) > apidiscovery.MaxRequestBodyBytes+1 {
		body = body[:apidiscovery.MaxRequestBodyBytes+1]
	}
	c.setPostDataForTracked(job.requestID, job.requestURL, job.tracked, body)
}

func (c *runtimeCapture) endPostDataFetch() {
	c.mu.Lock()
	if c.postDataPending > 0 {
		c.postDataPending--
	}
	c.signalPostDataIdleLocked()
	c.mu.Unlock()
}

func (c *runtimeCapture) signalPostDataIdleLocked() {
	if c.postDataPending != 0 {
		return
	}
	select {
	case <-c.postDataIdle:
	default:
		close(c.postDataIdle)
	}
}

func (c *runtimeCapture) waitForPostDataContext(ctx context.Context) bool {
	if ctx.Err() != nil {
		return false
	}
	c.mu.Lock()
	if c.postDataPending == 0 {
		c.mu.Unlock()
		return true
	}
	idle := c.postDataIdle
	c.mu.Unlock()
	select {
	case <-idle:
		return ctx.Err() == nil
	case <-ctx.Done():
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
		inFlight, nextExpiry := c.idleBlockersLocked(time.Now())
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
			wait := quiet
			if nextExpiry > 0 && nextExpiry < wait {
				wait = nextExpiry
			}
			resetTimer(timer, wait)
		}

		select {
		case <-ctx.Done():
			return false
		case <-c.activity:
		case <-timer.C:
		}
	}
}

func (c *runtimeCapture) idleBlockersLocked(now time.Time) (int, time.Duration) {
	blockers := 0
	var nextExpiry time.Duration
	for _, tracked := range c.active {
		if !countsForIdleString(tracked.request.ResourceType) {
			continue
		}
		age := now.Sub(tracked.startedAt)
		if age >= networkQuietRequestMaxAge {
			continue
		}
		blockers++
		untilExpiry := networkQuietRequestMaxAge - age
		if nextExpiry == 0 || untilExpiry < nextExpiry {
			nextExpiry = untilExpiry
		}
	}
	return blockers, nextExpiry
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

func cloneHeaders(headers map[string]string) map[string]string {
	if len(headers) == 0 {
		return nil
	}
	out := make(map[string]string, len(headers))
	for name, value := range headers {
		out[name] = value
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
