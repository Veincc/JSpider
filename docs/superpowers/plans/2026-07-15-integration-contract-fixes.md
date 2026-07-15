# JSpider Integration Contract Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make canonical-origin policy, entry-specific API provenance, preprocessing deadlines, and programmatic API mode behavior consistent across the entire run.

**Architecture:** Reuse `urlutil.CanonicalOrigin` as the only HTTP(S) authority identity; retain origin-scoped runtimes while giving API entries independent crawl state; propagate one caller-derived processing context through Go and Node preprocessing; bound decoded source-map input at 128 MiB. Preserve normal-mode deduplication, per-origin attempt budgets, atomic output, and existing raw-data behavior.

**Tech Stack:** Go 1.24+ standard library (`context`, `encoding/json`, `net/url`), `golang.org/x/net/idna`, existing tdewolff JavaScript lexer, existing Node worker actor, Go unit/integration/fuzz/race/benchmark tests.

## Global Constraints

- Work only in `/tmp/JSpider-full-audit-remediation` on `codex/full-audit-remediation`; never modify the user's original checkout or its three untracked documents.
- Use RED-GREEN TDD for every behavioral change and commit each task independently.
- `urlutil.CanonicalOrigin` is the sole HTTP(S) same-origin identity; invalid origins fail closed, schemes and non-default ports remain distinct.
- Exact entry URLs remain provenance identities even when their canonical origins match.
- API Discovery uses fresh `queued` and `processed` maps per entry; normal and Headless-only modes retain origin-wide crawl deduplication.
- The per-origin JavaScript-attempt budget remains shared and failed/repeated API-entry attempts count.
- Source-map decoded input is capped at exactly 128 MiB; recovered application sources remain capped at 512 files and 64 MiB aggregate content.
- The caller context and `ProcessTimeoutSeconds` apply before source-map scanning; inferred adjacent probes retain a three-second sub-deadline.
- Timeout/cancellation falls back to the original source and may not confirm an artifact until atomic fallback persistence succeeds.
- `run` applies mode implications to a copy and never mutates the caller's configuration.
- Preserve raw query/header/body behavior, output naming/layout, deterministic ordering, CI/release targets, and the no-push rule.

---

### Task 1: Canonical Origin Policy and API Authority Keys

**Files:**
- Modify: `internal/urlutil/resolve.go:52-72`
- Modify: `internal/urlutil/resolve_test.go:49-81`
- Modify: `internal/fetcher/fetcher_test.go`
- Modify: `internal/headless/headless_test.go`
- Modify: `internal/apidiscovery/match.go:105-205,315-445,765-789`
- Modify: `internal/apidiscovery/match_test.go`
- Modify: `internal/apidiscovery/match_bench_test.go` only if benchmark fixtures encode the old explicit-default-port distinction

**Interfaces:**
- Consumes: `urlutil.CanonicalOrigin(rawURL string) (string, error)`.
- Produces: `urlutil.IsSameOrigin(left, right string) bool` and `urlutil.GetOrigin(raw string) string` with canonical HTTP(S) semantics; `associationCandidateScope` keyed by canonical origin.

- [ ] **Step 1: Add URL RED tests**

Add table rows proving hostname case, explicit default ports, IDNA, and IPv6 canonical equivalence, plus non-default-port and scheme distinction:

```go
func TestIsSameOriginUsesCanonicalHTTPOrigin(t *testing.T) {
	tests := []struct{ left, right string; want bool }{
		{"https://EXAMPLE.com:443/a", "https://example.com/b", true},
		{"http://example.com:80/a", "http://example.com/b", true},
		{"https://bücher.example/a", "https://xn--bcher-kva.example/b", true},
		{"http://[2001:0db8::1]:80/a", "http://[2001:db8::1]/b", true},
		{"https://example.com:444/a", "https://example.com/b", false},
		{"http://example.com/a", "https://example.com/a", false},
	}
	for _, test := range tests {
		if got := IsSameOrigin(test.left, test.right); got != test.want {
			t.Errorf("IsSameOrigin(%q, %q) = %v, want %v", test.left, test.right, got, test.want)
		}
	}
}
```

Also assert `GetOrigin("https://EXAMPLE.com:443/a") == "https://example.com"` and invalid/non-HTTP(S) inputs return empty.

- [ ] **Step 2: Run URL tests and record RED**

Run:

```sh
go test -count=1 ./internal/urlutil -run 'Test(IsSameOriginUsesCanonicalHTTPOrigin|GetOrigin)'
```

Expected: hostname-case/default-port/IDNA cases fail under raw `Scheme`/`Host` comparison.

- [ ] **Step 3: Implement canonical URL helpers**

Replace raw comparison/formatting with:

```go
func IsSameOrigin(left, right string) bool {
	leftOrigin, leftErr := CanonicalOrigin(left)
	rightOrigin, rightErr := CanonicalOrigin(right)
	return leftErr == nil && rightErr == nil && leftOrigin == rightOrigin
}

func GetOrigin(rawURL string) string {
	origin, err := CanonicalOrigin(rawURL)
	if err != nil {
		return ""
	}
	return origin
}
```

- [ ] **Step 4: Add fetcher and Headless RED tests**

Add direct regressions around existing internal helpers:

```go
func TestShouldSendCookiesUsesCanonicalOrigin(t *testing.T) {
	if !shouldSendCookies("https://EXAMPLE.com:443/app.js", "https://example.com/") {
		t.Fatal("canonical same-origin request lost cookies")
	}
}
```

Construct a redirect request whose target is `https://EXAMPLE.com:443/next` and whose policy context entry is `https://example.com/start`; `redirectChecker` must return nil. Add a Headless external-link/click test proving the same pair is internal while `:444` remains external.

- [ ] **Step 5: Run policy tests and record RED, then GREEN**

Run before and after the URL helper change:

```sh
go test -count=1 ./internal/fetcher -run 'Test(ShouldSendCookiesUsesCanonicalOrigin|Redirect.*Canonical)'
go test -count=1 ./internal/headless -run 'Test.*CanonicalOrigin'
```

Expected before: logical same-origin requests are rejected. Expected after: canonical pairs pass and non-default ports remain rejected.

- [ ] **Step 6: Replace API raw authority keys and comparisons**

Change `associationCandidateScope` to store one canonical origin string:

```go
type associationCandidateScope struct {
	kind     associationCandidateScopeKind
	entryURL string
	origin   string
}

func associationAuthorityScope(kind associationCandidateScopeKind, entryURL string, parsed *url.URL) (associationCandidateScope, bool) {
	origin := urlutil.GetOrigin(parsed.String())
	if origin == "" {
		return associationCandidateScope{}, false
	}
	return associationCandidateScope{kind: kind, entryURL: entryURL, origin: origin}, true
}
```

Make runtime index creation skip invalid/non-HTTP(S) authorities. Make static absolute/protocol-relative candidates return no candidates when canonicalization fails. In `associateOne`, compare absolute authorities with `urlutil.IsSameOrigin(staticURL.String(), runtimeURL.String())`. Compute the entry-origin score with canonical `GetOrigin` on both entry and runtime URLs. Remove the now-unused Unicode folding helper/import.

- [ ] **Step 7: Add and run API RED-GREEN tests**

Replace the old explicit-`:443`-is-distinct assertion. Add cases for:

```go
static := StaticEndpoint{RawURL: "https://EXAMPLE.com:443/api/v1/users", Method: "GET"}
runtime := RuntimeRequest{URL: "https://example.com/api/v1/users", Method: "GET", ResourceType: "xhr"}
```

Assert one association, one canonical authority candidate, the entry-origin evidence bonus, and methodless same-origin static-only reportability. Add non-default `:444` controls that do not associate.

Run:

```sh
CGO_ENABLED=1 go test -count=1 ./internal/apidiscovery -run 'Test.*(Authority|Origin|StaticOnly|DefaultPort)'
CGO_ENABLED=1 go test -race -count=1 ./internal/urlutil ./internal/fetcher ./internal/headless ./internal/apidiscovery
```

- [ ] **Step 8: Verify Task 1 and commit**

Run:

```sh
CGO_ENABLED=0 go test -count=1 ./internal/urlutil ./internal/fetcher ./internal/headless ./internal/apidiscovery
CGO_ENABLED=1 go test -count=1 ./internal/urlutil ./internal/fetcher ./internal/headless ./internal/apidiscovery
go vet ./internal/urlutil ./internal/fetcher ./internal/headless ./internal/apidiscovery
git diff --check
```

Commit:

```sh
git add internal/urlutil/resolve.go internal/urlutil/resolve_test.go internal/fetcher/fetcher_test.go internal/headless/headless_test.go internal/apidiscovery/match.go internal/apidiscovery/match_test.go internal/apidiscovery/match_bench_test.go
git commit -m "Use canonical origins across runtime policy"
```

---

### Task 2: Entry-Specific API Provenance and Effective Run Configuration

**Files:**
- Modify: `cmd/jspider/main.go:188-245,263-343,366-412`
- Modify: `cmd/jspider/main_test.go`
- Modify: `cmd/jspider/api_discovery_cgo_test.go`

**Interfaces:**
- Consumes: `config.ApplyModeImplications(*config.Config)`, origin-scoped `siteRuntime`, `apidiscovery.SourceIdentity`.
- Produces: an effective configuration local to `run`; fresh `crawlState` per API entry while normal modes keep `site.state`; a test seam `newAPISession func() apiDiscoverySession` whose production value returns `apidiscovery.NewSession()`.

- [ ] **Step 1: Add programmatic API-mode RED test**

Build a valid config with `APIDiscovery: true` and `Headless: false`, stub `checkBrowserAvailable` and `discoverBrowser`, run one local entry, and assert:

```go
if browserChecks != 1 || browserDiscoveries != 1 {
	t.Fatalf("browser calls = check %d discovery %d, want 1/1", browserChecks, browserDiscoveries)
}
if cfg.Headless {
	t.Fatal("run mutated caller configuration")
}
```

Run `CGO_ENABLED=1 go test -count=1 ./cmd/jspider -run TestRunAppliesAPIModeImplicationWithoutMutatingCaller`; expect RED because browser work is skipped.

- [ ] **Step 2: Apply implications to a copied config**

At the start of `run`, before validation:

```go
effective := *cfg
effective.AllowCDN = append([]string(nil), cfg.AllowCDN...)
effective.Headers = maps.Clone(cfg.Headers)
config.ApplyModeImplications(&effective)
cfg = &effective
```

If avoiding the Go `maps` helper for compatibility, clone headers with an explicit loop. Validate and use only `cfg = &effective` thereafter. Re-run the focused test and expect GREEN.

- [ ] **Step 3: Add same-origin multi-entry API provenance RED test**

Use one `httptest.Server` with `/first`, `/second`, and shared `/app.js`. Stub browser discovery so only `/second` returns a runtime XHR matching a relative API in `/app.js`. Configure a URL-list containing both entries and API Discovery enabled. Assert:

```go
if got := session.Stats(firstURL).Sources; got != 1 { t.Fatalf("first sources = %d", got) }
if got := session.Stats(secondURL).Sources; got != 1 { t.Fatalf("second sources = %d", got) }
if len(report.Associations) != 1 { t.Fatalf("associations = %d", len(report.Associations)) }
if report.Associations[0].EntryURL != secondURL { t.Fatalf("association entry = %q", report.Associations[0].EntryURL) }
```

Add the production seam and use it in `newSiteRuntime`:

```go
var newAPISession = func() apiDiscoverySession { return apidiscovery.NewSession() }

// In newSiteRuntime:
if cfg.APIDiscovery {
	site.apiSession = newAPISession()
}
```

The test temporarily replaces `newAPISession` with a function returning its captured session and restores it with `t.Cleanup`. Also assert the shared script is requested twice in API mode and both attempts count toward the origin budget.

- [ ] **Step 4: Run provenance test and record RED**

Run:

```sh
CGO_ENABLED=1 go test -count=1 ./cmd/jspider -run TestRunSameOriginEntriesRetainAPIProvenance
```

Expected: second entry has zero sources and no association because origin-wide `queued` suppresses the shared script.

- [ ] **Step 5: Select crawl state per entry**

Before calling `analyzeEntryContext`:

```go
entryState := site.state
if cfg.APIDiscovery {
	entryState = &crawlState{queued: make(map[string]bool), processed: make(map[string]bool)}
}
```

Pass `entryState.queued` and `entryState.processed`. Keep `site.attempts`, `site.analyzed`, processor, store, and session shared. Do not reset the attempt counter or processor content references.

- [ ] **Step 6: Preserve normal-mode deduplication**

Extend `TestCrawlStateIsSharedWithinSiteOnly` or add a runner test proving two same-origin normal-mode entries sharing `/app.js` fetch it once, while the API-mode integration test fetches it once per entry. Run both focused tests and expect GREEN.

- [ ] **Step 7: Verify Task 2 and commit**

Run:

```sh
CGO_ENABLED=0 go test -count=1 ./cmd/jspider
CGO_ENABLED=1 go test -count=1 ./cmd/jspider
CGO_ENABLED=1 go test -race -count=1 ./cmd/jspider
go vet ./cmd/jspider
git diff --check
```

Commit:

```sh
git add cmd/jspider/main.go cmd/jspider/main_test.go cmd/jspider/api_discovery_cgo_test.go
git commit -m "Preserve API provenance for every entry"
```

---

### Task 3: Context-Bounded Source-Map and Worker Processing

**Files:**
- Create: `internal/preprocess/deadline.go`
- Create: `internal/preprocess/deadline_test.go`
- Modify: `internal/preprocess/preprocess.go:38-185,235-583`
- Modify: `internal/preprocess/preprocess_test.go`
- Modify: `internal/preprocess/worker.go:15-266`
- Modify: `cmd/jspider/main.go:58-61,693-752`
- Modify: `cmd/jspider/output_test.go` and other processor fakes that implement `javaScriptProcessor`
- Modify: `internal/preprocess/sourcemap_fuzz_test.go`

**Interfaces:**
- Produces: `(*preprocess.Processor).ProcessContext(ctx context.Context, entryURL, jsURL string, body []byte) FileResult`.
- Retains: `Process(entryURL, jsURL string, body []byte) FileResult` as a background-context compatibility wrapper.
- Produces internally: context-aware JSON/data-URL helpers and `(*workerActor).processContext(context.Context, []byte)`.

- [ ] **Step 1: Add caller-cancellation and timeout RED tests**

Add tests that create a processor with a controlled fake Node worker/fetcher and assert:

```go
ctx, cancel := context.WithCancel(context.Background())
cancel()
started := time.Now()
result := processor.ProcessContext(ctx, entryURL, jsURL, bundle)
if time.Since(started) > 500*time.Millisecond { t.Fatal("canceled processing did not return promptly") }
if !result.Failed || len(result.Analysis) != 1 { t.Fatalf("result = %+v", result) }
```

Add a declared-map fetch that blocks until `ctx.Done()`, a nested section fetch with the same behavior, and a Node response that blocks. Assert each returns original analysis, writes an original fallback, and does not leave a confirmed recovered result.

- [ ] **Step 2: Run deadline tests and record RED**

Run:

```sh
go test -count=1 ./internal/preprocess -run 'TestProcessContext.*(Cancel|Timeout|Nested|Worker)'
```

Expected: `ProcessContext` is absent or cancellation is ignored by Go-side work/worker submission.

- [ ] **Step 3: Add bounded decoding helpers**

Create `deadline.go` with exact bounds and context reader:

```go
const maxSourceMapInputBytes = 128 << 20

var errSourceMapTooLarge = fmt.Errorf("source map exceeds %d-byte input limit", maxSourceMapInputBytes)

type contextReader struct {
	ctx context.Context
	r   *bytes.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil { return 0, err }
	return r.r.Read(p)
}

func decodeSourceMapJSON(ctx context.Context, data []byte, target any) error {
	if len(data) > maxSourceMapInputBytes { return errSourceMapTooLarge }
	decoder := json.NewDecoder(contextReader{ctx: ctx, r: bytes.NewReader(data)})
	if err := decoder.Decode(target); err != nil { return err }
	if err := ctx.Err(); err != nil { return err }
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil { return errors.New("multiple source-map JSON values") }
		return err
	}
	return nil
}
```

Add a percent-decoded-length scanner that validates `%XX` escapes without allocating, and check `base64.StdEncoding.DecodedLen` before decoding. Check the final decoded slice again.

- [ ] **Step 4: Add 128 MiB boundary RED-GREEN tests without allocating oversized payloads unnecessarily**

Test the length-check helpers directly at `maxSourceMapInputBytes`, `maxSourceMapInputBytes+1`, and base64/percent encoded equivalents. For fetched maps, use a `make([]byte, maxSourceMapInputBytes+1)` only in one serial test, assert fallback, and release it before other memory-heavy tests. Verify exact-bound minimal JSON reaches parsing rather than returning `errSourceMapTooLarge`.

Run `go test -count=1 ./internal/preprocess -run 'Test(SourceMapInputLimit|DecodeDataURLLimit)'` and expect GREEN after helpers are wired.

- [ ] **Step 5: Thread context through source-map scanning and traversal**

Implement `extractSourceMapReferenceContext(ctx, body []byte) (string, error)` with the existing lexer and a context check before every token. Change resolver methods to return `(sourceMapCollection, error)`, check `ctx.Err()` at entry and in every sources/sections loop, and use `decodeSourceMapJSON` for envelopes, arrays, and offsets. Propagate only context/size errors; malformed JSON remains an incomplete recovery.

Wrap slot-owned recovery in a buffered result channel:

```go
type sourceMapAttemptResult struct {
	recovery sourceMapRecovery
	err      error
}

func runSourceMapAttempt(ctx context.Context, work func(context.Context) (sourceMapRecovery, error)) (sourceMapRecovery, error) {
	select {
	case sourceMapWorkSlots <- struct{}{}:
	case <-ctx.Done():
		return sourceMapRecovery{}, ctx.Err()
	}
	result := make(chan sourceMapAttemptResult, 1)
	go func() {
		defer func() { <-sourceMapWorkSlots }()
		recovery, err := work(ctx)
		result <- sourceMapAttemptResult{recovery: recovery, err: err}
	}()
	select {
	case got := <-result:
		return got.recovery, got.err
	case <-ctx.Done():
		return sourceMapRecovery{}, ctx.Err()
	}
}
```

Change recovery to `recoverSourceMap(ctx context.Context, entryURL, jsURL, reference string) (location, status string, recovery sourceMapRecovery, err error)` and add the bundle wrapper:

```go
func (p *Processor) recoverForBundle(ctx context.Context, entryURL, jsURL string, body []byte) (sourceMapRecovery, error) {
	return runSourceMapAttempt(ctx, func(operationContext context.Context) (sourceMapRecovery, error) {
		reference, err := extractSourceMapReferenceContext(operationContext, body)
		if err != nil { return sourceMapRecovery{}, err }
		mapContext := operationContext
		cancel := func() {}
		if reference == "" {
			mapContext, cancel = context.WithTimeout(operationContext, 3*time.Second)
		}
		defer cancel()
		_, _, recovery, err := p.recoverSourceMap(mapContext, entryURL, jsURL, reference)
		if reference == "" && errors.Is(err, context.DeadlineExceeded) && operationContext.Err() == nil {
			return sourceMapRecovery{}, nil
		}
		return recovery, err
	})
}
```

The worker must observe the canceled context and release the slot; tests must wait for and assert slot availability before completion.

- [ ] **Step 6: Implement one operation context and fallback behavior**

Implement:

```go
func (p *Processor) Process(entryURL, jsURL string, body []byte) FileResult {
	return p.ProcessContext(context.Background(), entryURL, jsURL, body)
}

func (p *Processor) ProcessContext(parent context.Context, entryURL, jsURL string, body []byte) FileResult {
	if parent == nil { parent = context.Background() }
	ctx, cancel := context.WithTimeout(parent, p.processTimeout)
	defer cancel()

	result := FileResult{Analysis: originalAnalysis(jsURL, body), Outputs: []string{}}
	recovery, recoveryErr := p.recoverForBundle(ctx, entryURL, jsURL, body)
	if recoveryErr != nil {
		return p.recordFailure(jsURL, body, recoveryErr.Error())
	}
	outputs := make([]string, 0, len(recovery.Files))
	for _, source := range recovery.Files {
		if err := ctx.Err(); err != nil {
			return p.recordFailureWithOutputs(jsURL, body, err.Error(), outputs)
		}
		rel, err := p.writeSource(source.OutputPath, []byte(source.Content))
		if err != nil {
			return p.recordFailureWithOutputs(jsURL, body, fmt.Sprintf("write recovered source: %v", err), outputs)
		}
		if !contains(outputs, rel) { outputs = append(outputs, rel) }
	}
	if len(outputs) > 0 {
		sort.Strings(outputs)
		result.Status, result.Outputs = "sourcemap", outputs
		if recovery.Complete { result.Analysis = recoveredAnalysis(jsURL, recovery.Files) }
		return result
	}

	code, err := p.actor.processContext(ctx, body)
	if err != nil { return p.recordFailure(jsURL, body, err.Error()) }
	if len(code) == 0 { code = body }
	rel, err := p.writeGenerated(jsURL, ".js", code)
	if err != nil { return p.recordFailure(jsURL, body, fmt.Sprintf("write processed bundle: %v", err)) }
	result.Status, result.Outputs = "processed", []string{rel}
	return result
}
```

Use `context.WithTimeout(ctx, 3*time.Second)` only for an inferred adjacent probe. If that sub-deadline expires while the enclosing context is still live, continue to Node processing with the enclosing context's remaining time. If the enclosing context is done, persist the original fallback immediately.

- [ ] **Step 7: Make the Node actor context-aware**

Add `ctx context.Context` to `actorRequest`. `submit` must select `ctx.Done()` both while enqueueing and waiting. `run` computes the exchange timeout as the smaller of `processTimeout` and the context deadline's remaining duration. `nodeWorker.exchange` selects a distinct context-done channel and kills the worker on cancellation so the next request lazily restarts it.

Retain `process(source)` as `processContext(context.Background(), source)`. Add RED-GREEN tests for cancellation while queued, during encode/decode exchange, and successful lazy restart.

- [ ] **Step 8: Pass the run context to preprocessing**

Change the command interface and call:

```go
type javaScriptProcessor interface {
	ProcessContext(context.Context, string, string, []byte) preprocess.FileResult
	Close() error
}

prepResult := prep.ProcessContext(ctx, entryURL, finalURL, res.result.Body)
```

Thread `ctx` into `analyzeResultWithPreprocess`. Update every test fake with a context-aware method; concrete processor callers may continue using `Process`.

- [ ] **Step 9: Add race/lifecycle and fuzz assertions**

Assert no post-timeout recovered-source writes, the four-slot maximum, eventual slot release, Close during cancellation, and restart after a killed Node worker. Extend `FuzzParseApplicationSourceMap` to exercise the context-aware parser wrapper while retaining the 2 MiB fuzz input cap.

- [ ] **Step 10: Verify Task 3 and commit**

Run:

```sh
go test -count=1 ./internal/preprocess ./cmd/jspider
go test -race -count=1 ./internal/preprocess ./cmd/jspider
CGO_ENABLED=0 go test -count=1 ./internal/preprocess ./cmd/jspider
CGO_ENABLED=1 go test -count=1 ./internal/preprocess ./cmd/jspider
go vet ./internal/preprocess ./cmd/jspider
git diff --check
```

Commit:

```sh
git add internal/preprocess/deadline.go internal/preprocess/deadline_test.go internal/preprocess/preprocess.go internal/preprocess/preprocess_test.go internal/preprocess/worker.go internal/preprocess/sourcemap_fuzz_test.go cmd/jspider/main.go cmd/jspider/main_test.go cmd/jspider/output_test.go
git commit -m "Bound preprocessing by caller context"
```

---

### Task 4: Documentation, Performance Guard, and Final Integration Gate

**Files:**
- Modify: `README.md`
- Modify: `internal/config/config.go`
- Create untracked: `.superpowers/sdd/integration-contract-fixes-report.md`

**Interfaces:**
- Consumes all Task 1-3 behavior.
- Produces truthful user-facing limits and final evidence for the full `origin/main..HEAD` branch.

- [ ] **Step 1: Update documentation**

Document that the processing timeout begins before source-map scanning, caller cancellation is propagated, inferred adjacent probing has a three-second sub-deadline, and decoded source-map input has a 128 MiB hard cap separate from the 512-file/64 MiB recovery caps. State that API mode may refetch a shared script once per entry and all such attempts count against the per-origin `-n` budget.

Add the same compact facts to CLI `Behavior and limits` output and extend `TestUsageDocumentsBehaviorAndLimits` with exact substrings.

- [ ] **Step 2: Run documentation RED-GREEN test**

Run:

```sh
go test -count=1 ./internal/config -run TestUsageDocumentsBehaviorAndLimits
go run ./cmd/jspider -h
```

Expected: test fails before help changes, then passes and rendered help states all new limits.

- [ ] **Step 3: Run complete fresh verification**

Run in a loopback-capable environment:

```sh
CGO_ENABLED=0 go test -count=1 ./...
CGO_ENABLED=1 go test -count=1 ./...
CGO_ENABLED=1 go test -race -count=1 ./...
CGO_ENABLED=0 go vet ./...
CGO_ENABLED=1 go vet ./...
CGO_ENABLED=0 go build ./...
CGO_ENABLED=1 go build ./...
GOCACHE=/tmp/jspider-final-gocache go mod tidy -diff
git diff origin/main..HEAD --check
```

- [ ] **Step 4: Re-run coverage, fuzz, and performance gates**

Run:

```sh
CGO_ENABLED=1 go test -covermode=atomic -coverprofile=/tmp/jspider-integration-final-cover.out -count=1 ./...
go tool cover -func=/tmp/jspider-integration-final-cover.out
go test ./internal/analyzer -run '^$' -bench '^BenchmarkAnalyzerDiscoverJS$' -benchmem -benchtime=500ms -count=10 -cpu=1
go test ./internal/apidiscovery -run '^$' -bench '^Benchmark' -benchmem -benchtime=1x -count=1
go test ./internal/html -run '^$' -fuzz '^FuzzExtractEntryJS$' -fuzztime=10s
go test ./internal/urlutil -run '^$' -fuzz '^FuzzResolveAndCanonicalOrigin$' -fuzztime=10s
go test ./internal/preprocess -run '^$' -fuzz '^FuzzParseApplicationSourceMap$' -fuzztime=10s
go test ./internal/apidiscovery -run '^$' -fuzz '^FuzzParseRequestData$' -fuzztime=10s
```

Coverage must be at least 69.0%. Re-run the identical detached-base analyzer harness and official pinned `benchstat`; 1 MiB B/op must remain at least 25% below base with no statistically significant CPU regression.

- [ ] **Step 5: Validate workflows and release portability**

Parse both YAML files, assert the exact six unique native CGO release targets and action majors, build all six CGO-disabled portability binaries plus the host-native CGO-enabled binary into `/tmp`, inspect with `file`, and generate SHA-256 checksums. Report that only hosted runners can prove the other five native CGO builds.

- [ ] **Step 6: Commit documentation**

```sh
git add README.md internal/config/config.go internal/config/config_test.go
git commit -m "Document preprocessing and provenance limits"
```

- [ ] **Step 7: Write evidence and run final review**

Write `.superpowers/sdd/integration-contract-fixes-report.md` with RED/GREEN evidence, commit hashes, commands/results, coverage, benchmark math, fuzz counts, release limitations, and final status. Keep it untracked. Generate a formal review package from `975f6e3` to final HEAD for the integration fixes, then a full `origin/main..HEAD` package. Resolve every Critical/Important finding and repeat review until both verdicts are approved.

- [ ] **Step 8: Finish branch**

Confirm `git status --short` contains only `.superpowers/`, detect base/worktree state, and use the finishing-development-branch workflow. Do not merge, push, create a PR, discard, or remove the worktree without the user's selected completion option.
