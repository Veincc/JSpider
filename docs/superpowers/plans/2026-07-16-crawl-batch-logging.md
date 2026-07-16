# Crawl Batch Logging Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make recursive crawl work visible with one fixed summary line per completed batch and classify expected non-JavaScript responses separately from real fetch failures.

**Architecture:** Preserve the existing ordered breadth-first downloader and serial analyzer. Add a typed fetch validation error, a focused progress/accounting unit in the `main` package, and writer injection for deterministic log tests; the serial result consumer owns all counters, so crawl ordering and synchronization do not change.

**Tech Stack:** Go 1.24, standard library `errors`, `io`, `time`, `httptest`, existing JSpider fetcher/analyzer/preprocessor.

## Global Constraints

- Emit one durable normal-level log line after each crawl batch completes.
- Count rejected non-JavaScript responses separately from actual download failures.
- Preserve deterministic crawling, default recursion depth, fetch limits, output content, and discovery coverage.
- Keep per-resource URLs and detailed decisions in verbose logging.
- Do not add a dynamic terminal progress display, quick mode, new dependency, or parallel preprocessing path.
- Do not suppress network, HTTP, cancellation, persistence, or processing failures.

---

## File Structure

- `internal/fetcher/fetcher.go`: define and return a stable typed error for content rejected as non-JavaScript.
- `internal/fetcher/fetcher_test.go`: prove classification without relying on error text.
- `internal/logging/logging.go`: route logger output through injected writers while retaining the existing constructor behavior.
- `internal/logging/logging_test.go`: prove info/verbose and warning/error routing.
- `cmd/jspider/progress.go`: own entry prefixes, duration formatting, depth ranges, and batch counters.
- `cmd/jspider/progress_test.go`: unit-test accounting and formatting independently of network timing.
- `cmd/jspider/main.go`: integrate discovery, batch, rejection, and completion logging into the existing crawl.
- `cmd/jspider/main_test.go`: integration-test mixed batch output and normal/verbose non-JavaScript behavior.

### Task 1: Stable non-JavaScript fetch classification

**Files:**
- Modify: `internal/fetcher/fetcher.go:1-365`
- Test: `internal/fetcher/fetcher_test.go:495-597`

**Interfaces:**
- Consumes: existing `validateJSResult(*Result, string) *Result` validation path.
- Produces: `type ErrNotJavaScript struct { ContentType string }` and `func IsNotJavaScript(error) bool` for crawl accounting.

- [ ] **Step 1: Write the failing classification tests**

Add `errors.As` assertions to the explicit-content-type and missing-content-type tests, and prove unrelated failures are not misclassified:

```go
func TestFetchJSNonJavaScriptErrorsAreClassifiable(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
	}{
		{name: "explicit JSON", contentType: "application/json", body: `{"ok":true}`},
		{name: "missing content type", body: `{"ok":true}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tt.contentType == "" {
					w.Header()["Content-Type"] = nil
				} else {
					w.Header().Set("Content-Type", tt.contentType)
				}
				_, _ = io.WriteString(w, tt.body)
			}))
			defer ts.Close()

			result := newTestFetcher(t, ts).FetchJS(ts.URL + "/candidate")
			var rejected *ErrNotJavaScript
			if !errors.As(result.Err, &rejected) || !IsNotJavaScript(result.Err) {
				t.Fatalf("FetchJS() error = %T %v, want ErrNotJavaScript", result.Err, result.Err)
			}
			if rejected.ContentType != tt.contentType {
				t.Fatalf("ContentType = %q, want %q", rejected.ContentType, tt.contentType)
			}
		})
	}

	if IsNotJavaScript(context.DeadlineExceeded) {
		t.Fatal("deadline error classified as non-JavaScript")
	}
}
```

- [ ] **Step 2: Run the focused test and verify RED**

Run:

```bash
go test ./internal/fetcher -run TestFetchJSNonJavaScriptErrorsAreClassifiable -count=1
```

Expected: compilation fails because `ErrNotJavaScript` and `IsNotJavaScript` do not exist.

- [ ] **Step 3: Implement the typed error and classification helper**

Add the standard `errors` import and this type near `ErrDecompressTooLarge`:

```go
type ErrNotJavaScript struct {
	ContentType string
}

func (e *ErrNotJavaScript) Error() string {
	if strings.TrimSpace(e.ContentType) == "" {
		return "Not a JS resource: content-type missing"
	}
	return fmt.Sprintf("Not a JS resource: content-type=%s", e.ContentType)
}

func IsNotJavaScript(err error) bool {
	var rejected *ErrNotJavaScript
	return errors.As(err, &rejected)
}
```

Replace only the two content-rejection assignments in `validateJSResult`:

```go
clone.Err = &ErrNotJavaScript{ContentType: clone.ContentType}
```

and:

```go
clone.Err = &ErrNotJavaScript{}
```

HTTP status and transport errors must keep their existing types and messages.

- [ ] **Step 4: Run focused and package tests and verify GREEN**

Run:

```bash
go test ./internal/fetcher -count=1
```

Expected: package passes, including existing exact rejection behavior.

- [ ] **Step 5: Commit the fetch classification**

```bash
git add internal/fetcher/fetcher.go internal/fetcher/fetcher_test.go
git commit -m "fix: classify non-JavaScript responses"
```

### Task 2: Deterministic logger writer injection

**Files:**
- Modify: `internal/logging/logging.go:1-51`
- Create: `internal/logging/logging_test.go`

**Interfaces:**
- Consumes: existing `logging.New(verbose, outDir)` calls without modification.
- Produces: `logging.NewWithWriters(verbose bool, stdout, stderr io.Writer) *Logger` for focused log assertions.

- [ ] **Step 1: Write the failing writer-routing test**

Create `internal/logging/logging_test.go`:

```go
package logging

import (
	"bytes"
	"strings"
	"testing"
)

func TestNewWithWritersRoutesByLevel(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	log := NewWithWriters(false, &stdout, &stderr)

	log.Info("info %d", 1)
	log.Verbose("hidden")
	log.Warn("warning")
	log.LogError("fetch", "failed")

	if got := stdout.String(); !strings.Contains(got, "info 1") || strings.Contains(got, "hidden") {
		t.Fatalf("stdout = %q", got)
	}
	if got := stderr.String(); !strings.Contains(got, "[WARN] warning") || !strings.Contains(got, "[ERR] fetch: failed") {
		t.Fatalf("stderr = %q", got)
	}
}
```

- [ ] **Step 2: Run the focused test and verify RED**

Run:

```bash
go test ./internal/logging -run TestNewWithWritersRoutesByLevel -count=1
```

Expected: compilation fails because `NewWithWriters` does not exist.

- [ ] **Step 3: Route logger methods through stored writers**

Replace the logger construction and direct process writers with:

```go
type Logger struct {
	verbose bool
	stdout  io.Writer
	stderr  io.Writer
}

func New(verbose bool, _ string) *Logger {
	return NewWithWriters(verbose, os.Stdout, os.Stderr)
}

func NewWithWriters(verbose bool, stdout, stderr io.Writer) *Logger {
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	return &Logger{verbose: verbose, stdout: stdout, stderr: stderr}
}
```

Use `fmt.Fprintf(l.stdout, ...)` in `Info` and `Verbose`; use `fmt.Fprintf(l.stderr, ...)` in `Warn`, `Error`, and `LogError`. Preserve the existing timestamp and level text byte-for-byte.

- [ ] **Step 4: Run logging tests and verify GREEN**

Run:

```bash
go test ./internal/logging -count=1
```

Expected: package passes with info routed to stdout, verbose suppressed, and warnings/errors routed to stderr.

- [ ] **Step 5: Commit logger injection**

```bash
git add internal/logging/logging.go internal/logging/logging_test.go
git commit -m "test: make logger output injectable"
```

### Task 3: Batch progress model and formatting

**Files:**
- Create: `cmd/jspider/progress.go`
- Create: `cmd/jspider/progress_test.go`

**Interfaces:**
- Consumes: `fetchReq`, `fetcher.Result`, `fetcher.IsNotJavaScript`, and `logging.Logger`.
- Produces: `newEntryProgress(int, int, time.Time) *entryProgress`, `newCrawlBatchStats(int, []fetchReq) crawlBatchStats`, `(*crawlBatchStats).observeFetch(*fetcher.Result)`, `crawlBatchStats.depthLabel() string`, and `crawlBatchStats.log(*logging.Logger, *entryProgress, time.Duration)`.

- [ ] **Step 1: Write failing tests for depth and outcome accounting**

Create `cmd/jspider/progress_test.go`:

```go
package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Veincc/JSpider/internal/fetcher"
	"github.com/Veincc/JSpider/internal/logging"
)

func TestCrawlBatchStatsFormatsUniformAndMixedDepth(t *testing.T) {
	uniform := newCrawlBatchStats(1, []fetchReq{{depth: 2}, {depth: 2}})
	if got := uniform.depthLabel(); got != "2" {
		t.Fatalf("uniform depth = %q, want 2", got)
	}
	mixed := newCrawlBatchStats(2, []fetchReq{{depth: 3}, {depth: 1}, {depth: 2}})
	if got := mixed.depthLabel(); got != "1-3" {
		t.Fatalf("mixed depth = %q, want 1-3", got)
	}
}

func TestCrawlBatchStatsSeparatesFetchOutcomes(t *testing.T) {
	stats := newCrawlBatchStats(1, []fetchReq{{depth: 0}, {depth: 0}, {depth: 0}})
	stats.observeFetch(&fetcher.Result{IsJS: true})
	stats.observeFetch(&fetcher.Result{Err: &fetcher.ErrNotJavaScript{ContentType: "application/json"}})
	stats.observeFetch(&fetcher.Result{Err: errors.New("connection reset")})
	if stats.js != 1 || stats.nonJS != 1 || stats.failed != 1 {
		t.Fatalf("outcomes = %+v", stats)
	}
}

func TestCrawlBatchStatsLogsFixedSummary(t *testing.T) {
	var stdout bytes.Buffer
	log := logging.NewWithWriters(false, &stdout, nil)
	progress := newEntryProgress(1, 2, time.Now())
	stats := newCrawlBatchStats(3, []fetchReq{{depth: 1}, {depth: 1}})
	stats.js = 1
	stats.nonJS = 1
	stats.analyzed = 1
	stats.discovered = 7
	stats.next = 7
	stats.total = 9
	stats.log(log, progress, 1500*time.Millisecond)

	want := "[1/2] Batch 3: depth=1 attempted=2 js=1 non-js=1 failed=0 analyzed=1 discovered=7 next=7 total=9 elapsed=1.5s"
	if got := stdout.String(); !strings.Contains(got, want) || strings.Count(got, "Batch 3:") != 1 {
		t.Fatalf("batch log = %q, want one %q", got, want)
	}
}
```

- [ ] **Step 2: Run the progress tests and verify RED**

Run:

```bash
go test ./cmd/jspider -run 'TestCrawlBatchStats' -count=1
```

Expected: compilation fails because the progress types and constructors do not exist.

- [ ] **Step 3: Implement the progress model**

Create `cmd/jspider/progress.go` with the following concrete model:

```go
package main

import (
	"fmt"
	"time"

	"github.com/Veincc/JSpider/internal/fetcher"
	"github.com/Veincc/JSpider/internal/logging"
)

type entryProgress struct {
	current     int
	total       int
	started     time.Time
	batchNumber int
	failed      int
}

func newEntryProgress(current, total int, started time.Time) *entryProgress {
	return &entryProgress{current: current, total: total, started: started}
}

func (p *entryProgress) prefix() string {
	return fmt.Sprintf("[%d/%d]", p.current, p.total)
}

type crawlBatchStats struct {
	number     int
	minDepth   int
	maxDepth   int
	attempted  int
	js         int
	nonJS      int
	failed     int
	analyzed   int
	discovered int
	next       int
	total      int
}

func newCrawlBatchStats(number int, batch []fetchReq) crawlBatchStats {
	stats := crawlBatchStats{number: number, attempted: len(batch)}
	if len(batch) == 0 {
		return stats
	}
	stats.minDepth, stats.maxDepth = batch[0].depth, batch[0].depth
	for _, item := range batch[1:] {
		if item.depth < stats.minDepth {
			stats.minDepth = item.depth
		}
		if item.depth > stats.maxDepth {
			stats.maxDepth = item.depth
		}
	}
	return stats
}

func (s *crawlBatchStats) observeFetch(result *fetcher.Result) {
	if result == nil {
		s.failed++
		return
	}
	if fetcher.IsNotJavaScript(result.Err) {
		s.nonJS++
		return
	}
	if result.Err != nil {
		s.failed++
		return
	}
	s.js++
}

func (s crawlBatchStats) depthLabel() string {
	if s.minDepth == s.maxDepth {
		return fmt.Sprintf("%d", s.minDepth)
	}
	return fmt.Sprintf("%d-%d", s.minDepth, s.maxDepth)
}

func formatElapsed(elapsed time.Duration) string {
	if elapsed < time.Second {
		return elapsed.Round(time.Millisecond).String()
	}
	return elapsed.Round(100 * time.Millisecond).String()
}

func (s crawlBatchStats) log(log *logging.Logger, progress *entryProgress, elapsed time.Duration) {
	log.Info("%s Batch %d: depth=%s attempted=%d js=%d non-js=%d failed=%d analyzed=%d discovered=%d next=%d total=%d elapsed=%s",
		progress.prefix(), s.number, s.depthLabel(), s.attempted, s.js, s.nonJS, s.failed,
		s.analyzed, s.discovered, s.next, s.total, formatElapsed(elapsed))
}
```

- [ ] **Step 4: Run focused tests and verify GREEN**

Run:

```bash
go test ./cmd/jspider -run 'TestCrawlBatchStats' -count=1
```

Expected: all progress model tests pass.

- [ ] **Step 5: Commit the progress model**

```bash
git add cmd/jspider/progress.go cmd/jspider/progress_test.go
git commit -m "feat: add crawl batch progress model"
```

### Task 4: Integrate discovery, batch, rejection, and completion logs

**Files:**
- Modify: `cmd/jspider/main.go:311-588`
- Modify: `cmd/jspider/main.go:709-734`
- Test: `cmd/jspider/main_test.go`

**Interfaces:**
- Consumes: the Task 1 fetch classification, Task 2 injected logger, and Task 3 progress model.
- Produces: one discovery completion line and one line per fully completed batch; existing `analyzeEntry` and `analyzeEntryContext` continue returning `(int, error)`.

- [ ] **Step 1: Write the failing mixed-batch integration test**

Add a test that runs entry analysis with a buffered logger and real HTTP responses:

```go
func TestAnalyzeEntryLogsOneSummaryPerCompletedBatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			_, _ = io.WriteString(w, `<script src="/app.js"></script><script src="/data"></script><script src="/missing.js"></script>`)
		case "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = io.WriteString(w, `import("./child.js");`)
		case "/child.js":
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = io.WriteString(w, `export const child = true;`)
		case "/data":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"ok":true}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	outDir := t.TempDir()
	cfg := testConfig(server.URL+"/", outDir)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	log := logging.NewWithWriters(false, &stdout, &stderr)
	f, err := fetcher.New(cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	processor, err := preprocess.New(filepath.Join(outDir, "site"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer processor.Close()
	progress := newEntryProgress(1, 1, time.Now())
	queued, processed := make(map[string]bool), make(map[string]bool)
	totalAnalyzed, totalAttempts := 0, 0

	got, err := analyzeEntryContext(context.Background(), cfg, store.New(outDir), f, analyzer.NewAnalyzer(log), html.NewExtractor(), log, processor, nil,
		server.URL+"/", "site", queued, processed, &totalAnalyzed, &totalAttempts, progress)
	if err != nil {
		t.Fatal(err)
	}
	if got != 2 {
		t.Fatalf("analyzed = %d, want 2", got)
	}
	output := stdout.String()
	if strings.Count(output, " Batch ") != 2 {
		t.Fatalf("batch lines = %q, want exactly two", output)
	}
	for _, want := range []string{
		"[1/1] Discovery complete: static=3 headless=0 unique=3 elapsed=",
		"[1/1] Batch 1: depth=0 attempted=3 js=1 non-js=1 failed=1 analyzed=1 discovered=1 next=1 total=1 elapsed=",
		"[1/1] Batch 2: depth=1 attempted=1 js=1 non-js=0 failed=0 analyzed=1 discovered=0 next=0 total=2 elapsed=",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("output missing %q:\n%s", want, output)
		}
	}
	if strings.Contains(stderr.String(), server.URL+"/data") {
		t.Fatalf("non-JavaScript response logged as normal error: %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), server.URL+"/missing.js") {
		t.Fatalf("real fetch failure missing from stderr: %s", stderr.String())
	}
}
```

Add `bytes` and `io` imports to `cmd/jspider/main_test.go`.

Also add a focused test proving that a rejected response URL is visible only in verbose output:

```go
func TestAnalyzeResultLogsNonJavaScriptURLOnlyInVerboseMode(t *testing.T) {
	const rawURL = "https://example.com/data"
	for _, verbose := range []bool{false, true} {
		t.Run(fmt.Sprintf("verbose=%t", verbose), func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			log := logging.NewWithWriters(verbose, &stdout, &stderr)
			cfg := testConfig("https://example.com/", t.TempDir())
			queued := map[string]bool{rawURL: true}
			processed := make(map[string]bool)
			var queue []fetchReq
			analyzed, total := 0, 0
			res := fetchRes{
				req: fetchReq{url: rawURL, from: "https://example.com/"},
				result: &fetcher.Result{
					ContentType: "application/json",
					Err:         &fetcher.ErrNotJavaScript{ContentType: "application/json"},
				},
			}

			err := analyzeResultWithPreprocess(context.Background(), cfg, store.New(cfg.OutDir), analyzer.NewAnalyzer(log), log,
				nil, nil, res, "https://example.com/", "example_com", queued, processed, &queue, &analyzed, &total)
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Contains(stdout.String(), rawURL); got != verbose {
				t.Fatalf("stdout URL visibility = %t, want %t: %s", got, verbose, stdout.String())
			}
			if strings.Contains(stderr.String(), rawURL) {
				t.Fatalf("non-JavaScript URL written as error: %s", stderr.String())
			}
		})
	}
}
```

- [ ] **Step 2: Run the integration test and verify RED**

Run:

```bash
go test ./cmd/jspider -run 'TestAnalyzeEntryLogsOneSummaryPerCompletedBatch|TestAnalyzeResultLogsNonJavaScriptURLOnlyInVerboseMode' -count=1
```

Expected: compilation fails because `analyzeEntryContext` does not accept `*entryProgress`; after adding only that parameter, the test fails because the new summary lines are absent and JSON is still logged as an error.

- [ ] **Step 3: Pass stable entry progress into analysis**

In `run`, create progress immediately before the existing analyzing log:

```go
progress := newEntryProgress(i+1, len(planned), time.Now())
log.Info("%s Analyzing: %s", progress.prefix(), entry.url)
```

Pass `progress` as the final `analyzeEntryContext` argument. Update `analyzeEntryContext` to accept that argument. The compatibility wrapper `analyzeEntry` constructs `newEntryProgress(1, 1, time.Now())` and passes it onward, keeping its current return signature.

- [ ] **Step 4: Consolidate discovery logs**

Track `headlessCount := 0`, assign it after successful headless discovery, and replace the separate completion count messages with:

```go
log.Info("%s Discovery: downloading entry HTML: %s", progress.prefix(), entryURL)
log.Verbose("Entry HTML size: %d bytes", len(htmlContent))
log.Verbose("Static extraction found %d JS assets", len(staticAssets))
```

Before browser discovery:

```go
log.Info("%s Discovery: running headless browser: %s", progress.prefix(), entryURL)
```

After sorting the final entry assets, emit:

```go
log.Info("%s Discovery complete: static=%d headless=%d unique=%d elapsed=%s",
	progress.prefix(), len(staticAssets), headlessCount, len(entryAssets), formatElapsed(time.Since(progress.started)))
```

Keep browser failure warnings unchanged and keep raw count/details available through verbose logging.

- [ ] **Step 5: Account for and log each completed batch**

At the beginning of each loop iteration, after applying the `MaxJS` slice, create:

```go
progress.batchNumber++
batchStats := newCrawlBatchStats(progress.batchNumber, batch)
batchStarted := time.Now()
analyzedBefore := analyzed
```

For every ordered response, before calling `analyzeResultWithPreprocess`, record:

```go
batchStats.observeFetch(res.result)
nextBefore := len(queue)
```

After successful analysis of the result:

```go
batchStats.discovered += len(queue) - nextBefore
```

Only after the result channel has closed successfully and attempt reconciliation is complete, populate and emit:

```go
batchStats.analyzed = analyzed - analyzedBefore
batchStats.next = len(queue)
batchStats.total = analyzed
progress.failed += batchStats.failed
batchStats.log(log, progress, time.Since(batchStarted))
```

Do not emit this block on fatal persistence or cancellation returns.

- [ ] **Step 6: Downgrade expected non-JavaScript URL details to verbose**

In the `res.result.Err != nil` branch of `analyzeResultWithPreprocess`, classify first:

```go
if fetcher.IsNotJavaScript(res.result.Err) {
	log.Verbose("Skipping non-JavaScript response: URL=%s content-type=%s", item.url, res.result.ContentType)
} else {
	log.LogError("Download failed", "URL=%s error=%v", item.url, res.result.Err)
}
```

Keep the existing failed-store record and return behavior below this logging branch unchanged.

- [ ] **Step 7: Add completion totals**

Replace the successful entry completion line in `run` with:

```go
log.Info("%s Done: %s attempts=%d analyzed=%d failed=%d elapsed=%s",
	progress.prefix(), entry.url, site.attempts-attemptsBefore, analyzed, progress.failed,
	formatElapsed(time.Since(progress.started)))
```

This retains the URL while making attempts, real failures, and total elapsed time explicit. Non-JavaScript rejections remain visible in batch summaries and are not counted as `failed`.

- [ ] **Step 8: Update existing direct callers and run focused tests**

Update direct `analyzeEntryContext` test calls to pass a fresh `newEntryProgress(1, 1, time.Now())`. The `analyzeEntry` compatibility wrapper keeps the API discovery test source-compatible.

Run:

```bash
go test ./cmd/jspider -run 'TestAnalyzeEntryLogsOneSummaryPerCompletedBatch|TestAnalysisDoesNotApplyFetchBudgetAfterScheduling|TestFetchBatch' -count=1
```

Expected: all focused crawl and logging tests pass.

- [ ] **Step 9: Commit crawl log integration**

```bash
git add cmd/jspider/main.go cmd/jspider/main_test.go
git commit -m "feat: report crawl batch progress"
```

### Task 5: Regression and live verification

**Files:**
- Modify only if verification exposes a defect in the preceding tasks.

**Interfaces:**
- Consumes: completed implementation from Tasks 1-4.
- Produces: fresh evidence that tests, build, deterministic crawl semantics, and live log behavior satisfy the specification.

- [ ] **Step 1: Format all changed Go files**

Run:

```bash
gofmt -w internal/fetcher/fetcher.go internal/fetcher/fetcher_test.go internal/logging/logging.go internal/logging/logging_test.go cmd/jspider/progress.go cmd/jspider/progress_test.go cmd/jspider/main.go cmd/jspider/main_test.go
```

Expected: files are formatted without changing behavior.

- [ ] **Step 2: Run the full test suite**

Run:

```bash
go test ./... -count=1
```

Expected: all packages pass with zero failures.

- [ ] **Step 3: Run the race-sensitive crawl and fetch packages**

Run:

```bash
go test -race ./internal/fetcher ./internal/logging ./cmd/jspider -count=1
```

Expected: all selected packages pass with no race reports.

- [ ] **Step 4: Build the CLI**

Run:

```bash
go build ./cmd/jspider
```

Expected: exit status 0.

- [ ] **Step 5: Verify the full live crawl log**

Run with network permission:

```bash
go run ./cmd/jspider -u https://tds.uniin.cn --headless -o /tmp/jspider-batch-log-full
```

Expected: discovery reports `static=2`, approximately 64 headless/unique entry assets, followed by fixed batch lines that expose the large recursive batch; the four JSON responses contribute to `non-js` and do not appear as `[ERR] Download failed`.

- [ ] **Step 6: Verify the no-recursion live log**

Run with network permission:

```bash
go run ./cmd/jspider -u https://tds.uniin.cn --headless -d 0 -o /tmp/jspider-batch-log-depth0
```

Expected: exactly one crawl batch is reported, with approximately 60 analyzed JavaScript responses and four `non-js` responses.

- [ ] **Step 7: Inspect the final diff and commit verification-only adjustments if any**

Run:

```bash
git diff --check
git status --short
```

Expected: no whitespace errors; only intentional task files and the user's pre-existing untracked documents are present. If verification required code adjustments, stage only those task files and commit them with a message describing the verified defect.
