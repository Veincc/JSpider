# Crawl Batch Logging Design

## Context

A headless crawl of `https://tds.uniin.cn` reports 64 unique entry assets, then appears idle for roughly 30 seconds before reporting 1,218 analyzed JavaScript resources. Investigation showed that the apparent stall is recursive work: a 2.67 MB bootstrap bundle contains 1,941 JavaScript paths and 751 dynamic imports, causing 1,158 additional chunks to be fetched and analyzed.

Same-environment measurements did not reproduce a version regression:

- Current version, default recursion: 46 seconds and 1,218 analyzed JavaScript resources.
- Pre-merge version, default recursion: 49 seconds and 1,222 analyzed JavaScript resources.
- Current version with `-d 0`: 15 seconds and 60 analyzed JavaScript resources.

The defect is therefore observability, not a demonstrated slowdown in the current implementation. The normal log does not show recursive queue growth, batch progress, or phase duration, so expected work looks like a hang. It also reports runtime JSON responses as JavaScript download errors even though rejecting them is expected.

## Goals

- Emit one durable normal-level log line after each crawl batch completes.
- Make entry discovery, recursive crawl growth, and completion timing distinguishable without `-v`.
- Count rejected non-JavaScript responses separately from actual download failures.
- Preserve deterministic crawling, default recursion depth, fetch limits, output content, and discovery coverage.
- Keep per-resource URLs and detailed decisions in verbose logging.

## Non-Goals

- Do not introduce a dynamic, in-place terminal progress display.
- Do not change the default `-d`, `-n`, `-w`, or timeout values.
- Do not add a new quick mode.
- Do not parallelize JavaScript preprocessing or analysis.
- Do not suppress real network, HTTP, cancellation, persistence, or processing failures.

## Chosen Approach

Retain the current breadth-first batch crawl and add structured batch accounting around it. This is preferred over reducing default crawl coverage or redesigning the serial analysis pipeline because the benchmark does not show a current-version performance regression, while the missing progress information directly explains the reported experience.

Each entry receives a start time and stable `[current/total]` prefix. Discovery emits a single completion line with static, headless, unique, and elapsed values. Each completed crawl batch emits one line containing the batch number, depth range, attempted responses, valid JavaScript responses, rejected non-JavaScript responses, actual failures, successfully analyzed resources, newly discovered resources, next-batch queue size, cumulative analyzed count, and batch elapsed time. Entry completion includes attempts, analyzed count, failures, and total elapsed time.

## Log Contract

Normal output follows this shape:

```text
[15:01:49] [1/1] Discovery complete: static=2 headless=64 unique=64 elapsed=11.2s
[15:01:52] [1/1] Batch 1: depth=0 attempted=64 js=60 non-js=4 failed=0 analyzed=60 discovered=1158 next=1158 total=60 elapsed=3.1s
[15:02:23] [1/1] Batch 2: depth=1 attempted=1158 js=1158 non-js=0 failed=0 analyzed=1158 discovered=0 next=0 total=1218 elapsed=31.0s
[15:02:24] [1/1] Done: https://tds.uniin.cn attempts=1222 analyzed=1218 failed=0 elapsed=46.0s
```

Formatting requirements:

- One fixed line is printed only after a batch is fully consumed and analyzed.
- Durations use a compact human-readable representation with sub-second precision where useful.
- `depth=N` is used for a uniform batch; `depth=N-M` is used defensively if a batch contains multiple depths.
- `attempted` counts every reserved fetch attempt in the completed batch, including non-JavaScript responses and failures.
- `js` counts responses accepted by the JavaScript fetcher.
- `non-js` counts responses rejected solely because their content type is not JavaScript.
- `failed` counts all other fetch failures in the batch.
- `analyzed` counts successfully persisted and analyzed JavaScript responses in the batch.
- `discovered` counts URLs newly admitted to the crawl queue during the batch, after URL, origin, confidence, depth, and deduplication filters.
- `next` is the size of the next queue after the batch completes.
- `total` is the entry's cumulative analyzed count.

The existing detailed URL messages remain available under `-v`. A non-JavaScript rejection is verbose informational output, not an error. Real fetch failures remain error output and also increment `failed`.

## Components and Data Flow

### Fetch error classification

The fetcher will expose a typed or otherwise reliably classifiable non-JavaScript error. Classification must not depend on matching the rendered error string. Existing callers that only check `Result.Err` continue to work.

### Batch accounting

The crawl orchestrator creates a fresh batch statistics value before launching each batch. As ordered results are consumed, it classifies the fetch outcome and records the analyzed counter before and after processing. Queue length before and after result analysis supplies admitted discovery growth without counting low-confidence candidates or filtered URLs.

Batch accounting remains on the serial consumer goroutine. No new synchronization is required and deterministic result ordering remains unchanged.

### Entry-level logging context

The entry index, entry total, and entry start time are passed into or wrapped around the entry analysis operation so all normal phase lines use the same context. The public result structures retain their current meanings; logging-only statistics do not become persistence formats or public API contracts.

## Error Handling

- Non-JavaScript content is recorded as `non-js`, marked failed/candidate in the store exactly as required by the existing crawl contract, and shown per URL only with `-v`.
- Network, TLS, timeout, body-size, and other fetch errors remain visible as errors and increment `failed`.
- Fatal persistence, cancellation, and processing errors preserve current early-return behavior. If a batch aborts before completion, no misleading completed-batch line is emitted.
- Max-attempt truncation continues to reserve and reconcile attempts using the current semantics. The final successfully completed partial batch reports its actual consumed attempts.

## Testing

Tests will be written before implementation and will verify:

- The fetcher provides a stable classification for non-JavaScript content-type rejection.
- A mixed batch reports separate `js`, `non-js`, and `failed` counts.
- Newly admitted URLs and `next` reflect the post-filter queue, not raw analyzer findings.
- Uniform and mixed depth ranges format correctly.
- Normal logging emits exactly one batch line per completed batch.
- Non-JavaScript URLs do not produce normal error lines, while real fetch failures still do.
- Existing crawl ordering, attempt limits, cancellation behavior, and output tests remain green.

The full Go test suite and build will be run after the focused tests. A live verification against `https://tds.uniin.cn` will confirm that default output exposes the large depth-1 batch and that `-d 0` reports only the entry batch.

## Acceptance Criteria

- The default headless crawl no longer has an unexplained gap while recursive work is running.
- The user can identify which batch dominates runtime and why the analyzed total exceeds the headless discovery count.
- Expected JSON/API responses are summarized as `non-js` rather than printed as download errors.
- No default coverage or crawl-limit semantics change.
- Focused tests, the full test suite, build, and live log verification pass.
