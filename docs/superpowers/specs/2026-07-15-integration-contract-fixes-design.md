# JSpider Integration Contract Fixes Design

Date: 2026-07-15
Branch: `codex/full-audit-remediation`
Base: `origin/main` at `3093ee9c3b6205516f64262d2981eaa9d1d8d6e4`

## Purpose

Close four cross-layer defects found by the final integration review without weakening the established crawl, provenance, timeout, output, or performance contracts:

1. HTTP(S) origins that canonicalize to the same value must behave as the same origin everywhere, not only during output-directory planning.
2. API Discovery must retain entry-specific source provenance when multiple entries from one canonical origin load the same JavaScript.
3. The processing deadline and caller cancellation must cover Go-side source-map work as well as the Node worker, with a hard decoded-map input bound.
4. Programmatic callers of `run` must receive the same `APIDiscovery => Headless` implication as CLI callers.

## Chosen Design

### Canonical origin as the sole HTTP(S) authority identity

`urlutil.CanonicalOrigin` remains the authoritative normalization function. `IsSameOrigin` will canonicalize both operands and fail closed on either error. `GetOrigin` will return the canonical HTTP(S) origin or an empty string.

Fetcher cookie forwarding and redirect policy, Headless external-link filtering, API absolute-authority comparison, association authority indexes, entry-origin scoring, and static-only reportability will all consume canonical origins. Hostname case, IDNA equivalents, IPv6 spelling, and explicit default ports therefore compare consistently; schemes and non-default ports remain distinct. Entry provenance itself remains keyed by the exact configured entry URL because two separate entries must not be conflated merely because their origins match.

### Entry-specific API crawl state

Normal and Headless-only runs retain origin-wide `queued`/`processed` state to avoid repeated fetch and analysis work. In API Discovery mode, every configured entry receives fresh crawl-state maps while the origin runtime, output store, processor content-addressed artifact deduplication, API session, counters, and fetch-attempt budget remain shared.

This intentionally permits the same JavaScript URL to be fetched and analyzed once per entry in API mode. Each pass records a distinct `SourceIdentity` containing entry, requested URL, final URL, and content hash, and recursively discovered dependencies inherit that entry. This is the smallest complete fix: caching only the root identity would omit dependency provenance, while retaining bodies or full analysis graphs across entries would reintroduce large permanent caches.

### One cancellable preprocessing operation

The processor will expose a context-aware processing method. The caller's run context will be combined with `ProcessTimeoutSeconds` before source-map-reference scanning begins. The same operation context will flow through:

- source-map directive scanning;
- source-map slot acquisition;
- inline data-URL validation and decoding;
- declared, adjacent, and indexed-section fetches;
- JSON decoding and recursive section traversal;
- recovered-source accounting and writes between cancellation checks; and
- the Node worker request, using only the remaining operation time.

Inferred adjacent-map probing retains its three-second sub-deadline, capped by the enclosing operation deadline. A declared map uses the enclosing deadline. Cancellation or deadline exhaustion produces the established original-source fallback and prevents new recursive work. The source-map semaphore is released only when the corresponding recovery work has actually stopped.

Go parsing is made cooperatively cancellable with context-aware readers and checks before and between decoding/traversal stages. Potentially long recovery work is isolated behind the existing four-slot bound; the caller waits only until its operation context completes, while any already-running bounded recovery must observe cancellation and release its slot before another begins.

### Source-map memory bound

Decoded source-map input is capped at 128 MiB before JSON decoding. For base64 data URLs, decoded length is checked before allocation; percent-encoded payload length is checked before unescaping and the decoded result is checked again. Fetched root and indexed-section maps are checked immediately after fetch and before parsing.

The existing recovered application-source limits remain separate and unchanged: at most 512 application sources and at most 64 MiB aggregate recovered content. Exceeding either the 128 MiB map-input cap or an existing recovery cap marks recovery incomplete and analyzes the original bundle only. Usable partial output may still be persisted only when it is already within the established output limits.

### Effective configuration at the run boundary

`run` will copy the caller's `config.Config`, apply mode implications to the copy, validate it, and use that effective copy for the entire run. The caller's object is not mutated. Thus `APIDiscovery=true, Headless=false` reliably performs browser preflight and runtime collection for both CLI and programmatic use.

## Error and Lifecycle Behavior

- Invalid or non-HTTP(S) origins fail closed; they never gain same-origin privileges.
- Context cancellation takes precedence over starting new map, Node, crawl, or browser work.
- A preprocessing timeout writes the original-source fallback atomically and does not mark the item confirmed unless that fallback succeeds.
- A source-map size-limit failure is a recoverable preprocessing fallback, not a process-wide crash.
- Per-origin attempt limits still include repeated per-entry API fetches and failures. Exhaustion may legitimately prevent later entries from acquiring provenance; this remains visible in per-entry and aggregate statistics.
- Site finalization remains best-effort and deterministic after entry failures.

## Testing Strategy

Behavioral changes use RED-GREEN tests before implementation:

1. URL/fetch/headless/API tests for hostname case, explicit `:80`/`:443`, IDNA/IPv6 normalization, non-default-port distinction, cookie forwarding, redirects, click filtering, association authority keys, entry-origin scoring, and static-only reportability.
2. A full runner integration test with two same-origin entries sharing one script, runtime evidence only from the second entry, and assertions for two source identities, second-entry source stats, association, and inferred base. A normal-mode test preserves origin-wide deduplication.
3. Processor tests for caller cancellation, timeout before/during map work, adjacent sub-deadline, oversized inline and fetched maps, nested-section cancellation, semaphore release, worker cancellation/restart, original fallback, and absence of post-timeout writes.
4. A programmatic `run` test with API Discovery true and Headless false that proves browser preflight and discovery execute while the input config remains unchanged.

After focused tests, run uncached CGO 0/1 full suites, full race tests, both vet/build modes, fuzz smoke, coverage, benchmarks, workflow/release checks, and a final base-to-HEAD integration review.

## Alternatives Rejected

- Moving all source-map parsing into a new subprocess would provide stronger process-level termination but would substantially expand protocol, packaging, and cross-platform release risk.
- Caching and replaying full analysis graphs across entries could avoid repeated API-mode fetches, but it would require durable body/analysis caches and dependency-graph replay, conflicting with the bounded-body and simple-lifecycle goals.
- Weakening the timeout documentation would leave actual caller cancellation and unbounded map input defects unresolved.

## Non-goals

- No change to raw query/header/body preservation decisions.
- No change to ordinary output layout or naming.
- No sanitization or new persisted raw-request artifacts.
- No global JavaScript body-size cap beyond the existing `-s` option.
- No push, pull request, release, or modification of the user's original checkout.
