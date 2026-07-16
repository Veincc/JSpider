# JSpider

JSpider is a command-line tool for recursively discovering and downloading JavaScript used by modern web applications.

Starting from one or more entry URLs, JSpider:

1. Downloads the entry HTML.
2. Extracts referenced JavaScript.
3. Downloads each JavaScript file.
4. Discovers additional imports, chunks, and JavaScript URLs.
5. Continues recursively until the queue is empty or a configured limit is reached.
6. Saves recovered source-map sources, readable bundles, or sole-artifact fallback bundles under each site's `js/` directory.
7. Writes a deterministic `js-map.txt` that maps every downloaded JavaScript URL to its processed output paths.

Optional flags can add browser-assisted discovery or correlate statically extracted APIs with browser requests. JavaScript preprocessing is always enabled.

## Installation

Install the latest version:

```bash
go install github.com/Veincc/JSpider/cmd/jspider@latest
```

Or build from the repository:

```bash
go build -o jspider ./cmd/jspider
```

The standard crawler and `--headless` mode are available in normal Go builds. The optional `--api-discovery` feature embeds jsluice and tree-sitter and therefore requires a CGO-enabled build:

```bash
CGO_ENABLED=1 go build -o jspider ./cmd/jspider
```

A `CGO_ENABLED=0` build still supports the existing static crawler and `--headless` JavaScript discovery. If `--api-discovery` is requested from that build, JSpider returns a clear CGO-enabled-build error.

Node.js 18 or newer is required in `PATH` for every run. The JavaScript processor and its dependencies are embedded in the JSpider binary, so users do not need to run `npm install`.

## Quick Start

```bash
jspider -u https://example.com
```

Output:

```text
output/
  example_com/
    js/
      app-a1b2c3d4.js
      src/
        feature.ts
    js-map.txt
```

Analyze multiple entry URLs:

```bash
jspider -l urls.txt
```

Allow known CDN domains:

```bash
jspider -u https://example.com -c cdn.example.com,static.example.net
```

Use an HTTP, HTTPS, or SOCKS5 proxy:

```bash
jspider -u https://example.com --proxy http://127.0.0.1:8080
```

JSpider does not persist entry.html. It keeps entry HTML and recursive analysis bodies in memory while saving only processed JavaScript and `js-map.txt` in normal mode.

## Sensitive Data and Output Handling

JSpider is not a redaction boundary. Run it only on systems you are authorized to inspect, use narrowly scoped credentials, and protect the terminal, process environment, logs, and output directory as sensitive data.

- Values passed with `-k` and `-H` can be visible in the command line, shell history, and process listings.
- Full request URLs, query values, headers, request bodies, and body samples may remain in memory. Treat verbose logs as potentially containing the same raw data, including credentials and session values.
- `endpoints.txt` deliberately preserves full query strings. `js-map.txt` likewise records complete JavaScript URLs, including queries.
- JSpider does not create separate raw-header or raw-request-body artifacts. That does not make the in-memory data, verbose logs, downloaded code, or URL-bearing output files safe to share.
- Output permissions are mixed. On Unix, `endpoints.txt` and `js-map.txt` are written as `0600`, but downloaded, generated, and recovered JavaScript uses `0644` and normal output directories use `0755`; Windows access is governed by its ACLs. Put `-o` beneath a protected parent directory and use an appropriate umask/ACLs. Backups, copied logs, and retention remain the operator's responsibility. Avoid `-v` for credentialed runs unless required, and remove outputs and logs according to your data-handling policy.

## Runtime API Discovery

Use `--api-discovery` to extract API candidates from downloaded JavaScript with jsluice and correlate them with requests observed in Chrome:

```bash
jspider -u https://example.com --api-discovery
```

`--api-discovery` automatically enables the existing Headless/CDP flow; `--headless` does not automatically enable static API analysis. Chrome or Chromium must be available before the crawl starts.

API Discovery keeps JavaScript provenance separate for every exact entry URL. It may therefore fetch a shared script once per entry; every such attempt, including failures, counts against the shared `-n` budget for that canonical origin. Normal and Headless-only runs continue to deduplicate crawling across same-origin entries.

Request-body capture admits at most four active and four queued CDP post-data lookups; excess lookups are dropped without blocking Chrome's event stream. Parsing is capped at 1 MiB per admitted body and retained samples at 4 KiB. Chrome/CDP can still materialize each of the four active request bodies before JSpider applies the parse cap.

During API discovery JSpider:

1. Completes Headless-assisted and recursive JavaScript discovery first, retaining each downloaded in-memory analysis body by source URL.
2. Runs jsluice directly as a Go package across the complete collected JavaScript set, deterministically ordered by source URL.
3. Removes obvious static-asset/import matches and syntax noise while preserving API-like path candidates; HTTP verbs are inferred from common minified wrapper names such as `.get`, `.postWithMsg`, and `.delete`.
4. Enables CDP Network and Debugger domains before navigation.
5. Records XHR, Fetch, and EventSource requests, including JavaScript initiator stacks when Chrome provides them.
6. Records WebSocket connections separately without using them for HTTP prefix inference.
7. Scrolls the page and clicks only the existing bounded set of safe-looking elements.
8. Waits for XHR/Fetch activity to remain quiet for 750 ms after clicks, within the existing Headless timeout.
9. Associates static paths with runtime paths using path-segment boundaries, methods, initiators, and parameter-name evidence.
10. Preserves all confirmed runtime bases when more than one is supported by evidence.

The browser uses the configured proxy, User-Agent, Cookie, extra headers, same-origin/CDN policy, and TLS setting. Page behavior may make requests to cross-origin APIs; those observed APIs can still be recorded and associated.

JSpider does not replay requests or send additional probing requests. It never replays POST, PUT, PATCH, or DELETE requests and does not create response-body artifacts. Browser-side page execution and safe clicks can still trigger application requests, so use this feature only on systems you are authorized to test. Raw request metadata and samples may remain in memory or verbose logs as described in [Sensitive Data and Output Handling](#sensitive-data-and-output-handling).

Output:

```text
output/
  example_com/
    js/
      app-a1b2c3d4.js
      src/
        feature.ts
    js-map.txt
    endpoints.txt
```

`endpoints.txt` exists only in API Discovery mode. It contains one absolute HTTP(S) URL per line, with fragments removed and full query strings and values preserved. Rows are deduplicated, sorted, atomically replaced, and written with `0600` permissions. An API run with no final endpoints creates a zero-byte file.

Static extraction, runtime capture, association evidence, base inference, and the final report remain available in memory during the run. JSpider does not persist API intermediate JSON or JSONL reports.

## Processed JavaScript Output

Every mode uses the same JavaScript processing pipeline. There is no opt-out flag.

One per-bundle processing timeout starts before source-map reference scanning, covers recovery and Node-based regeneration, and observes caller cancellation. An inferred adjacent-map probe receives a 3-second sub-deadline; if only that probe expires, processing continues with Node under the enclosing timeout.

For each JavaScript bundle, JSpider:

1. Uses its `sourceMappingURL` when present, including inline source maps.
2. If no source map is declared, tries the adjacent `<bundle-url>.map` within the 3-second sub-deadline.
3. If the map contains application `sourcesContent`, exports those source files.
4. Excludes obvious dependency and bundler runtime sources such as `node_modules`, Webpack runtime code, and Vite virtual modules.
5. If no usable application source is available, parses and regenerates the bundle as readable JavaScript while safely restoring simple static strings and wrappers.
6. If parsing fails, saves the original bundle as the only artifact for that URL.

JSpider does not execute target JavaScript, decoded strings, `eval`, `Function`, navigation, network calls, or browser-side behavior during preprocessing.

Output:

```text
output/
  example_com/
    js/
      src/
        app.ts
      chunk-e5f6a7b8.js
      broken-f1e2d3c4.js
    js-map.txt
```

Complete source-map recovery within the limits analyzes the recovered application sources and writes only those recovered source artifacts; it does not also analyze or save the original compressed bundle. Decoded source-map input has a separate hard cap of 128 MiB. Recovered output is capped at 512 application source files, 64 MiB of aggregate content, and four nested indexed-map levels. If recovery is incomplete or exceeds a cap, crawl discovery analyzes only the original bundle, never both the original and recovered sources. Any usable recovered files within the output caps may still be retained as artifacts; when there are no usable recovered files, JSpider falls back to a generated readable bundle or, if parsing fails, the original bundle. Timeout or caller cancellation also persists the original bundle as the truthful fallback. Raw source maps are not saved.

`js-map.txt` is Tab-separated. Each row contains the complete JavaScript URL, a Tab character, and a path relative to the site directory:

```text
https://example.com/assets/app.js	js/src/app.ts
https://example.com/assets/app.js	js/src/router.ts
https://cdn.example.net/chunk.js	js/chunk-e5f6a7b8.js
```

One URL can map to multiple recovered sources, and multiple URLs can map to one deduplicated artifact. Rows are sorted by URL and then path. The file is atomically replaced with `0600` permissions; sites without a successful JavaScript download receive a zero-byte map.

## Headless Discovery

```bash
jspider -u https://example.com --headless
```

`--headless` uses Chrome or Chromium to supplement static discovery with scripts observed at runtime.

Browser discovery can trigger page-side requests and limited safe-looking interactions. Use it only against systems where you have authorization. `--headless` alone preserves its previous JavaScript-discovery behavior and does not run jsluice or write API discovery reports.

The `-t` value is also the total Headless discovery budget. It is divided by absolute elapsed-time cutoffs: browser startup and navigation through 50%, scrolling through 70%, clicking/settling/DOM extraction through 95%, and pending body/request-data drain through 100%. A slow early phase does not shift the later deadlines; exhausted phases are skipped while already captured results are kept.

`--headless-body-mb` caps each captured text or JSON XHR/Fetch response at 8 MiB by default. Oversized responses reported by Chrome are skipped, and returned bodies are truncated before parsing. Chrome's `Network.getResponseBody` API has no streaming limit, so a compressed response can still be fully materialized by Chrome/CDP before JSpider applies the post-read cap.

## Options

| Option | Default | Description |
| --- | --- | --- |
| `-u <url>` | none | Entry URL. |
| `-l <file>` | none | File containing one entry URL per line. |
| `-o <dir>` | `output` | Output directory. |
| `--headless` | `false` | Add Chrome or Chromium browser discovery. |
| `--api-discovery` | `false` | Extract static APIs and correlate them with browser XHR/Fetch/EventSource requests; safely clicks bounded elements, requires CGO and Chrome/Chromium, and implies `--headless`. |
| `-n <count>` | unlimited | Maximum JavaScript fetch attempts per canonical origin across its entries; failed attempts count, entry HTML does not. |
| `-d <depth>` | `10` | Maximum recursive discovery depth; `0` fetches entry-discovered JavaScript but does not schedule JavaScript discovered from it. |
| `-s <mb>` | unlimited | Maximum compressed and decompressed resource size; `0` disables the limit. |
| `-w <workers>` | `5` | Concurrent download workers. |
| `--same-origin` | `true` | Restrict discovery to the entry origin and allowed CDN domains. |
| `-c <domains>` | none | Comma-separated allowed CDN domains. |
| `--proxy <url>` | none | HTTP, HTTPS, or SOCKS5 proxy used by requests and headless Chrome. |
| `-t <seconds>` | `15` | HTTP timeout. |
| `--process-timeout <seconds>` | `30` | Per-bundle timeout starting before source-map scanning; propagates caller cancellation and covers recovery plus Node processing. Adjacent-map probing without a declaration uses a 3-second sub-deadline. |
| `--headless-body-mb <mb>` | `8` | Positive per-response cap for captured text/JSON XHR/Fetch bodies; see the Headless allocation caveat above. |
| `-a <ua>` | Chrome-like UA | Custom User-Agent. |
| `-k <cookie>` | none | Cookie header value. |
| `-H <headers>` | none | Extra headers as `Header1=Value1;Header2=Value2`. |
| `-v` | `false` | Print verbose logs. |
| `--insecure` | `false` | Disable TLS certificate verification. Use only for authorized testing. |

At least one of `-u` or `-l` is required.

Resources are read into memory. The default `-s 0` is unlimited; set an explicit size limit when scanning untrusted or potentially large endpoints.

The previous `--insecure-skip-verify` option remains accepted as a deprecated compatibility alias for `--insecure`.

## Output Rules

- Files discovered through an allowed CDN are stored under the entry site's directory.
- Identical JavaScript content is saved once per entry site.
- Multiple entry sites receive separate self-contained directories.
- Multiple entry URLs for the same site accumulate into one site map and one optional endpoint file.
- Canonical origins use the legacy host-only directory name when unambiguous (for example, `example_com`). A non-default port is included (for example, `example_com_8443`). If distinct origins sanitize to the same name, every colliding origin receives an eight-hex-character SHA-256 suffix; default ports normalize away before naming.
- Entry failures do not discard successful output from other entries. JSpider continues after non-fatal entry failures, finalizes the accumulated outputs, prints success/failure/skipped counts, and exits nonzero if any entry or finalization failed. Process-wide initialization errors, cancellation, and fatal output errors can skip remaining entries.
- Starting a new run resets only each affected site directory; unrelated top-level files and other site directories are preserved.
- Normal and Headless-only runs write `js/` and `js-map.txt`. API Discovery additionally writes `endpoints.txt`.
- Entry HTML, raw source maps, and API intermediate reports are retained only in memory when needed and are not persisted.

## Development

Run the Go checks:

```bash
CGO_ENABLED=1 go test ./...
CGO_ENABLED=1 go build ./...
CGO_ENABLED=0 go test ./...
CGO_ENABLED=0 go build ./...
go vet ./...
```

Rebuild the embedded JavaScript processor helper after editing `tools/js-audit-prep/src/worker.js`:

```bash
cd tools/js-audit-prep
npm ci
npm run build
```

The build writes the bundled helper to `internal/preprocess/audit-prep.cjs`.
