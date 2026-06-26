# JSpider

JSpider is a command-line tool for recursively discovering and downloading JavaScript used by modern web applications.

Starting from one or more entry URLs, JSpider:

1. Downloads the entry HTML.
2. Extracts referenced JavaScript.
3. Downloads each JavaScript file.
4. Discovers additional imports, chunks, and JavaScript URLs.
5. Continues recursively until the queue is empty or a configured limit is reached.
6. Saves the entry HTML and deduplicated JavaScript files.

Optional flags can add browser-assisted discovery, correlate statically extracted APIs with browser requests, or prepare downloaded code for static security review.

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

The optional `--audit-prep` feature requires Node.js 18 or newer in `PATH`. Its helper and dependencies are embedded in the JSpider binary, so users do not need to run `npm install`.

## Quick Start

```bash
jspider -u https://example.com
```

Output:

```text
output/
  example_com/
    entry.html
    js/
      app-a1b2c3d4.js
      chunk-e5f6a7b8.js
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

By default, JSpider saves only the entry HTML and downloaded JavaScript. It does not generate analysis reports, source map files, or formatted copies.

## Runtime API Discovery

Use `--api-discovery` to extract API candidates from downloaded JavaScript with jsluice and correlate them with requests observed in Chrome:

```bash
jspider -u https://example.com --api-discovery
jspider -u https://example.com --api-discovery --audit-prep
```

`--api-discovery` automatically enables the existing Headless/CDP flow; `--headless` does not automatically enable static API analysis. Chrome or Chromium must be available before the crawl starts.

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

JSpider does not replay requests or send additional probing requests. It never replays POST, PUT, PATCH, or DELETE requests and does not save response bodies. Browser-side page execution and safe clicks can still trigger application requests, so use this feature only on systems you are authorized to test.

Sensitive request headers such as `Authorization`, `Cookie`, `Set-Cookie`, and proxy authorization are never written. Common credential and session fields are stored as `[REDACTED]`; other values are truncated.

Output:

```text
output/
  example_com/
    runtime/
      requests.jsonl
    analysis/
      static-endpoints.jsonl
      endpoints.jsonl
      runtime-bases.json
```

All API discovery records use schema `version: 1`. JSONL output is deterministically sorted. Files are atomically replaced with `0600` permissions.

- `runtime/requests.jsonl` contains sanitized CDP requests, redirect hops, request phases, response status, failure state, and transfer size.
- `analysis/static-endpoints.jsonl` contains jsluice results, including the original URI, method, parameters, type, source JavaScript URL, and source snippet.
- `analysis/endpoints.jsonl` contains matched, `runtime_only`, and `static_only` endpoints plus resolved candidates derived from confirmed bases. Unobserved third-party URLs, query-only fragments, and document/example files are excluded from this correlated endpoint view; the raw jsluice evidence remains available in `static-endpoints.jsonl`.
- `analysis/runtime-bases.json` contains candidate and confirmed origins, prefixes, runtime bases, evidence counts, and matched pairs.

## Audit Preparation

Use `--audit-prep` when the downloaded JavaScript will be reviewed by a security auditor or analysis agent:

```bash
jspider -u https://example.com --audit-prep
```

This option keeps the same recursive discovery process but changes the saved JavaScript output.

For each JavaScript bundle, JSpider:

1. Uses its `sourceMappingURL` when present, including inline source maps.
2. If no source map is declared, tries the adjacent `<bundle-url>.map`.
3. If the map contains application `sourcesContent`, exports those source files.
4. Excludes obvious dependency and bundler runtime sources such as `node_modules`, Webpack runtime code, and Vite virtual modules.
5. If no usable application source is available, parses and regenerates the bundle as readable JavaScript while safely restoring simple static strings and wrappers.
6. If parsing fails, saves the original bundle under `failures/`.

JSpider does not execute target JavaScript, decoded strings, `eval`, `Function`, navigation, network calls, or browser-side behavior during preprocessing.

Output:

```text
output/
  example_com/
    entry.html
    audit/
      sources/
        src/
          app.ts
      bundles/
        chunk-e5f6a7b8.js
      failures/
        broken-f1e2d3c4.js
      manifest.json
```

Only directories that contain files are created. Successful source map recovery does not also save the compressed bundle. Generated readable bundles do not also save the original compressed file. Raw source maps are not saved.

The manifest records:

- Entry URL.
- JavaScript URL.
- Result status: `sourcemap`, `processed`, or `failed`.
- Source map URL and source map status.
- Final output paths.
- Processing error when applicable.

## Headless Discovery

```bash
jspider -u https://example.com --headless
jspider -u https://example.com --headless --audit-prep
```

`--headless` uses Chrome or Chromium to supplement static discovery with scripts observed at runtime.

Browser discovery can trigger page-side requests and limited safe-looking interactions. Use it only against systems where you have authorization. `--headless` alone preserves its previous JavaScript-discovery behavior and does not run jsluice or write API discovery reports.

## Options

| Option | Default | Description |
| --- | --- | --- |
| `-u <url>` | none | Entry URL. |
| `-l <file>` | none | File containing one entry URL per line. |
| `-o <dir>` | `output` | Output directory. |
| `--audit-prep` | `false` | Recover source map sources or generate readable JavaScript. |
| `--headless` | `false` | Add Chrome or Chromium browser discovery. |
| `--api-discovery` | `false` | Extract static APIs and correlate them with browser XHR/Fetch/EventSource requests; safely clicks bounded elements, requires CGO and Chrome/Chromium, and implies `--headless`. |
| `-n <count>` | unlimited | Maximum JavaScript files processed across the run. |
| `-d <depth>` | `10` | Maximum recursive discovery depth. |
| `-s <mb>` | unlimited | Maximum compressed and decompressed resource size; `0` disables the limit. |
| `-w <workers>` | `5` | Concurrent download workers. |
| `--same-origin` | `true` | Restrict discovery to the entry origin and allowed CDN domains. |
| `-c <domains>` | none | Comma-separated allowed CDN domains. |
| `--proxy <url>` | none | HTTP, HTTPS, or SOCKS5 proxy used by requests and headless Chrome. |
| `-t <seconds>` | `15` | HTTP timeout. |
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
- Starting a new run resets each affected site directory so previous crawler and audit-preparation outputs do not mix.
- API discovery outputs are written under each entry site's `runtime/` and `analysis/` directories.
- Legacy top-level report files and the old audit directory are removed when a run starts.

## Development

Run the Go checks:

```bash
CGO_ENABLED=1 go test ./...
CGO_ENABLED=1 go build ./...
CGO_ENABLED=0 go test ./...
CGO_ENABLED=0 go build ./...
go vet ./...
```

Rebuild the embedded audit helper after editing `tools/js-audit-prep/src/worker.js`:

```bash
cd tools/js-audit-prep
npm ci
npm run build
```

The build writes the bundled helper to `internal/preprocess/audit-prep.cjs`.
