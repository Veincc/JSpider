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

## Runtime API Discovery

Use `--api-discovery` to extract API candidates from downloaded JavaScript with jsluice and correlate them with requests observed in Chrome:

```bash
jspider -u https://example.com --api-discovery
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
    js/
      app-a1b2c3d4.js
      src/
        feature.ts
    js-map.txt
    endpoints.txt
```

`endpoints.txt` exists only in API Discovery mode. It contains one absolute HTTP(S) URL per line, with fragments removed and query strings preserved. Rows are deduplicated, sorted, atomically replaced, and written with `0600` permissions. An API run with no final endpoints creates a zero-byte file.

Static extraction, runtime capture, association evidence, base inference, and the final report remain available in memory during the run. JSpider does not persist API intermediate JSON or JSONL reports.

## Processed JavaScript Output

Every mode uses the same JavaScript processing pipeline. There is no opt-out flag.

For each JavaScript bundle, JSpider:

1. Uses its `sourceMappingURL` when present, including inline source maps.
2. If no source map is declared, tries the adjacent `<bundle-url>.map`.
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

Successful source-map recovery does not also save the compressed bundle. Generated readable bundles do not also save the original compressed file. Raw source maps are not saved. A parsing failure writes the original bundle only once, directly beneath `js/`.

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

## Options

| Option | Default | Description |
| --- | --- | --- |
| `-u <url>` | none | Entry URL. |
| `-l <file>` | none | File containing one entry URL per line. |
| `-o <dir>` | `output` | Output directory. |
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
- Multiple entry URLs for the same site accumulate into one site map and one optional endpoint file.
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
