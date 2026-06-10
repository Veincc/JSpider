# JSpider

JSpider discovers and downloads JavaScript used by modern web applications.

It has two modes:

- Normal mode recursively downloads JavaScript and saves the original files.
- Audit preparation mode recovers application source code from source maps when possible, otherwise it generates a readable statically simplified bundle.

## Installation

Install the latest version:

```bash
go install github.com/Veincc/JSpider/cmd/jspider@latest
```

Or build from the repository:

```bash
go build -o jspider ./cmd/jspider
```

Normal mode is Go-only. Audit preparation requires Node.js 18 or newer in `PATH`. The Node helper and its dependencies are embedded in the JSpider binary; users do not need to run `npm install`.

## Normal Mode

```bash
jspider -u https://example.com
```

Normal mode:

1. Downloads the entry HTML.
2. Finds JavaScript referenced by the page.
3. Downloads each JavaScript file.
4. Extracts additional import and chunk URLs needed to continue discovery.
5. Recursively downloads those files.
6. Saves only the entry HTML and deduplicated original JavaScript.

Output:

```text
output/
  example_com/
    entry.html
    js/
      app-a1b2c3d4.js
      chunk-e5f6a7b8.js
```

Normal mode does not generate analysis reports, source map output, formatted copies, or audit artifacts.

## Audit Preparation

```bash
jspider -u https://example.com --audit-prep
```

Audit preparation performs the same recursive JavaScript discovery, but changes how downloaded code is saved.

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

`--headless` uses Chrome or Chromium to supplement static discovery with scripts observed at runtime. It is optional in both modes.

Browser discovery can trigger page-side requests and limited safe-looking interactions. Use it only against systems where you have authorization.

## Options

| Option | Default | Description |
| --- | --- | --- |
| `-u <url>` | none | Entry URL. |
| `-l <file>` | none | File containing one entry URL per line. |
| `-o <dir>` | `output` | Output directory. |
| `--audit-prep` | `false` | Recover source map sources or generate readable JavaScript. |
| `--headless` | `false` | Add Chrome or Chromium browser discovery. |
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

## Output Rules

- Files discovered through an allowed CDN are stored under the entry site's directory.
- Identical JavaScript content is saved once per entry site.
- Multiple entry sites receive separate self-contained directories.
- Starting a new run resets each affected site directory so normal and audit outputs do not mix.
- Legacy top-level report files and the old audit directory are removed when a run starts.

## Development

Run the Go checks:

```bash
go test ./...
go build ./...
go vet ./...
```

Rebuild the embedded audit helper after editing `tools/js-audit-prep/src/worker.js`:

```bash
cd tools/js-audit-prep
npm ci
npm run build
```

The build writes the bundled helper to `internal/preprocess/audit-prep.cjs`.
