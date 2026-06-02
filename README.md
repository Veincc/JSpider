# JSpider

JSpider is a command-line tool for discovering JavaScript assets from modern web applications. It starts from one or more entry URLs, extracts JavaScript references from HTML, downloads confirmed JavaScript resources, analyzes them for additional chunks and route-related imports, and writes deterministic output files for review.

The default mode is static analysis. The optional `--headless` flag adds Chrome/Chromium-based browser discovery for applications that load scripts after page execution.

## Core Capabilities

- Extracts entry JavaScript from `<script src>`, `modulepreload`, script preloads, prefetches, and selected inline script references.
- Downloads JavaScript with configurable timeout, worker count, per-file size limit, custom headers, cookies, and User-Agent.
- Handles gzip, deflate, and Brotli responses with decompressed-size protection.
- Identifies JavaScript by URL path, Content-Type, and conservative content sniffing for extensionless resources.
- Analyzes JavaScript for dynamic `import(...)`, route-to-chunk hints, source maps, and framework-specific patterns.
- Includes analyzers for common Vite, Webpack, Next.js, Nuxt, Angular, and generic bundled JavaScript patterns.
- Deduplicates URLs globally across entry points and writes stable, sorted result files.

## Static Analysis Default

Static analysis is always enabled and is the default behavior:

```bash
jspider -u https://example.com
```

In this mode JSpider downloads the entry HTML, extracts JavaScript references visible in the HTML, downloads JavaScript resources that pass the configured origin policy, and recursively analyzes discovered JavaScript up to the configured depth and count limits.

Static analysis does not execute page JavaScript. It is safer and more predictable than browser-assisted discovery, but it may miss scripts that are injected only after client-side rendering, interaction, or API responses.

## Headless Discovery

Use `--headless` to add Chrome/Chromium-based discovery:

```bash
jspider -u https://example.com --headless
```

When enabled, JSpider starts a headless Chrome/Chromium session, observes script network requests and JavaScript Content-Type responses, extracts script references from the rendered DOM, scrolls the page, and performs a limited number of cautious clicks on same-origin, non-dangerous elements.

Requirements and boundaries:

- Chrome or Chromium must be installed and available in `PATH`.
- Discovery is bounded by the configured timeout and may return partial results when pages load slowly.
- Some applications require authentication, feature flags, anti-bot checks, consent flows, or user interaction that JSpider cannot safely complete.
- Browser execution can trigger page-side requests and limited same-origin clicks. Use it only against systems where you have authorization.
- JSpider deliberately skips elements that look state-changing, such as logout, delete, submit, save, pay, purchase, unsubscribe, approve, accept, or confirm actions. This is a safety guard, not a guarantee.

## Installation

Build from source:

```bash
go build -o jspider ./cmd/jspider
```

Run the built binary:

```bash
./jspider -u https://example.com
```

Or run directly with Go:

```bash
go run ./cmd/jspider -u https://example.com
```

Optional beautification requires `js-beautify`:

```bash
npm install -g js-beautify
```

## Quick Start

Analyze one site with default static analysis:

```bash
jspider -u https://example.com
```

Write output to a custom directory:

```bash
jspider -u https://example.com -o results
```

Analyze multiple URLs from a file:

```bash
jspider -l urls.txt
```

Enable browser-assisted discovery:

```bash
jspider -u https://example.com --headless
```

Allow a known CDN while keeping same-origin filtering enabled:

```bash
jspider -u https://example.com -c cdn.example.com,static.example.net
```

## CLI Options

| Option | Default | Description |
| --- | --- | --- |
| `-u <url>` | none | Start URL. URLs without a scheme default to `https://`. |
| `-l <file>` | none | URL list file, one URL per line. Blank lines and `#` comments are ignored. |
| `-o <dir>` | `output` | Output directory. |
| `--headless` | `false` | Enable Chrome/Chromium-based discovery in addition to static analysis. |
| `-n <count>` | `0` | Maximum JavaScript files to analyze. `0` means unlimited. |
| `-d <depth>` | `6` | Maximum recursive discovery depth. |
| `-s <mb>` | `10` | Maximum compressed and decompressed download size per resource, in MB. |
| `-w <workers>` | `5` | Concurrent download workers. |
| `--same-origin` | `true` | Restrict analysis to the entry origin plus domains allowed with `-c`. Use `--same-origin=false` to disable. |
| `-c <domains>` | none | Comma-separated allowed CDN or static asset domains. Subdomains are allowed. |
| `-m` | `false` | Download and parse discovered source maps. |
| `-t <seconds>` | `15` | HTTP request timeout and `--headless` discovery budget. |
| `-a <ua>` | Chrome-like UA | Custom User-Agent. |
| `-k <cookie>` | none | Optional Cookie header value. |
| `-H <headers>` | none | Extra headers as `Header1=Value1;Header2=Value2`. |
| `-b` | `false` | Beautify saved JavaScript with `js-beautify` when installed. |
| `-v` | `false` | Enable verbose logs. |

## Output Files

JSpider writes results under the configured output directory:

| Path | Description |
| --- | --- |
| `js.txt` | Sorted list of confirmed and candidate JavaScript URLs. |
| `dynamic_imports.json` | Extracted dynamic import records, including resolved URLs when available. |
| `route_chunk_map.json` | Route and component hints associated with lazy chunks. |
| `sourcemaps.txt` | Source map discovery and parsing status. |
| `framework_detect.json` | Framework detection results and supporting reasons. |
| `analysis_errors.log` | Download and analysis errors captured during execution. |
| `<domain>/entry.html` | Raw entry HTML saved per entry domain. |
| `<domain>/*.js` | Downloaded JavaScript bodies, optionally beautified. |
| `<domain>/*.map` | Downloaded source maps when `-m` is enabled. |

## Examples

Static analysis with a hard JavaScript count limit:

```bash
jspider -u https://example.com -n 100
```

Use cookies and a custom header:

```bash
jspider -u https://example.com -k "session=SESSION_VALUE" -H "X-Test=1;Accept-Language=en-US"
```

Increase recursion depth and workers:

```bash
jspider -u https://example.com -d 8 -w 10
```

Fetch source maps and beautify saved JavaScript:

```bash
jspider -u https://example.com -m -b
```

Disable same-origin filtering:

```bash
jspider -u https://example.com --same-origin=false
```

## How It Works

1. Parse CLI options and normalize entry URLs.
2. Download entry HTML and save it under the output directory.
3. Extract static JavaScript references from HTML tags and inline script strings.
4. Optionally run `--headless` discovery and merge browser-discovered assets.
5. Apply same-origin and allowed-CDN policy.
6. Download JavaScript resources concurrently with caching and in-flight request deduplication.
7. Validate HTTP status, size limits, decompression limits, and JavaScript identity.
8. Save JavaScript bodies and analyze imports, chunks, routes, frameworks, and source maps.
9. Queue newly discovered JavaScript until depth or count limits are reached.
10. Write deterministic result files.

## Limits And Known Boundaries

- Static analysis cannot see scripts created only after page execution.
- `--headless` discovery is best-effort and bounded by timeout, browser availability, site behavior, and safe interaction rules.
- JavaScript parsing combines framework heuristics, regex extraction, and AST analysis; minified or obfuscated bundles may still hide relationships.
- Dynamic import expressions with variables, template expressions, import maps, or bare module specifiers may be recorded without a resolved URL.
- Same-origin matching is scheme and host exact for the entry origin. Allowed CDN entries match the specified domain and its subdomains.
- Content sniffing is intentionally conservative. Extensionless JavaScript can be missed if it lacks recognizable JavaScript indicators.
- Duplicate content is saved once by content hash, even if multiple URLs return identical bodies.
- JSpider does not authenticate, solve challenges, bypass access controls, or guarantee complete asset coverage.

## Authorized Use

Use JSpider only on applications and infrastructure you own or are explicitly authorized to assess. The tool downloads resources, may send authenticated headers or cookies when configured, and can run a browser session with limited interaction when `--headless` is enabled. You are responsible for complying with applicable laws, contracts, rules of engagement, and site policies.

## Development And Testing

Run the test suite:

```bash
go test ./...
```

Build the CLI:

```bash
go build -o jspider ./cmd/jspider
```

Optional checks before release:

```bash
go test ./...
go build ./...
go vet ./...
```

The headless integration test is opt-in because it requires Chrome/Chromium and network/browser behavior:

```bash
JSPIDER_HEADLESS_TEST=1 go test ./internal/headless
```
