package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Veincc/JSpider/internal/config"
	"github.com/Veincc/JSpider/internal/preprocess"
	"github.com/Veincc/JSpider/internal/urlutil"
)

func TestNormalModeOnlySavesEntryAndRecursiveJavaScript(t *testing.T) {
	server := newSiteServer(t, map[string]string{
		"/":                `<script src="/assets/app.js"></script>`,
		"/assets/app.js":   `import("./chunk.js");`,
		"/assets/chunk.js": `console.log("chunk");`,
	})
	defer server.Close()

	outDir := t.TempDir()
	cfg := testConfig(server.URL+"/", outDir)
	if err := run(cfg); err != nil {
		t.Fatalf("run() error = %v", err)
	}

	siteDir := filepath.Join(outDir, urlutil.SanitizeDomain(server.URL))
	assertPathExists(t, filepath.Join(siteDir, "entry.html"))
	if count := countFiles(t, filepath.Join(siteDir, "js")); count != 2 {
		t.Fatalf("saved JavaScript files = %d, want 2", count)
	}
	assertPathMissing(t, filepath.Join(siteDir, "audit"))
	assertNoLegacyReports(t, outDir)
}

func TestAuditModeUsesSourceMapsThenFallsBackToReadableBundle(t *testing.T) {
	if err := preprocess.CheckNodeRuntime(); err != nil {
		t.Skip(err)
	}

	server := newSiteServer(t, map[string]string{
		"/": `<script src="/app.js"></script>`,
		"/app.js": `import("./chunk.js");
//# sourceMappingURL=app.js.map`,
		"/app.js.map": `{
			"version":3,
			"sources":["src/main.ts","webpack:///node_modules/lib/index.js"],
			"sourcesContent":["export const main = true;","vendor"]
		}`,
		"/chunk.js": `const value=atob("L2FwaS9jaHVuaw==");console.log(value);`,
	})
	defer server.Close()

	outDir := t.TempDir()
	cfg := testConfig(server.URL+"/", outDir)
	cfg.AuditPrep = true
	if err := run(cfg); err != nil {
		t.Fatalf("run() error = %v", err)
	}

	siteDir := filepath.Join(outDir, urlutil.SanitizeDomain(server.URL))
	assertPathExists(t, filepath.Join(siteDir, "entry.html"))
	assertPathMissing(t, filepath.Join(siteDir, "js"))
	assertPathExists(t, filepath.Join(siteDir, "audit", "sources", "src", "main.ts"))
	if count := countFiles(t, filepath.Join(siteDir, "audit", "bundles")); count != 1 {
		t.Fatalf("processed bundles = %d, want 1", count)
	}
	assertPathMissing(t, filepath.Join(siteDir, "audit", "indexes"))
	assertPathMissing(t, filepath.Join(siteDir, "audit", "slices"))
	assertPathMissing(t, filepath.Join(siteDir, "audit", "transform_log.json"))

	manifest := readManifest(t, filepath.Join(siteDir, "audit", "manifest.json"))
	if len(manifest.Files) != 2 {
		t.Fatalf("manifest files = %d, want 2", len(manifest.Files))
	}
	statuses := make(map[string]string)
	for _, file := range manifest.Files {
		statuses[file.JSURL] = file.Status
	}
	if statuses[server.URL+"/app.js"] != "sourcemap" {
		t.Fatalf("app.js status = %q", statuses[server.URL+"/app.js"])
	}
	if statuses[server.URL+"/chunk.js"] != "processed" {
		t.Fatalf("chunk.js status = %q", statuses[server.URL+"/chunk.js"])
	}
	assertNoLegacyReports(t, outDir)
}

func TestAuditFailureSavesOriginalOnlyInFailures(t *testing.T) {
	if err := preprocess.CheckNodeRuntime(); err != nil {
		t.Skip(err)
	}

	server := newSiteServer(t, map[string]string{
		"/":          `<script src="/broken.js"></script>`,
		"/broken.js": `function broken(`,
	})
	defer server.Close()

	outDir := t.TempDir()
	cfg := testConfig(server.URL+"/", outDir)
	cfg.AuditPrep = true
	if err := run(cfg); err != nil {
		t.Fatalf("run() error = %v", err)
	}

	auditDir := filepath.Join(outDir, urlutil.SanitizeDomain(server.URL), "audit")
	if count := countFiles(t, filepath.Join(auditDir, "failures")); count != 1 {
		t.Fatalf("failure files = %d, want 1", count)
	}
	assertPathMissing(t, filepath.Join(auditDir, "bundles"))
	manifest := readManifest(t, filepath.Join(auditDir, "manifest.json"))
	if len(manifest.Files) != 1 || manifest.Files[0].Status != "failed" {
		t.Fatalf("manifest = %+v", manifest)
	}
}

func TestAllowedCDNJavaScriptBelongsToEntrySite(t *testing.T) {
	assetServer := newSiteServer(t, map[string]string{
		"/cdn.js": `console.log("cdn");`,
	})
	defer assetServer.Close()

	entryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<script src="%s/cdn.js"></script>`, assetServer.URL)
	}))
	defer entryServer.Close()

	entryURL := strings.Replace(entryServer.URL, "127.0.0.1", "localhost", 1) + "/"
	outDir := t.TempDir()
	cfg := testConfig(entryURL, outDir)
	cfg.AllowCDN = []string{"127.0.0.1"}
	if err := run(cfg); err != nil {
		t.Fatalf("run() error = %v", err)
	}

	entrySite := filepath.Join(outDir, "localhost", "js")
	if count := countFiles(t, entrySite); count != 1 {
		t.Fatalf("entry-site JavaScript files = %d, want 1", count)
	}
	assertPathMissing(t, filepath.Join(outDir, "127_0_0_1"))
}

func TestMultipleEntrySitesAreIsolated(t *testing.T) {
	first := newSiteServer(t, map[string]string{
		"/":         `<script src="/first.js"></script>`,
		"/first.js": `console.log("first");`,
	})
	defer first.Close()
	second := newSiteServer(t, map[string]string{
		"/":          `<script src="/second.js"></script>`,
		"/second.js": `console.log("second");`,
	})
	defer second.Close()

	listPath := filepath.Join(t.TempDir(), "urls.txt")
	secondURL := strings.Replace(second.URL, "127.0.0.1", "localhost", 1) + "/"
	if err := os.WriteFile(listPath, []byte(secondURL+"\n"), 0644); err != nil {
		t.Fatalf("write URL list: %v", err)
	}

	outDir := t.TempDir()
	cfg := testConfig(first.URL+"/", outDir)
	cfg.URLList = listPath
	if err := run(cfg); err != nil {
		t.Fatalf("run() error = %v", err)
	}

	if count := countFiles(t, filepath.Join(outDir, "127_0_0_1", "js")); count != 1 {
		t.Fatalf("first site JavaScript files = %d, want 1", count)
	}
	if count := countFiles(t, filepath.Join(outDir, "localhost", "js")); count != 1 {
		t.Fatalf("second site JavaScript files = %d, want 1", count)
	}
}

func TestRunRemovesLegacyAndPreviousModeOutputs(t *testing.T) {
	server := newSiteServer(t, map[string]string{
		"/":       `<script src="/app.js"></script>`,
		"/app.js": `console.log("app");`,
	})
	defer server.Close()

	outDir := t.TempDir()
	site := urlutil.SanitizeDomain(server.URL)
	for _, stale := range []string{
		"js.txt",
		"dynamic_imports.json",
		"route_chunk_map.json",
		"sourcemaps.txt",
		"framework_detect.json",
		"analysis_errors.log",
		"audit_bundle/manifest.json",
		filepath.Join(site, "audit", "manifest.json"),
	} {
		path := filepath.Join(outDir, stale)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatalf("MkdirAll stale path: %v", err)
		}
		if err := os.WriteFile(path, []byte("stale"), 0644); err != nil {
			t.Fatalf("write stale path: %v", err)
		}
	}

	if err := run(testConfig(server.URL+"/", outDir)); err != nil {
		t.Fatalf("run() error = %v", err)
	}
	assertNoLegacyReports(t, outDir)
	assertPathMissing(t, filepath.Join(outDir, site, "audit"))
}

func TestCLIAndDocumentationRemoveLegacyFlagsAndReports(t *testing.T) {
	configSource, err := os.ReadFile(filepath.Join("..", "..", "internal", "config", "config.go"))
	if err != nil {
		t.Fatalf("read config.go: %v", err)
	}
	configText := string(configSource)
	for _, removed := range []string{
		`"m"`,
		`"b"`,
		`"insecure-skip-verify"`,
		"FetchSourcemap",
		"AuditPrepAlias",
	} {
		if strings.Contains(configText, removed) {
			t.Fatalf("config still contains removed CLI behavior %q", removed)
		}
	}

	readme, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	readmeText := string(readme)
	for _, removed := range []string{
		"js.txt",
		"dynamic_imports.json",
		"route_chunk_map.json",
		"framework_detect.json",
		"indexes/",
		"slices/",
		"transform_log.json",
		"`-m`",
		"`-b`",
		"`--insecure-skip-verify`",
	} {
		if strings.Contains(readmeText, removed) {
			t.Fatalf("README still contains removed output or flag %q", removed)
		}
	}
	for _, required := range []string{"`--insecure`", "`--proxy <url>`", "| `-d <depth>` | `10`", "| `-s <mb>` | unlimited"} {
		if !strings.Contains(readmeText, required) {
			t.Fatalf("README is missing %q", required)
		}
	}
}

func TestBuildHeadlessConfigIncludesNetworkOptions(t *testing.T) {
	cfg := &config.Config{
		Timeout:            21,
		SameOrigin:         true,
		AllowCDN:           []string{"cdn.example.com"},
		Verbose:            true,
		InsecureSkipVerify: true,
		Proxy:              "socks5://127.0.0.1:1080",
	}

	got := buildHeadlessConfig(cfg, "https://example.com")
	if got.Timeout.String() != "21s" {
		t.Fatalf("Timeout = %s, want 21s", got.Timeout)
	}
	if !got.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify = false, want true")
	}
	if got.Proxy != cfg.Proxy {
		t.Fatalf("Proxy = %q, want %q", got.Proxy, cfg.Proxy)
	}
}

func testConfig(entryURL, outDir string) *config.Config {
	return &config.Config{
		URL:        entryURL,
		OutDir:     outDir,
		MaxJS:      100,
		MaxDepth:   config.DefaultMaxDepth,
		MaxSizeMB:  config.DefaultMaxSizeMB,
		Workers:    2,
		SameOrigin: true,
		Timeout:    5,
		UserAgent:  "JSpider-Test/1.0",
	}
}

func newSiteServer(t *testing.T, routes map[string]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := routes[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if strings.HasSuffix(r.URL.Path, ".map") {
			w.Header().Set("Content-Type", "application/json")
		} else if strings.HasSuffix(r.URL.Path, ".js") {
			w.Header().Set("Content-Type", "application/javascript")
		} else {
			w.Header().Set("Content-Type", "text/html")
		}
		_, _ = w.Write([]byte(body))
	}))
}

func readManifest(t *testing.T, path string) preprocess.Manifest {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var manifest preprocess.Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	return manifest
}

func countFiles(t *testing.T, root string) int {
	t.Helper()
	count := 0
	err := filepath.WalkDir(root, func(_ string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			count++
		}
		return nil
	})
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		t.Fatalf("WalkDir %s: %v", root, err)
	}
	return count
}

func assertNoLegacyReports(t *testing.T, outDir string) {
	t.Helper()
	for _, name := range []string{
		"analysis_errors.log",
		"js.txt",
		"dynamic_imports.json",
		"route_chunk_map.json",
		"sourcemaps.txt",
		"framework_detect.json",
		"audit_bundle",
	} {
		assertPathMissing(t, filepath.Join(outDir, name))
	}
}

func assertPathExists(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected %s: %v", path, err)
	}
}

func assertPathMissing(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected %s to be absent, stat error = %v", path, err)
	}
}
