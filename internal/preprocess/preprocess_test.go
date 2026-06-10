package preprocess

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExternalSourceMapRecoversApplicationSources(t *testing.T) {
	if err := CheckNodeRuntime(); err != nil {
		t.Skip(err)
	}

	siteDir := t.TempDir()
	mapBody := []byte(`{
		"version": 3,
		"sources": ["../../src/main.ts", "webpack:///node_modules/vue/index.js"],
		"sourcesContent": ["export const value = 1;", "vendor code"]
	}`)
	p := newTestProcessor(t, siteDir, func(rawURL string) ([]byte, error) {
		if rawURL != "https://example.com/assets/app.js.map" {
			t.Fatalf("unexpected map URL %q", rawURL)
		}
		return mapBody, nil
	})

	result := p.Process(
		"https://example.com/",
		"https://example.com/assets/app.js",
		[]byte("console.log(1);\n//# sourceMappingURL=app.js.map"),
	)
	if result.Failed || result.Status != "sourcemap" {
		t.Fatalf("Process() = %+v", result)
	}
	if len(result.Outputs) != 1 || result.Outputs[0] != "sources/src/main.ts" {
		t.Fatalf("outputs = %v", result.Outputs)
	}
	assertAuditFile(t, siteDir, "sources/src/main.ts")
	assertMissing(t, filepath.Join(siteDir, "audit", "bundles"))
	assertMissing(t, filepath.Join(siteDir, "audit", "failures"))
}

func TestInlineAndIndexedSourceMaps(t *testing.T) {
	if err := CheckNodeRuntime(); err != nil {
		t.Skip(err)
	}

	siteDir := t.TempDir()
	mapJSON := `{
		"version": 3,
		"sections": [
			{"offset":{"line":0,"column":0},"map":{
				"version":3,
				"sources":["src/app.tsx"],
				"sourcesContent":["export const App = () => <main />;"]
			}}
		]
	}`
	inline := "data:application/json;base64," + base64.StdEncoding.EncodeToString([]byte(mapJSON))
	p := newTestProcessor(t, siteDir, func(string) ([]byte, error) {
		t.Fatal("inline source map should not use fetch")
		return nil, nil
	})

	result := p.Process(
		"https://example.com/",
		"https://example.com/app.js",
		[]byte("console.log(1);\n//# sourceMappingURL="+inline),
	)
	if result.Status != "sourcemap" || len(result.Outputs) != 1 {
		t.Fatalf("Process() = %+v", result)
	}
	assertAuditFile(t, siteDir, "sources/src/app.tsx")
}

func TestAdjacentSourceMapProbe(t *testing.T) {
	if err := CheckNodeRuntime(); err != nil {
		t.Skip(err)
	}

	siteDir := t.TempDir()
	p := newTestProcessor(t, siteDir, func(rawURL string) ([]byte, error) {
		if rawURL != "https://example.com/app.js.map?version=1" {
			t.Fatalf("adjacent map URL = %q", rawURL)
		}
		return []byte(`{
			"version":3,
			"sources":["src/app.js"],
			"sourcesContent":["export default 1;"]
		}`), nil
	})

	result := p.Process(
		"https://example.com/",
		"https://example.com/app.js?version=1",
		[]byte("console.log(1);"),
	)
	if result.Status != "sourcemap" {
		t.Fatalf("Process() = %+v", result)
	}
}

func TestUnavailableSourceMapFallsBackToReadableBundle(t *testing.T) {
	if err := CheckNodeRuntime(); err != nil {
		t.Skip(err)
	}

	siteDir := t.TempDir()
	p := newTestProcessor(t, siteDir, func(string) ([]byte, error) {
		return nil, errors.New("HTTP 404")
	})
	body := []byte(`const table=["/api/value"];const value=atob("L2FwaS9iNjQ=");fetch(table[0]);`)
	result := p.Process("https://example.com/", "https://example.com/app.js", body)
	if result.Failed || result.Status != "processed" || len(result.Outputs) != 1 {
		t.Fatalf("Process() = %+v", result)
	}
	if string(result.AnalysisBody) != string(body) {
		t.Fatal("audit processing must not change the crawler discovery input")
	}
	output := readAuditFile(t, siteDir, result.Outputs[0])
	for _, want := range []string{`const value = "/api/b64";`, `fetch("/api/value");`} {
		if !strings.Contains(output, want) {
			t.Fatalf("processed output missing %q:\n%s", want, output)
		}
	}
	assertMissing(t, filepath.Join(siteDir, "audit", "sources"))
}

func TestVendorOnlySourceMapFallsBackToBundle(t *testing.T) {
	if err := CheckNodeRuntime(); err != nil {
		t.Skip(err)
	}

	siteDir := t.TempDir()
	p := newTestProcessor(t, siteDir, func(string) ([]byte, error) {
		return []byte(`{
			"version":3,
			"sources":["webpack:///node_modules/lib/index.js"],
			"sourcesContent":["export default 1;"]
		}`), nil
	})
	result := p.Process("https://example.com/", "https://example.com/app.js", []byte("const value=1;"))
	if result.Status != "processed" {
		t.Fatalf("Process() = %+v", result)
	}
	manifest := saveAndReadManifest(t, p, siteDir)
	if manifest.Files[0].SourceMapStatus != "no_application_sources" {
		t.Fatalf("source map status = %q", manifest.Files[0].SourceMapStatus)
	}
}

func TestParseFailureSavesOnlyFailureSource(t *testing.T) {
	if err := CheckNodeRuntime(); err != nil {
		t.Skip(err)
	}

	siteDir := t.TempDir()
	p := newTestProcessor(t, siteDir, func(string) ([]byte, error) {
		return nil, errors.New("HTTP 404")
	})
	body := []byte("function broken(")
	result := p.Process("https://example.com/", "https://example.com/broken.js", body)
	if !result.Failed || result.Status != "failed" || len(result.Outputs) != 1 {
		t.Fatalf("Process() = %+v", result)
	}
	if got := readAuditFile(t, siteDir, result.Outputs[0]); got != string(body) {
		t.Fatalf("failure output = %q", got)
	}
	assertMissing(t, filepath.Join(siteDir, "audit", "bundles"))
}

func TestManifestIsMinimalAndContentIsDeduplicated(t *testing.T) {
	if err := CheckNodeRuntime(); err != nil {
		t.Skip(err)
	}

	siteDir := t.TempDir()
	mapBody := []byte(`{
		"version":3,
		"sources":["src/shared.ts"],
		"sourcesContent":["export const shared = true;"]
	}`)
	p := newTestProcessor(t, siteDir, func(string) ([]byte, error) {
		return mapBody, nil
	})
	first := p.Process("https://first.example/", "https://cdn.example/a.js", []byte("//# sourceMappingURL=a.js.map"))
	second := p.Process("https://second.example/", "https://cdn.example/b.js", []byte("//# sourceMappingURL=b.js.map"))
	if first.Outputs[0] != second.Outputs[0] {
		t.Fatalf("deduplicated outputs differ: %v vs %v", first.Outputs, second.Outputs)
	}

	manifest := saveAndReadManifest(t, p, siteDir)
	if manifest.Version != 1 || len(manifest.Files) != 2 {
		t.Fatalf("manifest = %+v", manifest)
	}
	if _, err := os.Stat(filepath.Join(siteDir, "audit", "manifest.json")); err != nil {
		t.Fatalf("manifest missing: %v", err)
	}
	for _, unwanted := range []string{"indexes", "slices", "transform_log.json"} {
		assertMissing(t, filepath.Join(siteDir, "audit", unwanted))
	}
}

func TestMissingNodeProducesClearError(t *testing.T) {
	t.Setenv("PATH", "")
	if err := CheckNodeRuntime(); err == nil || err.Error() != NodeRuntimeError {
		t.Fatalf("CheckNodeRuntime() error = %v", err)
	}
	if p, err := New(t.TempDir(), nil); err == nil {
		_ = p.Close()
		t.Fatal("New() succeeded without Node.js")
	}
}

func newTestProcessor(t *testing.T, siteDir string, fetch FetchFunc) *Processor {
	t.Helper()
	p, err := New(siteDir, fetch)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() {
		_ = p.Close()
	})
	return p
}

func saveAndReadManifest(t *testing.T, p *Processor, siteDir string) Manifest {
	t.Helper()
	if err := p.Save(); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	var manifest Manifest
	data, err := os.ReadFile(filepath.Join(siteDir, "audit", "manifest.json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	return manifest
}

func assertAuditFile(t *testing.T, siteDir, rel string) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(siteDir, "audit", filepath.FromSlash(rel))); err != nil {
		t.Fatalf("expected audit file %s: %v", rel, err)
	}
}

func readAuditFile(t *testing.T, siteDir, rel string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(siteDir, "audit", filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read audit file %s: %v", rel, err)
	}
	return string(data)
}

func assertMissing(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected %s to be absent, stat error = %v", path, err)
	}
}
