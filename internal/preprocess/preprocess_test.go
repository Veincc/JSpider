package preprocess

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	if version := os.Getenv("JSPIDER_TEST_NODE_VERSION"); version != "" {
		_, _ = os.Stdout.WriteString(version + "\n")
		os.Exit(0)
	}
	os.Exit(m.Run())
}

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
	if len(result.Outputs) != 1 || result.Outputs[0] != "js/src/main.ts" {
		t.Fatalf("outputs = %v", result.Outputs)
	}
	assertOutputFile(t, siteDir, "js/src/main.ts")
	assertMissing(t, filepath.Join(siteDir, "audit"))
}

func TestExtractSourceMapReferenceAllowsAsterisk(t *testing.T) {
	source := `console.log(1);
//# sourceMappingURL=https://cdn.example/assets/v2*beta/app.js.map`
	want := "https://cdn.example/assets/v2*beta/app.js.map"
	if got := extractSourceMapReference(source); got != want {
		t.Fatalf("extractSourceMapReference() = %q, want %q", got, want)
	}
}

func TestExtractSourceMapReferenceTrimsBlockComment(t *testing.T) {
	source := `console.log(1);
/*# sourceMappingURL=maps/app*beta.js.map */`
	want := "maps/app*beta.js.map"
	if got := extractSourceMapReference(source); got != want {
		t.Fatalf("extractSourceMapReference() = %q, want %q", got, want)
	}
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
	assertOutputFile(t, siteDir, "js/src/app.tsx")
	assertMissing(t, filepath.Join(siteDir, "audit"))
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
	if !strings.HasPrefix(result.Outputs[0], "js/") || !strings.HasSuffix(result.Outputs[0], ".js") {
		t.Fatalf("processed output = %q", result.Outputs[0])
	}
	output := readOutputFile(t, siteDir, result.Outputs[0])
	for _, want := range []string{`const value = "/api/b64";`, `fetch("/api/value");`} {
		if !strings.Contains(output, want) {
			t.Fatalf("processed output missing %q:\n%s", want, output)
		}
	}
	assertMissing(t, filepath.Join(siteDir, "audit"))
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
	if result.Failed || result.Status != "processed" || len(result.Outputs) != 1 {
		t.Fatalf("Process() = %+v", result)
	}
	assertOutputFile(t, siteDir, result.Outputs[0])
	assertMissing(t, filepath.Join(siteDir, "audit"))
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
	if got := readOutputFile(t, siteDir, result.Outputs[0]); got != string(body) {
		t.Fatalf("failure output = %q", got)
	}
	if count := countOutputFiles(t, filepath.Join(siteDir, "js")); count != 1 {
		t.Fatalf("fallback files = %d, want 1", count)
	}
	assertMissing(t, filepath.Join(siteDir, "audit"))
}

func TestProcessedOutputsAreDeduplicatedWithoutManifest(t *testing.T) {
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
	if !reflect.DeepEqual(first.Outputs, second.Outputs) {
		t.Fatalf("deduplicated outputs differ: %v vs %v", first.Outputs, second.Outputs)
	}
	if count := countOutputFiles(t, filepath.Join(siteDir, "js")); count != 1 {
		t.Fatalf("deduplicated files = %d, want 1", count)
	}
	assertMissing(t, filepath.Join(siteDir, "audit"))
	assertMissing(t, filepath.Join(siteDir, "manifest.json"))
}

func TestSourcePathCollisionPreservesBothContents(t *testing.T) {
	if err := CheckNodeRuntime(); err != nil {
		t.Fatal(err)
	}
	siteDir := t.TempDir()
	maps := map[string][]byte{
		"https://example.com/a.js.map": []byte(`{"version":3,"sources":["src/shared.ts"],"sourcesContent":["export const value = 1;"]}`),
		"https://example.com/b.js.map": []byte(`{"version":3,"sources":["src/shared.ts"],"sourcesContent":["export const value = 2;"]}`),
	}
	p := newTestProcessor(t, siteDir, func(rawURL string) ([]byte, error) { return maps[rawURL], nil })
	first := p.Process("https://example.com/", "https://example.com/a.js", []byte("//# sourceMappingURL=a.js.map"))
	second := p.Process("https://example.com/", "https://example.com/b.js", []byte("//# sourceMappingURL=b.js.map"))
	if len(first.Outputs) != 1 || len(second.Outputs) != 1 || first.Outputs[0] == second.Outputs[0] {
		t.Fatalf("collision outputs = %v and %v", first.Outputs, second.Outputs)
	}
	if got := readOutputFile(t, siteDir, first.Outputs[0]); got != "export const value = 1;" {
		t.Fatalf("first collision output = %q", got)
	}
	if got := readOutputFile(t, siteDir, second.Outputs[0]); got != "export const value = 2;" {
		t.Fatalf("second collision output = %q", got)
	}
}

func TestProcessedOutputIsAtomicAndUsesJavaScriptPermissions(t *testing.T) {
	if err := CheckNodeRuntime(); err != nil {
		t.Fatal(err)
	}
	siteDir := t.TempDir()
	p := newTestProcessor(t, siteDir, func(string) ([]byte, error) { return nil, errors.New("404") })
	result := p.Process("https://example.com/", "https://example.com/app.js", []byte("const value=1;"))
	if len(result.Outputs) != 1 {
		t.Fatalf("Process() = %+v", result)
	}
	info, err := os.Stat(filepath.Join(siteDir, filepath.FromSlash(result.Outputs[0])))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0644 {
		t.Fatalf("mode = %o, want 644", info.Mode().Perm())
	}
	temps, err := filepath.Glob(filepath.Join(siteDir, "js", ".*.tmp-*"))
	if err != nil || len(temps) != 0 {
		t.Fatalf("temporary outputs = %v, error = %v", temps, err)
	}
}

func TestMissingNodeProducesClearGlobalError(t *testing.T) {
	t.Setenv("PATH", "")
	if err := CheckNodeRuntime(); err == nil || err.Error() != NodeRuntimeError {
		t.Fatalf("CheckNodeRuntime() error = %v", err)
	}
	if p, err := New(t.TempDir(), nil); err == nil {
		_ = p.Close()
		t.Fatal("New() succeeded without Node.js")
	}
}

func TestNodeOlderThan18ProducesClearError(t *testing.T) {
	dir := t.TempDir()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	nodeName := "node"
	if runtime.GOOS == "windows" {
		nodeName += ".exe"
	}
	node := filepath.Join(dir, nodeName)
	if runtime.GOOS == "windows" {
		binary, readErr := os.ReadFile(executable)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if writeErr := os.WriteFile(node, binary, 0755); writeErr != nil {
			t.Fatal(writeErr)
		}
	} else if err := os.Link(executable, node); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("JSPIDER_TEST_NODE_VERSION", "v17.9.1")
	if err := CheckNodeRuntime(); err == nil || err.Error() != NodeVersionError {
		t.Fatalf("CheckNodeRuntime() error = %v", err)
	}
}

func newTestProcessor(t *testing.T, siteDir string, fetch func(string) ([]byte, error)) *Processor {
	t.Helper()
	var fetchForEntry FetchFunc
	if fetch != nil {
		fetchForEntry = func(_ string, rawURL string) ([]byte, error) {
			return fetch(rawURL)
		}
	}
	p, err := New(siteDir, fetchForEntry)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() {
		_ = p.Close()
	})
	return p
}

func assertOutputFile(t *testing.T, siteDir, rel string) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(siteDir, filepath.FromSlash(rel))); err != nil {
		t.Fatalf("expected output %s: %v", rel, err)
	}
}

func readOutputFile(t *testing.T, siteDir, rel string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(siteDir, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read output %s: %v", rel, err)
	}
	return string(data)
}

func countOutputFiles(t *testing.T, root string) int {
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
		t.Fatal(err)
	}
	return count
}

func assertMissing(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected %s to be absent, stat error = %v", path, err)
	}
}
