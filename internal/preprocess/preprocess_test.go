package preprocess

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if mode := os.Getenv("JSPIDER_FAKE_NODE_MODE"); mode != "" {
		runFakeNode(mode)
		os.Exit(0)
	}
	if version := os.Getenv("JSPIDER_TEST_NODE_VERSION"); version != "" {
		_, _ = os.Stdout.WriteString(version + "\n")
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func runFakeNode(mode string) {
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		if mode == "version_hang" {
			time.Sleep(time.Hour)
		}
		_, _ = os.Stdout.WriteString("v20.1.0\n")
		return
	}

	instance := incrementFakeNodeStarts(os.Getenv("JSPIDER_FAKE_NODE_STATE"))
	scanner := bufio.NewScanner(os.Stdin)
	encoder := json.NewEncoder(os.Stdout)
	for scanner.Scan() {
		var request workerRequest
		if err := json.Unmarshal(scanner.Bytes(), &request); err != nil {
			_ = encoder.Encode(workerResponse{ID: 0, OK: false, Error: err.Error()})
			continue
		}
		switch request.Command {
		case "ping":
			if mode == "ping_hang" {
				time.Sleep(time.Hour)
			}
			_ = encoder.Encode(workerResponse{ID: request.ID, OK: true, NodeVersion: "20.1.0"})
		case "shutdown":
			return
		default:
			if marker := os.Getenv("JSPIDER_FAKE_NODE_REQUEST_FILE"); marker != "" {
				_ = os.WriteFile(marker, []byte("received"), 0600)
			}
			if mode == "process_hang_first" && instance == 1 {
				time.Sleep(time.Hour)
			}
			responseID := request.ID
			if mode == "wrong_id_first" && instance == 1 {
				responseID++
			}
			if mode == "missing_code_first" && instance == 1 {
				_ = encoder.Encode(map[string]any{"id": responseID, "ok": true})
				continue
			}
			if mode == "missing_ok_first" && instance == 1 {
				_ = encoder.Encode(map[string]any{"id": responseID, "code": request.Source + "\n"})
				continue
			}
			_ = encoder.Encode(workerResponse{ID: responseID, OK: true, Code: request.Source + "\n"})
		}
	}
}

func incrementFakeNodeStarts(path string) int {
	data, _ := os.ReadFile(path)
	count, _ := strconv.Atoi(strings.TrimSpace(string(data)))
	count++
	_ = os.WriteFile(path, []byte(strconv.Itoa(count)), 0600)
	return count
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

func TestCompleteSourceMapUsesRecoveredAnalysisUnits(t *testing.T) {
	if err := CheckNodeRuntime(); err != nil {
		t.Skip(err)
	}

	const bundleURL = "https://cdn.example/assets/app.js"
	p := newTestProcessor(t, t.TempDir(), func(string) ([]byte, error) {
		return []byte(`{
			"version":3,
			"sources":["https://sources.example/src/app.ts","webpack:///src/local.ts","webpack:///node_modules/lib/index.js"],
			"sourcesContent":["export const app = 1;","export const local = 2;","vendor"]
		}`), nil
	})

	result := p.Process("https://example.com/", bundleURL, []byte("bundle\n//# sourceMappingURL=app.js.map"))
	if result.Failed || len(result.Analysis) != 2 {
		t.Fatalf("Process() = %+v", result)
	}
	want := []AnalysisUnit{
		{SourceName: "https://sources.example/src/app.ts", BaseURL: "https://sources.example/src/app.ts", Body: []byte("export const app = 1;")},
		{SourceName: "webpack:///src/local.ts", BaseURL: bundleURL, Body: []byte("export const local = 2;")},
	}
	if !reflect.DeepEqual(result.Analysis, want) {
		t.Fatalf("analysis = %#v, want %#v", result.Analysis, want)
	}
}

func TestRecoveredHTTPBaseURLSchemeIsCaseInsensitive(t *testing.T) {
	files := []sourceFile{{Name: "HTTPS://sources.example/src/app.ts", Content: "export default true;", HasContent: true}}
	units := recoveredAnalysis("https://example.com/app.js", files)
	if len(units) != 1 || units[0].BaseURL != files[0].Name {
		t.Fatalf("recoveredAnalysis() = %#v", units)
	}
}

func TestPartialSourceMapPersistsUsableSourcesButAnalyzesOnlyOriginal(t *testing.T) {
	if err := CheckNodeRuntime(); err != nil {
		t.Skip(err)
	}

	siteDir := t.TempDir()
	p := newTestProcessor(t, siteDir, func(string) ([]byte, error) {
		return []byte(`{
			"version":3,
			"sources":["src/available.ts","src/missing.ts"],
			"sourcesContent":["export const available = true;",null]
		}`), nil
	})
	body := []byte("const original = true;\n//# sourceMappingURL=app.js.map")
	result := p.Process("https://example.com/", "https://example.com/app.js", body)
	assertOriginalAnalysis(t, result, "https://example.com/app.js", body)
	if len(result.Outputs) != 1 || readOutputFile(t, siteDir, result.Outputs[0]) != "export const available = true;" {
		t.Fatalf("partial map outputs = %v", result.Outputs)
	}
}

func TestSourceMapFileCapFallsBackToOriginalAnalysis(t *testing.T) {
	if err := CheckNodeRuntime(); err != nil {
		t.Skip(err)
	}

	sources := make([]string, 513)
	contents := make([]string, 513)
	for i := range sources {
		sources[i] = fmt.Sprintf("src/file-%03d.js", i)
		contents[i] = fmt.Sprintf("export default %d;", i)
	}
	mapBody, err := json.Marshal(map[string]any{
		"version": 3, "sources": sources, "sourcesContent": contents,
	})
	if err != nil {
		t.Fatal(err)
	}
	p := newTestProcessor(t, t.TempDir(), func(string) ([]byte, error) { return mapBody, nil })
	body := []byte("const original = true;\n//# sourceMappingURL=app.js.map")
	result := p.Process("https://example.com/", "https://example.com/app.js", body)
	assertOriginalAnalysis(t, result, "https://example.com/app.js", body)
	if len(result.Outputs) != 513 {
		t.Fatalf("persisted outputs = %d, want 513", len(result.Outputs))
	}
}

func TestSourceMapAggregateContentCapRejectsRecoveredAnalysis(t *testing.T) {
	chunk := strings.Repeat("x", 1024*1024)
	collection := sourceMapCollection{Complete: true, Files: make([]sourceFile, 65)}
	for i := range collection.Files {
		collection.Files[i] = sourceFile{
			Name:       fmt.Sprintf("src/file-%02d.js", i),
			Content:    chunk,
			HasContent: true,
		}
	}
	recovery, _ := applicationRecovery(collection)
	if recovery.Complete {
		t.Fatal("65 MiB of recovered source was accepted for analysis")
	}
	if recovery.ContentSize != 65*1024*1024 {
		t.Fatalf("aggregate content = %d", recovery.ContentSize)
	}
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

func TestExtractSourceMapReferenceIgnoresStringAndTemplateLiterals(t *testing.T) {
	source := `
const quoted = "//# sourceMappingURL=quoted.js.map";
const blocked = '/*# sourceMappingURL=blocked.js.map */';
const templated = ` + "`//# sourceMappingURL=templated.js.map`" + `;
`
	if got := extractSourceMapReference(source); got != "" {
		t.Fatalf("extractSourceMapReference() = %q, want no reference", got)
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

func TestIndexedSourceMapResolvesSectionURLsRelativeToEachParent(t *testing.T) {
	if err := CheckNodeRuntime(); err != nil {
		t.Skip(err)
	}

	maps := map[string][]byte{
		"https://example.com/maps/root.map": []byte(`{
			"version":3,
			"sections":[
				{"map":{"version":3,"sources":["src/embedded.ts"],"sourcesContent":["export const embedded = true;"]}},
				{"url":"chunks/child.map"}
			]
		}`),
		"https://example.com/maps/chunks/child.map": []byte(`{
			"version":3,
			"sections":[{"url":"grandchild.map"}]
		}`),
		"https://example.com/maps/chunks/grandchild.map": []byte(`{
			"version":3,
			"sources":["https://sources.example/grandchild.ts"],
			"sourcesContent":["export const grandchild = true;"]
		}`),
	}
	p := newTestProcessor(t, t.TempDir(), func(rawURL string) ([]byte, error) {
		body, ok := maps[rawURL]
		if !ok {
			return nil, fmt.Errorf("unexpected map URL %s", rawURL)
		}
		return body, nil
	})
	result := p.Process(
		"https://example.com/",
		"https://example.com/assets/app.js",
		[]byte("bundle\n//# sourceMappingURL=../maps/root.map"),
	)
	if result.Failed || len(result.Analysis) != 2 {
		t.Fatalf("Process() = %+v", result)
	}
	if result.Analysis[0].SourceName != "src/embedded.ts" ||
		result.Analysis[1].SourceName != "https://sources.example/grandchild.ts" {
		t.Fatalf("analysis sources = %#v", result.Analysis)
	}
}

func TestIndexedSourceMapUnresolvedSectionFallsBackButPersistsRecoveredSources(t *testing.T) {
	if err := CheckNodeRuntime(); err != nil {
		t.Skip(err)
	}

	root := []byte(`{
		"version":3,
		"sections":[
			{"map":{"version":3,"sources":["src/available.ts"],"sourcesContent":["export const available = true;"]}},
			{"url":"missing.map"}
		]
	}`)
	siteDir := t.TempDir()
	p := newTestProcessor(t, siteDir, func(rawURL string) ([]byte, error) {
		if strings.HasSuffix(rawURL, "root.map") {
			return root, nil
		}
		return nil, errors.New("missing section")
	})
	body := []byte("const original = true;\n//# sourceMappingURL=root.map")
	result := p.Process("https://example.com/", "https://example.com/app.js", body)
	assertOriginalAnalysis(t, result, "https://example.com/app.js", body)
	if len(result.Outputs) != 1 || readOutputFile(t, siteDir, result.Outputs[0]) != "export const available = true;" {
		t.Fatalf("partial indexed outputs = %v", result.Outputs)
	}
}

func TestInvalidIndexedSectionFallsBackButPersistsRecoveredSources(t *testing.T) {
	if err := CheckNodeRuntime(); err != nil {
		t.Skip(err)
	}

	tests := []struct {
		name  string
		root  string
		child []byte
	}{
		{
			name: "embedded empty object",
			root: `{"version":3,"sections":[
				{"map":{"version":3,"sources":["src/available.ts"],"sourcesContent":["export const available = true;"]}},
				{"map":{}}
			]}`,
		},
		{
			name:  "section URL null",
			root:  `{"version":3,"sections":[{"map":{"version":3,"sources":["src/available.ts"],"sourcesContent":["export const available = true;"]}},{"url":"child.map"}]}`,
			child: []byte(`null`),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			siteDir := t.TempDir()
			p := newTestProcessor(t, siteDir, func(rawURL string) ([]byte, error) {
				if strings.HasSuffix(rawURL, "root.map") {
					return []byte(test.root), nil
				}
				if strings.HasSuffix(rawURL, "child.map") && test.child != nil {
					return test.child, nil
				}
				return nil, fmt.Errorf("unexpected map URL %s", rawURL)
			})
			body := []byte("const original = true;\n//# sourceMappingURL=root.map")
			result := p.Process("https://example.com/", "https://example.com/app.js", body)
			assertOriginalAnalysis(t, result, "https://example.com/app.js", body)
			if len(result.Outputs) != 1 || readOutputFile(t, siteDir, result.Outputs[0]) != "export const available = true;" {
				t.Fatalf("invalid-section outputs = %v", result.Outputs)
			}
		})
	}
}

func TestIndexedSourceMapDepthCapFallsBackButKeepsShallowerSources(t *testing.T) {
	if err := CheckNodeRuntime(); err != nil {
		t.Skip(err)
	}

	leaf := `{"version":3,"sources":["src/too-deep.ts"],"sourcesContent":["too deep"]}`
	for i := 0; i < 5; i++ {
		leaf = `{"version":3,"sections":[{"map":` + leaf + `}]}`
	}
	root := `{
		"version":3,
		"sources":["src/shallow.ts"],
		"sourcesContent":["export const shallow = true;"],
		"sections":[{"map":` + leaf + `}]
	}`
	siteDir := t.TempDir()
	p := newTestProcessor(t, siteDir, func(string) ([]byte, error) { return []byte(root), nil })
	body := []byte("const original = true;\n//# sourceMappingURL=app.js.map")
	result := p.Process("https://example.com/", "https://example.com/app.js", body)
	assertOriginalAnalysis(t, result, "https://example.com/app.js", body)
	if len(result.Outputs) != 1 || readOutputFile(t, siteDir, result.Outputs[0]) != "export const shallow = true;" {
		t.Fatalf("depth-capped outputs = %v", result.Outputs)
	}
}

func TestIndexedSourceMapCycleFallsBackButPersistsRecoveredSources(t *testing.T) {
	if err := CheckNodeRuntime(); err != nil {
		t.Skip(err)
	}

	root := []byte(`{
		"version":3,
		"sources":["src/available.ts"],
		"sourcesContent":["export const available = true;"],
		"sections":[{"url":"root.map"}]
	}`)
	siteDir := t.TempDir()
	fetches := 0
	p := newTestProcessor(t, siteDir, func(string) ([]byte, error) {
		fetches++
		return root, nil
	})
	body := []byte("const original = true;\n//# sourceMappingURL=root.map")
	result := p.Process("https://example.com/", "https://example.com/app.js", body)
	assertOriginalAnalysis(t, result, "https://example.com/app.js", body)
	if len(result.Outputs) != 1 || readOutputFile(t, siteDir, result.Outputs[0]) != "export const available = true;" {
		t.Fatalf("cyclic outputs = %v", result.Outputs)
	}
	if fetches != 1 {
		t.Fatalf("cyclic map fetches = %d, want no refetch of the active root", fetches)
	}
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

func TestSourceMapFetchUsesExplicitAndInferredDeadlines(t *testing.T) {
	if err := CheckNodeRuntime(); err != nil {
		t.Skip(err)
	}

	const processTimeout = 7 * time.Second
	type observedDeadline struct {
		url       string
		remaining time.Duration
	}
	var observed []observedDeadline
	p := newContextTestProcessor(t, t.TempDir(), processTimeout, func(ctx context.Context, rawURL string) ([]byte, error) {
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Fatalf("map fetch %s has no deadline", rawURL)
		}
		observed = append(observed, observedDeadline{url: rawURL, remaining: time.Until(deadline)})
		return nil, errors.New("not found")
	})
	p.Process("https://example.com/", "https://example.com/explicit.js", []byte("bundle\n//# sourceMappingURL=explicit.map"))
	p.Process("https://example.com/", "https://example.com/inferred.js", []byte("bundle"))

	if len(observed) != 2 {
		t.Fatalf("map fetches = %#v", observed)
	}
	if observed[0].url != "https://example.com/explicit.map" || observed[0].remaining < 6*time.Second || observed[0].remaining > processTimeout {
		t.Fatalf("explicit deadline = %#v", observed[0])
	}
	if observed[1].url != "https://example.com/inferred.js.map" || observed[1].remaining < 2*time.Second || observed[1].remaining > 3*time.Second {
		t.Fatalf("inferred deadline = %#v", observed[1])
	}
}

func TestSourceMapFetchConcurrencyIsBoundedToFour(t *testing.T) {
	if err := CheckNodeRuntime(); err != nil {
		t.Skip(err)
	}

	started := make(chan struct{}, 8)
	release := make(chan struct{})
	processors := []*Processor{
		newContextTestProcessor(t, t.TempDir(), 2*time.Second, func(ctx context.Context, _ string) ([]byte, error) {
			started <- struct{}{}
			select {
			case <-release:
				return []byte(`{"version":3,"sources":["src/app.js"],"sourcesContent":["export default true;"]}`), nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}),
		newContextTestProcessor(t, t.TempDir(), 2*time.Second, func(ctx context.Context, _ string) ([]byte, error) {
			started <- struct{}{}
			select {
			case <-release:
				return []byte(`{"version":3,"sources":["src/app.js"],"sourcesContent":["export default true;"]}`), nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}),
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body := []byte(fmt.Sprintf("bundle\n//# sourceMappingURL=app-%d.map", i))
			_ = processors[i%len(processors)].Process("https://example.com/", fmt.Sprintf("https://example.com/app-%d.js", i), body)
		}(i)
	}
	for i := 0; i < 4; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatalf("only %d source-map fetches started", i)
		}
	}
	select {
	case <-started:
		t.Fatal("more than four source-map fetches ran concurrently")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	wg.Wait()
}

func TestSourceMapQueueWaitConsumesProcessingDeadline(t *testing.T) {
	if err := CheckNodeRuntime(); err != nil {
		t.Skip(err)
	}

	started := make(chan struct{}, 4)
	release := make(chan struct{})
	blocker := newContextTestProcessor(t, t.TempDir(), 2*time.Second, func(ctx context.Context, _ string) ([]byte, error) {
		started <- struct{}{}
		select {
		case <-release:
			return []byte(`{"version":3,"sources":["src/app.js"],"sourcesContent":["export default true;"]}`), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body := []byte(fmt.Sprintf("bundle\n//# sourceMappingURL=block-%d.map", i))
			_ = blocker.Process("https://example.com/", fmt.Sprintf("https://example.com/block-%d.js", i), body)
		}(i)
	}
	for i := 0; i < 4; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatalf("only %d blocking source-map fetches started", i)
		}
	}

	queuedFetches := 0
	queued := newContextTestProcessor(t, t.TempDir(), 50*time.Millisecond, func(context.Context, string) ([]byte, error) {
		queuedFetches++
		return nil, errors.New("unexpected fetch after queue deadline")
	})
	timer := time.AfterFunc(500*time.Millisecond, func() { close(release) })
	start := time.Now()
	result := queued.Process(
		"https://example.com/",
		"https://example.com/queued.js",
		[]byte("bundle\n//# sourceMappingURL=queued.map"),
	)
	elapsed := time.Since(start)
	if timer.Stop() {
		close(release)
	}
	wg.Wait()
	if result.Failed {
		t.Fatalf("queued Process() = %+v", result)
	}
	if elapsed > 300*time.Millisecond {
		t.Fatalf("source-map queue ignored 50ms processing deadline: %s", elapsed)
	}
	if queuedFetches != 0 {
		t.Fatalf("queued source-map fetches = %d, want no fetch after queue deadline", queuedFetches)
	}
}

func TestSafeTransformsDoNotPromoteUseStrictDirective(t *testing.T) {
	if err := CheckNodeRuntime(); err != nil {
		t.Skip(err)
	}

	tests := []struct {
		name string
		body string
	}{
		{name: "escaped literal", body: `"use\x20strict"; sloppyEscaped = 1; console.log("ok");`},
		{name: "concatenated literal", body: `"use " + "strict"; sloppyConcat = 1; console.log("ok");`},
		{name: "static if", body: `if (true) "use strict"; sloppyIf = 1; console.log("ok");`},
		{name: "static conditional", body: `true ? "use strict" : "other"; sloppyConditional = 1; console.log("ok");`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			siteDir := t.TempDir()
			p := newTestProcessor(t, siteDir, nil)
			result := p.Process("https://example.com/", "https://example.com/app.js", []byte(test.body))
			if result.Failed || len(result.Outputs) != 1 {
				t.Fatalf("Process() = %+v", result)
			}
			outputPath := filepath.Join(siteDir, filepath.FromSlash(result.Outputs[0]))
			command := exec.Command("node", outputPath)
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("transformed program changed sloppy-mode execution: %v\n%s", err, output)
			}
			if strings.TrimSpace(string(output)) != "ok" {
				t.Fatalf("program output = %q, want ok", output)
			}
		})
	}
}

func TestUnavailableSourceMapUsesOnlyScopeSafeTransforms(t *testing.T) {
	if err := CheckNodeRuntime(); err != nil {
		t.Skip(err)
	}

	siteDir := t.TempDir()
	p := newTestProcessor(t, siteDir, func(string) ([]byte, error) {
		return nil, errors.New("HTTP 404")
	})
	body := []byte(`
function atob(value){return "shadow:"+value}
const table=["/api/value"];
const wrapper=value=>value;
if(false){var hoisted="/api/hidden"}
fetch(atob("L2FwaS9iNjQ="));
fetch(table[0]);
fetch(wrapper("/api/wrapped"));
fetch("/api/"+"joined");
fetch("\x2fapi\x2fescaped");
if(false){fetch("/api/dead")}else{fetch("/api/live")}
console.log(hoisted);
`)
	result := p.Process("https://example.com/", "https://example.com/app.js", body)
	if result.Failed || result.Status != "processed" || len(result.Outputs) != 1 {
		t.Fatalf("Process() = %+v", result)
	}
	assertOriginalAnalysis(t, result, "https://example.com/app.js", body)
	if !strings.HasPrefix(result.Outputs[0], "js/") || !strings.HasSuffix(result.Outputs[0], ".js") {
		t.Fatalf("processed output = %q", result.Outputs[0])
	}
	output := readOutputFile(t, siteDir, result.Outputs[0])
	for _, want := range []string{
		`fetch(atob("L2FwaS9iNjQ="));`,
		`fetch(table[0]);`,
		`fetch(wrapper("/api/wrapped"));`,
		`fetch("/api/joined");`,
		`fetch("/api/escaped");`,
		`if (false)`,
		`var hoisted = "/api/hidden";`,
		`fetch("/api/live");`,
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("processed output missing %q:\n%s", want, output)
		}
	}
	if strings.Contains(output, `fetch("/api/dead")`) {
		t.Fatalf("scope-safe dead branch was not removed:\n%s", output)
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

func TestNodeVersionCheckTimesOut(t *testing.T) {
	installFakeNode(t, "version_hang")
	started := time.Now()
	err := checkNodeRuntime(50 * time.Millisecond)
	if err == nil || err.Error() != NodeRuntimeError {
		t.Fatalf("checkNodeRuntime() error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("version timeout took %s", elapsed)
	}
}

func TestWorkerPingTimesOut(t *testing.T) {
	installFakeNode(t, "ping_hang")
	started := time.Now()
	p, err := newProcessor(t.TempDir(), nil, 2*time.Second, 50*time.Millisecond)
	if p != nil {
		_ = p.Close()
	}
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "timeout") {
		t.Fatalf("newProcessor() error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("ping timeout took %s", elapsed)
	}
}

func TestWorkerFailureFallsBackAndLazilyRestarts(t *testing.T) {
	for _, mode := range []string{"process_hang_first", "wrong_id_first", "missing_code_first", "missing_ok_first"} {
		t.Run(mode, func(t *testing.T) {
			stateFile, _ := installFakeNode(t, mode)
			p, err := newProcessor(t.TempDir(), nil, 50*time.Millisecond, workerStartupTimeout)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = p.Close() })

			firstBody := []byte("const first = true;")
			first := p.Process("https://example.com/", "https://example.com/first.js", firstBody)
			if !first.Failed {
				t.Fatalf("first Process() = %+v, want fallback failure", first)
			}
			assertOriginalAnalysis(t, first, "https://example.com/first.js", firstBody)

			second := p.Process("https://example.com/", "https://example.com/second.js", []byte("const second = true;"))
			if second.Failed || second.Status != "processed" {
				t.Fatalf("second Process() = %+v", second)
			}
			if got := readFakeNodeStarts(t, stateFile); got != 2 {
				t.Fatalf("worker starts = %d, want 2", got)
			}
		})
	}
}

func TestCloseInterruptsBlockedWorkerIO(t *testing.T) {
	_, requestFile := installFakeNode(t, "process_hang_first")
	p, err := newProcessor(t.TempDir(), nil, 10*time.Second, workerStartupTimeout)
	if err != nil {
		t.Fatal(err)
	}
	processDone := make(chan FileResult, 1)
	go func() {
		processDone <- p.Process("https://example.com/", "https://example.com/app.js", []byte("const blocked = true;"))
	}()
	waitForFile(t, requestFile)

	started := time.Now()
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("Close() took %s while worker I/O was blocked", elapsed)
	}
	select {
	case result := <-processDone:
		if !result.Failed {
			t.Fatalf("blocked Process() = %+v", result)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked Process did not return after Close")
	}
}

func TestConcurrentWorkerRequestsAreSerializedByActor(t *testing.T) {
	if err := CheckNodeRuntime(); err != nil {
		t.Skip(err)
	}
	p := newTestProcessor(t, t.TempDir(), nil)

	results := make(chan FileResult, 8)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body := []byte(fmt.Sprintf("const value%d = %d;", i, i))
			results <- p.Process("https://example.com/", fmt.Sprintf("https://example.com/app-%d.js", i), body)
		}(i)
	}
	wg.Wait()
	close(results)
	for result := range results {
		if result.Failed || result.Status != "processed" || len(result.Outputs) != 1 {
			t.Fatalf("concurrent Process() = %+v", result)
		}
	}
}

func TestNodeOlderThan18ProducesClearError(t *testing.T) {
	if raceDetectorEnabled && runtime.GOOS == "windows" {
		t.Skip("race-instrumented test binary cannot satisfy the fixed 5 second fake-node startup deadline")
	}
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
	} else if err := os.WriteFile(node, []byte("#!/bin/sh\nprintf 'v17.9.1\\n'\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	if runtime.GOOS == "windows" {
		t.Setenv("JSPIDER_TEST_NODE_VERSION", "v17.9.1")
	}
	if err := CheckNodeRuntime(); err == nil || err.Error() != NodeVersionError {
		t.Fatalf("CheckNodeRuntime() error = %v", err)
	}
}

func newTestProcessor(t *testing.T, siteDir string, fetch func(string) ([]byte, error)) *Processor {
	t.Helper()
	var fetchForEntry FetchFunc
	if fetch != nil {
		fetchForEntry = func(_ context.Context, _ string, rawURL string) ([]byte, error) {
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

func newContextTestProcessor(t *testing.T, siteDir string, timeout time.Duration, fetch func(context.Context, string) ([]byte, error)) *Processor {
	t.Helper()
	var fetchForEntry FetchFunc
	if fetch != nil {
		fetchForEntry = func(ctx context.Context, _ string, rawURL string) ([]byte, error) {
			return fetch(ctx, rawURL)
		}
	}
	p, err := NewWithTimeout(siteDir, fetchForEntry, timeout)
	if err != nil {
		t.Fatalf("NewWithTimeout() error = %v", err)
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

func assertOriginalAnalysis(t *testing.T, result FileResult, sourceName string, body []byte) {
	t.Helper()
	want := []AnalysisUnit{{SourceName: sourceName, BaseURL: sourceName, Body: body}}
	if !reflect.DeepEqual(result.Analysis, want) {
		t.Fatalf("analysis = %#v, want original %#v", result.Analysis, want)
	}
}

func installFakeNode(t *testing.T, mode string) (stateFile, requestFile string) {
	t.Helper()
	if raceDetectorEnabled && runtime.GOOS == "windows" {
		t.Skip("race-instrumented test binary cannot satisfy the fixed 5 second fake-node startup deadline")
	}
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
	} else if err := os.WriteFile(node, []byte(fakeNodeScript), 0755); err != nil {
		t.Fatal(err)
	}
	stateFile = filepath.Join(dir, "starts")
	requestFile = filepath.Join(dir, "request")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("JSPIDER_FAKE_NODE_MODE", mode)
	t.Setenv("JSPIDER_FAKE_NODE_STATE", stateFile)
	t.Setenv("JSPIDER_FAKE_NODE_REQUEST_FILE", requestFile)
	return stateFile, requestFile
}

const fakeNodeScript = `#!/bin/sh
if [ "$1" = "--version" ]; then
  if [ "$JSPIDER_FAKE_NODE_MODE" = "version_hang" ]; then
    sleep 3600
  fi
  printf 'v20.1.0\n'
  exit 0
fi

count=0
if [ -f "$JSPIDER_FAKE_NODE_STATE" ]; then
  IFS= read -r count < "$JSPIDER_FAKE_NODE_STATE"
fi
count=$((count + 1))
printf '%s' "$count" > "$JSPIDER_FAKE_NODE_STATE"

while IFS= read -r line; do
  id=${line#*\"id\":}
  id=${id%%,*}
  case "$line" in
    *\"command\":\"ping\"*)
      if [ "$JSPIDER_FAKE_NODE_MODE" = "ping_hang" ]; then
        sleep 3600
      fi
      printf '{"id":%s,"ok":true,"node_version":"20.1.0"}\n' "$id"
      ;;
    *\"command\":\"shutdown\"*)
      exit 0
      ;;
    *)
      if [ -n "$JSPIDER_FAKE_NODE_REQUEST_FILE" ]; then
        printf 'received' > "$JSPIDER_FAKE_NODE_REQUEST_FILE"
      fi
      if [ "$JSPIDER_FAKE_NODE_MODE" = "process_hang_first" ] && [ "$count" -eq 1 ]; then
        sleep 3600
      fi
      response_id=$id
      if [ "$JSPIDER_FAKE_NODE_MODE" = "wrong_id_first" ] && [ "$count" -eq 1 ]; then
        response_id=$((id + 1))
      fi
	  if [ "$JSPIDER_FAKE_NODE_MODE" = "missing_code_first" ] && [ "$count" -eq 1 ]; then
		printf '{"id":%s,"ok":true}\n' "$response_id"
		continue
	  fi
	  if [ "$JSPIDER_FAKE_NODE_MODE" = "missing_ok_first" ] && [ "$count" -eq 1 ]; then
		printf '{"id":%s,"code":"const fake = true;"}\n' "$response_id"
		continue
	  fi
      printf '{"id":%s,"ok":true,"code":"const fake = true;"}\n' "$response_id"
      ;;
  esac
done
`

func readFakeNodeStarts(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	count, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	return count
}

func waitForFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(workerStartupTimeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", path)
}
