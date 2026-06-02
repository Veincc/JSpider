package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/Veincc/JSpider/internal/analyzer"
)

func TestSaveAll_CreatesOutDir(t *testing.T) {
	outDir := filepath.Join(t.TempDir(), "nonexistent", "deep", "path")
	s := New(outDir)

	s.AddJS(&analyzer.JSAsset{
		URL:    "https://example.com/test.js",
		Status: analyzer.StatusConfirmed,
	})

	if err := s.SaveAll(); err != nil {
		t.Fatalf("SaveAll should create outDir, got: %v", err)
	}

	assertFileExists(t, outDir+"/js.txt")
}

func TestSaveAll_OutputStable(t *testing.T) {
	outDir1 := t.TempDir()
	outDir2 := t.TempDir()

	// Create identical data in different orders
	for _, outDir := range []string{outDir1, outDir2} {
		s := New(outDir)
		s.AddJS(&analyzer.JSAsset{URL: "https://example.com/b.js", Status: analyzer.StatusConfirmed})
		s.AddJS(&analyzer.JSAsset{URL: "https://example.com/a.js", Status: analyzer.StatusConfirmed})
		s.AddDynamicImport(analyzer.DynamicImport{FromJS: "b.js", Raw: "./x", ResolvedURL: "https://example.com/x.js"})
		s.AddDynamicImport(analyzer.DynamicImport{FromJS: "a.js", Raw: "./y", ResolvedURL: "https://example.com/y.js"})
		s.AddRoute(analyzer.RouteChunk{Route: "/b", FromJS: "b.js"})
		s.AddRoute(analyzer.RouteChunk{Route: "/a", FromJS: "a.js"})
		s.AddSourcemap(analyzer.SourceMapInfo{FromJS: "b.js", MapURL: "b.js.map", Status: "found"})
		s.AddSourcemap(analyzer.SourceMapInfo{FromJS: "a.js", MapURL: "a.js.map", Status: "found"})
		s.AddFramework(analyzer.FrameworkDetect{URL: "b.js", Framework: "vite"})
		s.AddFramework(analyzer.FrameworkDetect{URL: "a.js", Framework: "webpack"})

		if err := s.SaveAll(); err != nil {
			t.Fatalf("SaveAll failed: %v", err)
		}
	}

	// Compare outputs
	files := []string{
		"js.txt",
		"dynamic_imports.json", "route_chunk_map.json", "sourcemaps.txt", "framework_detect.json",
	}
	for _, f := range files {
		data1, err1 := os.ReadFile(filepath.Join(outDir1, f))
		data2, err2 := os.ReadFile(filepath.Join(outDir2, f))
		if err1 != nil || err2 != nil {
			t.Errorf("ReadFile %s: %v, %v", f, err1, err2)
			continue
		}
		if string(data1) != string(data2) {
			t.Errorf("Output not stable for %s:\n--- run 1 ---\n%s\n--- run 2 ---\n%s", f, data1, data2)
		}
	}
}

func TestSaveAll_SourcemapsDeduped(t *testing.T) {
	outDir := t.TempDir()
	s := New(outDir)

	// Add same sourcemap twice (e.g., from different analysis phases)
	s.AddSourcemap(analyzer.SourceMapInfo{FromJS: "a.js", MapURL: "a.js.map", Status: "found"})
	s.AddSourcemap(analyzer.SourceMapInfo{FromJS: "a.js", MapURL: "a.js.map", Status: "parsed", SourceCount: 3})

	if err := s.SaveAll(); err != nil {
		t.Fatalf("SaveAll failed: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(outDir, "sourcemaps.txt"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	// Should only have one entry (deduped), with latest status
	lines := splitLines(string(data))
	if len(lines) != 1 {
		t.Errorf("Expected 1 sourcemap line, got %d: %v", len(lines), lines)
	}
}

func TestSaveAll_FrameworksDeduped(t *testing.T) {
	outDir := t.TempDir()
	s := New(outDir)

	s.AddFramework(analyzer.FrameworkDetect{URL: "a.js", Framework: "vite", Score: 5})
	s.AddFramework(analyzer.FrameworkDetect{URL: "a.js", Framework: "vite", Score: 3})

	if err := s.SaveAll(); err != nil {
		t.Fatalf("SaveAll failed: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(outDir, "framework_detect.json"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	var fws []analyzer.FrameworkDetect
	if err := json.Unmarshal(data, &fws); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(fws) != 1 {
		t.Errorf("Expected 1 framework entry, got %d", len(fws))
	}
}

func TestSaveAll_AtomicWrite(t *testing.T) {
	outDir := t.TempDir()
	s := New(outDir)

	s.AddJS(&analyzer.JSAsset{URL: "https://example.com/a.js", Status: analyzer.StatusConfirmed})

	if err := s.SaveAll(); err != nil {
		t.Fatalf("SaveAll failed: %v", err)
	}

	// No .tmp files should remain
	entries, _ := os.ReadDir(outDir)
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Errorf("Found leftover .tmp file: %s", e.Name())
		}
	}
}

func TestSaveRaw_Deduplication(t *testing.T) {
	outDir := t.TempDir()
	s := New(outDir)

	data := []byte("same content")

	// First save should succeed
	if err := s.SaveRaw("example_com", "a.js", data); err != nil {
		t.Fatalf("SaveRaw a.js: %v", err)
	}

	// Second save with same content should be skipped (no error)
	if err := s.SaveRaw("example_com", "b.js", data); err != nil {
		t.Fatalf("SaveRaw b.js: %v", err)
	}

	// Only a.js should exist
	assertFileExists(t, outDir+"/example_com/a.js")
	if _, err := os.Stat(outDir + "/example_com/b.js"); err == nil {
		t.Error("b.js should not exist (deduplicated)")
	}
}

func TestConcurrentAdd(t *testing.T) {
	s := New(t.TempDir())

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(3)
		go func(i int) {
			defer wg.Done()
			s.AddDynamicImport(analyzer.DynamicImport{FromJS: "a.js", Raw: "./x"})
		}(i)
		go func(i int) {
			defer wg.Done()
			s.AddRoute(analyzer.RouteChunk{Route: "/r", FromJS: "a.js"})
		}(i)
		go func(i int) {
			defer wg.Done()
			s.AddSourcemap(analyzer.SourceMapInfo{FromJS: "a.js", MapURL: "a.js.map"})
		}(i)
	}
	wg.Wait()

	// Should not panic (race detector would catch data races)
	imports := s.GetDynamicImports()
	if len(imports) != 100 {
		t.Errorf("Expected 100 imports, got %d", len(imports))
	}
}

func TestSaveAll_CreatesJS(t *testing.T) {
	outDir := t.TempDir()
	s := New(outDir)

	s.AddJS(&analyzer.JSAsset{URL: "https://example.com/b.js", Status: analyzer.StatusConfirmed})
	s.AddJS(&analyzer.JSAsset{URL: "https://example.com/a.js", Status: analyzer.StatusCandidate})
	s.AddJS(&analyzer.JSAsset{URL: "https://example.com/c.js", Status: analyzer.StatusFailed})

	if err := s.SaveAll(); err != nil {
		t.Fatalf("SaveAll failed: %v", err)
	}

	assertFileExists(t, outDir+"/js.txt")

	data, err := os.ReadFile(filepath.Join(outDir, "js.txt"))
	if err != nil {
		t.Fatalf("ReadFile js.txt: %v", err)
	}

	lines := splitLines(string(data))
	// Should contain a.js and b.js (confirmed + candidate), but NOT c.js (failed)
	if len(lines) != 2 {
		t.Fatalf("Expected 2 lines in js.txt, got %d: %v", len(lines), lines)
	}
	if lines[0] != "https://example.com/a.js" {
		t.Errorf("First line = %q, want %q", lines[0], "https://example.com/a.js")
	}
	if lines[1] != "https://example.com/b.js" {
		t.Errorf("Second line = %q, want %q", lines[1], "https://example.com/b.js")
	}
}

func TestSaveAll_JSTxtDeduplication(t *testing.T) {
	outDir := t.TempDir()
	s := New(outDir)

	// Add same URL twice with different statuses — should only appear once
	s.AddJS(&analyzer.JSAsset{URL: "https://example.com/a.js", Status: analyzer.StatusCandidate})
	s.AddJS(&analyzer.JSAsset{URL: "https://example.com/a.js", Status: analyzer.StatusConfirmed})

	if err := s.SaveAll(); err != nil {
		t.Fatalf("SaveAll failed: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(outDir, "js.txt"))
	if err != nil {
		t.Fatalf("ReadFile js.txt: %v", err)
	}

	lines := splitLines(string(data))
	if len(lines) != 1 {
		t.Errorf("Expected 1 line in js.txt (deduped), got %d: %v", len(lines), lines)
	}
}

func TestSaveAll_JSTxtSorted(t *testing.T) {
	outDir := t.TempDir()
	s := New(outDir)

	s.AddJS(&analyzer.JSAsset{URL: "https://example.com/z.js", Status: analyzer.StatusConfirmed})
	s.AddJS(&analyzer.JSAsset{URL: "https://example.com/a.js", Status: analyzer.StatusConfirmed})
	s.AddJS(&analyzer.JSAsset{URL: "https://example.com/m.js", Status: analyzer.StatusCandidate})

	if err := s.SaveAll(); err != nil {
		t.Fatalf("SaveAll failed: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(outDir, "js.txt"))
	if err != nil {
		t.Fatalf("ReadFile js.txt: %v", err)
	}

	lines := splitLines(string(data))
	if len(lines) != 3 {
		t.Fatalf("Expected 3 lines, got %d: %v", len(lines), lines)
	}
	if lines[0] != "https://example.com/a.js" || lines[1] != "https://example.com/m.js" || lines[2] != "https://example.com/z.js" {
		t.Errorf("js.txt not sorted: %v", lines)
	}
}

func TestSaveAll_JSTxtIncludesHeadlessSources(t *testing.T) {
	outDir := t.TempDir()
	s := New(outDir)

	// Add assets from headless sources
	s.AddJS(&analyzer.JSAsset{
		URL: "https://example.com/net.js", Status: analyzer.StatusCandidate,
		Source: analyzer.SourceHeadlessNetwork,
	})
	s.AddJS(&analyzer.JSAsset{
		URL: "https://example.com/dom.js", Status: analyzer.StatusCandidate,
		Source: analyzer.SourceHeadlessDOM,
	})
	s.AddJS(&analyzer.JSAsset{
		URL: "https://example.com/resp.js", Status: analyzer.StatusCandidate,
		Source: analyzer.SourceHeadlessResponse,
	})

	if err := s.SaveAll(); err != nil {
		t.Fatalf("SaveAll failed: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(outDir, "js.txt"))
	if err != nil {
		t.Fatalf("ReadFile js.txt: %v", err)
	}

	lines := splitLines(string(data))
	if len(lines) != 3 {
		t.Errorf("Expected 3 lines (all headless sources), got %d: %v", len(lines), lines)
	}
}

func splitLines(s string) []string {
	var lines []string
	for _, line := range splitByNewline(s) {
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func splitByNewline(s string) []string {
	var result []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			result = append(result, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		result = append(result, s[start:])
	}
	return result
}

func assertFileExists(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Errorf("File does not exist: %s", path)
	}
}
