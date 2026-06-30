package store

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/Veincc/JSpider/internal/analyzer"
)

func TestWriteJSMapSortsDeduplicatesAndUsesSiteRelativePaths(t *testing.T) {
	outDir := t.TempDir()
	s := New(outDir)
	s.RecordJSOutputs("example_com", "https://example.com/z.js", []string{"js/shared.js", "js/shared.js"})
	s.RecordJSOutputs("example_com", "https://example.com/a.js", []string{"js/src/b.ts", "js/src/a.ts", "js/shared.js"})

	if err := s.WriteJSMap("example_com"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(outDir, "example_com", "js-map.txt"))
	if err != nil {
		t.Fatal(err)
	}
	want := "https://example.com/a.js\tjs/shared.js\n" +
		"https://example.com/a.js\tjs/src/a.ts\n" +
		"https://example.com/a.js\tjs/src/b.ts\n" +
		"https://example.com/z.js\tjs/shared.js\n"
	if string(data) != want {
		t.Fatalf("js-map.txt = %q, want %q", data, want)
	}
	info, err := os.Stat(filepath.Join(outDir, "example_com", "js-map.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatalf("map mode = %o, want 600", info.Mode().Perm())
	}
}

func TestWriteJSMapCreatesAtomicEmptyFile(t *testing.T) {
	outDir := t.TempDir()
	s := New(outDir)
	if err := s.WriteJSMap("empty_com"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(outDir, "empty_com", "js-map.txt"))
	if err != nil || len(data) != 0 {
		t.Fatalf("empty map = %q, error = %v", data, err)
	}
	temps, err := filepath.Glob(filepath.Join(outDir, "empty_com", ".js-map.txt.tmp-*"))
	if err != nil || len(temps) != 0 {
		t.Fatalf("temporary maps = %v, error = %v", temps, err)
	}
}

func TestJSMappingsAreIsolatedBySite(t *testing.T) {
	s := New(t.TempDir())
	s.RecordJSOutputs("first_com", "https://cdn.example/app.js", []string{"js/first.js"})
	s.RecordJSOutputs("second_com", "https://cdn.example/app.js", []string{"js/second.js"})
	if got := s.JSMapEntries("first_com"); len(got) != 1 || got[0].Path != "js/first.js" {
		t.Fatalf("first-site mappings = %+v", got)
	}
	if got := s.JSMapEntries("second_com"); len(got) != 1 || got[0].Path != "js/second.js" {
		t.Fatalf("second-site mappings = %+v", got)
	}
}

func TestConfirmedAssetCannotBeDowngraded(t *testing.T) {
	s := New(t.TempDir())
	s.AddJS(&analyzer.JSAsset{
		URL:        "https://example.com/app.js",
		Status:     analyzer.StatusConfirmed,
		Confidence: analyzer.ConfHigh,
	})
	s.AddJS(&analyzer.JSAsset{
		URL:        "https://example.com/app.js",
		Status:     analyzer.StatusCandidate,
		Confidence: analyzer.ConfMedium,
	})

	confirmed := s.GetConfirmedURLs()
	if len(confirmed) != 1 || confirmed[0] != "https://example.com/app.js" {
		t.Fatalf("confirmed URLs = %v", confirmed)
	}
}

func TestMergeJSAssetPreservesMinimumDepth(t *testing.T) {
	entry := &analyzer.JSAsset{URL: "https://example.com/app.js", Depth: 0}
	rediscovered := &analyzer.JSAsset{URL: entry.URL, Depth: 2}
	if got := mergeJSAsset(entry, rediscovered).Depth; got != 0 {
		t.Fatalf("merged depth = %d, want 0", got)
	}

	deep := &analyzer.JSAsset{URL: entry.URL, Depth: 3}
	shallower := &analyzer.JSAsset{URL: entry.URL, Depth: 1}
	if got := mergeJSAsset(deep, shallower).Depth; got != 1 {
		t.Fatalf("merged depth = %d, want 1", got)
	}
}
