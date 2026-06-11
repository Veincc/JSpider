package store

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Veincc/JSpider/internal/analyzer"
)

func TestSaveEntryAndJavaScriptLayout(t *testing.T) {
	outDir := t.TempDir()
	s := New(outDir)

	if err := s.SaveEntry("example_com", []byte("<html></html>")); err != nil {
		t.Fatalf("SaveEntry() error = %v", err)
	}
	rel, created, err := s.SaveJS(
		"example_com",
		"https://cdn.example.net/assets/app.min.js?v=1",
		[]byte("console.log('app')"),
	)
	if err != nil {
		t.Fatalf("SaveJS() error = %v", err)
	}
	if !created {
		t.Fatal("first SaveJS() should create a file")
	}
	if !strings.HasPrefix(rel, "example_com/js/app.min-") || !strings.HasSuffix(rel, ".js") {
		t.Fatalf("SaveJS() path = %q", rel)
	}
	assertExists(t, filepath.Join(outDir, "example_com", "entry.html"))
	assertExists(t, filepath.Join(outDir, filepath.FromSlash(rel)))
}

func TestSaveJavaScriptDeduplicatesWithinSite(t *testing.T) {
	outDir := t.TempDir()
	s := New(outDir)
	body := []byte("same")

	first, created, err := s.SaveJS("example_com", "https://example.com/a.js", body)
	if err != nil || !created {
		t.Fatalf("first SaveJS() = %q, %v, %v", first, created, err)
	}
	second, created, err := s.SaveJS("example_com", "https://example.com/b.js", body)
	if err != nil {
		t.Fatalf("second SaveJS() error = %v", err)
	}
	if created || second != first {
		t.Fatalf("duplicate SaveJS() = %q, %v; want existing %q", second, created, first)
	}
}

func TestSaveJavaScriptKeepsSitesSelfContained(t *testing.T) {
	outDir := t.TempDir()
	s := New(outDir)
	body := []byte("same")

	_, firstCreated, err := s.SaveJS("first_com", "https://cdn.example/app.js", body)
	if err != nil {
		t.Fatalf("first site SaveJS() error = %v", err)
	}
	_, secondCreated, err := s.SaveJS("second_com", "https://cdn.example/app.js", body)
	if err != nil {
		t.Fatalf("second site SaveJS() error = %v", err)
	}
	if !firstCreated || !secondCreated {
		t.Fatal("each entry site should keep its own copy")
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

func TestSaveJavaScriptConcurrentDeduplication(t *testing.T) {
	outDir := t.TempDir()
	s := New(outDir)
	body := []byte("same concurrent body")

	const callers = 16
	results := make(chan string, callers)
	errors := make(chan error, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rel, _, err := s.SaveJS("example_com", "https://example.com/app.js", body)
			if err != nil {
				errors <- err
				return
			}
			results <- rel
		}()
	}
	wg.Wait()
	close(results)
	close(errors)

	for err := range errors {
		t.Fatalf("SaveJS() error = %v", err)
	}
	var expected string
	for rel := range results {
		if expected == "" {
			expected = rel
		}
		if rel != expected {
			t.Fatalf("SaveJS() path = %q, want %q", rel, expected)
		}
	}
	assertExists(t, filepath.Join(outDir, filepath.FromSlash(expected)))
	if count := countRegularFiles(t, filepath.Join(outDir, "example_com", "js")); count != 1 {
		t.Fatalf("saved files = %d, want 1", count)
	}
}

func assertExists(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected %s: %v", path, err)
	}
}

func countRegularFiles(t *testing.T, root string) int {
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
	if err != nil {
		t.Fatalf("WalkDir() error = %v", err)
	}
	return count
}
