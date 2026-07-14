package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Veincc/JSpider/internal/apidiscovery"
	"github.com/Veincc/JSpider/internal/preprocess"
	"github.com/Veincc/JSpider/internal/store"
)

type closeErrorProcessor struct {
	err error
}

func (p *closeErrorProcessor) Process(string, string, []byte) preprocess.FileResult {
	return preprocess.FileResult{}
}

func (p *closeErrorProcessor) Close() error { return p.err }

func TestFinalizeOutputsJoinsCloseErrorsAndStillWritesEveryMap(t *testing.T) {
	outDir := t.TempDir()
	sites := map[string]*siteRuntime{
		"first": {
			origin: "first", directory: "first", store: store.New(outDir),
			processor: &closeErrorProcessor{err: errors.New("first close failed")},
		},
		"second": {
			origin: "second", directory: "second", store: store.New(outDir),
			processor: &closeErrorProcessor{err: errors.New("second close failed")},
		},
	}

	err := finalizeOutputs(outDir, sites, false, nil)
	if err == nil || !strings.Contains(err.Error(), "first close failed") || !strings.Contains(err.Error(), "second close failed") {
		t.Fatalf("finalizeOutputs() error = %v, want both close failures", err)
	}
	for origin, site := range sites {
		if site.processor != nil {
			t.Fatalf("processor for %s was retained after close failure", origin)
		}
		assertPathExists(t, filepath.Join(outDir, site.directory, "js-map.txt"))
	}
}

func TestFinalizeOutputsJoinsSiteErrorsAndContinuesFinalizing(t *testing.T) {
	outDir := t.TempDir()
	sites := make(map[string]*siteRuntime)
	for _, site := range []string{"first_com", "second_com", "third_com"} {
		processor, err := preprocess.New(filepath.Join(outDir, site), nil)
		if err != nil {
			t.Fatal(err)
		}
		sites[site] = &siteRuntime{origin: site, directory: site, store: store.New(outDir), processor: processor}
	}
	t.Cleanup(func() {
		for _, site := range sites {
			if site.processor != nil {
				_ = site.processor.Close()
			}
		}
	})
	for _, site := range []string{"first_com", "second_com"} {
		if err := os.Mkdir(filepath.Join(outDir, site, "js-map.txt"), 0755); err != nil {
			t.Fatal(err)
		}
	}

	err := finalizeOutputs(outDir, sites, false, nil)
	if err == nil || !strings.Contains(err.Error(), "first_com") || !strings.Contains(err.Error(), "second_com") {
		t.Fatalf("finalizeOutputs() error = %v, want both site failures", err)
	}
	for origin, site := range sites {
		if site.processor != nil {
			t.Fatalf("processor for %s was not closed", origin)
		}
	}
	assertPathExists(t, filepath.Join(outDir, "third_com", "js-map.txt"))
}

func TestFinalizeOutputsWritesMapsWithoutEndpoints(t *testing.T) {
	outDir := t.TempDir()
	sites := make(map[string]*siteRuntime)
	for _, site := range []string{"second_com", "first_com"} {
		processor, err := preprocess.New(filepath.Join(outDir, site), nil)
		if err != nil {
			t.Fatal(err)
		}
		result := processor.Process("https://"+site+"/", "https://"+site+"/app.js", []byte("console.log('"+site+"');"))
		if len(result.Outputs) != 1 {
			t.Fatalf("%s Process() = %+v", site, result)
		}
		siteStore := store.New(outDir)
		siteStore.RecordJSOutputs(site, "https://"+site+"/app.js", result.Outputs)
		sites[site] = &siteRuntime{origin: site, directory: site, store: siteStore, processor: processor}
	}
	t.Cleanup(func() {
		for _, site := range sites {
			if site.processor != nil {
				_ = site.processor.Close()
			}
		}
	})

	err := finalizeOutputs(outDir, sites, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, site := range []string{"first_com", "second_com"} {
		assertPathExists(t, filepath.Join(outDir, site, "js-map.txt"))
		assertPathMissing(t, filepath.Join(outDir, site, "endpoints.txt"))
	}
	for origin, site := range sites {
		if site.processor != nil {
			t.Fatalf("processor for %s was not closed", origin)
		}
	}
}

func TestFinalizeOutputsWritesAPIEndpoints(t *testing.T) {
	outDir := t.TempDir()
	site := "example_com"
	processor, err := preprocess.New(filepath.Join(outDir, site), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = processor.Close() })
	session := apidiscovery.NewSession()
	session.AddEntryURL("https://example.com/")
	session.AddRuntime([]apidiscovery.RuntimeRequest{{
		RequestID: "runtime", URL: "https://example.com/api/runtime", Method: "GET", ResourceType: "Fetch",
	}})

	sites := map[string]*siteRuntime{site: {
		origin: site, directory: site, store: store.New(outDir), processor: processor,
		apiSession: session, entryURLs: []string{"https://example.com/"},
	}}
	err = finalizeOutputs(outDir, sites, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(outDir, site, "endpoints.txt"))
	if err != nil || string(data) != "https://example.com/api/runtime\n" {
		t.Fatalf("endpoints = %q, error = %v", data, err)
	}
}
