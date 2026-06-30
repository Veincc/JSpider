package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Veincc/JSpider/internal/apidiscovery"
	"github.com/Veincc/JSpider/internal/preprocess"
	"github.com/Veincc/JSpider/internal/store"
)

func TestFinalizeOutputsWritesMapsWithoutEndpoints(t *testing.T) {
	outDir := t.TempDir()
	s := store.New(outDir)
	processors := make(map[string]*preprocess.Processor)
	for _, site := range []string{"second_com", "first_com"} {
		processor, err := preprocess.New(filepath.Join(outDir, site), nil)
		if err != nil {
			t.Fatal(err)
		}
		result := processor.Process("https://"+site+"/", "https://"+site+"/app.js", []byte("console.log('"+site+"');"))
		if len(result.Outputs) != 1 {
			t.Fatalf("%s Process() = %+v", site, result)
		}
		s.RecordJSOutputs(site, "https://"+site+"/app.js", result.Outputs)
		processors[site] = processor
	}
	t.Cleanup(func() {
		for _, processor := range processors {
			_ = processor.Close()
		}
	})

	err := finalizeOutputs(
		outDir,
		s,
		map[string]bool{"second_com": true, "first_com": true},
		processors,
		nil,
		nil,
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, site := range []string{"first_com", "second_com"} {
		assertPathExists(t, filepath.Join(outDir, site, "js-map.txt"))
		assertPathMissing(t, filepath.Join(outDir, site, "endpoints.txt"))
	}
	if len(processors) != 0 {
		t.Fatalf("processors after finalization = %d, want 0", len(processors))
	}
}

func TestFinalizeOutputsWritesAPIEndpoints(t *testing.T) {
	outDir := t.TempDir()
	site := "example_com"
	s := store.New(outDir)
	processor, err := preprocess.New(filepath.Join(outDir, site), nil)
	if err != nil {
		t.Fatal(err)
	}
	processors := map[string]*preprocess.Processor{site: processor}
	t.Cleanup(func() { _ = processor.Close() })
	session := apidiscovery.NewSession()
	session.AddEntryURL("https://example.com/")
	session.AddRuntime([]apidiscovery.RuntimeRequest{{
		RequestID: "runtime", URL: "https://example.com/api/runtime", Method: "GET", ResourceType: "Fetch",
	}})

	err = finalizeOutputs(
		outDir,
		s,
		map[string]bool{site: true},
		processors,
		map[string]*apidiscovery.Session{site: session},
		map[string][]string{site: {"https://example.com/"}},
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(outDir, site, "endpoints.txt"))
	if err != nil || string(data) != "https://example.com/api/runtime\n" {
		t.Fatalf("endpoints = %q, error = %v", data, err)
	}
}
