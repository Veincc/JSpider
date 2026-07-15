package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Veincc/JSpider/internal/apidiscovery"
	"github.com/Veincc/JSpider/internal/logging"
	"github.com/Veincc/JSpider/internal/preprocess"
	"github.com/Veincc/JSpider/internal/store"
)

type closeErrorProcessor struct {
	err error
}

type recoverableAPISession struct {
	analyzeErr   error
	report       apidiscovery.Report
	analyzeCalls int
	reportCalls  int
}

func (s *recoverableAPISession) AddEntryURL(string) {}
func (s *recoverableAPISession) AddRuntimeForEntry(string, []apidiscovery.RuntimeRequest) {
}
func (s *recoverableAPISession) AddSourceWithIdentity(apidiscovery.SourceIdentity, string, []byte) {
}
func (s *recoverableAPISession) Stats(string) apidiscovery.SessionStats {
	return apidiscovery.SessionStats{}
}
func (s *recoverableAPISession) AnalyzeSources() error {
	s.analyzeCalls++
	return s.analyzeErr
}
func (s *recoverableAPISession) Report() apidiscovery.Report {
	s.reportCalls++
	return s.report
}

func (p *closeErrorProcessor) ProcessContext(context.Context, string, string, []byte) preprocess.FileResult {
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

func TestFinalizeOutputsBuildsRecoverableReportAfterAnalysisFailureAndJoinsWriteError(t *testing.T) {
	outDir := t.TempDir()
	analysisErr := errors.New("jsluice analysis failed")
	newSession := func(entryURL, endpointURL string) *recoverableAPISession {
		return &recoverableAPISession{
			analyzeErr: analysisErr,
			report: apidiscovery.BuildReport(nil, []apidiscovery.RuntimeRequest{{
				RequestID: "runtime", URL: endpointURL, Method: "GET", ResourceType: "Fetch", EntryURL: entryURL,
			}}),
		}
	}

	recoverable := newSession("https://recoverable.example/", "https://recoverable.example/api/runtime")
	writeFailure := newSession("https://blocked.example/", "https://blocked.example/api/runtime")
	sites := map[string]*siteRuntime{
		"recoverable": {
			origin: "recoverable", directory: "recoverable", store: store.New(outDir),
			apiSession: recoverable, entryURLs: []string{"https://recoverable.example/"},
		},
		"write_failure": {
			origin: "write_failure", directory: "write_failure", store: store.New(outDir),
			apiSession: writeFailure, entryURLs: []string{"https://blocked.example/"},
		},
	}
	if err := os.MkdirAll(filepath.Join(outDir, "write_failure", "endpoints.txt"), 0755); err != nil {
		t.Fatal(err)
	}

	err := finalizeOutputs(outDir, sites, true, nil)
	if err == nil || !strings.Contains(err.Error(), analysisErr.Error()) || !strings.Contains(err.Error(), "write endpoints") {
		t.Fatalf("finalizeOutputs() error = %v, want joined analysis and endpoint-write errors", err)
	}
	data, readErr := os.ReadFile(filepath.Join(outDir, "recoverable", "endpoints.txt"))
	if readErr != nil || string(data) != "https://recoverable.example/api/runtime\n" {
		t.Fatalf("recoverable endpoints = %q, error = %v", data, readErr)
	}
	for name, session := range map[string]*recoverableAPISession{"recoverable": recoverable, "write_failure": writeFailure} {
		if session.analyzeCalls != 1 || session.reportCalls != 1 {
			t.Errorf("%s calls: AnalyzeSources=%d Report=%d, want once each", name, session.analyzeCalls, session.reportCalls)
		}
	}
}

func TestVerboseAPIReportPreservesRawFullQueryValues(t *testing.T) {
	longValue := strings.Repeat("q", apidiscovery.MaxParameterValueBytes+73)
	staticURL := "/api/users?access_token=static-secret&query=" + longValue
	runtimeURL := "https://example.com/api/users?access_token=runtime-secret&query=" + longValue
	report := apidiscovery.BuildReport(
		[]apidiscovery.StaticEndpoint{{RawURL: staticURL, Method: "GET"}},
		[]apidiscovery.RuntimeRequest{{URL: runtimeURL, Method: "GET", ResourceType: "Fetch"}},
	)

	readPipe, writePipe, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	originalStdout := os.Stdout
	os.Stdout = writePipe
	logAPIReport(logging.New(true, ""), "example", report)
	_ = writePipe.Close()
	os.Stdout = originalStdout
	output, readErr := io.ReadAll(readPipe)
	_ = readPipe.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	text := string(output)
	if !strings.Contains(text, staticURL) || !strings.Contains(text, runtimeURL) {
		t.Fatalf("verbose API report = %q, want raw static and runtime query values", text)
	}
}
