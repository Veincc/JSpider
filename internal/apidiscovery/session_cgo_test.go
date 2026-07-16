//go:build cgo

package apidiscovery

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSessionAnalyzesAllCollectedJavaScriptAfterDiscovery(t *testing.T) {
	session := NewSession()
	session.AddSource("https://example.com/b.js", []byte(`fetch("/api/b")`))
	session.AddSource("https://example.com/a.js", []byte(`fetch("/api/a")`))

	before := session.Report()
	if before.Summary.Static != 0 {
		t.Fatalf("static endpoints before AnalyzeSources = %d, want 0", before.Summary.Static)
	}
	if session.SourceCount() != 2 {
		t.Fatalf("source count = %d, want 2", session.SourceCount())
	}

	if err := session.AnalyzeSources(); err != nil {
		t.Fatalf("AnalyzeSources() error = %v", err)
	}

	after := session.Report()
	if after.Summary.Static != 2 {
		t.Fatalf("static endpoints after AnalyzeSources = %d, want 2: %+v", after.Summary.Static, after.StaticEndpoints)
	}
	if after.StaticEndpoints[0].RawURL != "/api/a" || after.StaticEndpoints[1].RawURL != "/api/b" {
		t.Fatalf("static endpoint order/content = %+v", after.StaticEndpoints)
	}
}

func TestSessionDeduplicatesCollectedJavaScriptByURL(t *testing.T) {
	session := NewSession()
	session.AddSource("https://example.com/app.js", []byte(`fetch("/api/old")`))
	session.AddSource("https://example.com/app.js", []byte(`fetch("/api/new")`))

	if session.SourceCount() != 1 {
		t.Fatalf("source count = %d, want 1", session.SourceCount())
	}
	if err := session.AnalyzeSources(); err != nil {
		t.Fatal(err)
	}

	report := session.Report()
	if report.Summary.Static != 1 || report.StaticEndpoints[0].RawURL != "/api/new" {
		t.Fatalf("static endpoints = %+v", report.StaticEndpoints)
	}
}

func TestSessionPreservesSourcesWithSharedAnalysisURLAcrossEntries(t *testing.T) {
	session := NewSession()
	sharedURL := "https://cdn.example.com/app.js"
	session.AddSourceWithIdentity(SourceIdentity{
		EntryURL: "https://first.example/", RequestedURL: sharedURL,
		FinalURL: sharedURL, ContentHash: "first-hash",
	}, sharedURL, []byte(`fetch("/api/first")`))
	session.AddSourceWithIdentity(SourceIdentity{
		EntryURL: "https://second.example/", RequestedURL: sharedURL,
		FinalURL: sharedURL, ContentHash: "second-hash",
	}, sharedURL, []byte(`fetch("/api/second")`))

	if err := session.AnalyzeSources(); err != nil {
		t.Fatal(err)
	}
	report := session.Report()
	if len(report.StaticEndpoints) != 2 {
		t.Fatalf("static endpoints = %+v, want both entry-specific source analyses", report.StaticEndpoints)
	}
}

func TestSessionAnalysisUnitsShareTheirFetchSourceIndex(t *testing.T) {
	session := NewSession()
	identity := SourceIdentity{
		EntryURL: "https://example.com/", RequestedURL: "https://example.com/app.js",
		FinalURL: "https://cdn.example.com/app.js", ContentHash: "shared-hash",
	}
	session.AddSourceWithIdentity(identity, "https://cdn.example.com/app.js#original", []byte(`fetch("/api/original")`))
	session.AddSourceWithIdentity(identity, "https://cdn.example.com/app.js#mapped", []byte(`fetch("/api/mapped")`))
	if err := session.AnalyzeSources(); err != nil {
		t.Fatal(err)
	}
	report := session.Report()
	if len(report.StaticEndpoints) != 2 {
		t.Fatalf("static endpoints = %+v, want both analysis units", report.StaticEndpoints)
	}
	for _, endpoint := range report.StaticEndpoints {
		if endpoint.SourceIndex != 0 || endpoint.SourceIdentity != identity {
			t.Fatalf("endpoint provenance = %+v, want shared fetch source index 0 and identity %+v", endpoint, identity)
		}
	}
}

func TestSessionReanalyzesSourceWhenContentChanges(t *testing.T) {
	session := NewSession()
	session.AddSource("https://example.com/app.js", []byte(`fetch("/api/old")`))
	if err := session.AnalyzeSources(); err != nil {
		t.Fatal(err)
	}

	session.AddSource("https://example.com/app.js", []byte(`fetch("/api/new")`))
	if err := session.AnalyzeSources(); err != nil {
		t.Fatal(err)
	}

	report := session.Report()
	if report.Summary.Static != 1 || report.StaticEndpoints[0].RawURL != "/api/new" {
		t.Fatalf("static endpoints after source replacement = %+v, want only /api/new", report.StaticEndpoints)
	}
}

func TestAnalyzeSourcesMarksSourcesInProgressBeforeReleasingLock(t *testing.T) {
	session := NewSession()
	var source strings.Builder
	for i := 0; i < 80; i++ {
		fmt.Fprintf(&source, "fetch('/api/%03d');\n", i)
	}
	session.AddSource("https://example.com/app.js", []byte(source.String()))

	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- session.AnalyzeSources()
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	report := session.Report()
	if report.Summary.Static != 80 {
		t.Fatalf("static endpoints after concurrent AnalyzeSources = %d, want 80; first endpoints: %+v", report.Summary.Static, firstStaticEndpoints(report.StaticEndpoints, 5))
	}
}

func TestAnalyzeSourcesConcurrentCallersWaitForSingleExecution(t *testing.T) {
	session := NewSession()
	session.AddSource("https://example.com/app.js", []byte(`fetch("/api/users")`))
	started := make(chan struct{})
	release := make(chan struct{})
	var calls int
	session.analyzeSource = func(_ []byte, sourceURL string) ([]StaticEndpoint, error) {
		calls++
		close(started)
		<-release
		return []StaticEndpoint{{RawURL: "/api/users", SourceJSURL: sourceURL}}, nil
	}

	firstDone := make(chan error, 1)
	go func() { firstDone <- session.AnalyzeSources() }()
	<-started
	secondDone := make(chan error, 1)
	go func() { secondDone <- session.AnalyzeSources() }()
	deadline := time.Now().Add(time.Second)
	for {
		session.mu.Lock()
		waiters := session.analysisWaiters[session.analysisGeneration]
		session.mu.Unlock()
		if waiters > 0 {
			break
		}
		if time.Now().After(deadline) {
			close(release)
			<-firstDone
			t.Fatal("concurrent AnalyzeSources caller did not register as a waiter")
		}
		runtime.Gosched()
	}

	select {
	case err := <-secondDone:
		t.Fatalf("concurrent AnalyzeSources returned before active execution completed: %v", err)
	default:
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	if err := <-secondDone; err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("analysis calls = %d, want one", calls)
	}
}

func TestAnalyzeSourcesFailureRollsBackEveryPendingSourceForRetry(t *testing.T) {
	session := NewSession()
	session.AddSource("https://example.com/a.js", []byte(`fetch("/api/a")`))
	session.AddSource("https://example.com/b.js", []byte(`fetch("/api/b")`))
	wantErr := errors.New("analysis failed")
	fail := true
	var calls []string
	session.analyzeSource = func(_ []byte, sourceURL string) ([]StaticEndpoint, error) {
		calls = append(calls, sourceURL)
		if fail {
			fail = false
			return nil, wantErr
		}
		return []StaticEndpoint{{RawURL: "/api/" + strings.TrimSuffix(strings.TrimPrefix(sourceURL, "https://example.com/"), ".js"), SourceJSURL: sourceURL}}, nil
	}

	if err := session.AnalyzeSources(); !errors.Is(err, wantErr) {
		t.Fatalf("first AnalyzeSources error = %v, want %v", err, wantErr)
	}
	if err := session.AnalyzeSources(); err != nil {
		t.Fatalf("retry AnalyzeSources error = %v", err)
	}
	if got := session.Report().Summary.Static; got != 2 {
		t.Fatalf("retry static endpoints = %d, want complete retry; calls=%v", got, calls)
	}
	if len(calls) != 3 {
		t.Fatalf("analysis calls = %v, want failed a then retried a and b", calls)
	}
}

func firstStaticEndpoints(endpoints []StaticEndpoint, limit int) []StaticEndpoint {
	if len(endpoints) <= limit {
		return endpoints
	}
	return endpoints[:limit]
}
