package apidiscovery

import "testing"

func TestSessionStatsAreCheapAndIsolatedPerEntry(t *testing.T) {
	session := NewSession()
	firstEntry := "https://example.com/first"
	secondEntry := "https://example.com/second"

	session.AddSourceWithIdentity(SourceIdentity{
		EntryURL:     firstEntry,
		RequestedURL: "https://example.com/app.js",
		FinalURL:     "https://cdn.example.com/assets/app.js",
		ContentHash:  "hash-first",
	}, "https://cdn.example.com/assets/app.js", []byte(`fetch("/api/first")`))
	// Re-observing an identical fetch identity must not inflate collection stats.
	session.AddSourceWithIdentity(SourceIdentity{
		EntryURL:     firstEntry,
		RequestedURL: "https://example.com/app.js",
		FinalURL:     "https://cdn.example.com/assets/app.js",
		ContentHash:  "hash-first",
	}, "https://cdn.example.com/assets/app.js", []byte(`fetch("/api/first")`))
	session.AddSourceWithIdentity(SourceIdentity{
		EntryURL:     secondEntry,
		RequestedURL: "https://example.com/app.js",
		FinalURL:     "https://cdn.example.com/assets/app.js",
		ContentHash:  "hash-second",
	}, "https://cdn.example.com/assets/app.js", []byte(`fetch("/api/second")`))
	firstRequests := []RuntimeRequest{{
		RequestID: "first", URL: "https://example.com/api/first", ResourceType: "Fetch",
	}}
	session.AddRuntimeForEntry(firstEntry, firstRequests)
	session.AddRuntimeForEntry(firstEntry, []RuntimeRequest{
		{RequestID: "document", URL: firstEntry, ResourceType: "Document"},
		{RequestID: "preflight", URL: "https://example.com/api/first", ResourceType: "Fetch", Preflight: true},
		{RequestID: "websocket", URL: "wss://example.com/socket", ResourceType: "Fetch", WebSocket: true},
	})
	if firstRequests[0].EntryURL != "" {
		t.Fatalf("AddRuntimeForEntry mutated caller request: %+v", firstRequests[0])
	}
	session.AddRuntimeForEntry(secondEntry, []RuntimeRequest{{
		RequestID: "second", URL: "https://example.com/api/second", ResourceType: "XHR",
	}})

	first := session.Stats(firstEntry)
	second := session.Stats(secondEntry)
	if first.Sources != 1 || first.Runtime != 1 {
		t.Fatalf("first entry stats = %+v", first)
	}
	if second.Sources != 1 || second.Runtime != 1 {
		t.Fatalf("second entry stats = %+v", second)
	}
	if report := session.Report(); report.Summary.Static != 0 {
		t.Fatalf("Stats performed static analysis: %+v", report.StaticEndpoints)
	}
	if session.SourceCount() != 1 {
		t.Fatalf("matching source set changed shape: count = %d, want current URL-keyed behavior", session.SourceCount())
	}
}
