package apidiscovery

import "testing"

func TestAssociateInfersSegmentBoundedPrefix(t *testing.T) {
	static := []StaticEndpoint{
		{RawURL: "/user/list", Method: "GET", SourceJSURL: "https://example.com/app.js"},
	}
	runtime := []RuntimeRequest{
		{
			URL:          "https://example.com/gw/user/list?page=1",
			Method:       "GET",
			ResourceType: "Fetch",
			EntryURL:     "https://example.com/",
			Initiator:    Initiator{StackURLs: []string{"https://example.com/app.js"}},
		},
	}

	report := BuildReport(static, runtime)
	if len(report.Associations) != 1 {
		t.Fatalf("associations = %d, want 1", len(report.Associations))
	}
	match := report.Associations[0]
	if match.Prefix != "/gw" || match.RuntimeBase != "https://example.com/gw" {
		t.Fatalf("match prefix/base = %q / %q", match.Prefix, match.RuntimeBase)
	}
	if match.Score < 90 || match.Confidence != ConfidenceConfirmed {
		t.Fatalf("score/confidence = %d/%q, want high confirmed", match.Score, match.Confidence)
	}
	if len(report.Bases) != 1 || report.Bases[0].Confidence != ConfidenceConfirmed {
		t.Fatalf("bases = %+v, want one confirmed base", report.Bases)
	}
}

func TestAssociateRejectsPathSubstringAndMethodMismatch(t *testing.T) {
	tests := []struct {
		name    string
		static  StaticEndpoint
		runtime RuntimeRequest
	}{
		{
			name:    "segment boundary",
			static:  StaticEndpoint{RawURL: "/user/list", Method: "GET"},
			runtime: RuntimeRequest{URL: "https://example.com/superuser/list", Method: "GET", ResourceType: "XHR"},
		},
		{
			name:    "method mismatch",
			static:  StaticEndpoint{RawURL: "/user/list", Method: "POST"},
			runtime: RuntimeRequest{URL: "https://example.com/gw/user/list", Method: "GET", ResourceType: "Fetch"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := BuildReport([]StaticEndpoint{tt.static}, []RuntimeRequest{tt.runtime})
			if len(report.Associations) != 0 {
				t.Fatalf("associations = %+v, want none", report.Associations)
			}
		})
	}
}

func TestAssociateSupportsEXPRAndCrossOriginRuntime(t *testing.T) {
	static := []StaticEndpoint{
		{RawURL: "/users/EXPR/details", Method: "GET", SourceJSURL: "https://example.com/app.js"},
	}
	runtime := []RuntimeRequest{
		{
			URL:          "https://api.example.net/gw/users/42/details",
			Method:       "GET",
			ResourceType: "XHR",
			EntryURL:     "https://example.com/",
			Initiator:    Initiator{StackURLs: []string{"https://example.com/app.js"}},
		},
	}

	report := BuildReport(static, runtime)
	if len(report.Associations) != 1 {
		t.Fatalf("associations = %+v, want one", report.Associations)
	}
	got := report.Associations[0]
	if !got.UsedExpression || got.RuntimeBase != "https://api.example.net/gw" {
		t.Fatalf("association = %+v", got)
	}
	if got.Score != 90 {
		t.Fatalf("score = %d, want 90 after EXPR penalty and no same-origin bonus", got.Score)
	}
}

func TestRuntimeBaseNeedsTwoOrdinaryEvidencePairs(t *testing.T) {
	oneStatic := []StaticEndpoint{{RawURL: "/user/list", Method: "GET", SourceJSURL: "https://example.com/a.js"}}
	oneRuntime := []RuntimeRequest{{
		URL:          "https://example.com/gw/user/list",
		Method:       "GET",
		ResourceType: "Fetch",
		EntryURL:     "https://example.com/",
	}}

	one := BuildReport(oneStatic, oneRuntime)
	if len(one.Bases) != 1 || one.Bases[0].Confidence != ConfidenceCandidate {
		t.Fatalf("single evidence bases = %+v, want candidate", one.Bases)
	}

	two := BuildReport(
		[]StaticEndpoint{
			{RawURL: "/user/list", Method: "GET", SourceJSURL: "https://example.com/a.js"},
			{RawURL: "/order/list", Method: "GET", SourceJSURL: "https://example.com/b.js"},
		},
		[]RuntimeRequest{
			{URL: "https://example.com/gw/user/list", Method: "GET", ResourceType: "Fetch", EntryURL: "https://example.com/"},
			{URL: "https://example.com/gw/order/list", Method: "GET", ResourceType: "XHR", EntryURL: "https://example.com/"},
		},
	)
	if len(two.Bases) != 1 || two.Bases[0].Confidence != ConfidenceConfirmed || two.Bases[0].EvidenceCount != 2 {
		t.Fatalf("two evidence bases = %+v, want confirmed with 2", two.Bases)
	}
}

func TestRuntimeBaseDoesNotCountQueryVariantsAsDifferentStaticInterfaces(t *testing.T) {
	report := BuildReport(
		[]StaticEndpoint{
			{RawURL: "/user/list?page=1", Method: "GET"},
			{RawURL: "/user/list?page=2", Method: "GET"},
		},
		[]RuntimeRequest{
			{
				URL:          "https://example.com/gw/user/list?page=1",
				Method:       "GET",
				ResourceType: "Fetch",
				EntryURL:     "https://example.com/",
			},
		},
	)

	if len(report.Bases) != 1 || report.Bases[0].Confidence != ConfidenceCandidate {
		t.Fatalf("query variants confirmed a runtime base: %+v", report.Bases)
	}
}

func TestOneSegmentPathDoesNotInferBaseWithoutExactInitiator(t *testing.T) {
	static := []StaticEndpoint{{RawURL: "/list", Method: "GET", SourceJSURL: "https://example.com/app.js"}}
	runtime := []RuntimeRequest{{
		URL:          "https://example.com/gw/list",
		Method:       "GET",
		ResourceType: "Fetch",
		EntryURL:     "https://example.com/",
	}}
	report := BuildReport(static, runtime)
	if len(report.Associations) != 0 || len(report.Bases) != 0 {
		t.Fatalf("one-segment ordinary result = %+v / %+v, want no association/base", report.Associations, report.Bases)
	}
}

func TestRelativeStaticPathsUseSuffixMatchingWithoutJSDirectoryResolution(t *testing.T) {
	for _, raw := range []string{"./api/users", "../api/users", "api/users"} {
		t.Run(raw, func(t *testing.T) {
			report := BuildReport(
				[]StaticEndpoint{{RawURL: raw, Method: "GET"}},
				[]RuntimeRequest{{
					URL:          "https://api.example.com/gateway/api/users",
					Method:       "GET",
					ResourceType: "Fetch",
				}},
			)
			if len(report.Associations) != 1 || report.Associations[0].Prefix != "/gateway" {
				t.Fatalf("association for %q = %+v", raw, report.Associations)
			}
		})
	}
}

func TestPathMatchingIsCaseSensitive(t *testing.T) {
	report := BuildReport(
		[]StaticEndpoint{{RawURL: "/User/List", Method: "GET"}},
		[]RuntimeRequest{{URL: "https://example.com/user/list", Method: "GET", ResourceType: "XHR"}},
	)
	if len(report.Associations) != 0 {
		t.Fatalf("case-insensitive association = %+v", report.Associations)
	}
}

func TestAbsoluteStaticURLDoesNotMatchDifferentRuntimeOrigin(t *testing.T) {
	report := BuildReport(
		[]StaticEndpoint{
			{
				RawURL:      "https://github.com/vendor/project/api/list",
				Method:      "GET",
				SourceJSURL: "https://example.com/app.js",
			},
		},
		[]RuntimeRequest{
			{
				URL:          "https://example.com/gw/vendor/project/api/list",
				Method:       "GET",
				ResourceType: "Fetch",
				EntryURL:     "https://example.com/",
				Initiator: Initiator{
					StackURLs: []string{"https://example.com/app.js"},
				},
			},
		},
	)

	if len(report.Associations) != 0 {
		t.Fatalf("cross-origin absolute static URL was associated: %+v", report.Associations)
	}
}

func TestRepeatedEndpointAssociationsKeepTheirRuntimeRecords(t *testing.T) {
	report := BuildReport(
		[]StaticEndpoint{
			{RawURL: "/api/users", Method: "GET", SourceJSURL: "https://example.com/a.js"},
			{RawURL: "/api/users", Method: "GET", SourceJSURL: "https://example.com/b.js"},
		},
		[]RuntimeRequest{
			{RequestID: "first", URL: "https://example.com/api/users", Method: "GET", ResourceType: "Fetch", StatusCode: 201},
			{RequestID: "second", URL: "https://example.com/api/users", Method: "GET", ResourceType: "Fetch", StatusCode: 503, Failed: true},
		},
	)

	statuses := map[int64]int{}
	failed := 0
	for _, endpoint := range report.Endpoints {
		if endpoint.Kind != EndpointMatched {
			continue
		}
		statuses[endpoint.RuntimeStatus]++
		if endpoint.RuntimeFailed {
			failed++
		}
	}
	if statuses[201] != 2 || statuses[503] != 2 || failed != 2 {
		t.Fatalf("matched runtime records = statuses %v failed %d, want each repeated request retained twice", statuses, failed)
	}
}

func TestStableCollectionIndicesSurviveReportSorting(t *testing.T) {
	report := BuildReport(
		[]StaticEndpoint{
			{RawURL: "/api/z", Method: "GET", SourceJSURL: "https://example.com/z.js"},
			{RawURL: "/api/a", Method: "GET", SourceJSURL: "https://example.com/a.js"},
		},
		[]RuntimeRequest{
			{RequestID: "z", URL: "https://example.com/api/z", Method: "GET", ResourceType: "Fetch"},
			{RequestID: "a", URL: "https://example.com/api/a", Method: "GET", ResourceType: "Fetch"},
		},
	)

	if report.StaticEndpoints[0].RawURL != "/api/a" || report.StaticEndpoints[0].SourceIndex != 1 ||
		report.StaticEndpoints[1].RawURL != "/api/z" || report.StaticEndpoints[1].SourceIndex != 0 {
		t.Fatalf("sorted static indices = %+v", report.StaticEndpoints)
	}
	if report.RuntimeRequests[0].RequestID != "a" || report.RuntimeRequests[0].RuntimeIndex != 1 ||
		report.RuntimeRequests[1].RequestID != "z" || report.RuntimeRequests[1].RuntimeIndex != 0 {
		t.Fatalf("sorted runtime indices = %+v", report.RuntimeRequests)
	}
	if len(report.Associations) != 2 ||
		report.Associations[0].SourceIndex != 1 || report.Associations[0].RuntimeIndex != 1 ||
		report.Associations[1].SourceIndex != 0 || report.Associations[1].RuntimeIndex != 0 {
		t.Fatalf("association indices = %+v", report.Associations)
	}
	if report.Endpoints[0].SourceIndex != 1 || report.Endpoints[0].RuntimeIndex != 1 ||
		report.Endpoints[1].SourceIndex != 0 || report.Endpoints[1].RuntimeIndex != 0 {
		t.Fatalf("endpoint indices = %+v", report.Endpoints)
	}
}

func TestRelativeStaticAssociationIsIsolatedToItsSourceEntry(t *testing.T) {
	firstEntry := "https://first.example/app/"
	report := BuildReport(
		[]StaticEndpoint{{
			RawURL: "/api/users", Method: "GET", SourceJSURL: "https://cdn.example/app.js",
			SourceIdentity: SourceIdentity{EntryURL: firstEntry, FinalURL: "https://cdn.example/app.js", ContentHash: "first"},
		}},
		[]RuntimeRequest{
			{RequestID: "first", URL: "https://api.example/api/users", Method: "GET", ResourceType: "Fetch", EntryURL: firstEntry},
			{RequestID: "second", URL: "https://api.example/api/users", Method: "GET", ResourceType: "Fetch", EntryURL: "https://second.example/app/"},
		},
	)
	if len(report.Associations) != 1 || report.Associations[0].RuntimeIndex != 0 {
		t.Fatalf("associations = %+v, want only the source entry's runtime request", report.Associations)
	}
}

func TestExpressionWithoutFixedPrefixRemainsStaticOnly(t *testing.T) {
	report := BuildReport(
		[]StaticEndpoint{{
			RawURL: "/EXPR/users", Method: "GET", SourceJSURL: "https://example.com/app.js",
		}},
		[]RuntimeRequest{{
			RequestID: "runtime", URL: "https://example.com/42/users", Method: "GET", ResourceType: "Fetch",
			Initiator: Initiator{StackURLs: []string{"https://example.com/app.js"}},
		}},
	)
	if len(report.Associations) != 0 {
		t.Fatalf("associations = %+v, want no-prefix expression to remain static-only", report.Associations)
	}
	foundStaticOnly := false
	for _, endpoint := range report.Endpoints {
		if endpoint.Kind == EndpointStaticOnly && endpoint.RawURL == "/EXPR/users" {
			foundStaticOnly = true
		}
	}
	if !foundStaticOnly {
		t.Fatalf("endpoints = %+v, want expression static evidence retained", report.Endpoints)
	}
}

func TestExpressionMatchesOnlyAnExactPathSegment(t *testing.T) {
	report := BuildReport(
		[]StaticEndpoint{{RawURL: "/api/preEXPRpost/users", Method: "GET"}},
		[]RuntimeRequest{{URL: "https://example.com/api/42/users", Method: "GET", ResourceType: "Fetch"}},
	)
	if len(report.Associations) != 0 {
		t.Fatalf("associations = %+v, want EXPR wildcard only for an exact segment", report.Associations)
	}
}

func TestAssociationIndexUsesMethodFinalSegmentAndFixedPrefix(t *testing.T) {
	report := BuildReport(
		[]StaticEndpoint{
			{RawURL: "/api/alpha/users", Method: "GET"},
			{RawURL: "/api/beta/users", Method: "POST"},
		},
		[]RuntimeRequest{
			{RequestID: "alpha", URL: "https://example.com/gw/api/alpha/users", Method: "GET", ResourceType: "Fetch"},
			{RequestID: "wrong-prefix", URL: "https://example.com/gw/other/alpha/users", Method: "GET", ResourceType: "Fetch"},
			{RequestID: "beta", URL: "https://example.com/gw/api/beta/users", Method: "POST", ResourceType: "Fetch"},
			{RequestID: "wrong-method", URL: "https://example.com/gw/api/beta/users", Method: "GET", ResourceType: "Fetch"},
		},
	)
	if len(report.Associations) != 2 {
		t.Fatalf("associations = %+v, want only exact method/final-segment/fixed-prefix pairs", report.Associations)
	}
	if report.Associations[0].Prefix != "/gw" || report.Associations[1].Prefix != "/gw" {
		t.Fatalf("association prefixes = %+v, want fixed /gw", report.Associations)
	}
}

func TestRuntimeBaseEvidenceDoesNotCrossSourceEntries(t *testing.T) {
	firstEntry := "https://first.example/"
	secondEntry := "https://second.example/"
	report := BuildReport(
		[]StaticEndpoint{
			{RawURL: "/user/list", Method: "GET", SourceIdentity: SourceIdentity{EntryURL: firstEntry}},
			{RawURL: "/order/list", Method: "GET", SourceIdentity: SourceIdentity{EntryURL: secondEntry}},
		},
		[]RuntimeRequest{
			{URL: "https://api.example/gw/user/list", Method: "GET", ResourceType: "Fetch", EntryURL: firstEntry},
			{URL: "https://api.example/gw/order/list", Method: "GET", ResourceType: "Fetch", EntryURL: secondEntry},
		},
	)
	if len(report.Bases) != 2 {
		t.Fatalf("bases = %+v, want one provenance-isolated base record per entry", report.Bases)
	}
	for _, base := range report.Bases {
		if base.Confidence != ConfidenceCandidate || base.EvidenceCount != 1 || len(base.EntryURLs) != 1 {
			t.Fatalf("cross-entry evidence confirmed a base: %+v", base)
		}
	}
	if report.Bases[0].EntryURLs[0] != firstEntry || report.Bases[1].EntryURLs[0] != secondEntry {
		t.Fatalf("base ordering = %+v, want stable entry URL tie-break", report.Bases)
	}
}
