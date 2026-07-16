package apidiscovery

import (
	"fmt"
	"strings"
	"testing"
)

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

func TestProtocolRelativeStaticAssociationUsesOwnEntryIdentityAndScheme(t *testing.T) {
	firstEntry := "http://first.example/app/"
	report := BuildReport(
		[]StaticEndpoint{{
			RawURL: "//api.example/api/users", Method: "GET",
			SourceIdentity: SourceIdentity{EntryURL: firstEntry},
		}},
		[]RuntimeRequest{
			{RequestID: "cross-entry", URL: "http://api.example/api/users", Method: "GET", ResourceType: "Fetch", EntryURL: "http://second.example/app/"},
			{RequestID: "cross-scheme", URL: "https://api.example/api/users", Method: "GET", ResourceType: "Fetch", EntryURL: firstEntry},
			{RequestID: "own-entry", URL: "http://api.example/api/users", Method: "GET", ResourceType: "Fetch", EntryURL: firstEntry},
		},
	)
	if len(report.Associations) != 1 || report.Associations[0].RuntimeIndex != 2 {
		t.Fatalf("associations = %+v, want only same-entry same-scheme runtime", report.Associations)
	}
}

func TestProtocolRelativeStaticWithoutSourceIdentityDoesNotAssociate(t *testing.T) {
	report := BuildReport(
		[]StaticEndpoint{{RawURL: "//api.example/api/users", Method: "GET"}},
		[]RuntimeRequest{
			{RequestID: "http-first", URL: "http://api.example/api/users", Method: "GET", ResourceType: "Fetch", EntryURL: "http://first.example/"},
			{RequestID: "https-first", URL: "https://api.example/api/users", Method: "GET", ResourceType: "Fetch", EntryURL: "http://first.example/"},
			{RequestID: "http-second", URL: "http://api.example/api/users", Method: "GET", ResourceType: "Fetch", EntryURL: "http://second.example/"},
		},
	)
	if len(report.Associations) != 0 {
		t.Fatalf("associations = %+v, want no binding without source entry provenance", report.Associations)
	}
}

func TestProtocolRelativeStaticOnlyUsesResolvedOriginAndCandidate(t *testing.T) {
	entry := "http://first.example/app/"
	session := NewSession()
	session.AddEntryURL(entry)
	session.AddStatic([]StaticEndpoint{{
		RawURL:         "//first.example/api/users",
		SourceIdentity: SourceIdentity{EntryURL: entry},
	}})
	report := session.Report()
	if len(report.Endpoints) != 1 || report.Endpoints[0].Kind != EndpointStaticOnly {
		t.Fatalf("endpoints = %+v, want methodless same-origin static endpoint", report.Endpoints)
	}
	want := []string{"http://first.example/api/users"}
	if got := report.Endpoints[0].ResolvedCandidates; len(got) != 1 || got[0] != want[0] {
		t.Fatalf("resolved candidates = %v, want %v", got, want)
	}
	if got := EndpointURLs(report, []string{entry}); len(got) != 1 || got[0] != want[0] {
		t.Fatalf("EndpointURLs() = %v, want %v", got, want)
	}
}

func TestDefaultPortAuthorityUsesCanonicalOrigin(t *testing.T) {
	report := BuildReport(
		[]StaticEndpoint{{
			RawURL: "https://EXAMPLE.com:443/api/users", Method: "GET",
		}},
		[]RuntimeRequest{{
			URL: "https://example.com/api/users", Method: "GET", ResourceType: "Fetch",
			EntryURL: "https://example.com/",
		}},
	)
	if len(report.Associations) != 1 {
		t.Fatalf("associations = %+v, want canonical same-origin match", report.Associations)
	}
	association := report.Associations[0]
	if association.RuntimeOrigin != "https://example.com" {
		t.Fatalf("runtime origin = %q, want canonical origin", association.RuntimeOrigin)
	}
	if !containsString(association.Evidence, "entry_origin") {
		t.Fatalf("evidence = %v, want canonical entry-origin evidence", association.Evidence)
	}
}

func TestMappedIPv6AuthorityDoesNotCollapseToIPv4Origin(t *testing.T) {
	ipv4Static := StaticEndpoint{RawURL: "https://192.0.2.1/api/users", Method: "GET"}
	mappedRuntime := RuntimeRequest{
		URL: "https://[::ffff:192.0.2.1]/api/users", Method: "GET", ResourceType: "Fetch",
	}
	ipv4Index := newRuntimeAssociationIndex([]StaticEndpoint{ipv4Static}, []RuntimeRequest{mappedRuntime})
	if candidates := ipv4Index.candidates(ipv4Static); len(candidates) != 0 {
		t.Fatalf("IPv4 candidates = %v, want mapped IPv6 authority isolated", candidates)
	}
	if report := BuildReport([]StaticEndpoint{ipv4Static}, []RuntimeRequest{mappedRuntime}); len(report.Associations) != 0 {
		t.Fatalf("IPv4/mapped-IPv6 associations = %+v, want none", report.Associations)
	}

	mappedStatic := StaticEndpoint{RawURL: "https://[::ffff:192.0.2.1]/api/users", Method: "GET"}
	equivalentRuntime := RuntimeRequest{
		URL: "https://[::ffff:c000:201]/api/users", Method: "GET", ResourceType: "Fetch",
	}
	mappedIndex := newRuntimeAssociationIndex([]StaticEndpoint{mappedStatic}, []RuntimeRequest{equivalentRuntime})
	if candidates := mappedIndex.candidates(mappedStatic); len(candidates) != 1 || candidates[0] != 0 {
		t.Fatalf("mapped IPv6 candidates = %v, want equivalent runtime 0", candidates)
	}
	report := BuildReport([]StaticEndpoint{mappedStatic}, []RuntimeRequest{equivalentRuntime})
	if len(report.Associations) != 1 || report.Associations[0].RuntimeOrigin != "https://[::ffff:192.0.2.1]" {
		t.Fatalf("mapped IPv6 associations = %+v, want canonical mapped origin", report.Associations)
	}
}

func TestProtocolRelativeDefaultPortAuthorityUsesCanonicalOrigin(t *testing.T) {
	entry := "https://entry.example/app/"
	static := StaticEndpoint{
		RawURL: "//API.EXAMPLE:443/api/users", Method: "GET",
		SourceIdentity: SourceIdentity{EntryURL: entry},
	}
	runtime := RuntimeRequest{
		URL: "https://api.example/api/users", Method: "GET", ResourceType: "XHR", EntryURL: entry,
	}

	associationIndex := newRuntimeAssociationIndex([]StaticEndpoint{static}, []RuntimeRequest{runtime})
	if candidates := associationIndex.candidates(static); len(candidates) != 1 || candidates[0] != 0 {
		t.Fatalf("candidates = %v, want one canonical authority candidate", candidates)
	}
	report := BuildReport([]StaticEndpoint{static}, []RuntimeRequest{runtime})
	if len(report.Associations) != 1 || report.Associations[0].RuntimeOrigin != "https://api.example" {
		t.Fatalf("associations = %+v, want canonical protocol-relative match", report.Associations)
	}
}

func TestEntryOriginEvidenceUsesCanonicalOrigin(t *testing.T) {
	entry := "https://EXAMPLE.com:443/start"
	report := BuildReport(
		[]StaticEndpoint{{
			RawURL: "/api/users", Method: "GET",
			SourceIdentity: SourceIdentity{EntryURL: entry},
		}},
		[]RuntimeRequest{{
			URL: "https://EXAMPLE.com:443/api/users", Method: "GET", ResourceType: "Fetch",
			EntryURL: entry,
		}},
	)
	if len(report.Associations) != 1 {
		t.Fatalf("associations = %+v, want one", report.Associations)
	}
	association := report.Associations[0]
	if association.RuntimeOrigin != "https://example.com" {
		t.Fatalf("runtime origin = %q, want canonical origin", association.RuntimeOrigin)
	}
	if !containsString(association.Evidence, "entry_origin") {
		t.Fatalf("evidence = %v, want canonical entry-origin evidence", association.Evidence)
	}
}

func TestMethodlessCanonicalSameOriginStaticOnlyIsReportable(t *testing.T) {
	session := NewSession()
	session.AddEntryURL("https://example.com/")
	session.AddStatic([]StaticEndpoint{{RawURL: "https://EXAMPLE.com:443/api/users"}})

	report := session.Report()
	if len(report.Endpoints) != 1 || report.Endpoints[0].Kind != EndpointStaticOnly {
		t.Fatalf("endpoints = %+v, want canonical same-origin static-only endpoint", report.Endpoints)
	}
}

func TestNonDefaultPortAuthorityRemainsDistinct(t *testing.T) {
	report := BuildReport(
		[]StaticEndpoint{{RawURL: "https://example.com:444/api/users", Method: "GET"}},
		[]RuntimeRequest{{URL: "https://example.com/api/users", Method: "GET", ResourceType: "Fetch"}},
	)
	if len(report.Associations) != 0 {
		t.Fatalf("associations = %+v, want non-default port isolated", report.Associations)
	}
}

func TestNonHTTPAuthorityDoesNotAssociate(t *testing.T) {
	report := BuildReport(
		[]StaticEndpoint{{RawURL: "ftp://example.com/api/users", Method: "GET"}},
		[]RuntimeRequest{{URL: "ftp://example.com/api/users", Method: "GET", ResourceType: "Fetch"}},
	)
	if len(report.Associations) != 0 {
		t.Fatalf("associations = %+v, want non-HTTP authority rejected", report.Associations)
	}
}

func TestAssociationIndexRejectsInvalidRuntimeAuthority(t *testing.T) {
	static := StaticEndpoint{RawURL: "/api/users", Method: "GET"}
	runtime := []RuntimeRequest{
		{URL: "ftp://example.com/api/users", Method: "GET", ResourceType: "Fetch"},
		{URL: "https://example.com:/api/users", Method: "GET", ResourceType: "Fetch"},
	}
	associationIndex := newRuntimeAssociationIndex([]StaticEndpoint{static}, runtime)
	if candidates := associationIndex.candidates(static); len(candidates) != 0 {
		t.Fatalf("candidates = %v, want invalid runtime authorities omitted from every scope", candidates)
	}
}

func TestInvalidStaticAuthorityFailsClosed(t *testing.T) {
	runtime := []RuntimeRequest{{
		URL: "https://example.com/api/users", Method: "GET", ResourceType: "Fetch",
	}}
	for _, rawURL := range []string{
		"https:/api/users",
		"https://example.com:/api/users",
		"ftp:/api/users",
		"ftp://example.com/api/users",
	} {
		t.Run(rawURL, func(t *testing.T) {
			static := StaticEndpoint{RawURL: rawURL, Method: "GET"}
			associationIndex := newRuntimeAssociationIndex([]StaticEndpoint{static}, runtime)
			if candidates := associationIndex.candidates(static); len(candidates) != 0 {
				t.Fatalf("candidates = %v, want invalid static authority rejected", candidates)
			}

			report := BuildReport([]StaticEndpoint{static}, runtime)
			if len(report.Associations) != 0 {
				t.Fatalf("associations = %+v, want invalid static authority rejected", report.Associations)
			}
			for _, endpoint := range report.Endpoints {
				if endpoint.Kind == EndpointStaticOnly && endpoint.RawURL == rawURL {
					t.Fatalf("invalid static-only endpoint was reported: %+v", endpoint)
				}
			}
		})
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

func TestExpressionAssociationIndexPartitionsFixedSegmentsAfterEXPR(t *testing.T) {
	const count = 64
	static := make([]StaticEndpoint, count)
	runtime := make([]RuntimeRequest, count)
	for index := 0; index < count; index++ {
		static[index] = StaticEndpoint{
			RawURL: fmt.Sprintf("/api/EXPR/item-%03d/users", index),
			Method: "GET",
		}
		runtime[index] = RuntimeRequest{
			URL:          fmt.Sprintf("https://example.com/gw/api/value/item-%03d/users", index),
			Method:       "GET",
			ResourceType: "Fetch",
		}
	}

	associationIndex := newRuntimeAssociationIndex(static, runtime)
	for staticIndex, endpoint := range static {
		candidates := associationIndex.candidates(endpoint)
		if len(candidates) != 1 || candidates[0] != staticIndex {
			t.Fatalf("static[%d] candidates = %v, want only runtime %d", staticIndex, candidates, staticIndex)
		}
	}
}

func TestAssociationIndexPartitionsSamePathBySourceEntry(t *testing.T) {
	const count = 64
	static := make([]StaticEndpoint, count)
	runtime := make([]RuntimeRequest, count)
	for index := 0; index < count; index++ {
		entry := fmt.Sprintf("https://entry-%03d.example/", index)
		rawURL := "/api/users"
		if index%2 == 1 {
			rawURL = "//api.example/api/users"
		}
		staticMethod := "GET"
		runtimeMethod := "GET"
		switch index % 3 {
		case 1:
			runtimeMethod = ""
		case 2:
			staticMethod = ""
			runtimeMethod = "POST"
		}
		static[index] = StaticEndpoint{
			RawURL: rawURL, Method: staticMethod, SourceIdentity: SourceIdentity{EntryURL: entry},
		}
		runtime[index] = RuntimeRequest{
			URL: "https://api.example/api/users", Method: runtimeMethod, ResourceType: "Fetch", EntryURL: entry,
		}
	}

	associationIndex := newRuntimeAssociationIndex(static, runtime)
	for staticIndex, endpoint := range static {
		candidates := associationIndex.candidates(endpoint)
		if len(candidates) != 1 || candidates[0] != staticIndex {
			t.Fatalf("static[%d] candidates = %v, want only same-entry runtime %d", staticIndex, candidates, staticIndex)
		}
	}

	unproven := make([]StaticEndpoint, count)
	for index := range unproven {
		unproven[index] = StaticEndpoint{RawURL: "//api.example/api/users", Method: "GET"}
	}
	unprovenIndex := newRuntimeAssociationIndex(unproven, runtime)
	for staticIndex, endpoint := range unproven {
		if candidates := unprovenIndex.candidates(endpoint); len(candidates) != 0 {
			t.Fatalf("unproven static[%d] candidates = %v, want none", staticIndex, candidates)
		}
	}
}

func TestAssociationIndexPartitionsSamePathByAuthority(t *testing.T) {
	const count = 64
	absolute := make([]StaticEndpoint, count)
	absoluteRuntime := make([]RuntimeRequest, count)
	protocolRelative := make([]StaticEndpoint, count)
	protocolRuntime := make([]RuntimeRequest, count)
	entry := "https://entry.example/app/"
	for index := 0; index < count; index++ {
		staticMethod := "GET"
		runtimeMethod := "GET"
		switch index % 3 {
		case 1:
			runtimeMethod = ""
		case 2:
			staticMethod = ""
			runtimeMethod = "POST"
		}
		scheme := "https"
		if index%2 == 1 {
			scheme = "http"
		}
		staticHost := fmt.Sprintf("API-%03d.EXAMPLE", index)
		runtimeHost := strings.ToLower(staticHost)
		absolute[index] = StaticEndpoint{
			RawURL: scheme + "://" + staticHost + "/api/users", Method: staticMethod,
		}
		absoluteRuntime[index] = RuntimeRequest{
			URL: scheme + "://" + runtimeHost + "/api/users", Method: runtimeMethod, ResourceType: "Fetch",
		}
		protocolRelative[index] = StaticEndpoint{
			RawURL: "//" + staticHost + "/api/users", Method: staticMethod,
			SourceIdentity: SourceIdentity{EntryURL: entry},
		}
		protocolRuntime[index] = RuntimeRequest{
			URL: "https://" + runtimeHost + "/api/users", Method: runtimeMethod, ResourceType: "Fetch", EntryURL: entry,
		}
	}

	tests := []struct {
		name    string
		static  []StaticEndpoint
		runtime []RuntimeRequest
	}{
		{name: "absolute", static: absolute, runtime: absoluteRuntime},
		{name: "proven protocol-relative", static: protocolRelative, runtime: protocolRuntime},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			associationIndex := newRuntimeAssociationIndex(test.static, test.runtime)
			for staticIndex, endpoint := range test.static {
				candidates := associationIndex.candidates(endpoint)
				if len(candidates) != 1 || candidates[0] != staticIndex {
					t.Fatalf("static[%d] candidates = %v, want only same-authority runtime %d", staticIndex, candidates, staticIndex)
				}
			}
		})
	}

	portStatic := StaticEndpoint{RawURL: "https://API.EXAMPLE:443/api/users", Method: "GET"}
	portRuntime := []RuntimeRequest{
		{URL: "http://api.example:443/api/users", Method: "GET", ResourceType: "Fetch"},
		{URL: "https://api.example/api/users", Method: "GET", ResourceType: "Fetch"},
		{URL: "https://api.example:444/api/users", Method: "GET", ResourceType: "Fetch"},
	}
	portIndex := newRuntimeAssociationIndex([]StaticEndpoint{portStatic}, portRuntime)
	if candidates := portIndex.candidates(portStatic); len(candidates) != 1 || candidates[0] != 1 {
		t.Fatalf("explicit-default-port candidates = %v, want canonical HTTPS runtime 1", candidates)
	}
}

func TestAssociationIndexLongExactPathMetadataIsLinear(t *testing.T) {
	const segmentCount = 512
	segments := make([]string, segmentCount)
	for index := range segments {
		segments[index] = fmt.Sprintf("segment-%03d", index)
	}
	pathValue := "/" + strings.Join(segments, "/")
	static := []StaticEndpoint{{RawURL: pathValue, Method: "GET"}}
	runtime := []RuntimeRequest{{
		URL: "https://example.com/gateway" + pathValue, Method: "GET", ResourceType: "Fetch",
	}}

	trie := buildAssociationPathTrie(static)
	if nodes := countAssociationPathTrieNodes(trie); nodes != segmentCount+1 {
		t.Fatalf("trie nodes = %d, want %d for one %d-segment static path", nodes, segmentCount+1, segmentCount)
	}
	associationIndex := newRuntimeAssociationIndex(static, runtime)
	if len(associationIndex.anyMethod) != 2 || len(associationIndex.byMethod) != 2 {
		t.Fatalf("candidate map keys = any:%d method:%d, want one global and one authority scope", len(associationIndex.anyMethod), len(associationIndex.byMethod))
	}
	if candidates := associationIndex.candidates(static[0]); len(candidates) != 1 || candidates[0] != 0 {
		t.Fatalf("candidates = %v, want runtime 0", candidates)
	}
}

func TestExpressionAssociationIndexPreservesEmptyMethodCompatibility(t *testing.T) {
	static := []StaticEndpoint{
		{RawURL: "/api/EXPR/users", Method: "GET"},
		{RawURL: "/api/EXPR/users"},
	}
	runtime := []RuntimeRequest{
		{URL: "https://example.com/api/one/users", ResourceType: "Fetch"},
		{URL: "https://example.com/api/two/users", Method: "POST", ResourceType: "Fetch"},
	}
	associationIndex := newRuntimeAssociationIndex(static, runtime)
	if candidates := associationIndex.candidates(static[0]); len(candidates) != 1 || candidates[0] != 0 {
		t.Fatalf("GET static candidates = %v, want empty-method runtime compatibility", candidates)
	}
	if candidates := associationIndex.candidates(static[1]); len(candidates) != 2 {
		t.Fatalf("methodless static candidates = %v, want both runtime methods", candidates)
	}
}

func countAssociationPathTrieNodes(node *associationPathTrie) int {
	if node == nil {
		return 0
	}
	count := 1
	for _, child := range node.children {
		count += countAssociationPathTrieNodes(child)
	}
	return count
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
