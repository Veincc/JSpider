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
