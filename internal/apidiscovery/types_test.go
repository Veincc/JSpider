package apidiscovery

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestSummaryUsesSnakeCaseJSONFields(t *testing.T) {
	encoded, err := json.Marshal(Summary{Static: 1, Runtime: 2, Matched: 3, Confirmed: 4, Bases: 5})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"static":1,"runtime":2,"matched":3,"confirmed":4,"bases":5}`
	if string(encoded) != want {
		t.Fatalf("Summary JSON = %s, want %s", encoded, want)
	}
}

func TestConfidenceAndEndpointKindConstantsAreTyped(t *testing.T) {
	if got := reflect.TypeOf(ConfidenceConfirmed).Name(); got != "Confidence" {
		t.Fatalf("ConfidenceConfirmed type = %q, want Confidence", got)
	}
	if got := reflect.TypeOf(EndpointMatched).Name(); got != "EndpointKind" {
		t.Fatalf("EndpointMatched type = %q, want EndpointKind", got)
	}
}

func TestSessionInputsAndReportsAreDeepCopied(t *testing.T) {
	static := []StaticEndpoint{{
		RawURL: "/api/static", Headers: map[string]string{"X-Test": "static-original"},
		QueryParams: []Parameter{{Name: "q", Value: "static-original"}},
	}}
	runtime := []RuntimeRequest{{
		RequestID: "runtime", URL: "https://example.com/api/runtime", ResourceType: "Document",
		Headers:     map[string]string{"X-Test": "runtime-original"},
		QueryParams: []Parameter{{Name: "q", Value: "runtime-original"}},
		GraphQL:     &GraphQLInfo{OperationName: "Original", Variables: []string{"id"}},
		Initiator:   Initiator{StackURLs: []string{"https://example.com/original.js"}},
	}}
	session := NewSession()
	session.AddStatic(static)
	session.AddRuntime(runtime)

	static[0].Headers["X-Test"] = "caller-mutated"
	static[0].QueryParams[0].Value = "caller-mutated"
	runtime[0].Headers["X-Test"] = "caller-mutated"
	runtime[0].QueryParams[0].Value = "caller-mutated"
	runtime[0].GraphQL.OperationName = "CallerMutated"
	runtime[0].Initiator.StackURLs[0] = "https://example.com/caller-mutated.js"

	first := session.Report()
	if first.StaticEndpoints[0].Headers["X-Test"] != "static-original" ||
		first.StaticEndpoints[0].QueryParams[0].Value != "static-original" ||
		first.RuntimeRequests[0].Headers["X-Test"] != "runtime-original" ||
		first.RuntimeRequests[0].GraphQL.OperationName != "Original" ||
		first.RuntimeRequests[0].Initiator.StackURLs[0] != "https://example.com/original.js" {
		t.Fatalf("session retained caller-owned nested values: %+v", first)
	}

	first.StaticEndpoints[0].Headers["X-Test"] = "report-mutated"
	first.StaticEndpoints[0].QueryParams[0].Value = "report-mutated"
	first.RuntimeRequests[0].Headers["X-Test"] = "report-mutated"
	first.RuntimeRequests[0].GraphQL.OperationName = "ReportMutated"
	first.RuntimeRequests[0].Initiator.StackURLs[0] = "https://example.com/report-mutated.js"
	second := session.Report()
	if second.StaticEndpoints[0].Headers["X-Test"] != "static-original" ||
		second.StaticEndpoints[0].QueryParams[0].Value != "static-original" ||
		second.RuntimeRequests[0].Headers["X-Test"] != "runtime-original" ||
		second.RuntimeRequests[0].GraphQL.OperationName != "Original" ||
		second.RuntimeRequests[0].Initiator.StackURLs[0] != "https://example.com/original.js" {
		t.Fatalf("Report returned session-owned nested values: %+v", second)
	}
}
