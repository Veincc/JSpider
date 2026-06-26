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
