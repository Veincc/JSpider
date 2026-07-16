package apidiscovery

import (
	"net/url"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func FuzzParseRequestData(f *testing.F) {
	longQueryValue := strings.Repeat("q", MaxParameterValueBytes+73)
	for _, seed := range []struct {
		rawURL      string
		contentType string
		body        []byte
	}{
		{"https://example.com/api?token=raw&tag=a&tag=b", "application/json", []byte(`{"user":{"name":"alice"},"token":"raw-secret"}`)},
		{"https://example.com/graphql", "application/graphql+json", []byte(`{"query":"query User($id: ID!){user(id:$id){name}}","variables":{"id":"42"}}`)},
		{"https://example.com/form", "application/x-www-form-urlencoded", []byte(`name=alice&token=raw-secret`)},
		{"https://example.com/api?query=" + longQueryValue, "", nil},
		{"%zz", `multipart/form-data; boundary=broken`, []byte("--broken\r\ninvalid")},
		{"http://[::1]/", "application/json; charset=utf-8", []byte("\x00{not-json")},
	} {
		f.Add(seed.rawURL, seed.contentType, seed.body)
	}

	f.Fuzz(func(t *testing.T, rawURL, contentType string, body []byte) {
		if len(rawURL) > 64*1024 || len(contentType) > 64*1024 || len(body) > 2*MaxRequestBodyBytes {
			t.Skip()
		}
		result := ParseRequestData(rawURL, map[string]string{"Content-Type": contentType}, body, len(body) > 0)
		if len(result.Body.Sample) > MaxBodySampleBytes {
			t.Fatalf("body sample length = %d, max %d", len(result.Body.Sample), MaxBodySampleBytes)
		}
		for _, parameter := range result.Body.Params {
			if len(parameter.Value) > MaxParameterValueBytes {
				t.Fatalf("body parameter %q value length = %d, max %d", parameter.Name, len(parameter.Value), MaxParameterValueBytes)
			}
		}

		parsed, err := url.Parse(rawURL)
		if err != nil {
			return
		}
		wantQuery := parsed.Query()
		gotQuery := make(url.Values)
		for _, parameter := range result.QueryParams {
			gotQuery[parameter.Name] = append(gotQuery[parameter.Name], parameter.Value)
		}
		for _, values := range wantQuery {
			sort.Strings(values)
		}
		for _, values := range gotQuery {
			sort.Strings(values)
		}
		if !reflect.DeepEqual(gotQuery, wantQuery) {
			t.Fatalf("query params = %#v, want full parsed values %#v", gotQuery, wantQuery)
		}
	})
}
