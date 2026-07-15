package apidiscovery

import "testing"

func FuzzParseRequestData(f *testing.F) {
	for _, seed := range []struct {
		rawURL      string
		contentType string
		body        []byte
	}{
		{"https://example.com/api?token=raw&tag=a&tag=b", "application/json", []byte(`{"user":{"name":"alice"},"token":"raw-secret"}`)},
		{"https://example.com/graphql", "application/graphql+json", []byte(`{"query":"query User($id: ID!){user(id:$id){name}}","variables":{"id":"42"}}`)},
		{"https://example.com/form", "application/x-www-form-urlencoded", []byte(`name=alice&token=raw-secret`)},
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
		for _, parameter := range append(append([]Parameter(nil), result.QueryParams...), result.Body.Params...) {
			if len(parameter.Value) > MaxParameterValueBytes {
				t.Fatalf("parameter %q value length = %d, max %d", parameter.Name, len(parameter.Value), MaxParameterValueBytes)
			}
		}
	})
}
