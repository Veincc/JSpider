package apidiscovery

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestParseRequestData(t *testing.T) {
	tests := []struct {
		name        string
		rawURL      string
		contentType string
		body        string
		wantQuery   []string
		wantBody    []string
		wantGraphQL bool
	}{
		{
			name:        "JSON nested fields",
			rawURL:      "https://api.example.com/users?page=1&token=secret",
			contentType: "application/json",
			body:        `{"filters":{"status":"active"},"password":"hunter2"}`,
			wantQuery:   []string{"page", "token"},
			wantBody:    []string{"filters.status", "password"},
		},
		{
			name:        "form",
			rawURL:      "https://api.example.com/login",
			contentType: "application/x-www-form-urlencoded",
			body:        "username=alice&passwd=secret",
			wantBody:    []string{"passwd", "username"},
		},
		{
			name:        "multipart",
			rawURL:      "https://api.example.com/upload",
			contentType: "multipart/form-data; boundary=BOUNDARY",
			body: "--BOUNDARY\r\nContent-Disposition: form-data; name=\"description\"\r\n\r\nhello\r\n" +
				"--BOUNDARY\r\nContent-Disposition: form-data; name=\"file\"; filename=\"secret.txt\"\r\nContent-Type: text/plain\r\n\r\nfile contents\r\n--BOUNDARY--\r\n",
			wantBody: []string{"description", "file"},
		},
		{
			name:        "GraphQL",
			rawURL:      "https://api.example.com/graphql",
			contentType: "application/json",
			body:        `{"operationName":"ListUsers","query":"query ListUsers { users { id } }","variables":{"filters":{"status":"active"},"token":"secret"}}`,
			wantBody:    []string{"operationName", "variables.filters.status", "variables.token"},
			wantGraphQL: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseRequestData(tt.rawURL, map[string]string{"Content-Type": tt.contentType}, []byte(tt.body), tt.body != "")
			if names := parameterNames(got.QueryParams); !equalStrings(names, tt.wantQuery) {
				t.Fatalf("query params = %v, want %v", names, tt.wantQuery)
			}
			if names := parameterNames(got.Body.Params); !equalStrings(names, tt.wantBody) {
				t.Fatalf("body params = %v, want %v", names, tt.wantBody)
			}
			if (got.Body.GraphQL != nil) != tt.wantGraphQL {
				t.Fatalf("GraphQL metadata present = %v, want %v", got.Body.GraphQL != nil, tt.wantGraphQL)
			}
			if strings.Contains(got.Body.Sample, "file contents") {
				t.Fatalf("multipart file contents leaked into body sample: %q", got.Body.Sample)
			}
			if len(got.Body.Sample) > MaxBodySampleBytes {
				t.Fatalf("body sample length = %d, want <= %d", len(got.Body.Sample), MaxBodySampleBytes)
			}
		})
	}
}

func TestRequestDataPreservesHeadersAndQueryWhileBoundingBodyFields(t *testing.T) {
	got := ParseRequestData(
		"https://example.com/api?access_token=top-secret&name="+strings.Repeat("x", 200),
		map[string]string{
			"Content-Type":        "application/json",
			"Authorization":       "Bearer secret",
			"Cookie":              "session=secret",
			"Proxy-Authorization": "Basic secret",
			"X-API-Key":           "header-secret",
			"X-Trace":             "trace-value",
		},
		[]byte(`{"api_key":"secret","display":"`+strings.Repeat("y", 200)+`"}`),
		true,
	)

	if len(got.Headers) != 6 || got.Headers["X-Trace"] != "trace-value" ||
		got.Headers["Content-Type"] != "application/json" || got.Headers["X-API-Key"] != "header-secret" ||
		got.Headers["Authorization"] != "Bearer secret" || got.Headers["Cookie"] != "session=secret" {
		t.Fatalf("preserved headers = %#v", got.Headers)
	}
	if valueFor(got.QueryParams, "access_token") != "top-secret" {
		t.Fatalf("access_token = %q", valueFor(got.QueryParams, "access_token"))
	}
	if valueFor(got.Body.Params, "api_key") != "secret" {
		t.Fatalf("api_key = %q", valueFor(got.Body.Params, "api_key"))
	}
	if len(valueFor(got.QueryParams, "name")) != 200 {
		t.Fatalf("query value length = %d, want full 200", len(valueFor(got.QueryParams, "name")))
	}
	if len(valueFor(got.Body.Params, "display")) != MaxParameterValueBytes {
		t.Fatalf("body value length = %d, want %d", len(valueFor(got.Body.Params, "display")), MaxParameterValueBytes)
	}
	sanitizedURL := SanitizeURL("https://example.com/api?access_token=top-secret&name=" + strings.Repeat("z", 200))
	if sanitizedURL != "https://example.com/api?access_token=top-secret&name="+strings.Repeat("z", 200) {
		t.Fatalf("SanitizeURL() = %q", sanitizedURL)
	}
	parsedURL := ParseRequestData(sanitizedURL, nil, nil, false)
	if len(valueFor(parsedURL.QueryParams, "name")) != 200 {
		t.Fatalf("sanitized URL name length = %d", len(valueFor(parsedURL.QueryParams, "name")))
	}
}

func TestRequestDataPreservesExistingRawValuesWithoutSanitization(t *testing.T) {
	longQuery := strings.Repeat("q", MaxParameterValueBytes+73)
	rawURL := "https://example.com/api?access_token=top-secret&query=" + longQuery
	got := ParseRequestData(
		rawURL,
		map[string]string{
			"Content-Type":  "application/json",
			"Authorization": "Bearer raw-secret",
			"Cookie":        "session=raw-secret",
		},
		[]byte(`{"password":"raw-password","display":"raw-display"}`),
		true,
	)

	if valueFor(got.QueryParams, "access_token") != "top-secret" {
		t.Fatalf("access_token = %q, want raw value", valueFor(got.QueryParams, "access_token"))
	}
	if valueFor(got.QueryParams, "query") != longQuery {
		t.Fatalf("query length = %d, want full %d", len(valueFor(got.QueryParams, "query")), len(longQuery))
	}
	if got.Headers["Authorization"] != "Bearer raw-secret" || got.Headers["Cookie"] != "session=raw-secret" {
		t.Fatalf("headers = %#v, want original values", got.Headers)
	}
	if valueFor(got.Body.Params, "password") != "raw-password" || !strings.Contains(got.Body.Sample, "raw-password") {
		t.Fatalf("body = %+v, want original values", got.Body)
	}
	if sanitized := SanitizeURL(rawURL); sanitized != rawURL {
		t.Fatalf("SanitizeURL changed existing URL value: %q", sanitized)
	}
}

func TestParseJSONBodyUsesOneMiBLimitBeforeSampling(t *testing.T) {
	body := []byte(`{"padding":"` + strings.Repeat("x", 96*1024) + `","tail":"seen"}`)
	got := ParseRequestData(
		"https://example.com/api",
		map[string]string{"Content-Type": "application/json"},
		body,
		true,
	)
	if got.Body.Truncated {
		t.Fatal("Truncated = true for JSON body below 1 MiB")
	}
	if got.Body.ParseError != "" {
		t.Fatalf("ParseError = %q, want empty", got.Body.ParseError)
	}
	if valueFor(got.Body.Params, "tail") != "seen" {
		t.Fatalf("body params = %+v, want tail parsed after previous 64 KiB boundary", got.Body.Params)
	}
	if len(got.Body.Sample) > MaxBodySampleBytes {
		t.Fatalf("sample length = %d, want <= %d", len(got.Body.Sample), MaxBodySampleBytes)
	}
}

func TestParseJSONBodyReportsTruncationAndParseErrors(t *testing.T) {
	t.Run("over 1 MiB", func(t *testing.T) {
		body := []byte(`{"padding":"` + strings.Repeat("x", MaxRequestBodyBytes+1) + `"}`)
		got := ParseRequestData("https://example.com/api", map[string]string{"Content-Type": "application/json"}, body, true)
		if !got.Body.Truncated {
			t.Fatal("Truncated = false, want true")
		}
		if got.Body.ParseError == "" {
			t.Fatal("ParseError is empty for a JSON document cut at the 1 MiB limit")
		}
	})
	t.Run("malformed", func(t *testing.T) {
		got := ParseRequestData("https://example.com/api", map[string]string{"Content-Type": "application/json"}, []byte(`{"broken":`), true)
		if got.Body.Truncated {
			t.Fatal("Truncated = true for malformed short JSON")
		}
		if got.Body.ParseError == "" {
			t.Fatal("ParseError is empty for malformed JSON")
		}
	})
	t.Run("trailing invalid data", func(t *testing.T) {
		got := ParseRequestData("https://example.com/api", map[string]string{"Content-Type": "application/json"}, []byte(`{"valid":1} trailing`), true)
		if got.Body.ParseError == "" {
			t.Fatal("ParseError is empty for trailing invalid JSON data")
		}
	})
}

func TestRequestDataPreservesAuthorizationAndCookieParameterValues(t *testing.T) {
	got := ParseRequestData(
		"https://example.com/api?authorization=Bearer+secret&cookie=session-secret&proxy_authorization=Basic+secret&set-cookie=sid%3Dsecret",
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
		[]byte("Authorization=form-secret&Cookie=form-cookie"),
		true,
	)

	wantQuery := map[string]string{
		"authorization": "Bearer secret", "cookie": "session-secret",
		"proxy_authorization": "Basic secret", "set-cookie": "sid=secret",
	}
	for name, want := range wantQuery {
		if valueFor(got.QueryParams, name) != want {
			t.Fatalf("query param %q = %q, want %q", name, valueFor(got.QueryParams, name), want)
		}
	}
	for name, want := range map[string]string{"Authorization": "form-secret", "Cookie": "form-cookie"} {
		if valueFor(got.Body.Params, name) != want {
			t.Fatalf("form param %q = %q, want %q", name, valueFor(got.Body.Params, name), want)
		}
	}
}

func TestSanitizeSourceSnippetPreservesExistingSource(t *testing.T) {
	source := `fetch("/api", {setCookie: "sid=secret", proxyAuthorization: "Basic secret", proxy_authorization: "Basic secret"})`
	got := SanitizeSourceSnippet(source)
	if got != source {
		t.Fatalf("SanitizeSourceSnippet() = %q, want original source", got)
	}
}

func TestRequestDataTruncationPreservesUTF8(t *testing.T) {
	longChineseValue := strings.Repeat("界", 43)
	got := ParseRequestData(
		"https://example.com/api?name="+urlQueryEscape(longChineseValue),
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
		[]byte("display="+urlQueryEscape(longChineseValue)),
		true,
	)

	for _, value := range []string{valueFor(got.QueryParams, "name"), valueFor(got.Body.Params, "display"), got.Body.Sample} {
		if !utf8.ValidString(value) {
			t.Fatalf("truncated value is invalid UTF-8: %q", value)
		}
	}
}

func TestOtherContentTypeDoesNotStoreRawBody(t *testing.T) {
	got := ParseRequestData(
		"https://example.com/api",
		map[string]string{"Content-Type": "application/octet-stream"},
		[]byte("raw-secret-body"),
		true,
	)
	if !got.Body.HasBody {
		t.Fatal("HasBody = false, want true")
	}
	if got.Body.Sample != "" || len(got.Body.Params) != 0 {
		t.Fatalf("unexpected raw body data: %+v", got.Body)
	}
}

func urlQueryEscape(value string) string {
	return strings.ReplaceAll(value, "界", "%E7%95%8C")
}

func TestBatchedGraphQLPreservesExistingBodySample(t *testing.T) {
	got := ParseRequestData(
		"https://example.com/graphql",
		map[string]string{"Content-Type": "application/json"},
		[]byte(`[
			{"operationName":"ListUsers","query":"query ListUsers { users { id email } }","variables":{"token":"secret","filters":{"status":"active"}}},
			{"operationName":"ListOrders","query":"query ListOrders { orders { id } }","variables":{"page":1}}
		]`),
		true,
	)

	if got.Body.GraphQL == nil {
		t.Fatal("batched GraphQL metadata was not detected")
	}
	if !strings.Contains(got.Body.Sample, "query ListUsers") || !strings.Contains(got.Body.Sample, "secret") {
		t.Fatalf("batched GraphQL sample did not preserve existing body values: %q", got.Body.Sample)
	}
	for _, name := range []string{"filters.status", "page", "token"} {
		found := false
		for _, variable := range got.Body.GraphQL.Variables {
			if variable == name {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("GraphQL variables = %v, missing %q", got.Body.GraphQL.Variables, name)
		}
	}
}

func TestGraphQLClassificationRequiresParsedDocument(t *testing.T) {
	t.Run("ordinary URL query parameter", func(t *testing.T) {
		got := ParseRequestData("https://example.com/api?query=foo", nil, nil, false)
		if got.Body.GraphQL != nil {
			t.Fatalf("GraphQL = %+v, want nil", got.Body.GraphQL)
		}
		if valueFor(got.QueryParams, "query") != "foo" {
			t.Fatalf("query params = %+v, want ordinary query evidence", got.QueryParams)
		}
	})

	t.Run("ordinary JSON query field", func(t *testing.T) {
		got := ParseRequestData(
			"https://example.com/search",
			map[string]string{"Content-Type": "application/json"},
			[]byte(`{"query":"foo","page":2}`),
			true,
		)
		if got.Body.GraphQL != nil {
			t.Fatalf("GraphQL = %+v, want nil", got.Body.GraphQL)
		}
		if valueFor(got.Body.Params, "query") != "foo" || valueFor(got.Body.Params, "page") != "2" {
			t.Fatalf("body params = %+v, want ordinary JSON evidence", got.Body.Params)
		}
	})

	t.Run("parsed GraphQL document", func(t *testing.T) {
		got := ParseRequestData(
			"https://example.com/graphql",
			map[string]string{"Content-Type": "application/json"},
			[]byte(`{"operationName":"UserByID","query":"query UserByID($id: ID!) { user(id: $id) { id } }","variables":{"id":"42"}}`),
			true,
		)
		if got.Body.GraphQL == nil || got.Body.GraphQL.OperationName != "UserByID" {
			t.Fatalf("GraphQL = %+v, want parsed UserByID metadata", got.Body.GraphQL)
		}
	})
}

func parameterNames(params []Parameter) []string {
	names := make([]string, 0, len(params))
	for _, param := range params {
		names = append(names, param.Name)
	}
	return names
}

func valueFor(params []Parameter, name string) string {
	for _, param := range params {
		if param.Name == name {
			return param.Value
		}
	}
	return ""
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
