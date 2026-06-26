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
			if strings.Contains(got.Body.Sample, "hunter2") || strings.Contains(got.Body.Sample, "secret") ||
				strings.Contains(got.Body.Sample, "query ListUsers") || strings.Contains(got.Body.Sample, "file contents") {
				t.Fatalf("body sample contains sensitive or forbidden content: %q", got.Body.Sample)
			}
			if len(got.Body.Sample) > MaxBodySampleBytes {
				t.Fatalf("body sample length = %d, want <= %d", len(got.Body.Sample), MaxBodySampleBytes)
			}
		})
	}
}

func TestRequestDataRedactsHeadersAndValues(t *testing.T) {
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

	if len(got.Headers) != 3 || got.Headers["X-Trace"] != "trace-value" ||
		got.Headers["Content-Type"] != "application/json" || got.Headers["X-Api-Key"] != RedactedValue {
		t.Fatalf("sanitized headers = %#v", got.Headers)
	}
	if valueFor(got.QueryParams, "access_token") != RedactedValue {
		t.Fatalf("access_token = %q", valueFor(got.QueryParams, "access_token"))
	}
	if valueFor(got.Body.Params, "api_key") != RedactedValue {
		t.Fatalf("api_key = %q", valueFor(got.Body.Params, "api_key"))
	}
	if len(valueFor(got.QueryParams, "name")) != MaxParameterValueBytes {
		t.Fatalf("query value length = %d, want %d", len(valueFor(got.QueryParams, "name")), MaxParameterValueBytes)
	}
	if len(valueFor(got.Body.Params, "display")) != MaxParameterValueBytes {
		t.Fatalf("body value length = %d, want %d", len(valueFor(got.Body.Params, "display")), MaxParameterValueBytes)
	}
	sanitizedURL := SanitizeURL("https://example.com/api?access_token=top-secret&name=" + strings.Repeat("z", 200))
	if strings.Contains(sanitizedURL, "top-secret") || !strings.Contains(sanitizedURL, "access_token=%5BREDACTED%5D") {
		t.Fatalf("SanitizeURL() = %q", sanitizedURL)
	}
	parsedURL := ParseRequestData(sanitizedURL, nil, nil, false)
	if len(valueFor(parsedURL.QueryParams, "name")) != MaxParameterValueBytes {
		t.Fatalf("sanitized URL name length = %d", len(valueFor(parsedURL.QueryParams, "name")))
	}
}

func TestRequestDataRedactsAuthorizationAndCookieParameterNames(t *testing.T) {
	got := ParseRequestData(
		"https://example.com/api?authorization=Bearer+secret&cookie=session-secret&proxy_authorization=Basic+secret&set-cookie=sid%3Dsecret",
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
		[]byte("Authorization=form-secret&Cookie=form-cookie"),
		true,
	)

	for _, name := range []string{"authorization", "cookie", "proxy_authorization", "set-cookie"} {
		if valueFor(got.QueryParams, name) != RedactedValue {
			t.Fatalf("query param %q = %q, want redacted", name, valueFor(got.QueryParams, name))
		}
	}
	for _, name := range []string{"Authorization", "Cookie"} {
		if valueFor(got.Body.Params, name) != RedactedValue {
			t.Fatalf("form param %q = %q, want redacted", name, valueFor(got.Body.Params, name))
		}
	}
}

func TestSanitizeSourceSnippetRedactsCookieAndProxyAuthorizationVariants(t *testing.T) {
	source := `fetch("/api", {setCookie: "sid=secret", proxyAuthorization: "Basic secret", proxy_authorization: "Basic secret"})`
	got := SanitizeSourceSnippet(source)
	if strings.Contains(got, "sid=secret") || strings.Contains(got, "Basic secret") {
		t.Fatalf("SanitizeSourceSnippet() leaked sensitive source: %q", got)
	}
	for _, name := range []string{"setCookie", "proxyAuthorization", "proxy_authorization"} {
		if !strings.Contains(got, name) {
			t.Fatalf("SanitizeSourceSnippet() removed key %q instead of only redacting the value: %q", name, got)
		}
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

func TestBatchedGraphQLDoesNotStoreQueryText(t *testing.T) {
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
	if strings.Contains(got.Body.Sample, "query List") || strings.Contains(got.Body.Sample, "secret") {
		t.Fatalf("batched GraphQL sample leaked query or secret: %q", got.Body.Sample)
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
