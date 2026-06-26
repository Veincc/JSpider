//go:build cgo

package apidiscovery

import (
	"net/url"
	"path"
	"sort"
	"strings"

	"github.com/BishopFox/jsluice"
)

func CheckAvailable() error {
	return nil
}

func AnalyzeJavaScript(source []byte, sourceJSURL string) ([]StaticEndpoint, error) {
	matches := jsluice.NewAnalyzer(source).GetURLs()
	endpoints := make([]StaticEndpoint, 0, len(matches))
	for _, match := range matches {
		if match == nil || strings.TrimSpace(match.URL) == "" {
			continue
		}
		rawURL := strings.TrimSpace(match.URL)
		if !isStaticEndpointCandidate(rawURL, match.Type) {
			continue
		}
		endpoint := StaticEndpoint{
			Version:     Version,
			RawURL:      SanitizeURL(rawURL),
			Method:      inferHTTPMethod(match.Method, match.Type),
			QueryParams: namesToParameters(match.QueryParams),
			BodyParams:  namesToParameters(match.BodyParams),
			Headers:     SanitizeHeaders(match.Headers),
			ContentType: match.ContentType,
			Type:        match.Type,
			Source:      truncateString(SanitizeSourceSnippet(match.Source), MaxBodySampleBytes),
			SourceJSURL: SanitizeURL(sourceJSURL),
		}
		endpoints = append(endpoints, endpoint)
	}
	sortStaticEndpoints(endpoints)
	return deduplicateStatic(endpoints), nil
}

func isStaticEndpointCandidate(rawURL, matchType string) bool {
	if strings.EqualFold(strings.TrimSpace(matchType), "import") {
		return false
	}
	if strings.IndexFunc(rawURL, func(r rune) bool {
		return r <= ' ' || r == '"' || r == '\'' || r == '`'
	}) >= 0 {
		return false
	}

	lower := strings.ToLower(rawURL)
	switch {
	case strings.HasPrefix(lower, "http://"),
		strings.HasPrefix(lower, "https://"),
		strings.HasPrefix(rawURL, "//"),
		strings.HasPrefix(rawURL, "/"),
		strings.HasPrefix(rawURL, "./"),
		strings.HasPrefix(rawURL, "../"):
	case strings.Contains(rawURL, "/") && !strings.Contains(rawURL, ":"):
	default:
		return false
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	extension := strings.ToLower(path.Ext(parsed.Path))
	switch extension {
	case ".js", ".mjs", ".cjs", ".css", ".map",
		".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif",
		".woff", ".woff2", ".ttf", ".otf", ".eot":
		return false
	}
	return true
}

func inferHTTPMethod(method, matchType string) string {
	if method = strings.ToUpper(strings.TrimSpace(method)); method != "" {
		return method
	}
	name := strings.TrimSpace(matchType)
	if index := strings.LastIndex(name, "."); index >= 0 {
		name = name[index+1:]
	}
	for _, candidate := range []struct {
		name   string
		method string
	}{
		{"get", "GET"},
		{"post", "POST"},
		{"put", "PUT"},
		{"patch", "PATCH"},
		{"delete", "DELETE"},
		{"head", "HEAD"},
		{"options", "OPTIONS"},
	} {
		if methodNameMatches(name, candidate.name) {
			return candidate.method
		}
	}
	return ""
}

func methodNameMatches(name, method string) bool {
	if strings.EqualFold(name, method) {
		return true
	}
	if len(name) <= len(method) || !strings.EqualFold(name[:len(method)], method) {
		return false
	}
	suffix := strings.TrimLeft(name[len(method):], "_-.")
	if suffix == "" {
		return true
	}
	lowerSuffix := strings.ToLower(suffix)
	for _, allowed := range []string{
		"request",
		"fetch",
		"with",
		"json",
		"form",
		"data",
		"http",
		"ajax",
		"xhr",
		"api",
		"call",
	} {
		if strings.HasPrefix(lowerSuffix, allowed) {
			return true
		}
	}
	return false
}

func namesToParameters(names []string) []Parameter {
	out := make([]Parameter, 0, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name != "" {
			out = append(out, Parameter{Name: name})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return deduplicateParameters(out)
}

func deduplicateStatic(endpoints []StaticEndpoint) []StaticEndpoint {
	if len(endpoints) == 0 {
		return []StaticEndpoint{}
	}
	contextual := make(map[string]bool)
	for _, endpoint := range endpoints {
		if endpoint.Method != "" {
			contextual[endpoint.RawURL+"\x00"+endpoint.SourceJSURL] = true
		}
	}

	merged := make(map[string]StaticEndpoint)
	for _, endpoint := range endpoints {
		groupKey := endpoint.RawURL + "\x00" + endpoint.SourceJSURL
		if endpoint.Method == "" && contextual[groupKey] {
			continue
		}
		key := groupKey + "\x00" + endpoint.Method
		existing, ok := merged[key]
		if !ok {
			merged[key] = endpoint
			continue
		}
		existing.QueryParams = mergeParameters(existing.QueryParams, endpoint.QueryParams)
		existing.BodyParams = mergeParameters(existing.BodyParams, endpoint.BodyParams)
		if existing.Type == "" || existing.Type == "string" {
			existing.Type = endpoint.Type
		}
		if existing.Source == "" {
			existing.Source = endpoint.Source
		}
		if existing.ContentType == "" {
			existing.ContentType = endpoint.ContentType
		}
		if len(existing.Headers) == 0 && len(endpoint.Headers) > 0 {
			existing.Headers = endpoint.Headers
		}
		merged[key] = existing
	}

	out := make([]StaticEndpoint, 0, len(merged))
	for _, endpoint := range merged {
		out = append(out, endpoint)
	}
	sortStaticEndpoints(out)
	return out
}
