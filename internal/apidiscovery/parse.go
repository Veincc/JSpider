package apidiscovery

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/textproto"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

var forbiddenHeaders = map[string]bool{
	"authorization":       true,
	"cookie":              true,
	"set-cookie":          true,
	"proxy-authorization": true,
}

const sensitiveSourceKeyPattern = `password|passwd|token|access[_-]?token|refresh[_-]?token|secret|api[_-]?key|session|csrf|otp|authorization|cookie|set-cookie|proxy-authorization`

// sensitiveSourcePatterns redact values in short source snippets while keeping
// the surrounding key names. This preserves evidence without leaking secrets.
var sensitiveSourcePatterns = []struct {
	pattern     *regexp.Regexp
	replacement string
}{
	{
		regexp.MustCompile(`(?i)((?:"|')?(?:` + sensitiveSourceKeyPattern + `)(?:"|')?\s*[:=]\s*)"([^"\\]|\\.)*"`),
		`$1"` + RedactedValue + `"`,
	},
	{
		regexp.MustCompile(`(?i)((?:"|')?(?:` + sensitiveSourceKeyPattern + `)(?:"|')?\s*[:=]\s*)'([^'\\]|\\.)*'`),
		`$1'` + RedactedValue + `'`,
	},
	{
		regexp.MustCompile("(?i)((?:\"|')?(?:" + sensitiveSourceKeyPattern + ")(?:\"|')?\\s*[:=]\\s*)`([^`\\\\]|\\\\.)*`"),
		"$1`" + RedactedValue + "`",
	},
	{
		regexp.MustCompile(`(?i)(\b(?:` + sensitiveSourceKeyPattern + `)\b\s*[:=]\s*)[^,\s}]+`),
		`$1` + RedactedValue,
	},
	{
		regexp.MustCompile(`(?i)([?&](?:` + sensitiveSourceKeyPattern + `)=)[^&"'` + "`" + `\s]+`),
		`$1` + RedactedValue,
	},
}

func ParseRequestData(rawURL string, headers map[string]string, body []byte, hasBody bool) RequestData {
	data := RequestData{
		Headers:     SanitizeHeaders(headers),
		QueryParams: parseQuery(rawURL),
		Body: BodyInfo{
			HasBody: hasBody,
			Params:  []Parameter{},
		},
	}

	contentType := headerValue(headers, "content-type")
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		mediaType = strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
		params = map[string]string{}
	}
	data.Body.ContentType = contentType

	if len(body) > MaxRequestBodyBytes {
		body = body[:MaxRequestBodyBytes]
	}
	if !hasBody && len(body) == 0 {
		return data
	}

	switch strings.ToLower(mediaType) {
	case "application/json", "application/graphql+json":
		parseJSONBody(body, &data.Body)
	case "application/x-www-form-urlencoded":
		parseFormBody(body, &data.Body)
	case "multipart/form-data":
		parseMultipartBody(body, params["boundary"], &data.Body)
	}
	return data
}

func SanitizeHeaders(headers map[string]string) map[string]string {
	if len(headers) == 0 {
		return nil
	}
	out := make(map[string]string)
	for name, value := range headers {
		if forbiddenHeaders[strings.ToLower(strings.TrimSpace(name))] {
			continue
		}
		canonicalName := textproto.CanonicalMIMEHeaderKey(name)
		out[canonicalName] = sanitizeValue(canonicalName, value)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func SanitizeURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return SanitizeSourceSnippet(raw)
	}
	query := parsed.Query()
	changed := false
	for name, values := range query {
		for i := range values {
			cleaned := sanitizeValue(name, values[i])
			if cleaned != values[i] {
				values[i] = cleaned
				changed = true
			}
		}
		query[name] = values
	}
	if !changed {
		return raw
	}
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func SanitizeSourceSnippet(source string) string {
	for _, item := range sensitiveSourcePatterns {
		source = item.pattern.ReplaceAllString(source, item.replacement)
	}
	return source
}

func parseQuery(rawURL string) []Parameter {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return []Parameter{}
	}
	params := make([]Parameter, 0)
	for name, values := range parsed.Query() {
		if len(values) == 0 {
			params = append(params, Parameter{Name: name})
			continue
		}
		for _, value := range values {
			params = append(params, Parameter{Name: name, Value: sanitizeValue(name, value)})
		}
	}
	sortParameters(params)
	return params
}

func parseJSONBody(body []byte, info *BodyInfo) {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return
	}

	if roots, ok := graphQLRoots(value); ok {
		parseGraphQL(roots, info)
		return
	}

	params := make([]Parameter, 0)
	collectJSONParams("", value, &params)
	sortParameters(params)
	info.Params = deduplicateParameters(params)

	sanitized := sanitizeJSONValue("", value, false)
	if encoded, err := json.Marshal(sanitized); err == nil {
		info.Sample = truncateBytes(encoded, MaxBodySampleBytes)
	}
}

func graphQLRoots(value any) ([]map[string]any, bool) {
	switch typed := value.(type) {
	case map[string]any:
		if _, hasQuery := typed["query"]; hasQuery {
			return []map[string]any{typed}, true
		}
	case []any:
		roots := make([]map[string]any, 0, len(typed))
		for _, item := range typed {
			root, ok := item.(map[string]any)
			if !ok {
				return nil, false
			}
			if _, hasQuery := root["query"]; !hasQuery {
				return nil, false
			}
			roots = append(roots, root)
		}
		if len(roots) > 0 {
			return roots, true
		}
	}
	return nil, false
}

func parseGraphQL(roots []map[string]any, info *BodyInfo) {
	operationNames := make([]string, 0, len(roots))
	graphQL := &GraphQLInfo{Variables: []string{}}
	params := []Parameter{}
	samples := make([]map[string]any, 0, len(roots))
	for _, root := range roots {
		operationName, _ := root["operationName"].(string)
		if operationName != "" {
			operationNames = append(operationNames, truncateString(operationName, MaxParameterValueBytes))
			params = append(params, Parameter{Name: "operationName", Value: sanitizeValue("operationName", operationName)})
		}
		sample := map[string]any{
			"operationName": sanitizeValue("operationName", operationName),
		}
		if variables, ok := root["variables"]; ok {
			var variableParams []Parameter
			collectJSONParams("variables", variables, &variableParams)
			params = append(params, variableParams...)
			for _, param := range variableParams {
				if strings.HasPrefix(param.Name, "variables.") {
					graphQL.Variables = append(graphQL.Variables, strings.TrimPrefix(param.Name, "variables."))
				}
			}
			sample["variables"] = sanitizeJSONValue("variables", variables, false)
		}
		samples = append(samples, sample)
	}
	operationNames = uniqueSortedStrings(operationNames)
	graphQL.OperationName = strings.Join(operationNames, ",")
	graphQL.Variables = uniqueSortedStrings(graphQL.Variables)
	sortParameters(params)
	info.Params = deduplicateParameters(params)
	info.GraphQL = graphQL

	var sample any = samples
	if len(samples) == 1 {
		sample = samples[0]
	}
	if encoded, err := json.Marshal(sample); err == nil {
		info.Sample = truncateBytes(encoded, MaxBodySampleBytes)
	}
}

func collectJSONParams(prefix string, value any, params *[]Parameter) {
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			name := joinParam(prefix, key)
			child := typed[key]
			switch child.(type) {
			case map[string]any, []any:
				collectJSONParams(name, child, params)
			default:
				*params = append(*params, Parameter{Name: name, Value: sanitizeAny(name, child)})
			}
		}
	case []any:
		for _, child := range typed {
			switch child.(type) {
			case map[string]any, []any:
				collectJSONParams(prefix, child, params)
			default:
				if prefix != "" {
					*params = append(*params, Parameter{Name: prefix, Value: sanitizeAny(prefix, child)})
				}
			}
		}
	}
}

func sanitizeJSONValue(prefix string, value any, omitQuery bool) any {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any)
		for key, child := range typed {
			if omitQuery && strings.EqualFold(key, "query") {
				continue
			}
			name := joinParam(prefix, key)
			if isSensitiveName(name) {
				out[key] = RedactedValue
			} else {
				out[key] = sanitizeJSONValue(name, child, omitQuery)
			}
		}
		return out
	case []any:
		out := make([]any, 0, len(typed))
		for _, child := range typed {
			out = append(out, sanitizeJSONValue(prefix, child, omitQuery))
		}
		return out
	case string:
		return sanitizeValue(prefix, typed)
	default:
		return typed
	}
}

func parseFormBody(body []byte, info *BodyInfo) {
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return
	}
	params := make([]Parameter, 0)
	sample := make(url.Values)
	for name, entries := range values {
		for _, value := range entries {
			cleaned := sanitizeValue(name, value)
			params = append(params, Parameter{Name: name, Value: cleaned})
			sample.Add(name, cleaned)
		}
	}
	sortParameters(params)
	info.Params = params
	info.Sample = truncateString(sample.Encode(), MaxBodySampleBytes)
}

func parseMultipartBody(body []byte, boundary string, info *BodyInfo) {
	if boundary == "" {
		return
	}
	reader := multipart.NewReader(bytes.NewReader(body), boundary)
	params := make([]Parameter, 0)
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		name := part.FormName()
		if name != "" {
			value := ""
			if part.FileName() != "" {
				value = "[FILE]"
			}
			params = append(params, Parameter{Name: name, Value: value})
		}
		_ = part.Close()
	}
	sortParameters(params)
	info.Params = deduplicateParameters(params)
}

func sanitizeAny(name string, value any) string {
	if value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return sanitizeValue(name, typed)
	case json.Number:
		return sanitizeValue(name, typed.String())
	case bool:
		if typed {
			return "true"
		}
		return "false"
	default:
		encoded, _ := json.Marshal(typed)
		return sanitizeValue(name, string(encoded))
	}
}

func sanitizeValue(name, value string) string {
	if isSensitiveName(name) {
		return RedactedValue
	}
	return truncateString(value, MaxParameterValueBytes)
}

func isSensitiveName(name string) bool {
	last := name
	if index := strings.LastIndex(last, "."); index >= 0 {
		last = last[index+1:]
	}
	var normalized strings.Builder
	for _, r := range strings.ToLower(last) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			normalized.WriteRune(r)
		}
	}
	key := normalized.String()
	switch key {
	case "password", "passwd", "accesstoken", "refreshtoken", "secret", "apikey", "session", "csrf", "otp",
		"authorization", "cookie", "setcookie", "proxyauthorization":
		return true
	}
	return strings.Contains(key, "token") ||
		strings.Contains(key, "password") ||
		strings.Contains(key, "passwd") ||
		strings.Contains(key, "secret") ||
		strings.Contains(key, "apikey") ||
		strings.Contains(key, "session") ||
		strings.Contains(key, "csrf") ||
		strings.Contains(key, "otp") ||
		strings.Contains(key, "authorization") ||
		strings.Contains(key, "cookie")
}

func headerValue(headers map[string]string, name string) string {
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return value
		}
	}
	return ""
}

func joinParam(prefix, key string) string {
	if prefix == "" {
		return key
	}
	return prefix + "." + key
}

func sortParameters(params []Parameter) {
	sort.Slice(params, func(i, j int) bool {
		if params[i].Name != params[j].Name {
			return params[i].Name < params[j].Name
		}
		return params[i].Value < params[j].Value
	})
}

func deduplicateParameters(params []Parameter) []Parameter {
	if len(params) == 0 {
		return []Parameter{}
	}
	out := make([]Parameter, 0, len(params))
	seen := make(map[string]bool)
	for _, param := range params {
		key := param.Name + "\x00" + param.Value
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, param)
	}
	return out
}

func uniqueSortedStrings(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	seen := make(map[string]bool)
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func truncateString(value string, limit int) string {
	if limit <= 0 {
		return ""
	}
	value = strings.ToValidUTF8(value, "\uFFFD")
	if len(value) <= limit {
		return value
	}
	end := 0
	for end < len(value) {
		_, size := utf8.DecodeRuneInString(value[end:])
		if size == 0 || end+size > limit {
			break
		}
		end += size
	}
	return value[:end]
}

func truncateBytes(value []byte, limit int) string {
	return truncateString(string(value), limit)
}
