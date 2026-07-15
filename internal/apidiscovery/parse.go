package apidiscovery

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/url"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"
)

const maxGraphQLTokens = 15000

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
		data.Body.Truncated = true
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
	return cloneHeaders(headers)
}

func SanitizeURL(raw string) string {
	return raw
}

func SanitizeSourceSnippet(source string) string {
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
			params = append(params, Parameter{Name: name, Value: value})
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
		info.ParseError = err.Error()
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			info.ParseError = "multiple JSON values"
		} else {
			info.ParseError = err.Error()
		}
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

	if encoded, err := json.Marshal(value); err == nil {
		info.Sample = truncateBytes(encoded, MaxBodySampleBytes)
	}
}

func graphQLRoots(value any) ([]map[string]any, bool) {
	switch typed := value.(type) {
	case map[string]any:
		if isGraphQLDocument(typed["query"]) {
			return []map[string]any{typed}, true
		}
	case []any:
		roots := make([]map[string]any, 0, len(typed))
		for _, item := range typed {
			root, ok := item.(map[string]any)
			if !ok {
				return nil, false
			}
			if !isGraphQLDocument(root["query"]) {
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

func isGraphQLDocument(value any) bool {
	document, ok := value.(string)
	if !ok || strings.TrimSpace(document) == "" {
		return false
	}
	parsed, err := parser.ParseQueryWithTokenLimit(&ast.Source{Name: "request.graphql", Input: document}, maxGraphQLTokens)
	return err == nil && parsed != nil && len(parsed.Operations) > 0
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
		sample := make(map[string]any, len(root))
		for name, value := range root {
			sample[name] = value
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
	return truncateString(value, MaxParameterValueBytes)
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
