package analyzer

import (
	"encoding/json"
	"strings"
)

// SourceMapAnalyzer is a Source Map analyzer
type SourceMapAnalyzer struct {
	regex *RegexAnalyzer
}

func NewSourceMapAnalyzer(regex *RegexAnalyzer) *SourceMapAnalyzer {
	return &SourceMapAnalyzer{regex: regex}
}

// ExtractSourceMappingURL extracts the sourceMappingURL from JS content
func (s *SourceMapAnalyzer) ExtractSourceMappingURL(jsContent string, fromJS string) string {
	return s.regex.ExtractSourceMappingURL(jsContent, fromJS)
}

// ParseSourceMap parses source map JSON content
func (s *SourceMapAnalyzer) ParseSourceMap(mapContent []byte, mapURL string, fromJS string) *SourceMapInfo {
	info := &SourceMapInfo{
		FromJS: fromJS,
		MapURL: mapURL,
		Status: "parsed",
	}

	var rawMap struct {
		Sources        []string `json:"sources"`
		SourcesContent []string `json:"sourcesContent"`
		Version        int      `json:"version"`
		File           string   `json:"file"`
	}

	if err := json.Unmarshal(mapContent, &rawMap); err != nil {
		info.Status = "parse_error"
		return info
	}

	info.SourceCount = len(rawMap.Sources)
	info.Sources = rawMap.Sources
	info.HasSourcesContent = len(rawMap.SourcesContent) > 0

	return info
}

// ExtractFromSourcesContent extracts additional information from sourcesContent
func (s *SourceMapAnalyzer) ExtractFromSourcesContent(sourcesContent []string, fromJS string) ([]DynamicImport, []RouteChunk) {
	var imports []DynamicImport
	var routes []RouteChunk

	for _, content := range sourcesContent {
		if len(content) == 0 {
			continue
		}

		// Extract dynamic imports
		contentImports := s.regex.ExtractDynamicImports(content, fromJS, "")
		imports = append(imports, contentImports...)

		// Extract routes
		contentRoutes := s.regex.ExtractRoutePaths(content, fromJS)
		routes = append(routes, contentRoutes...)

		// Extract JS paths
		// (Skip duplicate extraction here since imports already cover most cases)
	}

	return imports, routes
}

// FindSourceMappingURLs finds all sourceMappingURL entries in JS content
func (s *SourceMapAnalyzer) FindSourceMappingURLs(jsContent string) []string {
	var urls []string

	// Find all sourceMappingURL patterns
	patterns := []string{
		"//# sourceMappingURL=",
		"/*# sourceMappingURL=",
	}

	for _, pattern := range patterns {
		idx := 0
		for {
			pos := strings.Index(jsContent[idx:], pattern)
			if pos < 0 {
				break
			}
			start := idx + pos + len(pattern)
			end := start
			for end < len(jsContent) {
				c := jsContent[end]
				if c == ' ' || c == '\n' || c == '\r' || c == '\t' || c == '*' || c == '/' {
					break
				}
				end++
			}
			if end > start {
				url := strings.TrimSpace(jsContent[start:end])
				url = strings.TrimSuffix(url, "*/")
				url = strings.TrimSpace(url)
				if url != "" && !strings.HasPrefix(url, "data:") {
					urls = append(urls, url)
				}
			}
			idx = end
		}
	}

	return urls
}
