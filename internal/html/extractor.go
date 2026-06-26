package html

import (
	"strings"

	"github.com/Veincc/JSpider/internal/analyzer"
	"github.com/Veincc/JSpider/internal/urlutil"
)

type Extractor struct{}

func NewExtractor() *Extractor {
	return &Extractor{}
}

// ExtractEntryJS extracts entry JS assets from HTML.
func (e *Extractor) ExtractEntryJS(htmlContent string, htmlURL string) []analyzer.JSAsset {
	var assets []analyzer.JSAsset

	// Extract base href
	baseURL := htmlURL
	if bh := e.ExtractBaseHref(htmlContent); bh != "" {
		resolved, err := urlutil.Resolve(htmlURL, bh)
		if err == nil {
			baseURL = resolved
		}
	}

	// Parse all tags
	tags := parseAllTags(htmlContent)

	for _, tag := range tags {
		switch tag.Name {
		case "script":
			attrs := tag.Attrs
			src := attrs["src"]
			if src != "" {
				resolved, err := urlutil.Resolve(baseURL, src)
				if err != nil {
					continue
				}
				assets = append(assets, analyzer.JSAsset{
					URL:        resolved,
					Type:       analyzer.TypeEntryJS,
					Source:     analyzer.SourceHTMLScript,
					Confidence: analyzer.ConfHigh,
					Status:     analyzer.StatusCandidate,
				})
			} else if attrs["type"] == "module" && tag.Body != "" {
				// Extract paths from inline module script
				for _, p := range extractInlinePaths(tag.Body, baseURL) {
					if !assetExists(assets, p) {
						assets = append(assets, analyzer.JSAsset{
							URL:        p,
							Type:       analyzer.TypeEntryJS,
							Source:     analyzer.SourceInlineScript,
							Confidence: analyzer.ConfMedium,
							Status:     analyzer.StatusCandidate,
						})
					}
				}
			} else if tag.Body != "" {
				// Extract paths from inline script
				for _, p := range extractInlinePaths(tag.Body, baseURL) {
					if !assetExists(assets, p) {
						assets = append(assets, analyzer.JSAsset{
							URL:        p,
							Type:       analyzer.TypeEntryJS,
							Source:     analyzer.SourceInlineScript,
							Confidence: analyzer.ConfMedium,
							Status:     analyzer.StatusCandidate,
						})
					}
				}
			}

		case "link":
			attrs := tag.Attrs
			rel := strings.ToLower(attrs["rel"])
			href := attrs["href"]
			if href == "" {
				continue
			}
			resolved, err := urlutil.Resolve(baseURL, href)
			if err != nil {
				continue
			}

			switch rel {
			case "modulepreload":
				assets = append(assets, analyzer.JSAsset{
					URL:        resolved,
					Type:       analyzer.TypeEntryJS,
					Source:     analyzer.SourceModulepreload,
					Confidence: analyzer.ConfMedium,
					Status:     analyzer.StatusCandidate,
				})
			case "preload":
				as := strings.ToLower(attrs["as"])
				if as == "script" {
					assets = append(assets, analyzer.JSAsset{
						URL:        resolved,
						Type:       analyzer.TypeEntryJS,
						Source:     analyzer.SourcePreload,
						Confidence: analyzer.ConfMedium,
						Status:     analyzer.StatusCandidate,
					})
				}
			case "prefetch":
				assets = append(assets, analyzer.JSAsset{
					URL:        resolved,
					Type:       analyzer.TypeEntryJS,
					Source:     analyzer.SourcePrefetch,
					Confidence: analyzer.ConfLow,
					Status:     analyzer.StatusCandidate,
				})
			}
		}
	}

	// Deduplicate
	seen := make(map[string]bool)
	var result []analyzer.JSAsset
	for _, a := range assets {
		if !seen[a.URL] {
			seen[a.URL] = true
			result = append(result, a)
		}
	}

	return result
}

// ExtractModuleScripts extracts src from type="module" scripts.
func (e *Extractor) ExtractModuleScripts(htmlContent string, htmlURL string) []string {
	var urls []string
	tags := parseAllTags(htmlContent)
	for _, tag := range tags {
		if tag.Name != "script" {
			continue
		}
		if strings.ToLower(tag.Attrs["type"]) != "module" {
			continue
		}
		src := tag.Attrs["src"]
		if src == "" {
			continue
		}
		resolved, err := urlutil.Resolve(htmlURL, src)
		if err == nil {
			urls = append(urls, resolved)
		}
	}
	return urls
}

// HasInlineModule checks whether HTML contains an inline module script.
func (e *Extractor) HasInlineModule(htmlContent string) bool {
	tags := parseAllTags(htmlContent)
	for _, tag := range tags {
		if tag.Name == "script" && strings.ToLower(tag.Attrs["type"]) == "module" && tag.Body != "" {
			return true
		}
	}
	return false
}

// ExtractBaseHref extracts the <base href> value.
func (e *Extractor) ExtractBaseHref(htmlContent string) string {
	tags := parseAllTags(htmlContent)
	for _, tag := range tags {
		if tag.Name == "base" {
			if href := tag.Attrs["href"]; href != "" {
				return href
			}
		}
	}
	return ""
}

// ExtractInlineJSPaths extracts JS paths from inline scripts.
func (e *Extractor) ExtractInlineJSPaths(htmlContent string, htmlURL string) []string {
	var paths []string
	baseURL := htmlURL
	if bh := e.ExtractBaseHref(htmlContent); bh != "" {
		if resolved, err := urlutil.Resolve(htmlURL, bh); err == nil {
			baseURL = resolved
		}
	}

	tags := parseAllTags(htmlContent)
	for _, tag := range tags {
		if tag.Name != "script" || tag.Body == "" {
			continue
		}
		for _, p := range extractInlinePaths(tag.Body, baseURL) {
			paths = append(paths, p)
		}
	}
	return paths
}

// --- Internal implementation ---

// htmlTag represents a parsed HTML tag.
type htmlTag struct {
	Name  string
	Attrs map[string]string
	Body  string // only <script> tags have content
}

// isLetter checks whether a byte is a letter.
func isLetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// findTagEndQuoteAware finds the closing '>' of a tag in a quote-aware manner.
// Returns the offset of '>' in s, or -1 if not found.
func findTagEndQuoteAware(s string) int {
	inQuote := byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inQuote != 0 {
			if c == inQuote {
				inQuote = 0
			}
			continue
		}
		if c == '"' || c == '\'' {
			inQuote = c
			continue
		}
		if c == '>' {
			return i
		}
	}
	return -1
}

// parseAllTags parses all HTML tags and their attributes.
func parseAllTags(htmlContent string) []htmlTag {
	var tags []htmlTag
	i := 0
	n := len(htmlContent)

	for i < n {
		// Find '<'
		if htmlContent[i] != '<' {
			i++
			continue
		}

		// Skip comments
		if i+3 < n && htmlContent[i:i+4] == "<!--" {
			end := strings.Index(htmlContent[i+4:], "-->")
			if end < 0 {
				break
			}
			i = i + 4 + end + 3
			continue
		}

		// Skip <!DOCTYPE> etc.
		if i+1 < n && htmlContent[i+1] == '!' {
			end := findTagEndQuoteAware(htmlContent[i:])
			if end < 0 {
				break
			}
			i = i + end + 1
			continue
		}

		// Skip </closing> tags (must start with </ followed by a letter to be a real closing tag)
		if i+1 < n && htmlContent[i+1] == '/' {
			// Check if </ is followed by a letter (real closing tag name)
			if i+2 < n && isLetter(htmlContent[i+2]) {
				end := findTagEndQuoteAware(htmlContent[i:])
				if end < 0 {
					break
				}
				i = i + end + 1
				continue
			}
			// Not a closing tag (may be / in an attribute value), skip this '<' to prevent infinite loop
			i++
			continue
		}

		// Parse tag name
		tagStart := i + 1
		tagNameEnd := tagStart
		for tagNameEnd < n && htmlContent[tagNameEnd] != ' ' && htmlContent[tagNameEnd] != '\t' &&
			htmlContent[tagNameEnd] != '\n' && htmlContent[tagNameEnd] != '\r' &&
			htmlContent[tagNameEnd] != '>' && htmlContent[tagNameEnd] != '/' {
			tagNameEnd++
		}
		tagName := strings.ToLower(htmlContent[tagStart:tagNameEnd])

		// Find the closing '>' in a quote-aware manner
		tagEnd := findTagEndQuoteAware(htmlContent[tagNameEnd:])
		if tagEnd < 0 {
			break
		}
		tagEnd += tagNameEnd

		// Extract attribute section
		attrStr := htmlContent[tagNameEnd:tagEnd]
		attrs := parseAttrs(attrStr)

		tag := htmlTag{Name: tagName, Attrs: attrs}

		// Extract content for script tags
		if tagName == "script" {
			// Check if self-closing
			selfClosing := strings.HasSuffix(strings.TrimSpace(attrStr), "/")
			if !selfClosing {
				// Use iteration to find the real </script> (skip fake tags inside strings)
				remaining := htmlContent[tagEnd+1:]
				bodyEnd := findScriptEnd(remaining)
				if bodyEnd >= 0 {
					tag.Body = remaining[:bodyEnd]
					tagEnd = tagEnd + 1 + bodyEnd + len("</script>")
				}
			}
		}

		tags = append(tags, tag)
		i = tagEnd + 1
	}

	return tags
}

// findScriptEnd finds the position of </script>, skipping fake tags inside JS strings.
func findScriptEnd(s string) int {
	lower := strings.ToLower(s)
	searchFrom := 0
	for {
		idx := strings.Index(lower[searchFrom:], "</script>")
		if idx < 0 {
			return -1
		}
		idx += searchFrom

		// Check if this </script> is inside a JS string
		// Count unmatched quotes before this position
		prefix := s[:idx]
		if isInsideString(prefix) {
			searchFrom = idx + 1
			continue
		}
		return idx
	}
}

// isInsideString roughly checks whether a position is inside a JS string.
// Determine by counting quote parity.
func isInsideString(s string) bool {
	inSingle := false
	inDouble := false
	inBacktick := false
	escaped := false

	for i := 0; i < len(s); i++ {
		c := s[i]
		if escaped {
			escaped = false
			continue
		}
		if c == '\\' {
			escaped = true
			continue
		}
		if c == '\'' && !inDouble && !inBacktick {
			inSingle = !inSingle
		} else if c == '"' && !inSingle && !inBacktick {
			inDouble = !inDouble
		} else if c == '`' && !inSingle && !inDouble {
			inBacktick = !inBacktick
		}
	}

	return inSingle || inDouble || inBacktick
}

// parseAttrs parses a tag attribute string.
func parseAttrs(s string) map[string]string {
	attrs := make(map[string]string)
	i := 0
	n := len(s)

	for i < n {
		// Skip whitespace
		for i < n && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r') {
			i++
		}
		if i >= n {
			break
		}

		// Attribute name
		nameStart := i
		for i < n && s[i] != '=' && s[i] != ' ' && s[i] != '\t' && s[i] != '\n' && s[i] != '\r' && s[i] != '>' && s[i] != '/' {
			i++
		}
		attrName := strings.ToLower(strings.TrimSpace(s[nameStart:i]))
		if attrName == "" {
			i++
			continue
		}

		// Skip whitespace
		for i < n && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r') {
			i++
		}

		// Check for '='
		if i >= n || s[i] != '=' {
			// Boolean attribute
			attrs[attrName] = ""
			continue
		}
		i++ // Skip '='

		// Skip whitespace
		for i < n && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r') {
			i++
		}

		// Attribute value
		if i >= n {
			break
		}

		var attrValue string
		if s[i] == '"' {
			// Double quote
			i++
			end := strings.IndexByte(s[i:], '"')
			if end < 0 {
				attrValue = s[i:]
				i = n
			} else {
				attrValue = s[i : i+end]
				i = i + end + 1
			}
		} else if s[i] == '\'' {
			// Single quote
			i++
			end := strings.IndexByte(s[i:], '\'')
			if end < 0 {
				attrValue = s[i:]
				i = n
			} else {
				attrValue = s[i : i+end]
				i = i + end + 1
			}
		} else {
			// Unquoted (value ends at whitespace or >, / is a legal character e.g. src=/app.js)
			end := i
			for end < n && s[end] != ' ' && s[end] != '\t' && s[end] != '\n' && s[end] != '\r' && s[end] != '>' {
				end++
			}
			attrValue = s[i:end]
			i = end
		}

		attrs[attrName] = attrValue
	}

	return attrs
}

// extractInlinePaths extracts JS paths from inline script content.
func extractInlinePaths(body string, baseURL string) []string {
	var paths []string
	// Common JS resource path patterns
	patterns := []string{
		"/assets/", "/static/", "/_next/static/", "/_nuxt/", "/chunks/",
		"./assets/", "./static/", "../assets/",
	}

	// Simple quoted path extraction
	inQuote := byte(0)
	quoteStart := -1
	for i := 0; i < len(body); i++ {
		c := body[i]
		if inQuote == 0 {
			if c == '"' || c == '\'' || c == '`' {
				inQuote = c
				quoteStart = i + 1
			}
		} else {
			if c == inQuote && (i == 0 || body[i-1] != '\\') {
				// Extract quoted content
				content := body[quoteStart:i]
				// Check if it matches a JS path pattern
				if strings.HasSuffix(content, ".js") || strings.HasSuffix(content, ".mjs") {
					for _, p := range patterns {
						if strings.Contains(content, p) {
							resolved, err := urlutil.Resolve(baseURL, content)
							if err == nil {
								paths = append(paths, resolved)
							}
							break
						}
					}
				}
				inQuote = 0
			}
		}
	}

	return paths
}

// assetExists checks whether a URL already exists in assets.
func assetExists(assets []analyzer.JSAsset, url string) bool {
	for _, a := range assets {
		if a.URL == url {
			return true
		}
	}
	return false
}
