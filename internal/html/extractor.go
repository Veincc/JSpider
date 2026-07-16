package html

import (
	"strings"

	"github.com/Veincc/JSpider/internal/analyzer"
	"github.com/Veincc/JSpider/internal/urlutil"
	xhtml "golang.org/x/net/html"
)

type Extractor struct{}

func NewExtractor() *Extractor {
	return &Extractor{}
}

// ExtractEntryJS extracts entry JS assets from HTML.
func (e *Extractor) ExtractEntryJS(htmlContent string, htmlURL string) []analyzer.JSAsset {
	var assets []analyzer.JSAsset
	tags := parseAllTags(htmlContent)

	// Extract base href
	baseURL := htmlURL
	if bh, ok := firstBaseHref(tags); ok {
		if bh != "" {
			resolved, err := urlutil.Resolve(htmlURL, bh)
			if err == nil {
				baseURL = resolved
			}
		}
	}

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
			} else if strings.EqualFold(strings.TrimSpace(attrs["type"]), "module") && tag.Body != "" {
				// Extract paths from inline module script
				paths := append(extractInlinePaths(tag.Body, baseURL), extractInlineModulePaths(tag.Body, baseURL)...)
				for _, p := range paths {
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
			relations := strings.Fields(strings.ToLower(attrs["rel"]))
			href := attrs["href"]
			if href == "" {
				continue
			}
			resolved, err := urlutil.Resolve(baseURL, href)
			if err != nil {
				continue
			}

			switch {
			case containsToken(relations, "modulepreload"):
				assets = append(assets, analyzer.JSAsset{
					URL:        resolved,
					Type:       analyzer.TypeEntryJS,
					Source:     analyzer.SourceModulepreload,
					Confidence: analyzer.ConfMedium,
					Status:     analyzer.StatusCandidate,
				})
			case containsToken(relations, "preload"):
				as := strings.ToLower(strings.TrimSpace(attrs["as"]))
				if as == "script" {
					assets = append(assets, analyzer.JSAsset{
						URL:        resolved,
						Type:       analyzer.TypeEntryJS,
						Source:     analyzer.SourcePreload,
						Confidence: analyzer.ConfMedium,
						Status:     analyzer.StatusCandidate,
					})
				}
			case containsToken(relations, "prefetch"):
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
	baseURL := htmlURL
	if href, ok := firstBaseHref(tags); ok {
		if href != "" {
			if resolved, err := urlutil.Resolve(htmlURL, href); err == nil {
				baseURL = resolved
			}
		}
	}
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
		resolved, err := urlutil.Resolve(baseURL, src)
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
	if href, ok := firstBaseHref(tags); ok {
		return href
	}
	return ""
}

// ExtractInlineJSPaths extracts JS paths from inline scripts.
func (e *Extractor) ExtractInlineJSPaths(htmlContent string, htmlURL string) []string {
	var paths []string
	tags := parseAllTags(htmlContent)
	baseURL := htmlURL
	if bh, ok := firstBaseHref(tags); ok {
		if bh != "" {
			if resolved, err := urlutil.Resolve(htmlURL, bh); err == nil {
				baseURL = resolved
			}
		}
	}

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

func firstBaseHref(tags []htmlTag) (string, bool) {
	for _, tag := range tags {
		if tag.Name != "base" {
			continue
		}
		if href, ok := tag.Attrs["href"]; ok {
			return href, true
		}
	}
	return "", false
}

// --- Internal implementation ---

// htmlTag represents a parsed HTML tag.
type htmlTag struct {
	Name  string
	Attrs map[string]string
	Body  string // only <script> tags have content
}

// parseAllTags parses all HTML tags and their attributes.
func parseAllTags(htmlContent string) []htmlTag {
	var tags []htmlTag
	scriptIndex := -1
	tokenizer := xhtml.NewTokenizer(strings.NewReader(htmlContent))

	for {
		tokenType := tokenizer.Next()
		switch tokenType {
		case xhtml.ErrorToken:
			return tags

		case xhtml.StartTagToken, xhtml.SelfClosingTagToken:
			token := tokenizer.Token()
			attrs := make(map[string]string, len(token.Attr))
			for _, attr := range token.Attr {
				attrs[strings.ToLower(attr.Key)] = attr.Val
			}
			tags = append(tags, htmlTag{
				Name:  strings.ToLower(token.Data),
				Attrs: attrs,
			})
			if tokenType == xhtml.StartTagToken && strings.EqualFold(token.Data, "script") {
				scriptIndex = len(tags) - 1
			}

		case xhtml.TextToken:
			if scriptIndex >= 0 {
				tags[scriptIndex].Body += tokenizer.Token().Data
			}

		case xhtml.EndTagToken:
			if strings.EqualFold(tokenizer.Token().Data, "script") {
				scriptIndex = -1
			}
		}
	}
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

func extractInlineModulePaths(body string, baseURL string) []string {
	regex := analyzer.NewRegexAnalyzer()
	imports := regex.ExtractStaticImports(body, baseURL, "")
	imports = append(imports, regex.ExtractDynamicImports(body, baseURL, "")...)
	paths := make([]string, 0, len(imports))
	for _, imp := range imports {
		if imp.ResolvedURL != "" {
			paths = append(paths, imp.ResolvedURL)
		}
	}
	return paths
}

func containsToken(tokens []string, want string) bool {
	for _, token := range tokens {
		if token == want {
			return true
		}
	}
	return false
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
