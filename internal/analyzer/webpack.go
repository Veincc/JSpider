package analyzer

import (
	"regexp"
	"strings"

	"github.com/Veincc/JSpider/internal/urlutil"
)

var (
	// Webpack runtime regex
	wpPublicPathRe               = regexp.MustCompile(`__webpack_require__\.p\s*=\s*["']([^"']+)["']`)
	wpChunkFilenameRe            = regexp.MustCompile(`chunkFilename\s*[:=]\s*["']([^"']+)["']`)
	wpHashMapRe                  = regexp.MustCompile(`\{("[0-9]+"\s*:\s*"[a-zA-Z0-9]+"(?:\s*,\s*"[0-9]+"\s*:\s*"[a-zA-Z0-9]+")*)\}`)
	wpHashEntryRe                = regexp.MustCompile(`"([0-9]+)"\s*:\s*"([a-zA-Z0-9]+)"`)
	wpFilenamePattern            = regexp.MustCompile(`"([^"]*?)"\s*\+\s*\w+\s*\+\s*"([^"]*?)"`)
	wpFilenameWithHashMapPattern = regexp.MustCompile(`"([^"]*)"\s*\+\s*\w+\s*\+\s*"([^"]*)"\s*\+\s*\{[^}]+\}\[\w+\]\s*\+\s*"([^"]*)"`)
	wpChunkPushRe                = regexp.MustCompile(`(?:self\.webpackChunk\w*\s*\|\|\s*\[\]\)\.push\s*\(\s*\[\s*\[(\d+)\])|(?:\bwebpackJsonp\s*\w*\s*\.\s*push\s*\(\s*\[\s*\[(\d+)\])`)
	wpRequireERe                 = regexp.MustCompile(`__webpack_require__\.e\s*\(\s*(?:(\d+)|["'](\w+)["']|(\w+))\s*\)`)
	wpCssRe                      = regexp.MustCompile(`__webpack_require__\.miniCssExtracPlugin\s*=`)
)

// WebpackAnalyzer is a Webpack-specific analyzer
type WebpackAnalyzer struct {
	regex *RegexAnalyzer
}

func NewWebpackAnalyzer(regex *RegexAnalyzer) *WebpackAnalyzer {
	return &WebpackAnalyzer{regex: regex}
}

// Analyze analyzes JS built by Webpack
func (w *WebpackAnalyzer) Analyze(jsContent string, fromJS string) *AnalysisResult {
	result := &AnalysisResult{
		Framework: "webpack",
	}

	// 1. Extract publicPath
	publicPath := w.extractPublicPath(jsContent)
	chunkFilename := w.extractChunkFilename(jsContent)

	// 2. Extract chunkId -> hash mapping
	chunkHashes := w.extractChunkHashes(jsContent)

	// 3. Extract filename rules from __webpack_require__.u function
	filenameRule := w.extractFilenameRule(jsContent, publicPath)

	// 4. Extract webpackChunk pushes
	chunkImports := w.extractChunkPushes(jsContent, fromJS, publicPath, chunkHashes, filenameRule, chunkFilename)
	result.Imports = append(result.Imports, chunkImports...)

	// 5. Extract __webpack_require__.e calls
	requireEImports := w.extractRequireE(jsContent, fromJS, publicPath, chunkHashes, filenameRule, chunkFilename)
	result.Imports = append(result.Imports, requireEImports...)

	// 6. Extract generic dynamic imports
	directImports := w.regex.ExtractDynamicImports(jsContent, fromJS, "webpack")
	result.Imports = append(result.Imports, directImports...)

	// 7. Extract routes
	routes := w.regex.ExtractRoutePaths(jsContent, fromJS)
	for i := range routes {
		routes[i].Framework = "webpack"
	}
	result.Routes = append(result.Routes, routes...)

	// 8. Build new URL list
	newURLs := w.buildNewURLs(result.Imports, fromJS)
	result.NewURLs = newURLs

	// 9. Extract sourceMappingURL
	if mapURL := w.regex.ExtractSourceMappingURL(jsContent, fromJS); mapURL != "" {
		result.Sourcemaps = append(result.Sourcemaps, SourceMapInfo{
			FromJS: fromJS,
			MapURL: mapURL,
			Status: "found",
		})
	}

	return result
}

func (w *WebpackAnalyzer) extractPublicPath(jsContent string) string {
	if m := wpPublicPathRe.FindStringSubmatch(jsContent); m != nil {
		return m[1]
	}
	return ""
}

func (w *WebpackAnalyzer) extractChunkFilename(jsContent string) string {
	if m := wpChunkFilenameRe.FindStringSubmatch(jsContent); m != nil {
		return m[1]
	}
	return ""
}

func (w *WebpackAnalyzer) extractChunkHashes(jsContent string) map[string]string {
	hashes := make(map[string]string)

	// Find all hash mapping tables
	for _, blockMatch := range wpHashMapRe.FindAllStringSubmatch(jsContent, -1) {
		block := blockMatch[1]
		for _, entry := range wpHashEntryRe.FindAllStringSubmatch(block, -1) {
			hashes[entry[1]] = entry[2]
		}
	}

	return hashes
}

func (w *WebpackAnalyzer) extractFilenameRule(jsContent string, publicPath string) string {
	start := strings.Index(jsContent, "__webpack_require__.u")
	if start < 0 {
		return ""
	}
	bodyStart := strings.Index(jsContent[start:], "{")
	if bodyStart < 0 {
		return ""
	}
	bodyStart += start + 1

	depth := 1
	inQuote := byte(0)
	escaped := false
	for i := bodyStart; i < len(jsContent); i++ {
		c := jsContent[i]
		if inQuote != 0 {
			if escaped {
				escaped = false
				continue
			}
			if c == '\\' {
				escaped = true
				continue
			}
			if c == inQuote {
				inQuote = 0
			}
			continue
		}
		if c == '"' || c == '\'' || c == '`' {
			inQuote = c
			continue
		}
		if c == '{' {
			depth++
			continue
		}
		if c == '}' {
			depth--
			if depth == 0 {
				body := jsContent[bodyStart:i]
				if strings.Contains(body, ".js") || strings.Contains(body, ".chunk") {
					return body
				}
				return ""
			}
		}
	}
	return ""
}

func (w *WebpackAnalyzer) extractChunkPushes(jsContent string, fromJS string, publicPath string, hashes map[string]string, filenameRule string, chunkFilename string) []DynamicImport {
	var imports []DynamicImport

	for _, m := range wpChunkPushRe.FindAllStringSubmatch(jsContent, -1) {
		chunkId := ""
		if m[1] != "" {
			chunkId = m[1]
		} else if m[2] != "" {
			chunkId = m[2]
		}
		if chunkId == "" {
			continue
		}

		chunkURL := w.resolveChunkURL(chunkId, publicPath, hashes, filenameRule, chunkFilename, fromJS)
		confidence := ConfMedium
		if chunkURL == "" {
			confidence = ConfLow
		}

		imports = append(imports, DynamicImport{
			FromJS:      fromJS,
			Raw:         "webpackChunk:" + chunkId,
			ResolvedURL: chunkURL,
			Framework:   "webpack",
			Source:      SourceWebpackRuntime,
			Confidence:  confidence,
		})
	}

	return imports
}

func (w *WebpackAnalyzer) extractRequireE(jsContent string, fromJS string, publicPath string, hashes map[string]string, filenameRule string, chunkFilename string) []DynamicImport {
	var imports []DynamicImport

	for _, m := range wpRequireERe.FindAllStringSubmatch(jsContent, -1) {
		chunkId := ""
		if m[1] != "" {
			chunkId = m[1]
		} else if m[2] != "" {
			chunkId = m[2]
		} else if m[3] != "" {
			chunkId = m[3]
		}
		if chunkId == "" {
			continue
		}

		chunkURL := w.resolveChunkURL(chunkId, publicPath, hashes, filenameRule, chunkFilename, fromJS)
		confidence := ConfMedium
		if chunkURL == "" {
			confidence = ConfLow
		}

		imports = append(imports, DynamicImport{
			FromJS:      fromJS,
			Raw:         "__webpack_require__.e(" + chunkId + ")",
			ResolvedURL: chunkURL,
			Framework:   "webpack",
			Source:      SourceWebpackRuntime,
			Confidence:  confidence,
		})
	}

	return imports
}

// resolveChunkURL resolves the full URL for a chunk
func (w *WebpackAnalyzer) resolveChunkURL(chunkId string, publicPath string, hashes map[string]string, filenameRule string, chunkFilename string, fromJS string) string {
	if publicPath == "" {
		// Try to infer publicPath from fromJS
		if idx := strings.LastIndex(fromJS, "/"); idx >= 0 {
			publicPath = fromJS[:idx+1]
		} else {
			return ""
		}
	}

	// Resolve relative publicPath to absolute URL
	if !strings.HasPrefix(publicPath, "http://") && !strings.HasPrefix(publicPath, "https://") {
		if resolved, err := urlutil.ResolveJS(fromJS, publicPath); err == nil {
			publicPath = resolved
		}
	}

	hash, hasHash := hashes[chunkId]

	// Prefer chunkFilename
	if chunkFilename != "" {
		filename := chunkFilename
		filename = strings.ReplaceAll(filename, "[id]", chunkId)
		filename = strings.ReplaceAll(filename, "[chunkhash]", hash)
		filename = strings.ReplaceAll(filename, "[contenthash]", hash)
		filename = strings.ReplaceAll(filename, "[name]", chunkId)
		if hasHash {
			filename = strings.ReplaceAll(filename, "[hash]", hash)
		}
		return publicPath + filename
	}

	// Try to infer from filenameRule
	if filenameRule != "" {
		if filename := w.resolveChunkFilenameFromRule(filenameRule, chunkId, hash, hasHash); filename != "" {
			return publicPath + filename
		}

		// Try to extract "prefix" + var + "suffix" pattern with regex
		if fm := wpFilenamePattern.FindStringSubmatch(filenameRule); fm != nil {
			prefix := fm[1]
			suffix := fm[2]
			filename := prefix + chunkId
			if hasHash {
				// Replace hash placeholders in suffix
				suffix = strings.ReplaceAll(suffix, "[hash]", hash)
				suffix = strings.ReplaceAll(suffix, "[chunkhash]", hash)
				suffix = strings.ReplaceAll(suffix, "[contenthash]", hash)
			}
			filename += suffix
			return publicPath + filename
		}
	}

	// Generic fallback
	if hasHash {
		return publicPath + chunkId + "." + hash + ".js"
	}

	// No hash info available, can only provide a candidate
	return publicPath + chunkId + ".js"
}

func (w *WebpackAnalyzer) resolveChunkFilenameFromRule(filenameRule string, chunkId string, hash string, hasHash bool) string {
	if hasHash {
		if m := wpFilenameWithHashMapPattern.FindStringSubmatch(filenameRule); m != nil {
			return m[1] + chunkId + m[2] + hash + m[3]
		}
	}

	return ""
}

func (w *WebpackAnalyzer) buildNewURLs(imports []DynamicImport, fromJS string) []JSAsset {
	var assets []JSAsset
	seen := make(map[string]bool)

	for _, imp := range imports {
		if imp.ResolvedURL != "" && !seen[imp.ResolvedURL] && urlutil.IsJSPath(imp.ResolvedURL) {
			seen[imp.ResolvedURL] = true
			assets = append(assets, JSAsset{
				URL:        imp.ResolvedURL,
				FromURL:    fromJS,
				Type:       TypeLazyChunkJS,
				Framework:  "webpack",
				Source:     imp.Source,
				Confidence: imp.Confidence,
				Status:     StatusCandidate,
			})
		}
	}

	return assets
}

// IsWebpackJS checks whether the JS was built by Webpack
func (w *WebpackAnalyzer) IsWebpackJS(jsContent string) bool {
	indicators := []string{
		"__webpack_require__",
		"self.webpackChunk",
		"webpackJsonp",
	}
	count := 0
	for _, ind := range indicators {
		if strings.Contains(jsContent, ind) {
			count++
		}
	}
	return count >= 1
}
