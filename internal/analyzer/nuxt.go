package analyzer

import (
	"regexp"
	"strings"

	"github.com/Veincc/JSpider/internal/urlutil"
)

var (
	nuxtStaticPathRe = regexp.MustCompile(`/_nuxt/[^"'\s]+\.js`)
	nuxtPayloadRe    = regexp.MustCompile(`(?:window\.__NUXT__|__NUXT_DATA__)\s*=`)
	nuxtRouteMapRe   = regexp.MustCompile(`"([^"]+?)"\s*:\s*(?:function\s*\(\s*\)\s*\{)?\s*return\s+import\s*\(\s*["']([^"']+)["']`)
)

// NuxtAnalyzer is a Nuxt-specific analyzer
type NuxtAnalyzer struct {
	regex *RegexAnalyzer
}

func NewNuxtAnalyzer(regex *RegexAnalyzer) *NuxtAnalyzer {
	return &NuxtAnalyzer{regex: regex}
}

// Analyze analyzes JS built by Nuxt
func (n *NuxtAnalyzer) Analyze(jsContent string, fromJS string) *AnalysisResult {
	result := &AnalysisResult{
		Framework: "nuxt",
	}

	// 1. Extract /_nuxt/*.js paths
	nuxtPaths := n.regex.ExtractNuxtPaths(jsContent, fromJS)
	for _, p := range nuxtPaths {
		result.NewURLs = append(result.NewURLs, JSAsset{
			URL:        p,
			FromURL:    fromJS,
			Type:       TypeLazyChunkJS,
			Framework:  "nuxt",
			Source:     SourceNuxtStatic,
			Confidence: ConfMedium,
			Status:     StatusCandidate,
		})
	}

	// 2. Extract route mappings
	routes := n.extractRouteMap(jsContent, fromJS)
	result.Routes = append(result.Routes, routes...)

	// 3. Extract dynamic imports
	directImports := n.regex.ExtractDynamicImports(jsContent, fromJS, "nuxt")
	result.Imports = append(result.Imports, directImports...)

	// 4. Extract sourceMappingURL
	if mapURL := n.regex.ExtractSourceMappingURL(jsContent, fromJS); mapURL != "" {
		result.Sourcemaps = append(result.Sourcemaps, SourceMapInfo{
			FromJS: fromJS,
			MapURL: mapURL,
			Status: "found",
		})
	}

	return result
}

// extractRouteMap extracts Nuxt route mappings
func (n *NuxtAnalyzer) extractRouteMap(jsContent string, fromJS string) []RouteChunk {
	var routes []RouteChunk

	for _, m := range nuxtRouteMapRe.FindAllStringSubmatch(jsContent, -1) {
		routePath := m[1]
		chunkPath := m[2]

		if !strings.HasPrefix(routePath, "/") {
			routePath = "/" + routePath
		}

		resolvedURL, err := urlutil.ResolveJS(fromJS, chunkPath)
		if err != nil {
			resolvedURL = chunkPath
		}

		routes = append(routes, RouteChunk{
			Route:      routePath,
			LazyJS:     resolvedURL,
			FromJS:     fromJS,
			Framework:  "nuxt",
			Source:     SourceNuxtStatic,
			Confidence: ConfMedium,
		})
	}

	return routes
}

// IsNuxtJS checks whether the JS was built by Nuxt
func (n *NuxtAnalyzer) IsNuxtJS(jsContent string, jsURL string) bool {
	indicators := []string{
		"/_nuxt/",
		"window.__NUXT__",
		"__NUXT_DATA__",
		"nuxt_plugin",
		"nuxtLink",
	}
	for _, ind := range indicators {
		if strings.Contains(jsContent, ind) || strings.Contains(jsURL, ind) {
			return true
		}
	}
	return false
}
