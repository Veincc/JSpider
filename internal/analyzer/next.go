package analyzer

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/Veincc/JSpider/internal/urlutil"
)

var (
	nextBuildIDRe      = regexp.MustCompile(`"_buildId"\s*:\s*"([^"]+)"`)
	nextManifestURLRe  = regexp.MustCompile(`/_next/static/([^/]+)/(_buildManifest|_ssgManifest|app-build-manifest)\.js`)
	nextStaticChunkRe  = regexp.MustCompile(`/_next/static/chunks/[^"'\s]+\.js`)
	nextManifestDataRe = regexp.MustCompile(`self\.__BUILD_MANIFEST\s*=\s*(?:function\s*\(\s*\w*\s*\)\s*\{[\s\S]*?return\s*|)(\{[\s\S]*?\})\s*;`)
)

// NextAnalyzer is a Next.js-specific analyzer
type NextAnalyzer struct {
	regex *RegexAnalyzer
}

func NewNextAnalyzer(regex *RegexAnalyzer) *NextAnalyzer {
	return &NextAnalyzer{regex: regex}
}

// Analyze analyzes JS built by Next.js
func (n *NextAnalyzer) Analyze(jsContent string, fromJS string) *AnalysisResult {
	result := &AnalysisResult{
		Framework: "next",
	}

	// 1. Extract _buildManifest.js and other manifest URLs
	manifestURLs := n.extractManifestURLs(jsContent, fromJS)
	for _, mURL := range manifestURLs {
		result.NewURLs = append(result.NewURLs, JSAsset{
			URL:        mURL,
			FromURL:    fromJS,
			Type:       TypeRuntimeJS,
			Framework:  "next",
			Source:     SourceNextManifest,
			Confidence: ConfHigh,
			Status:     StatusCandidate,
		})
	}

	// 2. Extract JS from static/chunks
	chunkURLs := n.regex.ExtractNextChunks(jsContent, fromJS)
	for _, cURL := range chunkURLs {
		result.NewURLs = append(result.NewURLs, JSAsset{
			URL:        cURL,
			FromURL:    fromJS,
			Type:       TypeLazyChunkJS,
			Framework:  "next",
			Source:     SourceNextManifest,
			Confidence: ConfHigh,
			Status:     StatusCandidate,
		})
	}

	// 3. Try to parse __BUILD_MANIFEST content
	routes := n.parseBuildManifest(jsContent, fromJS)
	result.Routes = append(result.Routes, routes...)

	// 4. Extract dynamic imports
	directImports := n.regex.ExtractDynamicImports(jsContent, fromJS, "next")
	result.Imports = append(result.Imports, directImports...)

	// 5. Extract sourceMappingURL
	if mapURL := n.regex.ExtractSourceMappingURL(jsContent, fromJS); mapURL != "" {
		result.Sourcemaps = append(result.Sourcemaps, SourceMapInfo{
			FromJS: fromJS,
			MapURL: mapURL,
			Status: "found",
		})
	}

	return result
}

// extractManifestURLs extracts Next.js manifest file URLs
func (n *NextAnalyzer) extractManifestURLs(jsContent string, fromJS string) []string {
	var urls []string
	seen := make(map[string]bool)

	// Extract buildId from content
	buildID := ""
	if m := nextBuildIDRe.FindStringSubmatch(jsContent); m != nil {
		buildID = m[1]
	}

	// Extract buildId from URL
	if buildID == "" {
		if m := nextManifestURLRe.FindStringSubmatch(fromJS); m != nil {
			buildID = m[1]
		}
	}

	if buildID != "" {
		manifests := []string{
			"/_next/static/" + buildID + "/_buildManifest.js",
			"/_next/static/" + buildID + "/_ssgManifest.js",
			"/_next/static/" + buildID + "/app-build-manifest.js",
		}
		for _, m := range manifests {
			resolved, err := urlutil.ResolveJS(fromJS, m)
			if err == nil && !seen[resolved] {
				seen[resolved] = true
				urls = append(urls, resolved)
			}
		}
	}

	// Directly match manifest URLs
	for _, m := range nextManifestURLRe.FindAllString(jsContent, -1) {
		resolved, err := urlutil.ResolveJS(fromJS, m)
		if err == nil && !seen[resolved] {
			seen[resolved] = true
			urls = append(urls, resolved)
		}
	}

	return urls
}

// parseBuildManifest parses __BUILD_MANIFEST content
func (n *NextAnalyzer) parseBuildManifest(jsContent string, fromJS string) []RouteChunk {
	var routes []RouteChunk

	// Try to extract the __BUILD_MANIFEST object
	matches := nextManifestDataRe.FindStringSubmatch(jsContent)
	if matches == nil {
		return routes
	}

	manifestJSON := matches[1]
	// Try to parse JSON
	var manifest map[string][]string
	if err := json.Unmarshal([]byte(manifestJSON), &manifest); err != nil {
		// JSON may be incomplete or malformed, try simple parsing
		return n.parseManifestSimple(manifestJSON, fromJS)
	}

	for route, chunks := range manifest {
		routeChunk := RouteChunk{
			Route:      route,
			FromJS:     fromJS,
			Framework:  "next",
			Source:     SourceNextManifest,
			Confidence: ConfHigh,
		}

		for _, chunk := range chunks {
			resolved, err := urlutil.ResolveJS(fromJS, n.normalizeChunkPath(chunk))
			if err == nil {
				routeChunk.Deps = append(routeChunk.Deps, resolved)
			}
		}

		if len(routeChunk.Deps) > 0 {
			routeChunk.LazyJS = routeChunk.Deps[0]
		}

		routes = append(routes, routeChunk)
	}

	return routes
}

// parseManifestSimple performs simple (fault-tolerant) manifest JSON parsing
func (n *NextAnalyzer) parseManifestSimple(manifestStr string, fromJS string) []RouteChunk {
	var routes []RouteChunk

	// Simply extract "route": ["chunk1.js", "chunk2.js"] patterns
	routeRe := regexp.MustCompile(`"(/[^"]*?)"\s*:\s*\[(.*?)\]`)
	chunkRe := regexp.MustCompile(`"([^"]+\.js)"`)

	for _, m := range routeRe.FindAllStringSubmatch(manifestStr, -1) {
		route := m[1]
		chunksStr := m[2]

		routeChunk := RouteChunk{
			Route:      route,
			FromJS:     fromJS,
			Framework:  "next",
			Source:     SourceNextManifest,
			Confidence: ConfMedium,
		}

		for _, cm := range chunkRe.FindAllStringSubmatch(chunksStr, -1) {
			chunk := cm[1]
			resolved, err := urlutil.ResolveJS(fromJS, n.normalizeChunkPath(chunk))
			if err == nil {
				routeChunk.Deps = append(routeChunk.Deps, resolved)
			}
		}

		if len(routeChunk.Deps) > 0 {
			routeChunk.LazyJS = routeChunk.Deps[0]
			routes = append(routes, routeChunk)
		}
	}

	return routes
}

// normalizeChunkPath normalizes chunk paths to avoid duplicate /_next/static/chunks/ prefixes
func (n *NextAnalyzer) normalizeChunkPath(chunk string) string {
	// Already an absolute path (starts with /), use as-is
	if strings.HasPrefix(chunk, "/") {
		return chunk
	}
	// Relative path, prepend prefix
	return "/_next/static/chunks/" + chunk
}

// IsNextJS checks whether the JS was built by Next.js
func (n *NextAnalyzer) IsNextJS(jsContent string, jsURL string) bool {
	indicators := []string{
		"/_next/static/chunks/",
		"self.__BUILD_MANIFEST",
		"_buildManifest.js",
		"__NEXT_DATA__",
		"/_next/",
	}
	for _, ind := range indicators {
		if strings.Contains(jsContent, ind) || strings.Contains(jsURL, ind) {
			return true
		}
	}
	return false
}
