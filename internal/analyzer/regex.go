package analyzer

import (
	"regexp"
	"strings"

	"github.com/Veincc/JSpider/internal/urlutil"
)

// Common regex patterns
var (
	// import("...") / import('...') / import(`...`)
	dynamicImportRe = regexp.MustCompile(`import\s*\(\s*(?:"([^"]+)"|'([^']+)'|` + "`" + `([^` + "`" + `]+)` + "`" + `)\s*\)`)

	// sourceMappingURL
	sourceMappingURLRe = regexp.MustCompile(`(?m)(?://|/\*)[#@]\s*sourceMappingURL\s*=\s*(\S+?)(?:\s*\*/)?$`)

	// Route path pattern
	routePathRe = regexp.MustCompile(`(?:path|route)\s*:\s*["']([/][^"']*?)["']`)

	// Component pattern
	componentRe = regexp.MustCompile(`(?:component|Component)\s*:\s*(?:\(\)\s*=>\s*)?(?:import\s*\(\s*["']([^"']+)["']\s*\))`)

	// Vite signature patterns
	viteMapDepsRe     = regexp.MustCompile(`__vite__mapDeps\s*\(\s*\[([0-9,\s]+)\]`)
	viteMapDepsDefRe  = regexp.MustCompile(`__vite__mapDeps\s*=\s*(?:function\s*)?\(i\s*,\s*m\s*=\s*__vite__mapDeps\s*,\s*d\s*=\s*\(\s*m\.f\s*\|\|\s*\(\s*m\.f\s*=\s*(\[(?:[^\[\]]*|"(?:[^"\\]|\\.)*")*\])\s*\)\s*\)\s*\)\s*=>`)
	vitePreloadRe     = regexp.MustCompile(`__vitePreload\s*\(\s*(?:\(\)\s*=>\s*)?import\s*\(\s*["']([^"']+)["']`)
	viteAssetPathRe   = regexp.MustCompile(`(?:"([^"]+\.js)"\s*:\s*\(\)\s*=>\s*import|"\.\./[^"]*\.vue"\s*:\s*\(\)\s*=>)`)

	// Webpack signature patterns
	webpackChunkRe    = regexp.MustCompile(`self\.webpackChunk\w*\s*\|\|\s*\[\]\)\.push\s*\(\s*\[\s*\[([0-9]+)`)
	webpackPublicPath = regexp.MustCompile(`__webpack_require__\.p\s*=\s*["']([^"']+)["']`)
	webpackChunkId    = regexp.MustCompile(`__webpack_require__\.e\s*\(\s*["']?([^)"']+?)["']?\s*\)`)
	webpackURe        = regexp.MustCompile(`__webpack_require__\.u\s*=\s*function\s*\([^)]*\)\s*\{([\s\S]*?)\}`)
	webpackHashRe     = regexp.MustCompile(`\{"([0-9]+)"\s*:\s*"([a-zA-Z0-9]+)"\}`)

	// Resource path pattern
	jsPathRe = regexp.MustCompile(`(?:"|')((?:/|\.|\.\./)(?:assets|static|_next/static|_nuxt|chunks|js)[^"']*\.js)(?:"|')`)

	// Next.js manifest
	nextBuildManifestRe = regexp.MustCompile(`/_next/static/([^/]+)/_buildManifest\.js`)
	nextChunkRe         = regexp.MustCompile(`/_next/static/chunks/[^"'\s]+\.js`)

	// Nuxt signatures
	nuxtPathRe = regexp.MustCompile(`/_nuxt/[^"'\s]+\.js`)

	// Angular signatures
	angularRuntimeRe = regexp.MustCompile(`runtime\.[a-f0-9]+\.js`)
	angularMainRe    = regexp.MustCompile(`main\.[a-f0-9]+\.js`)
)

// RegexAnalyzer is a regex-based analyzer
type RegexAnalyzer struct{}

func NewRegexAnalyzer() *RegexAnalyzer {
	return &RegexAnalyzer{}
}

// ExtractDynamicImports extracts dynamic imports from JS content
func (r *RegexAnalyzer) ExtractDynamicImports(jsContent string, fromJS string, framework string) []DynamicImport {
	var imports []DynamicImport

	for _, m := range dynamicImportRe.FindAllStringSubmatch(jsContent, -1) {
		raw := ""
		if m[1] != "" {
			raw = m[1]
		} else if m[2] != "" {
			raw = m[2]
		} else if m[3] != "" {
			raw = m[3]
		}

		if raw == "" {
			continue
		}

		// Template string imports (containing ${}) cannot be determined as downloadable URLs
		if strings.Contains(raw, "${") {
			imp := DynamicImport{
				FromJS:      fromJS,
				Raw:         raw,
				ResolvedURL: "",
				Framework:   framework,
				Source:      SourceImportExpr,
				Confidence:  ConfLow,
			}
			imports = append(imports, imp)
			continue
		}

		resolvedURL := ""
		if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
			resolvedURL = raw
		} else if strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "./") || strings.HasPrefix(raw, "../") {
			// Path-like: resolve via shared resolver (handles deduplication)
			resolved, err := urlutil.ResolveJS(fromJS, raw)
			if err == nil && resolved != "" {
				resolvedURL = resolved
			}
		}
		// Bare specifiers (e.g. "lodash", "react") are left unresolved (ConfMedium)

		confidence := ConfHigh
		if resolvedURL == "" {
			confidence = ConfMedium
		}

		imp := DynamicImport{
			FromJS:      fromJS,
			Raw:         raw,
			ResolvedURL: resolvedURL,
			Framework:   framework,
			Source:      SourceImportExpr,
			Confidence:  confidence,
		}

		// Try to extract component information
		if strings.Contains(raw, "component") || strings.Contains(raw, "Component") || strings.Contains(raw, "view") || strings.Contains(raw, "page") {
			imp.Component = raw
		}

		imports = append(imports, imp)
	}

	return imports
}

// ExtractSourceMappingURL extracts the sourceMappingURL
func (r *RegexAnalyzer) ExtractSourceMappingURL(jsContent string, fromJS string) string {
	matches := sourceMappingURLRe.FindAllStringSubmatch(jsContent, -1)
	if len(matches) == 0 {
		return ""
	}

	// Take the last sourceMappingURL
	last := matches[len(matches)-1]
	mapURL := last[1]

	// Resolve relative URL
	if strings.HasPrefix(mapURL, "data:") {
		return "" // Skip data URLs
	}

	if strings.HasPrefix(mapURL, "http://") || strings.HasPrefix(mapURL, "https://") {
		return mapURL
	}

	resolved, err := urlutil.ResolveJS(fromJS, mapURL)
	if err != nil {
		return ""
	}
	return resolved
}

// ExtractRoutePaths extracts route paths
func (r *RegexAnalyzer) ExtractRoutePaths(jsContent string, fromJS string) []RouteChunk {
	var routes []RouteChunk

	for _, m := range routePathRe.FindAllStringSubmatch(jsContent, -1) {
		routePath := m[1]
		if routePath == "" {
			continue
		}

		route := RouteChunk{
			Route:      routePath,
			FromJS:     fromJS,
			Source:     SourceRegexCandidate,
			Confidence: ConfLow,
		}

		// Try to find a component import nearby
		idx := strings.Index(jsContent, m[0])
		if idx >= 0 {
			// Search for a component within 500 characters of the path
			neighborhood := jsContent[idx:min(idx+500, len(jsContent))]
			if cm := componentRe.FindStringSubmatch(neighborhood); cm != nil {
				route.Component = cm[1]
				route.Confidence = ConfMedium
			}
		}

		routes = append(routes, route)
	}

	return routes
}

// ExtractViteMapDeps extracts Vite __vite__mapDeps dependencies
func (r *RegexAnalyzer) ExtractViteMapDeps(jsContent string, fromJS string) ([]DynamicImport, []RouteChunk) {
	var imports []DynamicImport
	var routes []RouteChunk

	// Extract indices from mapDeps calls
	matches := viteMapDepsRe.FindAllStringSubmatch(jsContent, -1)
	if len(matches) == 0 {
		return imports, routes
	}

	// Extract the dependency array from the mapDeps definition
	deps := r.extractViteDepsArray(jsContent)

	for _, m := range matches {
		indices := parseIndices(m[1])
		if len(indices) == 0 {
			continue
		}

		// Resolve dependency files using indices
		var resolvedDeps []string
		for _, idx := range indices {
			if idx < len(deps) {
				dep := deps[idx]
				if !urlutil.IsCSSResource(dep) {
					resolved, err := urlutil.ResolveJS(fromJS, dep)
					if err == nil {
						resolvedDeps = append(resolvedDeps, resolved)
					} else {
						resolvedDeps = append(resolvedDeps, dep)
					}
				}
			}
		}

		if len(resolvedDeps) > 0 {
			imp := DynamicImport{
				FromJS:     fromJS,
				Raw:        m[0],
				Framework:  "vite",
				Source:     SourceViteMapDeps,
				Confidence: ConfMedium,
				Deps:       resolvedDeps,
			}
			imports = append(imports, imp)
		}
	}

	// Extract import patterns with routes: "../views/user/index.vue": () => import(...)
	for _, m := range viteAssetPathRe.FindAllStringSubmatch(jsContent, -1) {
		componentPath := m[1]
		if componentPath == "" {
			continue
		}

		// Search for import(...) nearby
		idx := strings.Index(jsContent, m[0])
		neighborhood := jsContent[idx:min(idx+300, len(jsContent))]
		if dm := dynamicImportRe.FindStringSubmatch(neighborhood); dm != nil {
			raw := dm[1]
			if raw == "" {
				raw = dm[2]
			}
			if raw == "" {
				raw = dm[3]
			}
			resolvedURL, _ := urlutil.ResolveJS(fromJS, raw)

			imp := DynamicImport{
				FromJS:      fromJS,
				Raw:         raw,
				ResolvedURL: resolvedURL,
				Framework:   "vite",
				Source:      SourceViteImport,
				Confidence:  ConfHigh,
				Component:   componentPath,
			}
			imports = append(imports, imp)

			// Try to extract routes
			routeIdx := strings.LastIndex(jsContent[:idx], "path:")
			if routeIdx >= 0 {
				routeNeighborhood := jsContent[routeIdx:min(routeIdx+200, len(jsContent))]
				if rm := routePathRe.FindStringSubmatch(routeNeighborhood); rm != nil {
					route := RouteChunk{
						Route:      rm[1],
						Component:  componentPath,
						LazyJS:     resolvedURL,
						FromJS:     fromJS,
						Framework:  "vite",
						Source:     SourceViteImport,
						Confidence: ConfHigh,
					}
					routes = append(routes, route)
				}
			}
		}
	}

	return imports, routes
}

// extractViteDepsArray extracts the dependency array from the __vite__mapDeps definition
func (r *RegexAnalyzer) extractViteDepsArray(jsContent string) []string {
	m := viteMapDepsDefRe.FindStringSubmatch(jsContent)
	if m == nil {
		return nil
	}

	arrayContent := m[1]
	// Parse strings in the array
	var deps []string
	strRe := regexp.MustCompile(`"([^"]+)"`)
	for _, sm := range strRe.FindAllStringSubmatch(arrayContent, -1) {
		deps = append(deps, sm[1])
	}
	return deps
}

// ExtractViteMapDepsDefinition extracts all JS file paths from the __vite__mapDeps definition
func (r *RegexAnalyzer) ExtractViteMapDepsDefinition(jsContent string) []string {
	m := viteMapDepsDefRe.FindStringSubmatch(jsContent)
	if m == nil {
		return nil
	}

	arrayContent := m[1]
	// Parse all strings in the array
	var deps []string
	strRe := regexp.MustCompile(`"([^"]+)"`)
	for _, sm := range strRe.FindAllStringSubmatch(arrayContent, -1) {
		deps = append(deps, sm[1])
	}
	return deps
}

// ExtractWebpackChunks extracts Webpack chunk information
func (r *RegexAnalyzer) ExtractWebpackChunks(jsContent string, fromJS string) ([]DynamicImport, []RouteChunk) {
	var imports []DynamicImport
	var routes []RouteChunk

	// Extract publicPath
	publicPath := ""
	if pm := webpackPublicPath.FindStringSubmatch(jsContent); pm != nil {
		publicPath = pm[1]
	}

	// Extract chunkId -> hash mapping
	chunkHashes := make(map[string]string)
	for _, m := range webpackHashRe.FindAllStringSubmatch(jsContent, -1) {
		chunkHashes[m[1]] = m[2]
	}

	// Extract chunk filename rules from __webpack_require__.u function
	chunkFilename := ""
	if um := webpackURe.FindStringSubmatch(jsContent); um != nil {
		// Try to extract filename pattern
		body := um[1]
		if strings.Contains(body, ".js") {
			// Extract patterns like "static/js/" + chunkId + "." + hash + ".js"
			filenameRe := regexp.MustCompile(`"([^"]*?)"\s*\+\s*\w+\s*\+\s*"([^"]*?)"`)
			if fm := filenameRe.FindStringSubmatch(body); fm != nil {
				chunkFilename = fm[1] + "{id}" + fm[2]
			}
		}
	}

	// Extract webpackChunk pushes
	for _, m := range webpackChunkRe.FindAllStringSubmatch(jsContent, -1) {
		chunkId := m[1]

		// Try to reconstruct the URL
		chunkURL := ""
		if publicPath != "" {
			if hash, ok := chunkHashes[chunkId]; ok {
				if chunkFilename != "" {
					filename := strings.Replace(chunkFilename, "{id}", chunkId, 1)
					filename = strings.Replace(filename, "{hash}", hash, 1)
					chunkURL = publicPath + filename
				} else {
					chunkURL = publicPath + chunkId + "." + hash + ".js"
				}
			} else {
				chunkURL = publicPath + chunkId + ".js"
			}
		}

		confidence := ConfMedium
		if chunkURL == "" || publicPath == "" {
			confidence = ConfLow
		}

		imp := DynamicImport{
			FromJS:      fromJS,
			Raw:         "webpackChunk:" + chunkId,
			ResolvedURL: chunkURL,
			Framework:   "webpack",
			Source:      SourceWebpackRuntime,
			Confidence:  confidence,
		}
		imports = append(imports, imp)
	}

	// Extract __webpack_require__.e(chunkId)
	for _, m := range webpackChunkId.FindAllStringSubmatch(jsContent, -1) {
		chunkId := m[1]

		chunkURL := ""
		if publicPath != "" {
			if hash, ok := chunkHashes[chunkId]; ok {
				chunkURL = publicPath + chunkId + "." + hash + ".js"
			} else {
				chunkURL = publicPath + chunkId + ".js"
			}
		}

		confidence := ConfMedium
		if chunkURL == "" {
			confidence = ConfLow
		}

		imp := DynamicImport{
			FromJS:      fromJS,
			Raw:         "__webpack_require__.e(" + chunkId + ")",
			ResolvedURL: chunkURL,
			Framework:   "webpack",
			Source:      SourceWebpackRuntime,
			Confidence:  confidence,
		}
		imports = append(imports, imp)
	}

	return imports, routes
}

// ExtractJSPaths extracts JS resource paths from JS content
func (r *RegexAnalyzer) ExtractJSPaths(jsContent string, fromJS string) []string {
	var urls []string
	seen := make(map[string]bool)

	for _, m := range jsPathRe.FindAllStringSubmatch(jsContent, -1) {
		path := m[1]
		resolved, err := urlutil.ResolveJS(fromJS, path)
		if err != nil {
			continue
		}
		if !seen[resolved] {
			seen[resolved] = true
			urls = append(urls, resolved)
		}
	}

	return urls
}

// ExtractNextChunks extracts Next.js chunk paths
func (r *RegexAnalyzer) ExtractNextChunks(jsContent string, fromJS string) []string {
	var urls []string
	seen := make(map[string]bool)

	for _, m := range nextChunkRe.FindAllStringSubmatch(jsContent, -1) {
		chunk := m[0]
		if !seen[chunk] {
			seen[chunk] = true
			resolved, err := urlutil.ResolveJS(fromJS, chunk)
			if err == nil {
				urls = append(urls, resolved)
			}
		}
	}

	return urls
}

// ExtractNuxtPaths extracts Nuxt resource paths
func (r *RegexAnalyzer) ExtractNuxtPaths(jsContent string, fromJS string) []string {
	var urls []string
	seen := make(map[string]bool)

	for _, m := range nuxtPathRe.FindAllStringSubmatch(jsContent, -1) {
		path := m[0]
		if !seen[path] {
			seen[path] = true
			resolved, err := urlutil.ResolveJS(fromJS, path)
			if err == nil {
				urls = append(urls, resolved)
			}
		}
	}

	return urls
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// parseIndices parses comma-separated numeric indices
func parseIndices(s string) []int {
	var indices []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		val := 0
		for _, c := range part {
			if c >= '0' && c <= '9' {
				val = val*10 + int(c-'0')
			}
		}
		indices = append(indices, val)
	}
	return indices
}
