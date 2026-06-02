package analyzer

import (
	"regexp"
	"strings"

	"github.com/Veincc/JSpider/internal/urlutil"
)

var (
	// Vite-specific regex
	viteImportMetaRe = regexp.MustCompile(`import\.meta\.url`)
	vitePreloadFnRe  = regexp.MustCompile(`(?:function\s+|const\s+|let\s+|var\s+)?(__vitePreload|__vite__mapDeps)\s*=`)
	viteAssetMapRe   = regexp.MustCompile(`"([^"]+?)"\s*:\s*\(\)\s*=>\s*(?:__vitePreload\s*\(\s*)?import\s*\(\s*["']\.\/([^"']+)["']`)
	viteLazyImportRe = regexp.MustCompile(`\(\)\s*=>\s*(?:__vitePreload\s*\(\s*)?import\s*\(\s*["']\.\/([^"']+)["']`)
)

// ViteAnalyzer is a Vite-specific analyzer
type ViteAnalyzer struct {
	regex *RegexAnalyzer
}

func NewViteAnalyzer(regex *RegexAnalyzer) *ViteAnalyzer {
	return &ViteAnalyzer{regex: regex}
}

// Analyze analyzes JS built by Vite
func (v *ViteAnalyzer) Analyze(jsContent string, fromJS string) *AnalysisResult {
	result := &AnalysisResult{
		Framework: "vite",
	}

	// 1. Extract direct dynamic imports
	directImports := v.regex.ExtractDynamicImports(jsContent, fromJS, "vite")
	for i := range directImports {
		directImports[i].Source = SourceViteImport
		directImports[i].Confidence = ConfHigh
	}
	result.Imports = append(result.Imports, directImports...)

	// 2. Extract __vite__mapDeps related data
	mapDepsImports, mapDepsRoutes := v.regex.ExtractViteMapDeps(jsContent, fromJS)
	result.Imports = append(result.Imports, mapDepsImports...)
	result.Routes = append(result.Routes, mapDepsRoutes...)

	// 3. Extract Vite asset map
	assetImports, assetRoutes := v.extractAssetMap(jsContent, fromJS)
	result.Imports = append(result.Imports, assetImports...)
	result.Routes = append(result.Routes, assetRoutes...)

	// 4. Extract new JS URLs
	newURLs := v.extractNewURLs(jsContent, fromJS, result.Imports)
	result.NewURLs = newURLs

	// 5. Extract sourceMappingURL
	if mapURL := v.regex.ExtractSourceMappingURL(jsContent, fromJS); mapURL != "" {
		result.Sourcemaps = append(result.Sourcemaps, SourceMapInfo{
			FromJS: fromJS,
			MapURL: mapURL,
			Status: "found",
		})
	}

	return result
}

// extractAssetMap extracts the Vite asset map
func (v *ViteAnalyzer) extractAssetMap(jsContent string, fromJS string) ([]DynamicImport, []RouteChunk) {
	var imports []DynamicImport
	var routes []RouteChunk

	// Match "path/to/file.vue": () => import("./chunk-xxx.js")
	for _, m := range viteAssetMapRe.FindAllStringSubmatch(jsContent, -1) {
		componentPath := m[1]
		chunkFile := m[2]

		resolvedURL, err := urlutil.ResolveJS(fromJS, "./"+chunkFile)
		if err != nil {
			continue
		}

		imp := DynamicImport{
			FromJS:      fromJS,
			Raw:         m[0],
			ResolvedURL: resolvedURL,
			Framework:   "vite",
			Source:      SourceViteImport,
			Confidence:  ConfHigh,
			Component:   componentPath,
		}
		imports = append(imports, imp)

		// Try to infer route from component path
		route := v.inferRouteFromComponent(componentPath)
		if route != "" {
			routes = append(routes, RouteChunk{
				Route:      route,
				Component:  componentPath,
				LazyJS:     resolvedURL,
				FromJS:     fromJS,
				Framework:  "vite",
				Source:     SourceViteImport,
				Confidence: ConfMedium,
			})
		}
	}

	return imports, routes
}

// extractNewURLs extracts newly discovered JS URLs
func (v *ViteAnalyzer) extractNewURLs(jsContent string, fromJS string, imports []DynamicImport) []JSAsset {
	var assets []JSAsset
	seen := make(map[string]bool)

	// Extract from import results
	for _, imp := range imports {
		if imp.ResolvedURL != "" && !seen[imp.ResolvedURL] {
			seen[imp.ResolvedURL] = true
			assets = append(assets, JSAsset{
				URL:        imp.ResolvedURL,
				FromURL:    fromJS,
				Type:       TypeLazyChunkJS,
				Framework:  "vite",
				Source:     imp.Source,
				Confidence: imp.Confidence,
				Status:     StatusCandidate,
			})
		}
		for _, dep := range imp.Deps {
			if !seen[dep] && urlutil.IsJSPath(dep) {
				seen[dep] = true
				assets = append(assets, JSAsset{
					URL:        dep,
					FromURL:    fromJS,
					Type:       TypeLazyChunkJS,
					Framework:  "vite",
					Source:     SourceViteMapDeps,
					Confidence: ConfMedium,
					Status:     StatusCandidate,
				})
			}
		}
	}

	// Extract all JS files from the mapDeps definition
	deps := v.regex.ExtractViteMapDepsDefinition(jsContent)
	for _, dep := range deps {
		if !seen[dep] && urlutil.IsJSPath(dep) {
			resolved, err := urlutil.ResolveJS(fromJS, dep)
			if err == nil {
				dep = resolved
			}
			if !seen[dep] {
				seen[dep] = true
				assets = append(assets, JSAsset{
					URL:        dep,
					FromURL:    fromJS,
					Type:       TypeLazyChunkJS,
					Framework:  "vite",
					Source:     SourceViteMapDeps,
					Confidence: ConfMedium,
					Status:     StatusCandidate,
				})
			}
		}
	}

	// Extract additional paths from JS content
	paths := v.regex.ExtractJSPaths(jsContent, fromJS)
	for _, p := range paths {
		if !seen[p] && urlutil.IsJSPath(p) {
			seen[p] = true
			assets = append(assets, JSAsset{
				URL:        p,
				FromURL:    fromJS,
				Type:       TypeLazyChunkJS,
				Framework:  "vite",
				Source:     SourceRegexCandidate,
				Confidence: ConfLow,
				Status:     StatusCandidate,
			})
		}
	}

	return assets
}

// inferRouteFromComponent infers route from component path
func (v *ViteAnalyzer) inferRouteFromComponent(component string) string {
	// Common patterns: "../views/user/index.vue" -> "/user"
	// "../views/dashboard/index.vue" -> "/dashboard"
	// "../pages/about.vue" -> "/about"

	lower := strings.ToLower(component)

	// Check if the path contains views or pages directories
	for _, dir := range []string{"/views/", "/pages/", "/router/"} {
		idx := strings.Index(lower, dir)
		if idx >= 0 {
			rest := component[idx+len(dir):]
			// Strip file extension
			for _, ext := range []string{".vue", ".jsx", ".tsx", ".js", ".ts"} {
				rest = strings.TrimSuffix(rest, ext)
			}
			// Strip filename (if there are subdirectories)
			if lastSlash := strings.LastIndex(rest, "/"); lastSlash >= 0 {
				rest = rest[:lastSlash]
			}
			// Strip index
			rest = strings.TrimSuffix(rest, "/index")
			rest = strings.TrimSuffix(rest, "/")
			if rest != "" {
				return "/" + rest
			}
		}
	}

	return ""
}

// IsViteJS checks whether the JS was built by Vite
func (v *ViteAnalyzer) IsViteJS(jsContent string, jsURL string) bool {
	indicators := []string{
		"__vite__mapDeps",
		"__vitePreload",
		"import.meta.url",
		"import.meta.hot",
	}
	count := 0
	for _, ind := range indicators {
		if strings.Contains(jsContent, ind) {
			count++
		}
	}
	// URL path heuristic
	if strings.Contains(jsURL, "/assets/") && strings.Contains(jsURL, ".js") {
		count++
	}
	return count >= 2
}
