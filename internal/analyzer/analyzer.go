package analyzer

import (
	"github.com/Veincc/JSpider/internal/logging"
)

// Analyzer is the main analyzer that orchestrates the specialized analyzers
type Analyzer struct {
	log       *logging.Logger
	regex     *RegexAnalyzer
	framework *FrameworkDetector
	vite      *ViteAnalyzer
	webpack   *WebpackAnalyzer
	next      *NextAnalyzer
	nuxt      *NuxtAnalyzer
	angular   *AngularAnalyzer
	sourcemap *SourceMapAnalyzer
	ast       *TdewolffASTAnalyzer
}

func NewAnalyzer(log *logging.Logger) *Analyzer {
	regex := NewRegexAnalyzer()
	webpack := NewWebpackAnalyzer(regex)

	return &Analyzer{
		log:       log,
		regex:     regex,
		framework: NewFrameworkDetector(),
		vite:      NewViteAnalyzer(regex),
		webpack:   webpack,
		next:      NewNextAnalyzer(regex),
		nuxt:      NewNuxtAnalyzer(regex),
		angular:   NewAngularAnalyzer(regex, webpack),
		sourcemap: NewSourceMapAnalyzer(regex),
		ast:       NewASTAnalyzer(regex),
	}
}

// AnalyzeJS analyzes a single JS file
func (a *Analyzer) AnalyzeJS(jsContent string, jsURL string, fromURL string, depth int) *AnalysisResult {
	// 1. Framework detection
	fwDetect := a.framework.Detect(jsContent, jsURL)
	framework := "unknown"
	if fwDetect != nil {
		framework = fwDetect.Framework
	}

	a.log.Verbose("Analyzing JS: %s (framework=%s, depth=%d)", jsURL, framework, depth)

	// 2. Select analyzer based on framework
	var result *AnalysisResult

	switch framework {
	case "vite":
		result = a.vite.Analyze(jsContent, jsURL)
	case "webpack", "vue-cli":
		result = a.webpack.Analyze(jsContent, jsURL)
	case "next":
		result = a.next.Analyze(jsContent, jsURL)
	case "nuxt":
		result = a.nuxt.Analyze(jsContent, jsURL)
	case "angular":
		result = a.angular.Analyze(jsContent, jsURL)
	default:
		// Unknown framework, use generic analysis
		result = a.analyzeGeneric(jsContent, jsURL, framework)
	}

	// 3. Supplementary AST analysis (only runs for files under 5MB)
	if len(jsContent) <= 5*1024*1024 {
		astResult := a.ast.AnalyzeAST(jsContent, jsURL, framework)
		mergeResults(result, astResult)
	}

	// 4. Supplementary generic analysis
	a.supplementWithGeneric(result, jsContent, jsURL, framework)

	// 5. Source Map analysis (if not already extracted by the framework analyzer)
	mapURL := a.sourcemap.ExtractSourceMappingURL(jsContent, jsURL)
	if mapURL != "" {
		alreadyFound := false
		for _, sm := range result.Sourcemaps {
			if sm.MapURL == mapURL {
				alreadyFound = true
				break
			}
		}
		if !alreadyFound {
			result.Sourcemaps = append(result.Sourcemaps, SourceMapInfo{
				FromJS: jsURL,
				MapURL: mapURL,
				Status: "found",
			})
		}
	}

	// 6. Set framework info
	if fwDetect != nil {
		result.FrameworkInfo = fwDetect
		result.Framework = fwDetect.Framework
	}

	// 7. Deduplication
	result.Imports = dedupImports(result.Imports)
	result.Routes = dedupRoutes(result.Routes)

	return result
}

// mergeResults merges supplementary results into the main result (does not overwrite existing items)
func mergeResults(dst, src *AnalysisResult) {
	if src == nil {
		return
	}

	// Merge imports (deduplicate by Raw+FromJS)
	seenImports := make(map[string]bool)
	for _, imp := range dst.Imports {
		key := imp.FromJS + "|" + imp.Raw
		seenImports[key] = true
	}
	for _, imp := range src.Imports {
		key := imp.FromJS + "|" + imp.Raw
		if !seenImports[key] {
			seenImports[key] = true
			dst.Imports = append(dst.Imports, imp)
		}
	}

	// Merge routes (deduplicate by Route+FromJS)
	seenRoutes := make(map[string]bool)
	for _, r := range dst.Routes {
		key := r.FromJS + "|" + r.Route
		seenRoutes[key] = true
	}
	for _, r := range src.Routes {
		key := r.FromJS + "|" + r.Route
		if !seenRoutes[key] {
			seenRoutes[key] = true
			dst.Routes = append(dst.Routes, r)
		}
	}

	// Merge NewURLs (deduplicate by URL)
	seenURLs := make(map[string]bool)
	for _, u := range dst.NewURLs {
		seenURLs[u.URL] = true
	}
	for _, u := range src.NewURLs {
		if !seenURLs[u.URL] {
			seenURLs[u.URL] = true
			dst.NewURLs = append(dst.NewURLs, u)
		}
	}
}

// dedupImports deduplicates imports by FromJS+Raw
func dedupImports(imports []DynamicImport) []DynamicImport {
	seen := make(map[string]bool)
	var result []DynamicImport
	for _, imp := range imports {
		key := imp.FromJS + "|" + imp.Raw
		if !seen[key] {
			seen[key] = true
			result = append(result, imp)
		}
	}
	return result
}

// dedupRoutes deduplicates routes by FromJS+Route
func dedupRoutes(routes []RouteChunk) []RouteChunk {
	seen := make(map[string]bool)
	var result []RouteChunk
	for _, r := range routes {
		key := r.FromJS + "|" + r.Route
		if !seen[key] {
			seen[key] = true
			result = append(result, r)
		}
	}
	return result
}

// analyzeGeneric performs generic analysis (unknown framework)
func (a *Analyzer) analyzeGeneric(jsContent string, jsURL string, framework string) *AnalysisResult {
	// Try detection with various analyzers
	if a.vite.IsViteJS(jsContent, jsURL) {
		viteResult := a.vite.Analyze(jsContent, jsURL)
		viteResult.Framework = "vite"
		return viteResult
	}

	if a.webpack.IsWebpackJS(jsContent) {
		wpResult := a.webpack.Analyze(jsContent, jsURL)
		wpResult.Framework = "webpack"
		return wpResult
	}

	if a.next.IsNextJS(jsContent, jsURL) {
		nextResult := a.next.Analyze(jsContent, jsURL)
		nextResult.Framework = "next"
		return nextResult
	}

	if a.nuxt.IsNuxtJS(jsContent, jsURL) {
		nuxtResult := a.nuxt.Analyze(jsContent, jsURL)
		nuxtResult.Framework = "nuxt"
		return nuxtResult
	}

	if a.angular.IsAngular(jsContent, jsURL) {
		angularResult := a.angular.Analyze(jsContent, jsURL)
		angularResult.Framework = "angular"
		return angularResult
	}

	// Pure generic analysis
	return a.genericAnalysis(jsContent, jsURL)
}

// genericAnalysis performs pure generic analysis
func (a *Analyzer) genericAnalysis(jsContent string, jsURL string) *AnalysisResult {
	result := &AnalysisResult{
		Framework: "unknown",
	}

	// Extract dynamic imports
	imports := a.regex.ExtractDynamicImports(jsContent, jsURL, "")
	result.Imports = append(result.Imports, imports...)

	// Extract routes
	routes := a.regex.ExtractRoutePaths(jsContent, jsURL)
	result.Routes = append(result.Routes, routes...)

	// Extract JS paths
	paths := a.regex.ExtractJSPaths(jsContent, jsURL)
	for _, p := range paths {
		result.NewURLs = append(result.NewURLs, JSAsset{
			URL:        p,
			FromURL:    jsURL,
			Type:       TypeLazyChunkJS,
			Framework:  "unknown",
			Source:     SourceRegexCandidate,
			Confidence: ConfLow,
			Status:     StatusCandidate,
		})
	}

	// Build new URL list
	for _, imp := range imports {
		if imp.ResolvedURL != "" {
			result.NewURLs = append(result.NewURLs, JSAsset{
				URL:        imp.ResolvedURL,
				FromURL:    jsURL,
				Type:       TypeLazyChunkJS,
				Framework:  "unknown",
				Source:     imp.Source,
				Confidence: imp.Confidence,
				Status:     StatusCandidate,
			})
		}
	}

	return result
}

// supplementWithGeneric supplements framework analysis results with generic analysis
func (a *Analyzer) supplementWithGeneric(result *AnalysisResult, jsContent string, jsURL string, framework string) {
	// Extract additional JS paths
	extraPaths := a.regex.ExtractJSPaths(jsContent, jsURL)
	seenURLs := make(map[string]bool)
	for _, imp := range result.Imports {
		if imp.ResolvedURL != "" {
			seenURLs[imp.ResolvedURL] = true
		}
	}
	for _, u := range result.NewURLs {
		seenURLs[u.URL] = true
	}

	for _, p := range extraPaths {
		if !seenURLs[p] {
			seenURLs[p] = true
			result.NewURLs = append(result.NewURLs, JSAsset{
				URL:        p,
				FromURL:    jsURL,
				Type:       TypeLazyChunkJS,
				Framework:  framework,
				Source:     SourceRegexCandidate,
				Confidence: ConfLow,
				Status:     StatusCandidate,
			})
		}
	}
}
