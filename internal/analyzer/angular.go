package analyzer

import (
	"regexp"
	"strings"

	"github.com/Veincc/JSpider/internal/urlutil"
)

var (
	loadChildrenRe = regexp.MustCompile(`loadChildren\s*:\s*(?:\(\)\s*=>|function\s*\(\s*\)\s*\{?\s*return\s*)import\s*\(\s*["']([^"']+)["']`)
)

// AngularAnalyzer is an Angular-specific analyzer
type AngularAnalyzer struct {
	regex *RegexAnalyzer
	wp    *WebpackAnalyzer
}

func NewAngularAnalyzer(regex *RegexAnalyzer, wp *WebpackAnalyzer) *AngularAnalyzer {
	return &AngularAnalyzer{regex: regex, wp: wp}
}

// Analyze analyzes JS built by Angular
func (a *AngularAnalyzer) Analyze(jsContent string, fromJS string) *AnalysisResult {
	result := &AnalysisResult{
		Framework: "angular",
	}

	// Angular typically relies on webpack runtime, reuse webpack analysis
	if a.wp.IsWebpackJS(jsContent) {
		wpResult := a.wp.Analyze(jsContent, fromJS)
		wpResult.Framework = "angular"
		result.Imports = append(result.Imports, wpResult.Imports...)
		result.Routes = append(result.Routes, wpResult.Routes...)
		result.NewURLs = append(result.NewURLs, wpResult.NewURLs...)
	}

	// Extract Angular-specific lazy loading information
	routes := a.extractLazyRoutes(jsContent, fromJS)
	result.Routes = append(result.Routes, routes...)

	// Extract generic dynamic imports
	directImports := a.regex.ExtractDynamicImports(jsContent, fromJS, "angular")
	result.Imports = append(result.Imports, directImports...)

	// Classify runtime/main/polyfills
	a.classifyAssets(result, fromJS)

	// Extract sourceMappingURL
	if mapURL := a.regex.ExtractSourceMappingURL(jsContent, fromJS); mapURL != "" {
		result.Sourcemaps = append(result.Sourcemaps, SourceMapInfo{
			FromJS: fromJS,
			MapURL: mapURL,
			Status: "found",
		})
	}

	return result
}

// extractLazyRoutes extracts Angular lazy-loaded routes
func (a *AngularAnalyzer) extractLazyRoutes(jsContent string, fromJS string) []RouteChunk {
	var routes []RouteChunk

	for _, m := range loadChildrenRe.FindAllStringSubmatch(jsContent, -1) {
		importPath := m[1]

		resolvedURL, err := urlutil.ResolveJS(fromJS, importPath)
		if err != nil {
			resolvedURL = importPath
		}

		routes = append(routes, RouteChunk{
			LazyJS:     resolvedURL,
			FromJS:     fromJS,
			Framework:  "angular",
			Source:     SourceRegexCandidate,
			Confidence: ConfMedium,
		})
	}

	return routes
}

// classifyAssets classifies Angular assets
func (a *AngularAnalyzer) classifyAssets(result *AnalysisResult, fromJS string) {
	for i := range result.NewURLs {
		url := strings.ToLower(result.NewURLs[i].URL)
		if strings.Contains(url, "runtime") {
			result.NewURLs[i].Type = TypeRuntimeJS
		} else if strings.Contains(url, "polyfills") {
			result.NewURLs[i].Type = TypeVendorJS
		} else if strings.Contains(url, "main") {
			result.NewURLs[i].Type = TypeEntryJS
		}
	}
	_ = fromJS
}

// IsAngular checks whether the JS was built by Angular
func (a *AngularAnalyzer) IsAngular(jsContent string, jsURL string) bool {
	indicators := []string{
		"ng-version",
		"@angular/core",
		"@angular/router",
		"loadChildren",
		"ɵɵdefineInjectable",
	}
	for _, ind := range indicators {
		if strings.Contains(jsContent, ind) {
			return true
		}
	}

	angularURLPatterns := []string{
		"runtime.",
		"polyfills.",
		"main.",
	}
	matchCount := 0
	for _, p := range angularURLPatterns {
		if strings.Contains(jsURL, p) {
			matchCount++
		}
	}
	return matchCount >= 2
}
