package analyzer

import (
	"sort"
	"strings"
)

// frameworkPriority defines framework priority (deterministic tie-break when scores are equal)
// Lower priority value means higher precedence; frameworks listed earlier are more specific and should be preferred
var frameworkPriority = map[string]int{
	"angular": 1,
	"next":    2,
	"nuxt":    3,
	"vite":    4,
	"webpack": 5,
	"vue-cli": 6,
}

// minScoreThreshold is the minimum score threshold; returns nil (no framework detected) if below this score
const minScoreThreshold = 2

// FrameworkDetector is a framework detector
type FrameworkDetector struct{}

func NewFrameworkDetector() *FrameworkDetector {
	return &FrameworkDetector{}
}

// Detect identifies the framework type of JS content
func (fd *FrameworkDetector) Detect(jsContent string, jsURL string) *FrameworkDetect {
	scores := map[string]int{
		"vite":    0,
		"webpack": 0,
		"next":    0,
		"nuxt":    0,
		"angular": 0,
		"vue-cli": 0,
	}
	reasons := map[string][]string{
		"vite":    {},
		"webpack": {},
		"next":    {},
		"nuxt":    {},
		"angular": {},
		"vue-cli": {},
	}

	// Vite signatures
	viteChecks := []struct {
		pattern string
		score   int
		reason  string
	}{
		{"import.meta.url", 3, "import.meta.url"},
		{"__vite__mapDeps", 5, "__vite__mapDeps"},
		{"__vitePreload", 5, "__vitePreload"},
		{"/assets/index-", 2, "/assets/index- path pattern"},
		{`type="module"`, 1, "type=module"},
		{"import.meta.hot", 3, "import.meta.hot (HMR)"},
		{"__vite_ssr_import__", 4, "__vite_ssr_import__"},
	}
	for _, vc := range viteChecks {
		if strings.Contains(jsContent, vc.pattern) {
			scores["vite"] += vc.score
			reasons["vite"] = append(reasons["vite"], vc.reason)
		}
	}

	// Webpack signatures
	webpackChecks := []struct {
		pattern string
		score   int
		reason  string
	}{
		{"__webpack_require__", 5, "__webpack_require__"},
		{"__webpack_require__.e", 4, "__webpack_require__.e (chunk loading)"},
		{"__webpack_require__.u", 4, "__webpack_require__.u (chunk URL)"},
		{"__webpack_require__.p", 3, "__webpack_require__.p (publicPath)"},
		{"self.webpackChunk", 4, "self.webpackChunk"},
		{"webpackJsonp", 4, "webpackJsonp"},
		{"chunkFilename", 2, "chunkFilename"},
	}
	for _, wc := range webpackChecks {
		if strings.Contains(jsContent, wc.pattern) {
			scores["webpack"] += wc.score
			reasons["webpack"] = append(reasons["webpack"], wc.reason)
		}
	}

	// Next.js signatures
	nextChecks := []struct {
		pattern string
		score   int
		reason  string
	}{
		{"/_next/static/chunks/", 4, "/_next/static/chunks/"},
		{"self.__BUILD_MANIFEST", 5, "self.__BUILD_MANIFEST"},
		{"_buildManifest.js", 4, "_buildManifest.js"},
		{"_ssgManifest.js", 4, "_ssgManifest.js"},
		{"app-build-manifest", 3, "app-build-manifest"},
		{"__NEXT_DATA__", 5, "__NEXT_DATA__"},
		{"/_next/", 2, "/_next/ path"},
	}
	for _, nc := range nextChecks {
		if strings.Contains(jsContent, nc.pattern) {
			scores["next"] += nc.score
			reasons["next"] = append(reasons["next"], nc.reason)
		}
	}

	// Nuxt signatures
	nuxtChecks := []struct {
		pattern string
		score   int
		reason  string
	}{
		{"/_nuxt/", 4, "/_nuxt/ path"},
		{"window.__NUXT__", 5, "window.__NUXT__"},
		{"__NUXT_DATA__", 5, "__NUXT_DATA__"},
		{"payload.js", 2, "payload.js"},
		{"nuxt_plugin", 3, "nuxt_plugin"},
		{"nuxtLink", 2, "nuxtLink"},
	}
	for _, nc := range nuxtChecks {
		if strings.Contains(jsContent, nc.pattern) {
			scores["nuxt"] += nc.score
			reasons["nuxt"] = append(reasons["nuxt"], nc.reason)
		}
	}

	// Angular signatures
	angularChecks := []struct {
		pattern string
		score   int
		reason  string
	}{
		{"ng-version", 4, "ng-version"},
		{"runtime.", 1, "runtime.*.js pattern"},
		{"polyfills.", 2, "polyfills.*.js pattern"},
		{"main.", 1, "main.*.js pattern"},
		{"@angular/core", 5, "@angular/core"},
		{"@angular/router", 5, "@angular/router"},
		{"loadChildren", 4, "loadChildren (lazy loading)"},
		{"ɵɵdefineInjectable", 3, "Angular DI marker"},
	}
	for _, ac := range angularChecks {
		if strings.Contains(jsContent, ac.pattern) {
			scores["angular"] += ac.score
			reasons["angular"] = append(reasons["angular"], ac.reason)
		}
	}

	// Vue CLI signatures
	vueCLIChecks := []struct {
		pattern string
		score   int
		reason  string
	}{
		{"/js/app.", 3, "/js/app. path pattern"},
		{"/js/chunk-vendors.", 4, "/js/chunk-vendors. path pattern"},
		{"__webpack_require__", 2, "__webpack_require__ (shared with webpack)"},
		{"webpackChunk", 2, "webpackChunk (shared with webpack)"},
		{"vue-router", 3, "vue-router"},
		{"vue.runtime", 3, "vue.runtime"},
	}
	for _, vc := range vueCLIChecks {
		if strings.Contains(jsContent, vc.pattern) {
			scores["vue-cli"] += vc.score
			reasons["vue-cli"] = append(reasons["vue-cli"], vc.reason)
		}
	}

	// URL path heuristics
	urlChecks := []struct {
		pattern string
		fw      string
		score   int
		reason  string
	}{
		{"/_next/", "next", 3, "URL contains /_next/"},
		{"/_nuxt/", "nuxt", 3, "URL contains /_nuxt/"},
		{"/assets/", "vite", 1, "URL contains /assets/ (vite default)"},
	}
	for _, uc := range urlChecks {
		if strings.Contains(jsURL, uc.pattern) {
			scores[uc.fw] += uc.score
			reasons[uc.fw] = append(reasons[uc.fw], uc.reason)
		}
	}

	// Collect all frameworks and sort
	type fwScore struct {
		fw    string
		score int
	}
	var candidates []fwScore
	for fw, score := range scores {
		if score > 0 {
			candidates = append(candidates, fwScore{fw, score})
		}
	}

	if len(candidates) == 0 {
		return nil
	}

	// Sort by score descending, break ties by priority
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].score != candidates[j].score {
			return candidates[i].score > candidates[j].score
		}
		pi := frameworkPriority[candidates[i].fw]
		pj := frameworkPriority[candidates[j].fw]
		return pi < pj
	})

	best := candidates[0]

	// Minimum threshold check
	if best.score < minScoreThreshold {
		return nil
	}

	return &FrameworkDetect{
		URL:       jsURL,
		Framework: best.fw,
		Score:     best.score,
		Reasons:   reasons[best.fw],
	}
}
