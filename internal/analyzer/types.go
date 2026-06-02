package analyzer

// JSAsset represents a JS resource
type JSAsset struct {
	URL         string   `json:"url"`
	FromURL     string   `json:"from_url,omitempty"`
	Type        string   `json:"type"`
	Framework   string   `json:"framework,omitempty"`
	Source      string   `json:"source"`
	Confidence  string   `json:"confidence"`
	Status      string   `json:"status"`
	Depth       int      `json:"depth"`
	ContentType string   `json:"content_type,omitempty"`
	Size        int64    `json:"size,omitempty"`
	Hash        string   `json:"hash,omitempty"`
	Reasons     []string `json:"reasons,omitempty"`
}

// DynamicImport represents a dynamic import()
type DynamicImport struct {
	FromJS      string   `json:"from_js"`
	Raw         string   `json:"raw"`
	ResolvedURL string   `json:"resolved_url,omitempty"`
	Framework   string   `json:"framework,omitempty"`
	Source      string   `json:"source"`
	Confidence  string   `json:"confidence"`
	Component   string   `json:"component,omitempty"`
	Route       string   `json:"route,omitempty"`
	Deps        []string `json:"deps,omitempty"`
}

// RouteChunk represents a route-to-chunk mapping
type RouteChunk struct {
	Route      string   `json:"route"`
	Component  string   `json:"component,omitempty"`
	LazyJS     string   `json:"lazy_js,omitempty"`
	Deps       []string `json:"deps,omitempty"`
	FromJS     string   `json:"from_js"`
	Framework  string   `json:"framework,omitempty"`
	Source     string   `json:"source"`
	Confidence string   `json:"confidence"`
}

// SourceMapInfo represents source map information
type SourceMapInfo struct {
	FromJS            string   `json:"from_js"`
	MapURL            string   `json:"map_url"`
	Status            string   `json:"status"`
	HasSourcesContent bool     `json:"has_sources_content"`
	SourceCount       int      `json:"source_count"`
	Sources           []string `json:"sources,omitempty"`
}

// FrameworkDetect represents a framework detection result
type FrameworkDetect struct {
	URL       string   `json:"url"`
	Framework string   `json:"framework"`
	Score     int      `json:"score"`
	Reasons   []string `json:"reasons"`
}

// AnalysisResult represents the analysis result of a single JS file
type AnalysisResult struct {
	Imports       []DynamicImport
	Routes        []RouteChunk
	Sourcemaps    []SourceMapInfo
	NewURLs       []JSAsset
	Framework     string
	FrameworkInfo *FrameworkDetect
}

const (
	// JS types
	TypeEntryJS     = "entry_js"
	TypeRuntimeJS   = "runtime_js"
	TypeVendorJS    = "vendor_js"
	TypeRouteJS     = "route_js"
	TypeLazyChunkJS = "lazy_chunk_js"
	TypeUnknownJS   = "unknown_js"

	// Sources
	SourceHTMLScript    = "html_script"
	SourceModulepreload = "modulepreload"
	SourcePreload       = "preload"
	SourcePrefetch      = "prefetch"
	SourceImportExpr    = "import_expression"
	SourceViteMapDeps   = "vite_map_deps"
	SourceViteImport    = "vite_import"
	SourceWebpackRuntime = "webpack_runtime"
	SourceNextManifest  = "next_manifest"
	SourceNuxtStatic    = "nuxt_static"
	SourceSourcemap     = "sourcemap"
	SourceRegexCandidate  = "regex_candidate"
	SourceInlineScript    = "inline_script"
	SourceHeadlessNetwork = "headless_network"
	SourceHeadlessDOM     = "headless_dom"
	SourceHeadlessResponse = "headless_response"

	// Confidence levels
	ConfHigh   = "high"
	ConfMedium = "medium"
	ConfLow    = "low"

	// Statuses
	StatusConfirmed = "confirmed"
	StatusCandidate = "candidate"
	StatusFailed    = "failed"
)
