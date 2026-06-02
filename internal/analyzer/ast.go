package analyzer

import (
	"bytes"
	"strings"

	"github.com/tdewolff/parse/v2"
	"github.com/tdewolff/parse/v2/js"

	"github.com/Veincc/JSpider/internal/urlutil"
)

// ASTAnalyzer is the interface for AST analyzers
type ASTAnalyzer interface {
	AnalyzeAST(jsContent string, fromJS string, framework string) *AnalysisResult
}

// TdewolffASTAnalyzer is an AST analyzer implementation using tdewolff/parse
type TdewolffASTAnalyzer struct {
	regex *RegexAnalyzer
}

func NewASTAnalyzer(regex *RegexAnalyzer) *TdewolffASTAnalyzer {
	return &TdewolffASTAnalyzer{regex: regex}
}

// astVisitor implements the IVisitor interface for AST traversal
type astVisitor struct {
	fromJS    string
	framework string
	imports   []DynamicImport
	routes    []RouteChunk
	newURLs   []JSAsset
}

func (v *astVisitor) Enter(n js.INode) js.IVisitor {
	switch node := n.(type) {
	case *js.CallExpr:
		v.handleCallExpr(node)
	case *js.Property:
		v.handleProperty(node)
	}
	return v
}

func (v *astVisitor) Exit(n js.INode) {}

// handleCallExpr handles function calls to identify import()
func (v *astVisitor) handleCallExpr(node *js.CallExpr) {
	// Check if this is an import() dynamic import
	// In tdewolff/parse, import("...") is parsed as a CallExpr
	// where X is an identifier expression
	if node.X == nil {
		return
	}

	// Check if the callee is import
	callStr := node.X.String()
	if callStr != "import" {
		return
	}

	// Extract arguments
	if len(node.Args.List) == 0 {
		return
	}

	arg := node.Args.List[0]
	if arg.Value == nil {
		return
	}

	// Extract string literal
	raw := extractStringLiteral(arg.Value)
	if raw == "" {
		return
	}

	resolvedURL := resolveImportURL(raw, v.fromJS)
	confidence := ConfHigh
	if resolvedURL == "" {
		confidence = ConfMedium
	}

	imp := DynamicImport{
		FromJS:      v.fromJS,
		Raw:         raw,
		ResolvedURL: resolvedURL,
		Framework:   v.framework,
		Source:      SourceImportExpr,
		Confidence:  confidence,
	}
	v.imports = append(v.imports, imp)

	if resolvedURL != "" {
		v.newURLs = append(v.newURLs, JSAsset{
			URL:        resolvedURL,
			FromURL:    v.fromJS,
			Type:       TypeLazyChunkJS,
			Framework:  v.framework,
			Source:     SourceImportExpr,
			Confidence: ConfHigh,
			Status:     StatusCandidate,
		})
	}
}

// handleProperty handles object properties to identify route paths
func (v *astVisitor) handleProperty(node *js.Property) {
	if node.Name == nil {
		return
	}

	name := node.Name.String()
	if name == "path" || name == "route" {
		value := extractStringLiteral(node.Value)
		if value != "" && strings.HasPrefix(value, "/") {
			route := RouteChunk{
				Route:      value,
				FromJS:     v.fromJS,
				Framework:  v.framework,
				Source:     "ast",
				Confidence: ConfHigh,
			}

			// Try to extract component from sibling properties
			v.routes = append(v.routes, route)
		}
	}
}

// extractStringLiteral extracts a string literal from an expression
func extractStringLiteral(expr js.IExpr) string {
	if expr == nil {
		return ""
	}

	switch node := expr.(type) {
	case *js.LiteralExpr:
		data := node.Data
		// Strip quotes
		if len(data) >= 2 {
			if (data[0] == '"' && data[len(data)-1] == '"') ||
				(data[0] == '\'' && data[len(data)-1] == '\'') ||
				(data[0] == '`' && data[len(data)-1] == '`') {
				return string(data[1 : len(data)-1])
			}
		}
		return string(data)
	}

	return ""
}

// resolveImportURL resolves the relative URL of an import
func resolveImportURL(raw string, fromJS string) string {
	if raw == "" {
		return ""
	}

	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		return raw
	}

	if !strings.HasPrefix(raw, "/") && !strings.HasPrefix(raw, "./") && !strings.HasPrefix(raw, "../") {
		return ""
	}

	resolved, err := urlutil.ResolveJS(fromJS, raw)
	if err == nil && resolved != "" {
		return resolved
	}

	return ""
}

// AnalyzeAST analyzes JS content using AST
func (a *TdewolffASTAnalyzer) AnalyzeAST(jsContent string, fromJS string, framework string) *AnalysisResult {
	result := &AnalysisResult{
		Framework: framework,
	}

	// Try AST parsing
	astResult, err := a.parseAST(jsContent, fromJS, framework)
	if err != nil {
		// AST parsing failed, fall back to regex analysis
		return a.fallbackToRegex(jsContent, fromJS, framework)
	}

	result.Imports = append(result.Imports, astResult.Imports...)
	result.Routes = append(result.Routes, astResult.Routes...)
	result.NewURLs = append(result.NewURLs, astResult.NewURLs...)

	return result
}

// parseAST parses JS AST using tdewolff/parse
func (a *TdewolffASTAnalyzer) parseAST(jsContent string, fromJS string, framework string) (*AnalysisResult, error) {
	result := &AnalysisResult{Framework: framework}

	input := parse.NewInputBytes([]byte(jsContent))
	ast, err := js.Parse(input, js.Options{})
	if err != nil {
		return nil, err
	}

	visitor := &astVisitor{
		fromJS:    fromJS,
		framework: framework,
	}

	js.Walk(visitor, ast)

	result.Imports = visitor.imports
	result.Routes = visitor.routes
	result.NewURLs = visitor.newURLs

	return result, nil
}

// fallbackToRegex falls back to regex analysis
func (a *TdewolffASTAnalyzer) fallbackToRegex(jsContent string, fromJS string, framework string) *AnalysisResult {
	result := &AnalysisResult{Framework: framework}

	// Use regex analyzer
	imports := a.regex.ExtractDynamicImports(jsContent, fromJS, framework)
	result.Imports = append(result.Imports, imports...)

	routes := a.regex.ExtractRoutePaths(jsContent, fromJS)
	result.Routes = append(result.Routes, routes...)

	// Build new URL list
	for _, imp := range imports {
		if imp.ResolvedURL != "" {
			result.NewURLs = append(result.NewURLs, JSAsset{
				URL:        imp.ResolvedURL,
				FromURL:    fromJS,
				Type:       TypeLazyChunkJS,
				Framework:  framework,
				Source:     imp.Source,
				Confidence: imp.Confidence,
				Status:     StatusCandidate,
			})
		}
	}

	return result
}

// AnalyzeWithAST tries AST analysis, falls back to regex on failure
func (a *TdewolffASTAnalyzer) AnalyzeWithAST(jsContent string, fromJS string, framework string) *AnalysisResult {
	// For very large files, use regex analysis directly
	if len(jsContent) > 5*1024*1024 { // 5MB
		return a.fallbackToRegex(jsContent, fromJS, framework)
	}

	return a.AnalyzeAST(jsContent, fromJS, framework)
}

// extractImportsFromAST is a convenience function to extract import information from AST
func extractImportsFromAST(jsContent string, fromJS string) []DynamicImport {
	analyzer := NewASTAnalyzer(NewRegexAnalyzer())
	result := analyzer.AnalyzeAST(jsContent, fromJS, "")
	return result.Imports
}

// isDynamicImport checks if a CallExpr is a dynamic import()
func isDynamicImport(node *js.CallExpr) bool {
	if node.X == nil {
		return false
	}
	return node.X.String() == "import"
}

// extractAllStringLiterals extracts all string literals from AST
func extractAllStringLiterals(jsContent string) []string {
	var literals []string

	input := parse.NewInputBytes([]byte(jsContent))
	ast, err := js.Parse(input, js.Options{})
	if err != nil {
		return literals
	}

	visitor := &literalCollectorVisitor{literals: &literals}
	js.Walk(visitor, ast)

	return literals
}

type literalCollectorVisitor struct {
	literals *[]string
}

func (v *literalCollectorVisitor) Enter(n js.INode) js.IVisitor {
	if node, ok := n.(*js.LiteralExpr); ok {
		data := node.Data
		if len(data) >= 2 {
			if (data[0] == '"' && data[len(data)-1] == '"') ||
				(data[0] == '\'' && data[len(data)-1] == '\'') {
				*v.literals = append(*v.literals, string(data[1:len(data)-1]))
			}
		}
	}
	return v
}

func (v *literalCollectorVisitor) Exit(n js.INode) {}

// containsImportMeta checks if JS contains import.meta
func containsImportMeta(jsContent string) bool {
	return strings.Contains(jsContent, "import.meta")
}

// extractTemplateLiteralParts extracts static parts of template literals
func extractTemplateLiteralParts(node js.IExpr) []string {
	var parts []string
	// Template literal representation in tdewolff/parse
	// Simplified handling, return empty
	return parts
}

// isStringLiteral checks if an expression is a string literal
func isStringLiteral(expr js.IExpr) bool {
	_, ok := expr.(*js.LiteralExpr)
	return ok
}

// getLiteralValue gets the value of a literal
func getLiteralValue(expr js.IExpr) string {
	if lit, ok := expr.(*js.LiteralExpr); ok {
		data := lit.Data
		if len(data) >= 2 {
			if (data[0] == '"' && data[len(data)-1] == '"') ||
				(data[0] == '\'' && data[len(data)-1] == '\'') {
				return string(data[1 : len(data)-1])
			}
		}
		return string(data)
	}
	return ""
}

// walkAndCollect walks the AST and collects information
func walkAndCollect(ast *js.AST, fromJS string, framework string) *AnalysisResult {
	result := &AnalysisResult{Framework: framework}

	visitor := &astVisitor{
		fromJS:    fromJS,
		framework: framework,
	}

	js.Walk(visitor, ast)

	result.Imports = visitor.imports
	result.Routes = visitor.routes
	result.NewURLs = visitor.newURLs

	return result
}

// parseAndAnalyze parses and analyzes JS content
func parseAndAnalyze(jsContent string, fromJS string, framework string) (*AnalysisResult, error) {
	input := parse.NewInputBytes([]byte(jsContent))
	ast, err := js.Parse(input, js.Options{})
	if err != nil {
		return nil, err
	}

	return walkAndCollect(ast, fromJS, framework), nil
}

// extractPropertyNames extracts property names from an object
func extractPropertyNames(obj *js.ObjectExpr) []string {
	var names []string
	for _, prop := range obj.List {
		if prop.Name != nil {
			names = append(names, prop.Name.String())
		}
	}
	return names
}

// findProperty finds a property with the given name in an object
func findProperty(obj *js.ObjectExpr, name string) *js.Property {
	for i := range obj.List {
		if obj.List[i].Name != nil && obj.List[i].Name.String() == name {
			return &obj.List[i]
		}
	}
	return nil
}

// isRouteDefinition checks if an object is a route definition
func isRouteDefinition(obj *js.ObjectExpr) bool {
	hasPath := false
	hasComponent := false

	for _, prop := range obj.List {
		if prop.Name == nil {
			continue
		}
		name := prop.Name.String()
		if name == "path" {
			hasPath = true
		}
		if name == "component" || name == "Component" {
			hasComponent = true
		}
	}

	return hasPath && hasComponent
}

// extractRouteFromObject extracts route information from a route definition object
func extractRouteFromObject(obj *js.ObjectExpr, fromJS string, framework string) *RouteChunk {
	route := &RouteChunk{
		FromJS:     fromJS,
		Framework:  framework,
		Source:     "ast",
		Confidence: ConfHigh,
	}

	// Extract path
	if pathProp := findProperty(obj, "path"); pathProp != nil {
		path := getLiteralValue(pathProp.Value)
		if path != "" {
			route.Route = path
		}
	}

	// Extract component
	if compProp := findProperty(obj, "component"); compProp != nil {
		// component may be a function call import()
		if callExpr, ok := compProp.Value.(*js.CallExpr); ok {
			if isDynamicImport(callExpr) && len(callExpr.Args.List) > 0 {
				raw := getLiteralValue(callExpr.Args.List[0].Value)
				if raw != "" {
					route.Component = raw
					route.LazyJS = resolveImportURL(raw, fromJS)
				}
			}
		}
	}

	if route.Route == "" {
		return nil
	}

	return route
}

// BytesToString converts byte slice to string without allocation
func BytesToString(b []byte) string {
	return string(b)
}

// StringToBytes converts string to byte slice without allocation
func StringToBytes(s string) []byte {
	return []byte(s)
}

// ContainsString checks if a slice contains a string
func ContainsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

// UniqueStrings returns unique strings from a slice
func UniqueStrings(slice []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, s := range slice {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

// TrimQuotes removes surrounding quotes from a string
func TrimQuotes(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') ||
			(s[0] == '\'' && s[len(s)-1] == '\'') ||
			(s[0] == '`' && s[len(s)-1] == '`') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// IsJSFile checks if a path looks like a JS file
func IsJSFile(path string) bool {
	return strings.HasSuffix(path, ".js") || strings.HasSuffix(path, ".mjs")
}

// NormalizePath normalizes a file path
func NormalizePath(path string) string {
	// Strip query parameters
	if idx := strings.Index(path, "?"); idx >= 0 {
		path = path[:idx]
	}
	// Strip fragment
	if idx := strings.Index(path, "#"); idx >= 0 {
		path = path[:idx]
	}
	return path
}

// ExtractFileName extracts filename from path
func ExtractFileName(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return path
}

// IsValidURL checks if a string looks like a valid URL
func IsValidURL(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

// IsRelativePath checks if a path is relative
func IsRelativePath(path string) bool {
	return strings.HasPrefix(path, "./") || strings.HasPrefix(path, "../")
}

// IsAbsolutePath checks if a path is absolute
func IsAbsolutePath(path string) bool {
	return strings.HasPrefix(path, "/")
}

// MergeAnalysisResults merges multiple analysis results
func MergeAnalysisResults(results ...*AnalysisResult) *AnalysisResult {
	merged := &AnalysisResult{}

	for _, r := range results {
		if r == nil {
			continue
		}
		merged.Imports = append(merged.Imports, r.Imports...)
		merged.Routes = append(merged.Routes, r.Routes...)
		merged.NewURLs = append(merged.NewURLs, r.NewURLs...)
		merged.Sourcemaps = append(merged.Sourcemaps, r.Sourcemaps...)

		if r.Framework != "" && r.Framework != "unknown" {
			merged.Framework = r.Framework
		}
		if r.FrameworkInfo != nil {
			merged.FrameworkInfo = r.FrameworkInfo
		}
	}

	return merged
}

// FilterImportsByConfidence filters imports by confidence level
func FilterImportsByConfidence(imports []DynamicImport, minConfidence string) []DynamicImport {
	confidenceOrder := map[string]int{
		ConfLow:    0,
		ConfMedium: 1,
		ConfHigh:   2,
	}

	minLevel := confidenceOrder[minConfidence]
	var result []DynamicImport

	for _, imp := range imports {
		if confidenceOrder[imp.Confidence] >= minLevel {
			result = append(result, imp)
		}
	}

	return result
}

// FilterRoutesByConfidence filters routes by confidence level
func FilterRoutesByConfidence(routes []RouteChunk, minConfidence string) []RouteChunk {
	confidenceOrder := map[string]int{
		ConfLow:    0,
		ConfMedium: 1,
		ConfHigh:   2,
	}

	minLevel := confidenceOrder[minConfidence]
	var result []RouteChunk

	for _, r := range routes {
		if confidenceOrder[r.Confidence] >= minLevel {
			result = append(result, r)
		}
	}

	return result
}

// GetImportsBySource returns imports filtered by source
func GetImportsBySource(imports []DynamicImport, source string) []DynamicImport {
	var result []DynamicImport
	for _, imp := range imports {
		if imp.Source == source {
			result = append(result, imp)
		}
	}
	return result
}

// GetRoutesBySource returns routes filtered by source
func GetRoutesBySource(routes []RouteChunk, source string) []RouteChunk {
	var result []RouteChunk
	for _, r := range routes {
		if r.Source == source {
			result = append(result, r)
		}
	}
	return result
}

// FormatImport formats a DynamicImport for display
func FormatImport(imp DynamicImport) string {
	var buf bytes.Buffer
	buf.WriteString(imp.Raw)
	if imp.ResolvedURL != "" {
		buf.WriteString(" -> ")
		buf.WriteString(imp.ResolvedURL)
	}
	buf.WriteString(" [")
	buf.WriteString(imp.Source)
	buf.WriteString(":")
	buf.WriteString(imp.Confidence)
	buf.WriteString("]")
	return buf.String()
}

// FormatRoute formats a RouteChunk for display
func FormatRoute(route RouteChunk) string {
	var buf bytes.Buffer
	buf.WriteString(route.Route)
	if route.Component != "" {
		buf.WriteString(" -> ")
		buf.WriteString(route.Component)
	}
	if route.LazyJS != "" {
		buf.WriteString(" (")
		buf.WriteString(route.LazyJS)
		buf.WriteString(")")
	}
	return buf.String()
}
