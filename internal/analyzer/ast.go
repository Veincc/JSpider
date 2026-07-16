package analyzer

import (
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
	fromJS     string
	framework  string
	imports    []DynamicImport
	routes     []RouteChunk
	newURLs    []JSAsset
	seenImport map[string]struct{}
	seenRoute  map[string]struct{}
}

func (v *astVisitor) Enter(n js.INode) js.IVisitor {
	switch node := n.(type) {
	case *js.CallExpr:
		v.handleCallExpr(node)
	case *js.ImportStmt:
		v.handleModuleSpecifier(node.Module)
	case *js.ExportStmt:
		v.handleModuleSpecifier(node.Module)
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

	v.addImport(raw)
}

func (v *astVisitor) handleModuleSpecifier(module []byte) {
	if len(module) < 2 {
		return
	}
	quote := module[0]
	if (quote != '\'' && quote != '"') || module[len(module)-1] != quote {
		return
	}
	v.addImport(string(module[1 : len(module)-1]))
}

func (v *astVisitor) addImport(raw string) {
	if raw == "" {
		return
	}
	key := v.fromJS + "|" + raw
	if _, exists := v.seenImport[key]; exists {
		return
	}
	v.seenImport[key] = struct{}{}

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
			key := v.fromJS + "|" + value
			if _, exists := v.seenRoute[key]; exists {
				return
			}
			v.seenRoute[key] = struct{}{}
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

	input := parse.NewInputString(jsContent)
	ast, err := js.Parse(input, js.Options{})
	if err != nil {
		return nil, err
	}

	visitor := &astVisitor{
		fromJS:     fromJS,
		framework:  framework,
		seenImport: make(map[string]struct{}),
		seenRoute:  make(map[string]struct{}),
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
	imports = append(imports, a.regex.ExtractStaticImports(jsContent, fromJS, framework)...)
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
