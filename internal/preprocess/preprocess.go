package preprocess

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Veincc/JSpider/internal/fileutil"
	"github.com/Veincc/JSpider/internal/urlutil"
	parsepkg "github.com/tdewolff/parse/v2"
	jslexer "github.com/tdewolff/parse/v2/js"
)

//go:embed audit-prep.cjs
var workerBundle []byte

const NodeRuntimeError = "JSpider requires Node.js runtime"
const NodeVersionError = "JSpider requires Node.js 18 or newer"

const workerStartupTimeout = 5 * time.Second

var sourceMapDirective = regexp.MustCompile(`//[#@]\s*sourceMappingURL\s*=\s*(\S+)|(?s:/\*[#@]\s*sourceMappingURL\s*=\s*(.*?)\s*\*/)`)

var sourceMapWorkSlots = make(chan struct{}, 4)

type FetchFunc func(ctx context.Context, entryURL, rawURL string) ([]byte, error)

type Processor struct {
	outputDir string
	tempDir   string
	fetch     FetchFunc
	outputMu  sync.Mutex
	actor     *workerActor

	processTimeout time.Duration

	stateMu     sync.Mutex
	closed      bool
	contentRefs map[string]string
	pathHashes  map[string]string
}

type FileResult struct {
	Analysis            []AnalysisUnit
	Status              string
	Outputs             []string
	Failed              bool
	FallbackWriteFailed bool
	Error               string
}

type AnalysisUnit struct {
	SourceName string
	BaseURL    string
	Body       []byte
}

type workerRequest struct {
	ID      int    `json:"id"`
	Source  string `json:"source"`
	Command string `json:"command,omitempty"`
}

type workerResponse struct {
	ID          int    `json:"id"`
	OK          bool   `json:"ok"`
	Error       string `json:"error,omitempty"`
	Code        string `json:"code,omitempty"`
	NodeVersion string `json:"node_version,omitempty"`

	idPresent          bool `json:"-"`
	okPresent          bool `json:"-"`
	codePresent        bool `json:"-"`
	nodeVersionPresent bool `json:"-"`
}

func (r *workerResponse) UnmarshalJSON(data []byte) error {
	var wire struct {
		ID          *int    `json:"id"`
		OK          *bool   `json:"ok"`
		Error       *string `json:"error"`
		Code        *string `json:"code"`
		NodeVersion *string `json:"node_version"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	if wire.ID != nil {
		r.ID = *wire.ID
		r.idPresent = true
	}
	if wire.OK != nil {
		r.OK = *wire.OK
		r.okPresent = true
	}
	if wire.Error != nil {
		r.Error = *wire.Error
	}
	if wire.Code != nil {
		r.Code = *wire.Code
		r.codePresent = true
	}
	if wire.NodeVersion != nil {
		r.NodeVersion = *wire.NodeVersion
		r.nodeVersionPresent = true
	}
	return nil
}

type sourceFile struct {
	Name       string
	OutputPath string
	Content    string
	HasContent bool
}

type sourceMapRecovery struct {
	Files       []sourceFile
	Complete    bool
	SourceCount int
	ContentSize int64
}

type sourceMapCollection struct {
	Files    []sourceFile
	Complete bool
}

type sourceMapOffset struct {
	Line   int
	Column int
}

type sourceMapResolver struct {
	p        *Processor
	entryURL string
	ctx      context.Context
}

func CheckNodeRuntime() error {
	return checkNodeRuntime(workerStartupTimeout)
}

func checkNodeRuntime(timeout time.Duration) error {
	nodePath, err := exec.LookPath("node")
	if err != nil {
		return errors.New(NodeRuntimeError)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	output, err := exec.CommandContext(ctx, nodePath, "--version").Output()
	if err != nil {
		return errors.New(NodeRuntimeError)
	}
	version := strings.TrimPrefix(strings.TrimSpace(string(output)), "v")
	majorText, _, _ := strings.Cut(version, ".")
	major, err := strconv.Atoi(majorText)
	if err != nil || major < 18 {
		return errors.New(NodeVersionError)
	}
	return nil
}

func New(siteDir string, fetch FetchFunc) (*Processor, error) {
	return NewWithTimeout(siteDir, fetch, 30*time.Second)
}

func NewWithTimeout(siteDir string, fetch FetchFunc, processTimeout time.Duration) (*Processor, error) {
	return newProcessor(siteDir, fetch, processTimeout, workerStartupTimeout)
}

func newProcessor(siteDir string, fetch FetchFunc, processTimeout, startupTimeout time.Duration) (*Processor, error) {
	if processTimeout <= 0 {
		return nil, errors.New("JavaScript processing timeout must be greater than zero")
	}
	if startupTimeout <= 0 {
		return nil, errors.New("audit-prep startup timeout must be greater than zero")
	}
	nodePath, err := exec.LookPath("node")
	if err != nil {
		return nil, errors.New(NodeRuntimeError)
	}

	outputDir := filepath.Join(siteDir, "js")
	if err := os.RemoveAll(outputDir); err != nil {
		return nil, fmt.Errorf("reset JavaScript output directory: %w", err)
	}
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, fmt.Errorf("create JavaScript output directory: %w", err)
	}

	tempDir, err := os.MkdirTemp("", "jspider-audit-prep-*")
	if err != nil {
		return nil, fmt.Errorf("create audit-prep runtime directory: %w", err)
	}
	helper := filepath.Join(tempDir, "audit-prep.cjs")
	if err := os.WriteFile(helper, workerBundle, 0700); err != nil {
		_ = os.RemoveAll(tempDir)
		return nil, fmt.Errorf("write audit-prep worker: %w", err)
	}

	p := &Processor{
		outputDir:      outputDir,
		tempDir:        tempDir,
		fetch:          fetch,
		processTimeout: processTimeout,
		contentRefs:    make(map[string]string),
		pathHashes:     make(map[string]string),
	}
	p.actor = newWorkerActor(nodePath, helper, processTimeout, startupTimeout)
	if err := p.actor.warmup(); err != nil {
		_ = p.actor.close()
		_ = os.RemoveAll(tempDir)
		return nil, err
	}
	return p, nil
}

func (p *Processor) Process(entryURL, jsURL string, body []byte) FileResult {
	return p.ProcessContext(context.Background(), entryURL, jsURL, body)
}

func (p *Processor) ProcessContext(parent context.Context, entryURL, jsURL string, body []byte) FileResult {
	p.stateMu.Lock()
	closed := p.closed
	p.stateMu.Unlock()
	if closed {
		return p.recordFailure(jsURL, body, "audit-prep processor is closed")
	}
	parent = processingContext(parent)
	ctx, cancel := context.WithTimeout(parent, p.processTimeout)
	defer cancel()

	result := FileResult{Analysis: originalAnalysis(jsURL, body), Outputs: make([]string, 0)}
	recovery, recoveryErr := p.recoverForBundle(ctx, entryURL, jsURL, body)
	if recoveryErr != nil {
		return p.recordFailure(jsURL, body, recoveryErr.Error())
	}
	if len(recovery.Files) > 0 {
		outputs := make([]string, 0, len(recovery.Files))
		for _, source := range recovery.Files {
			if err := ctx.Err(); err != nil {
				return p.recordFailureWithOutputs(jsURL, body, err.Error(), outputs)
			}
			rel, err := p.writeSourceContext(ctx, source.OutputPath, []byte(source.Content))
			if err != nil {
				if rel != "" && !contains(outputs, rel) {
					outputs = append(outputs, rel)
				}
				return p.recordFailureWithOutputs(jsURL, body, fmt.Sprintf("write recovered source: %v", err), outputs)
			}
			if !contains(outputs, rel) {
				outputs = append(outputs, rel)
			}
		}
		if err := ctx.Err(); err != nil {
			return p.recordFailureWithOutputs(jsURL, body, err.Error(), outputs)
		}
		sort.Strings(outputs)
		result.Status = "sourcemap"
		result.Outputs = outputs
		if recovery.Complete {
			result.Analysis = recoveredAnalysis(jsURL, recovery.Files)
		}
		if err := ctx.Err(); err != nil {
			return p.recordFailureWithOutputs(jsURL, body, err.Error(), outputs)
		}
		return result
	}
	if err := ctx.Err(); err != nil {
		return p.recordFailure(jsURL, body, err.Error())
	}
	code, err := p.actor.processContext(ctx, body)
	if err != nil {
		return p.recordFailure(jsURL, body, err.Error())
	}
	if len(code) == 0 {
		code = body
	}
	if err := ctx.Err(); err != nil {
		return p.recordFailure(jsURL, body, err.Error())
	}
	rel, err := p.writeGeneratedContext(ctx, jsURL, ".js", code)
	if err != nil {
		if rel != "" {
			return p.recordFailureWithOutputs(jsURL, body, fmt.Sprintf("write processed bundle: %v", err), []string{rel})
		}
		return p.recordFailure(jsURL, body, fmt.Sprintf("write processed bundle: %v", err))
	}
	if err := ctx.Err(); err != nil {
		return p.recordFailureWithOutputs(jsURL, body, err.Error(), []string{rel})
	}
	result.Status = "processed"
	result.Outputs = []string{rel}
	return result
}

func (p *Processor) recoverForBundle(ctx context.Context, entryURL, jsURL string, body []byte) (sourceMapRecovery, error) {
	return runSourceMapAttempt(ctx, func(operationContext context.Context) (sourceMapRecovery, error) {
		reference, err := extractSourceMapReferenceContext(operationContext, body)
		if err != nil {
			return sourceMapRecovery{}, err
		}

		mapContext := operationContext
		cancelMap := func() {}
		if reference == "" {
			mapContext, cancelMap = context.WithTimeout(operationContext, 3*time.Second)
		}
		defer cancelMap()

		_, _, recovery, err := p.recoverSourceMap(mapContext, entryURL, jsURL, reference)
		if reference == "" && errors.Is(err, context.DeadlineExceeded) && operationContext.Err() == nil {
			return sourceMapRecovery{}, nil
		}
		return recovery, err
	})
}

func (p *Processor) recoverSourceMap(ctx context.Context, entryURL, jsURL, reference string) (string, string, sourceMapRecovery, error) {
	ctx = processingContext(ctx)
	if err := ctx.Err(); err != nil {
		return "", "canceled", sourceMapRecovery{}, err
	}
	if strings.HasPrefix(reference, "data:") {
		data, err := decodeSourceMapDataURL(ctx, reference)
		if err != nil {
			if operationErr := sourceMapOperationError(ctx, err); operationErr != nil {
				return "inline", "parse_error", sourceMapRecovery{}, operationErr
			}
			return "inline", "parse_error", sourceMapRecovery{}, nil
		}
		resolver := sourceMapResolver{p: p, entryURL: entryURL, ctx: ctx}
		collection, err := resolver.collect(data, jsURL, 0, map[string]bool{reference: true})
		if err != nil {
			return "inline", "parse_error", sourceMapRecovery{}, err
		}
		recovery, status, err := applicationRecoveryContext(ctx, collection)
		return "inline", status, recovery, err
	}

	mapURL := ""
	explicit := reference != ""
	if explicit {
		resolved, err := urlutil.Resolve(jsURL, reference)
		if err != nil || resolved == "" {
			return reference, "invalid_url", sourceMapRecovery{}, nil
		}
		mapURL = resolved
	} else {
		mapURL = adjacentMapURL(jsURL)
	}
	if mapURL == "" || p.fetch == nil {
		return mapURL, "not_found", sourceMapRecovery{}, nil
	}

	data, err := p.fetchSourceMap(ctx, entryURL, mapURL)
	if err != nil {
		if operationErr := sourceMapOperationError(ctx, err); operationErr != nil {
			return mapURL, "fetch_error", sourceMapRecovery{}, operationErr
		}
		if explicit {
			return mapURL, "fetch_error", sourceMapRecovery{}, nil
		}
		return mapURL, "not_found", sourceMapRecovery{}, nil
	}
	resolver := sourceMapResolver{p: p, entryURL: entryURL, ctx: ctx}
	active := map[string]bool{mapURL: true}
	collection, err := resolver.collect(data, mapURL, 0, active)
	if err != nil {
		return mapURL, "parse_error", sourceMapRecovery{}, err
	}
	recovery, status, err := applicationRecoveryContext(ctx, collection)
	return mapURL, status, recovery, err
}

func sourceMapOperationError(ctx context.Context, err error) error {
	if ctx != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return contextErr
		}
	}
	if errors.Is(err, errSourceMapTooLarge) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return nil
}

func (p *Processor) fetchSourceMap(ctx context.Context, entryURL, mapURL string) ([]byte, error) {
	data, err := p.fetch(ctx, entryURL, mapURL)
	if err != nil {
		return nil, err
	}
	if err := checkSourceMapInputLength(len(data)); err != nil {
		return nil, err
	}
	return data, nil
}

func extractSourceMapReference(source string) string {
	reference, _ := extractSourceMapReferenceContext(context.Background(), []byte(source))
	return reference
}

func extractSourceMapReferenceContext(ctx context.Context, source []byte) (string, error) {
	ctx = processingContext(ctx)
	input := parsepkg.NewInputBytes(source)
	defer input.Restore()
	lexer := jslexer.NewLexer(input)
	reference := ""
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		tokenType, data := lexer.Next()
		if tokenType == jslexer.ErrorToken && len(data) == 0 {
			break
		}
		if tokenType != jslexer.CommentToken && tokenType != jslexer.CommentLineTerminatorToken {
			continue
		}
		matches := sourceMapDirective.FindAllStringSubmatch(string(data), -1)
		if len(matches) == 0 {
			continue
		}
		last := matches[len(matches)-1]
		if last[1] != "" {
			reference = strings.TrimSpace(last[1])
		} else {
			reference = strings.TrimSpace(last[2])
		}
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return reference, nil
}

func adjacentMapURL(jsURL string) string {
	parsed, err := url.Parse(jsURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	parsed.Path += ".map"
	parsed.RawPath = ""
	parsed.Fragment = ""
	return parsed.String()
}

func decodeDataURL(value string) ([]byte, error) {
	return decodeSourceMapDataURL(context.Background(), value)
}

func parseApplicationSources(data []byte) (sourceMapRecovery, string) {
	recovery, status, _ := parseApplicationSourcesContext(context.Background(), data)
	return recovery, status
}

func parseApplicationSourcesContext(ctx context.Context, data []byte) (sourceMapRecovery, string, error) {
	ctx = processingContext(ctx)
	resolver := sourceMapResolver{ctx: ctx}
	collection, err := resolver.collect(data, "", 0, make(map[string]bool))
	if err != nil {
		return sourceMapRecovery{}, "parse_error", err
	}
	recovery, status, err := applicationRecoveryContext(ctx, collection)
	return recovery, status, err
}

func applicationRecovery(collection sourceMapCollection) (sourceMapRecovery, string) {
	recovery, status, _ := applicationRecoveryContext(context.Background(), collection)
	return recovery, status
}

func applicationRecoveryContext(ctx context.Context, collection sourceMapCollection) (sourceMapRecovery, string, error) {
	ctx = processingContext(ctx)
	recovery := sourceMapRecovery{
		Files:    make([]sourceFile, 0, len(collection.Files)),
		Complete: collection.Complete,
	}
	for _, file := range collection.Files {
		if err := ctx.Err(); err != nil {
			return sourceMapRecovery{}, "canceled", err
		}
		safeName := safeApplicationSourcePath(file.Name)
		if safeName == "" {
			continue
		}
		recovery.SourceCount++
		if !file.HasContent || file.Content == "" {
			recovery.Complete = false
			continue
		}
		recovery.ContentSize += int64(len(file.Content))
		if len(recovery.Files) >= 512 || recovery.ContentSize > 64*1024*1024 {
			recovery.Complete = false
			continue
		}
		recovery.Files = append(recovery.Files, sourceFile{
			Name:       file.Name,
			OutputPath: safeName,
			Content:    file.Content,
			HasContent: true,
		})
	}
	if recovery.SourceCount == 0 || len(recovery.Files) == 0 {
		recovery.Complete = false
		return recovery, "no_application_sources", ctx.Err()
	}
	if recovery.SourceCount > 512 || recovery.ContentSize > 64*1024*1024 {
		recovery.Complete = false
	}
	if err := ctx.Err(); err != nil {
		return sourceMapRecovery{}, "canceled", err
	}
	return recovery, "used", nil
}

func (r sourceMapResolver) collect(data []byte, parentMapURL string, depth int, active map[string]bool) (sourceMapCollection, error) {
	ctx := processingContext(r.ctx)
	if err := ctx.Err(); err != nil {
		return sourceMapCollection{}, err
	}
	if depth > 4 {
		return sourceMapCollection{Complete: false}, nil
	}
	var envelope struct {
		Version        json.RawMessage `json:"version"`
		SourceRoot     string          `json:"sourceRoot"`
		Sources        json.RawMessage `json:"sources"`
		SourcesContent json.RawMessage `json:"sourcesContent"`
		Sections       json.RawMessage `json:"sections"`
	}
	if err := decodeSourceMapJSON(ctx, data, &envelope); err != nil {
		if operationErr := sourceMapOperationError(ctx, err); operationErr != nil {
			return sourceMapCollection{}, operationErr
		}
		return sourceMapCollection{Complete: false}, nil
	}
	var version int
	if len(envelope.Version) == 0 || decodeSourceMapJSON(ctx, envelope.Version, &version) != nil || version != 3 {
		if err := ctx.Err(); err != nil {
			return sourceMapCollection{}, err
		}
		return sourceMapCollection{Complete: false}, nil
	}

	var sources []string
	hasSources, err := sourceMapJSONPresent(ctx, envelope.Sources)
	if err != nil {
		return sourceMapCollection{}, err
	}
	if hasSources {
		if err := decodeSourceMapJSON(ctx, envelope.Sources, &sources); err != nil {
			if operationErr := sourceMapOperationError(ctx, err); operationErr != nil {
				return sourceMapCollection{}, operationErr
			}
			return sourceMapCollection{Complete: false}, nil
		}
	}
	var sourcesContent []*string
	hasSourcesContent, err := sourceMapJSONPresent(ctx, envelope.SourcesContent)
	if err != nil {
		return sourceMapCollection{}, err
	}
	if hasSourcesContent {
		if err := decodeSourceMapJSON(ctx, envelope.SourcesContent, &sourcesContent); err != nil {
			if operationErr := sourceMapOperationError(ctx, err); operationErr != nil {
				return sourceMapCollection{}, operationErr
			}
			return sourceMapCollection{Complete: false}, nil
		}
	}
	var sections []struct {
		Offset json.RawMessage `json:"offset"`
		Map    json.RawMessage `json:"map"`
		URL    string          `json:"url"`
	}
	hasSections, err := sourceMapJSONPresent(ctx, envelope.Sections)
	if err != nil {
		return sourceMapCollection{}, err
	}
	if hasSections {
		if err := decodeSourceMapJSON(ctx, envelope.Sections, &sections); err != nil {
			if operationErr := sourceMapOperationError(ctx, err); operationErr != nil {
				return sourceMapCollection{}, operationErr
			}
			return sourceMapCollection{Complete: false}, nil
		}
	}
	if !hasSources && !hasSections {
		return sourceMapCollection{Complete: false}, nil
	}

	collection := sourceMapCollection{Files: make([]sourceFile, 0, len(sources)), Complete: true}
	for i, name := range sources {
		if err := ctx.Err(); err != nil {
			return sourceMapCollection{}, err
		}
		file := sourceFile{Name: joinSourceRoot(envelope.SourceRoot, name)}
		if i < len(sourcesContent) && sourcesContent[i] != nil {
			file.Content = *sourcesContent[i]
			file.HasContent = true
		}
		collection.Files = append(collection.Files, file)
	}
	var previousOffset *sourceMapOffset
	for _, section := range sections {
		if err := ctx.Err(); err != nil {
			return sourceMapCollection{}, err
		}
		offset, validOffset, err := parseSourceMapOffsetContext(ctx, section.Offset)
		if err != nil {
			return sourceMapCollection{}, err
		}
		if !validOffset {
			collection.Complete = false
		} else {
			if previousOffset != nil && sourceMapOffsetLess(offset, *previousOffset) {
				collection.Complete = false
			}
			previousOffset = &offset
		}

		hasMap, err := sourceMapJSONPresent(ctx, section.Map)
		if err != nil {
			return sourceMapCollection{}, err
		}
		hasURL, err := sourceMapStringPresent(ctx, section.URL)
		if err != nil {
			return sourceMapCollection{}, err
		}
		if hasMap == hasURL {
			collection.Complete = false
			continue
		}

		var nested sourceMapCollection
		if hasMap {
			nested, err = r.collect(section.Map, parentMapURL, depth+1, active)
		} else {
			nested, err = r.collectURLSection(section.URL, parentMapURL, depth+1, active)
		}
		if err != nil {
			return sourceMapCollection{}, err
		}
		collection.Files = append(collection.Files, nested.Files...)
		collection.Complete = collection.Complete && nested.Complete
	}
	if err := ctx.Err(); err != nil {
		return sourceMapCollection{}, err
	}
	return collection, nil
}

func parseSourceMapOffset(raw json.RawMessage) (sourceMapOffset, bool) {
	offset, ok, _ := parseSourceMapOffsetContext(context.Background(), raw)
	return offset, ok
}

func parseSourceMapOffsetContext(ctx context.Context, raw json.RawMessage) (sourceMapOffset, bool, error) {
	var wire struct {
		Line   json.RawMessage `json:"line"`
		Column json.RawMessage `json:"column"`
	}
	if len(raw) == 0 {
		return sourceMapOffset{}, false, nil
	}
	if err := decodeSourceMapJSON(ctx, raw, &wire); err != nil {
		if operationErr := sourceMapOperationError(ctx, err); operationErr != nil {
			return sourceMapOffset{}, false, operationErr
		}
		return sourceMapOffset{}, false, nil
	}
	var offset sourceMapOffset
	if len(wire.Line) == 0 || len(wire.Column) == 0 ||
		decodeSourceMapJSON(ctx, wire.Line, &offset.Line) != nil ||
		decodeSourceMapJSON(ctx, wire.Column, &offset.Column) != nil ||
		offset.Line < 0 || offset.Column < 0 {
		if err := ctx.Err(); err != nil {
			return sourceMapOffset{}, false, err
		}
		return sourceMapOffset{}, false, nil
	}
	return offset, true, nil
}

func sourceMapOffsetLess(left, right sourceMapOffset) bool {
	return left.Line < right.Line || (left.Line == right.Line && left.Column < right.Column)
}

func (r sourceMapResolver) collectURLSection(reference, parentMapURL string, depth int, active map[string]bool) (sourceMapCollection, error) {
	ctx := processingContext(r.ctx)
	if err := ctx.Err(); err != nil {
		return sourceMapCollection{}, err
	}
	if depth > 4 {
		return sourceMapCollection{Complete: false}, nil
	}

	mapURL := reference
	nestedParentURL := parentMapURL
	var data []byte
	var err error
	if strings.HasPrefix(reference, "data:") {
		if active[mapURL] {
			return sourceMapCollection{Complete: false}, nil
		}
		data, err = decodeSourceMapDataURL(ctx, reference)
	} else {
		mapURL, err = urlutil.Resolve(parentMapURL, reference)
		nestedParentURL = mapURL
		if err == nil && mapURL != "" && active[mapURL] {
			return sourceMapCollection{Complete: false}, nil
		}
		if err == nil && mapURL != "" && r.p != nil && r.p.fetch != nil {
			data, err = r.p.fetchSourceMap(r.ctx, r.entryURL, mapURL)
		} else if err == nil {
			err = errors.New("source map section fetch unavailable")
		}
	}
	if err != nil {
		if operationErr := sourceMapOperationError(ctx, err); operationErr != nil {
			return sourceMapCollection{}, operationErr
		}
		return sourceMapCollection{Complete: false}, nil
	}
	if mapURL == "" {
		return sourceMapCollection{Complete: false}, nil
	}

	active[mapURL] = true
	nested, err := r.collect(data, nestedParentURL, depth, active)
	delete(active, mapURL)
	return nested, err
}

func joinSourceRoot(root, name string) string {
	if root == "" || strings.Contains(name, "://") || strings.HasPrefix(name, "/") {
		return name
	}
	return strings.TrimSuffix(root, "/") + "/" + strings.TrimPrefix(name, "./")
}

func safeApplicationSourcePath(name string) string {
	original := strings.ReplaceAll(strings.TrimSpace(name), "\\", "/")
	lower := strings.ToLower(original)
	for _, excluded := range []string{
		"node_modules/", "webpack/runtime", "webpack/bootstrap", "(webpack)/",
		"/@vite/", "\x00", "virtual:", "<stdin>", "<anonymous>",
	} {
		if strings.Contains(lower, excluded) {
			return ""
		}
	}

	if parsed, err := url.Parse(original); err == nil && parsed.Scheme != "" {
		original = parsed.Path
	}
	original = strings.TrimPrefix(original, "webpack:///")
	original = strings.TrimPrefix(original, "webpack://")
	original = strings.TrimPrefix(original, "file://")
	if index := strings.IndexAny(original, "?#"); index >= 0 {
		original = original[:index]
	}
	clean := path.Clean("/" + original)
	clean = strings.TrimPrefix(clean, "/")
	clean = strings.TrimPrefix(clean, "./")
	if clean == "" || clean == "." {
		return ""
	}

	switch strings.ToLower(path.Ext(clean)) {
	case ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".vue":
	default:
		return ""
	}

	parts := strings.Split(clean, "/")
	safeParts := make([]string, 0, len(parts))
	for _, part := range parts {
		part = urlutil.SanitizePathPart(part)
		if part != "" && part != "." && part != ".." {
			safeParts = append(safeParts, part)
		}
	}
	if len(safeParts) == 0 {
		return ""
	}
	return path.Join(safeParts...)
}

func (p *Processor) writeSource(name string, data []byte) (string, error) {
	return p.writeContent(filepath.ToSlash(filepath.FromSlash(name)), data)
}

func (p *Processor) writeSourceContext(ctx context.Context, name string, data []byte) (string, error) {
	return p.writeContentContext(ctx, filepath.ToSlash(filepath.FromSlash(name)), data)
}

func (p *Processor) writeGenerated(sourceURL, fallbackExt string, data []byte) (string, error) {
	return p.writeContent(urlutil.ArtifactFilename(sourceURL, fallbackExt, "script"), data)
}

func (p *Processor) writeGeneratedContext(ctx context.Context, sourceURL, fallbackExt string, data []byte) (string, error) {
	return p.writeContentContext(ctx, urlutil.ArtifactFilename(sourceURL, fallbackExt, "script"), data)
}

func (p *Processor) writeContent(preferredRel string, data []byte) (string, error) {
	return p.writeContentContext(context.Background(), preferredRel, data)
}

func (p *Processor) writeContentContext(ctx context.Context, preferredRel string, data []byte) (string, error) {
	ctx = processingContext(ctx)
	p.outputMu.Lock()
	defer p.outputMu.Unlock()
	if err := ctx.Err(); err != nil {
		return "", err
	}

	hash := fullHash(data)
	if rel, ok := p.contentRefs[hash]; ok {
		output := filepath.ToSlash(filepath.Join("js", rel))
		return output, ctx.Err()
	}

	rel := filepath.ToSlash(preferredRel)
	if existingHash, ok := p.pathHashes[rel]; ok && existingHash != hash {
		ext := path.Ext(rel)
		rel = strings.TrimSuffix(rel, ext) + "-" + hash[:8] + ext
	}
	fullPath := filepath.Join(p.outputDir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
		return "", err
	}
	if err := fileutil.WriteFileAtomic(fullPath, data, 0644); err != nil {
		return "", err
	}
	p.contentRefs[hash] = rel
	p.pathHashes[rel] = hash
	output := filepath.ToSlash(filepath.Join("js", rel))
	return output, ctx.Err()
}

func (p *Processor) recordFailure(jsURL string, body []byte, errText string) FileResult {
	return p.recordFailureWithOutputs(jsURL, body, errText, nil)
}

func (p *Processor) recordFailureWithOutputs(jsURL string, body []byte, errText string, existingOutputs []string) FileResult {
	outputs := append([]string(nil), existingOutputs...)
	rel, writeErr := p.writeGenerated(jsURL, ".js", body)
	fallbackWriteFailed := writeErr != nil
	if writeErr != nil {
		errText += fmt.Sprintf("; write fallback file: %v", writeErr)
		rel = ""
	}
	if rel != "" && !contains(outputs, rel) {
		outputs = append(outputs, rel)
	}
	sort.Strings(outputs)
	return FileResult{
		Analysis:            originalAnalysis(jsURL, body),
		Status:              "failed",
		Outputs:             outputs,
		Failed:              true,
		FallbackWriteFailed: fallbackWriteFailed,
		Error:               errText,
	}
}

func originalAnalysis(jsURL string, body []byte) []AnalysisUnit {
	return []AnalysisUnit{{SourceName: jsURL, BaseURL: jsURL, Body: body}}
}

func recoveredAnalysis(bundleURL string, files []sourceFile) []AnalysisUnit {
	units := make([]AnalysisUnit, 0, len(files))
	for _, file := range files {
		baseURL := bundleURL
		if parsed, err := url.Parse(file.Name); err == nil &&
			(strings.EqualFold(parsed.Scheme, "http") || strings.EqualFold(parsed.Scheme, "https")) && parsed.Host != "" {
			baseURL = file.Name
		}
		units = append(units, AnalysisUnit{
			SourceName: file.Name,
			BaseURL:    baseURL,
			Body:       []byte(file.Content),
		})
	}
	return units
}

func (p *Processor) Close() error {
	p.stateMu.Lock()
	if p.closed {
		p.stateMu.Unlock()
		return nil
	}
	p.closed = true
	actor := p.actor
	tempDir := p.tempDir
	p.stateMu.Unlock()

	err := actor.close()
	removeErr := os.RemoveAll(tempDir)
	if err != nil {
		return err
	}
	return removeErr
}

func fullHash(data []byte) string {
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum[:])
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
