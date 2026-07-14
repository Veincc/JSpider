package preprocess

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
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
	Analysis []AnalysisUnit
	Status   string
	Outputs  []string
	Failed   bool
	Error    string
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
	p.stateMu.Lock()
	closed := p.closed
	p.stateMu.Unlock()
	if closed {
		return p.recordFailure(jsURL, body, "audit-prep processor is closed")
	}

	result := FileResult{Analysis: originalAnalysis(jsURL, body), Outputs: make([]string, 0)}
	reference := extractSourceMapReference(string(body))
	sourceMapTimeout := p.processTimeout
	if reference == "" {
		sourceMapTimeout = 3 * time.Second
	}
	sourceMapContext, cancelSourceMap := context.WithTimeout(context.Background(), sourceMapTimeout)
	var recovery sourceMapRecovery
	acquiredSourceMapSlot := false
	select {
	case sourceMapWorkSlots <- struct{}{}:
		acquiredSourceMapSlot = true
		_, _, recovery = p.recoverSourceMap(sourceMapContext, entryURL, jsURL, reference)
	case <-sourceMapContext.Done():
	}
	cancelSourceMap()
	if len(recovery.Files) > 0 {
		defer func() {
			if acquiredSourceMapSlot {
				<-sourceMapWorkSlots
			}
		}()
		outputs := make([]string, 0, len(recovery.Files))
		for _, source := range recovery.Files {
			rel, err := p.writeSource(source.OutputPath, []byte(source.Content))
			if err != nil {
				return p.recordFailureWithOutputs(jsURL, body, fmt.Sprintf("write recovered source: %v", err), outputs)
			}
			if !contains(outputs, rel) {
				outputs = append(outputs, rel)
			}
		}
		sort.Strings(outputs)
		result.Status = "sourcemap"
		result.Outputs = outputs
		if recovery.Complete {
			result.Analysis = recoveredAnalysis(jsURL, recovery.Files)
		}
		return result
	}
	if acquiredSourceMapSlot {
		<-sourceMapWorkSlots
	}

	code, err := p.actor.process(body)
	if err != nil {
		return p.recordFailure(jsURL, body, err.Error())
	}
	if len(code) == 0 {
		code = body
	}
	rel, err := p.writeGenerated(jsURL, ".js", code)
	if err != nil {
		return p.recordFailure(jsURL, body, fmt.Sprintf("write processed bundle: %v", err))
	}
	result.Status = "processed"
	result.Outputs = []string{rel}
	return result
}

func (p *Processor) recoverSourceMap(ctx context.Context, entryURL, jsURL, reference string) (string, string, sourceMapRecovery) {
	if strings.HasPrefix(reference, "data:") {
		data, err := decodeDataURL(reference)
		if err != nil {
			return "inline", "parse_error", sourceMapRecovery{}
		}
		resolver := sourceMapResolver{p: p, entryURL: entryURL, ctx: ctx}
		collection := resolver.collect(data, jsURL, 0, map[string]bool{reference: true})
		recovery, status := applicationRecovery(collection)
		return "inline", status, recovery
	}

	mapURL := ""
	explicit := reference != ""
	if explicit {
		resolved, err := urlutil.Resolve(jsURL, reference)
		if err != nil || resolved == "" {
			return reference, "invalid_url", sourceMapRecovery{}
		}
		mapURL = resolved
	} else {
		mapURL = adjacentMapURL(jsURL)
	}
	if mapURL == "" || p.fetch == nil {
		return mapURL, "not_found", sourceMapRecovery{}
	}

	data, err := p.fetchSourceMap(ctx, entryURL, mapURL)
	if err != nil {
		if explicit {
			return mapURL, "fetch_error", sourceMapRecovery{}
		}
		return mapURL, "not_found", sourceMapRecovery{}
	}
	resolver := sourceMapResolver{p: p, entryURL: entryURL, ctx: ctx}
	active := map[string]bool{mapURL: true}
	collection := resolver.collect(data, mapURL, 0, active)
	recovery, status := applicationRecovery(collection)
	return mapURL, status, recovery
}

func (p *Processor) fetchSourceMap(ctx context.Context, entryURL, mapURL string) ([]byte, error) {
	return p.fetch(ctx, entryURL, mapURL)
}

func extractSourceMapReference(source string) string {
	lexer := jslexer.NewLexer(parsepkg.NewInputString(source))
	reference := ""
	for {
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
	return reference
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
	comma := strings.IndexByte(value, ',')
	if comma < 0 {
		return nil, errors.New("invalid source map data URL")
	}
	metadata := strings.ToLower(value[:comma])
	payload := value[comma+1:]
	if strings.Contains(metadata, ";base64") {
		return base64.StdEncoding.DecodeString(payload)
	}
	decoded, err := url.PathUnescape(payload)
	if err != nil {
		return nil, err
	}
	return []byte(decoded), nil
}

func parseApplicationSources(data []byte) (sourceMapRecovery, string) {
	resolver := sourceMapResolver{}
	collection := resolver.collect(data, "", 0, make(map[string]bool))
	return applicationRecovery(collection)
}

func applicationRecovery(collection sourceMapCollection) (sourceMapRecovery, string) {
	recovery := sourceMapRecovery{
		Files:    make([]sourceFile, 0, len(collection.Files)),
		Complete: collection.Complete,
	}
	for _, file := range collection.Files {
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
		recovery.Files = append(recovery.Files, sourceFile{
			Name:       file.Name,
			OutputPath: safeName,
			Content:    file.Content,
			HasContent: true,
		})
	}
	if recovery.SourceCount == 0 || len(recovery.Files) == 0 {
		recovery.Complete = false
		return recovery, "no_application_sources"
	}
	if recovery.SourceCount > 512 || recovery.ContentSize > 64*1024*1024 {
		recovery.Complete = false
	}
	return recovery, "used"
}

func (r sourceMapResolver) collect(data []byte, parentMapURL string, depth int, active map[string]bool) sourceMapCollection {
	if depth > 4 {
		return sourceMapCollection{Complete: false}
	}
	var envelope struct {
		Version        json.RawMessage `json:"version"`
		SourceRoot     string          `json:"sourceRoot"`
		Sources        json.RawMessage `json:"sources"`
		SourcesContent json.RawMessage `json:"sourcesContent"`
		Sections       json.RawMessage `json:"sections"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return sourceMapCollection{Complete: false}
	}
	var version int
	if len(envelope.Version) == 0 || json.Unmarshal(envelope.Version, &version) != nil || version != 3 {
		return sourceMapCollection{Complete: false}
	}

	var sources []string
	hasSources := len(envelope.Sources) > 0 && !bytes.Equal(bytes.TrimSpace(envelope.Sources), []byte("null"))
	if hasSources {
		if err := json.Unmarshal(envelope.Sources, &sources); err != nil {
			return sourceMapCollection{Complete: false}
		}
	}
	var sourcesContent []*string
	if len(envelope.SourcesContent) > 0 && !bytes.Equal(bytes.TrimSpace(envelope.SourcesContent), []byte("null")) {
		if err := json.Unmarshal(envelope.SourcesContent, &sourcesContent); err != nil {
			return sourceMapCollection{Complete: false}
		}
	}
	var sections []struct {
		Offset json.RawMessage `json:"offset"`
		Map    json.RawMessage `json:"map"`
		URL    string          `json:"url"`
	}
	hasSections := len(envelope.Sections) > 0 && !bytes.Equal(bytes.TrimSpace(envelope.Sections), []byte("null"))
	if hasSections {
		if err := json.Unmarshal(envelope.Sections, &sections); err != nil {
			return sourceMapCollection{Complete: false}
		}
	}
	if !hasSources && !hasSections {
		return sourceMapCollection{Complete: false}
	}

	collection := sourceMapCollection{Files: make([]sourceFile, 0, len(sources)), Complete: true}
	for i, name := range sources {
		file := sourceFile{Name: joinSourceRoot(envelope.SourceRoot, name)}
		if i < len(sourcesContent) && sourcesContent[i] != nil {
			file.Content = *sourcesContent[i]
			file.HasContent = true
		}
		collection.Files = append(collection.Files, file)
	}
	var previousOffset *sourceMapOffset
	for _, section := range sections {
		offset, validOffset := parseSourceMapOffset(section.Offset)
		if !validOffset {
			collection.Complete = false
		} else {
			if previousOffset != nil && sourceMapOffsetLess(offset, *previousOffset) {
				collection.Complete = false
			}
			previousOffset = &offset
		}

		trimmedMap := bytes.TrimSpace(section.Map)
		hasMap := len(trimmedMap) > 0 && !bytes.Equal(trimmedMap, []byte("null"))
		hasURL := strings.TrimSpace(section.URL) != ""
		if hasMap == hasURL {
			collection.Complete = false
			continue
		}

		var nested sourceMapCollection
		if hasMap {
			nested = r.collect(section.Map, parentMapURL, depth+1, active)
		} else {
			nested = r.collectURLSection(section.URL, parentMapURL, depth+1, active)
		}
		collection.Files = append(collection.Files, nested.Files...)
		collection.Complete = collection.Complete && nested.Complete
	}
	return collection
}

func parseSourceMapOffset(raw json.RawMessage) (sourceMapOffset, bool) {
	var wire struct {
		Line   json.RawMessage `json:"line"`
		Column json.RawMessage `json:"column"`
	}
	if len(raw) == 0 || json.Unmarshal(raw, &wire) != nil {
		return sourceMapOffset{}, false
	}
	var offset sourceMapOffset
	if len(wire.Line) == 0 || len(wire.Column) == 0 ||
		json.Unmarshal(wire.Line, &offset.Line) != nil ||
		json.Unmarshal(wire.Column, &offset.Column) != nil ||
		offset.Line < 0 || offset.Column < 0 {
		return sourceMapOffset{}, false
	}
	return offset, true
}

func sourceMapOffsetLess(left, right sourceMapOffset) bool {
	return left.Line < right.Line || (left.Line == right.Line && left.Column < right.Column)
}

func (r sourceMapResolver) collectURLSection(reference, parentMapURL string, depth int, active map[string]bool) sourceMapCollection {
	if depth > 4 {
		return sourceMapCollection{Complete: false}
	}

	mapURL := reference
	nestedParentURL := parentMapURL
	var data []byte
	var err error
	if strings.HasPrefix(reference, "data:") {
		if active[mapURL] {
			return sourceMapCollection{Complete: false}
		}
		data, err = decodeDataURL(reference)
	} else {
		mapURL, err = urlutil.Resolve(parentMapURL, reference)
		nestedParentURL = mapURL
		if err == nil && mapURL != "" && active[mapURL] {
			return sourceMapCollection{Complete: false}
		}
		if err == nil && mapURL != "" && r.p != nil && r.p.fetch != nil {
			data, err = r.p.fetchSourceMap(r.ctx, r.entryURL, mapURL)
		} else if err == nil {
			err = errors.New("source map section fetch unavailable")
		}
	}
	if err != nil || mapURL == "" {
		return sourceMapCollection{Complete: false}
	}

	active[mapURL] = true
	nested := r.collect(data, nestedParentURL, depth, active)
	delete(active, mapURL)
	return nested
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

func (p *Processor) writeGenerated(sourceURL, fallbackExt string, data []byte) (string, error) {
	return p.writeContent(urlutil.ArtifactFilename(sourceURL, fallbackExt, "script"), data)
}

func (p *Processor) writeContent(preferredRel string, data []byte) (string, error) {
	p.outputMu.Lock()
	defer p.outputMu.Unlock()

	hash := fullHash(data)
	if rel, ok := p.contentRefs[hash]; ok {
		return filepath.ToSlash(filepath.Join("js", rel)), nil
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
	return filepath.ToSlash(filepath.Join("js", rel)), nil
}

func (p *Processor) recordFailure(jsURL string, body []byte, errText string) FileResult {
	return p.recordFailureWithOutputs(jsURL, body, errText, nil)
}

func (p *Processor) recordFailureWithOutputs(jsURL string, body []byte, errText string, existingOutputs []string) FileResult {
	outputs := append([]string(nil), existingOutputs...)
	rel, writeErr := p.writeGenerated(jsURL, ".js", body)
	if writeErr != nil {
		errText += fmt.Sprintf("; write fallback file: %v", writeErr)
		rel = ""
	}
	if rel != "" && !contains(outputs, rel) {
		outputs = append(outputs, rel)
	}
	sort.Strings(outputs)
	return FileResult{
		Analysis: originalAnalysis(jsURL, body),
		Status:   "failed",
		Outputs:  outputs,
		Failed:   true,
		Error:    errText,
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
