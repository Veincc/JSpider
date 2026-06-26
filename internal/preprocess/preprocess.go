package preprocess

import (
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

	"github.com/Veincc/JSpider/internal/urlutil"
)

//go:embed audit-prep.cjs
var workerBundle []byte

const NodeRuntimeError = "--audit-prep requires Node.js runtime"
const NodeVersionError = "--audit-prep requires Node.js 18 or newer"

var sourceMapDirective = regexp.MustCompile(`//[#@]\s*sourceMappingURL\s*=\s*(\S+)|(?s:/\*[#@]\s*sourceMappingURL\s*=\s*(.*?)\s*\*/)`)

type FetchFunc func(entryURL, rawURL string) ([]byte, error)

type Processor struct {
	auditDir string
	tempDir  string
	fetch    FetchFunc
	cmd      *exec.Cmd
	stdin    io.WriteCloser
	stdout   *json.Decoder
	stderr   strings.Builder
	stderrMu sync.Mutex

	mu          sync.Mutex
	nextID      int
	closed      bool
	workerErr   string
	records     []ManifestFile
	contentRefs map[string]string
	pathHashes  map[string]string
}

type FileResult struct {
	AnalysisBody []byte
	Status       string
	Outputs      []string
	Failed       bool
	Error        string
}

type Manifest struct {
	Version int            `json:"version"`
	Files   []ManifestFile `json:"files"`
}

type ManifestFile struct {
	EntryURL        string   `json:"entry_url"`
	JSURL           string   `json:"js_url"`
	Status          string   `json:"status"`
	SourceMapURL    string   `json:"source_map_url,omitempty"`
	SourceMapStatus string   `json:"source_map_status"`
	Outputs         []string `json:"outputs"`
	Error           string   `json:"error,omitempty"`
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
}

type sourceFile struct {
	Name    string
	Content string
}

func CheckNodeRuntime() error {
	if _, err := exec.LookPath("node"); err != nil {
		return errors.New(NodeRuntimeError)
	}
	return nil
}

func New(siteDir string, fetch FetchFunc) (*Processor, error) {
	nodePath, err := exec.LookPath("node")
	if err != nil {
		return nil, errors.New(NodeRuntimeError)
	}

	auditDir := filepath.Join(siteDir, "audit")
	if err := os.RemoveAll(auditDir); err != nil {
		return nil, fmt.Errorf("reset audit directory: %w", err)
	}
	if err := os.MkdirAll(auditDir, 0755); err != nil {
		return nil, fmt.Errorf("create audit directory: %w", err)
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

	cmd := exec.Command(nodePath, helper)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		_ = os.RemoveAll(tempDir)
		return nil, fmt.Errorf("open audit-prep stdin: %w", err)
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		_ = os.RemoveAll(tempDir)
		return nil, fmt.Errorf("open audit-prep stdout: %w", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		_ = os.RemoveAll(tempDir)
		return nil, fmt.Errorf("open audit-prep stderr: %w", err)
	}

	p := &Processor{
		auditDir:    auditDir,
		tempDir:     tempDir,
		fetch:       fetch,
		cmd:         cmd,
		stdin:       stdin,
		stdout:      json.NewDecoder(stdoutPipe),
		records:     make([]ManifestFile, 0),
		contentRefs: make(map[string]string),
		pathHashes:  make(map[string]string),
	}
	if err := cmd.Start(); err != nil {
		_ = os.RemoveAll(tempDir)
		return nil, fmt.Errorf("start audit-prep worker: %w", err)
	}
	go func() {
		_, _ = io.Copy(lockedBuilder{mu: &p.stderrMu, b: &p.stderr}, stderrPipe)
	}()
	if err := p.checkWorker(); err != nil {
		_ = p.Close()
		return nil, err
	}
	return p, nil
}

func (p *Processor) Process(entryURL, jsURL string, body []byte) FileResult {
	p.mu.Lock()
	defer p.mu.Unlock()

	result := FileResult{AnalysisBody: body, Outputs: make([]string, 0)}
	if p.closed {
		return p.recordFailure(entryURL, jsURL, body, "not_attempted", "", "audit-prep processor is closed")
	}

	mapURL, mapStatus, sources := p.recoverSourceMap(entryURL, jsURL, body)
	if len(sources) > 0 {
		outputs := make([]string, 0, len(sources))
		for _, source := range sources {
			rel, err := p.writeSource(source.Name, []byte(source.Content))
			if err != nil {
				return p.recordFailure(entryURL, jsURL, body, mapStatus, mapURL, fmt.Sprintf("write recovered source: %v", err))
			}
			if !contains(outputs, rel) {
				outputs = append(outputs, rel)
			}
		}
		sort.Strings(outputs)
		p.records = append(p.records, ManifestFile{
			EntryURL:        entryURL,
			JSURL:           jsURL,
			Status:          "sourcemap",
			SourceMapURL:    mapURL,
			SourceMapStatus: "used",
			Outputs:         outputs,
		})
		result.Status = "sourcemap"
		result.Outputs = outputs
		return result
	}

	if p.workerErr != "" {
		return p.recordFailure(entryURL, jsURL, body, mapStatus, mapURL, "audit-prep worker unavailable after previous failure: "+p.workerErr)
	}

	p.nextID++
	id := p.nextID
	if err := json.NewEncoder(p.stdin).Encode(workerRequest{ID: id, Source: string(body)}); err != nil {
		errText := fmt.Sprintf("send audit-prep request: %v", err)
		p.latchWorkerFailure(errText)
		return p.recordFailure(entryURL, jsURL, body, mapStatus, mapURL, errText)
	}

	var response workerResponse
	if err := p.stdout.Decode(&response); err != nil {
		errText := "audit-prep worker stopped"
		if !errors.Is(err, io.EOF) {
			errText = fmt.Sprintf("decode audit-prep response: %v", err)
		}
		if stderr := strings.TrimSpace(p.stderrString()); stderr != "" {
			errText += ": " + stderr
		}
		p.latchWorkerFailure(errText)
		return p.recordFailure(entryURL, jsURL, body, mapStatus, mapURL, errText)
	}
	if response.ID != id {
		errText := fmt.Sprintf("audit-prep response id mismatch: got %d want %d", response.ID, id)
		p.latchWorkerFailure(errText)
		return p.recordFailure(entryURL, jsURL, body, mapStatus, mapURL, errText)
	}
	if !response.OK {
		errText := response.Error
		if errText == "" {
			errText = "audit-prep processing failed"
		}
		return p.recordFailure(entryURL, jsURL, body, mapStatus, mapURL, errText)
	}

	code := []byte(response.Code)
	if len(code) == 0 {
		code = body
	}
	rel, err := p.writeGenerated("bundles", jsURL, ".js", code)
	if err != nil {
		return p.recordFailure(entryURL, jsURL, body, mapStatus, mapURL, fmt.Sprintf("write processed bundle: %v", err))
	}
	p.records = append(p.records, ManifestFile{
		EntryURL:        entryURL,
		JSURL:           jsURL,
		Status:          "processed",
		SourceMapURL:    mapURL,
		SourceMapStatus: mapStatus,
		Outputs:         []string{rel},
	})
	result.Status = "processed"
	result.Outputs = []string{rel}
	return result
}

func (p *Processor) recoverSourceMap(entryURL, jsURL string, body []byte) (string, string, []sourceFile) {
	reference := extractSourceMapReference(string(body))
	if strings.HasPrefix(reference, "data:") {
		data, err := decodeDataURL(reference)
		if err != nil {
			return "inline", "parse_error", nil
		}
		sources, status := parseApplicationSources(data)
		return "inline", status, sources
	}

	mapURL := ""
	explicit := reference != ""
	if explicit {
		resolved, err := urlutil.Resolve(jsURL, reference)
		if err != nil || resolved == "" {
			return reference, "invalid_url", nil
		}
		mapURL = resolved
	} else {
		mapURL = adjacentMapURL(jsURL)
	}
	if mapURL == "" || p.fetch == nil {
		return mapURL, "not_found", nil
	}

	data, err := p.fetch(entryURL, mapURL)
	if err != nil {
		if explicit {
			return mapURL, "fetch_error", nil
		}
		return mapURL, "not_found", nil
	}
	sources, status := parseApplicationSources(data)
	return mapURL, status, sources
}

func extractSourceMapReference(source string) string {
	matches := sourceMapDirective.FindAllStringSubmatch(source, -1)
	if len(matches) == 0 {
		return ""
	}
	last := matches[len(matches)-1]
	if last[1] != "" {
		return strings.TrimSpace(last[1])
	}
	return strings.TrimSpace(last[2])
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

func parseApplicationSources(data []byte) ([]sourceFile, string) {
	var raw json.RawMessage = data
	files, err := collectSourceFiles(raw)
	if err != nil {
		return nil, "parse_error"
	}
	if len(files) == 0 {
		return nil, "no_sources_content"
	}

	application := make([]sourceFile, 0, len(files))
	for _, file := range files {
		safeName := safeApplicationSourcePath(file.Name)
		if safeName == "" || file.Content == "" {
			continue
		}
		application = append(application, sourceFile{Name: safeName, Content: file.Content})
	}
	if len(application) == 0 {
		return nil, "no_application_sources"
	}
	return application, "used"
}

func collectSourceFiles(data json.RawMessage) ([]sourceFile, error) {
	var envelope struct {
		SourceRoot     string    `json:"sourceRoot"`
		Sources        []string  `json:"sources"`
		SourcesContent []*string `json:"sourcesContent"`
		Sections       []struct {
			Map json.RawMessage `json:"map"`
		} `json:"sections"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, err
	}

	files := make([]sourceFile, 0)
	for i, name := range envelope.Sources {
		if i >= len(envelope.SourcesContent) || envelope.SourcesContent[i] == nil {
			continue
		}
		files = append(files, sourceFile{
			Name:    joinSourceRoot(envelope.SourceRoot, name),
			Content: *envelope.SourcesContent[i],
		})
	}
	for _, section := range envelope.Sections {
		nested, err := collectSourceFiles(section.Map)
		if err != nil {
			return nil, err
		}
		files = append(files, nested...)
	}
	return files, nil
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
	return p.writeContent(filepath.ToSlash(filepath.Join("sources", filepath.FromSlash(name))), data)
}

func (p *Processor) writeGenerated(dir, sourceURL, fallbackExt string, data []byte) (string, error) {
	return p.writeContent(filepath.ToSlash(filepath.Join(dir, urlutil.ArtifactFilename(sourceURL, fallbackExt, "bundle"))), data)
}

func (p *Processor) writeContent(preferredRel string, data []byte) (string, error) {
	hash := fullHash(data)
	category, _, _ := strings.Cut(preferredRel, "/")
	contentKey := category + "\x00" + hash
	if rel, ok := p.contentRefs[contentKey]; ok {
		return rel, nil
	}

	rel := preferredRel
	if existingHash, ok := p.pathHashes[rel]; ok && existingHash != hash {
		ext := path.Ext(rel)
		rel = strings.TrimSuffix(rel, ext) + "-" + hash[:8] + ext
	}
	fullPath := filepath.Join(p.auditDir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
		return "", err
	}
	if err := os.WriteFile(fullPath, data, 0644); err != nil {
		return "", err
	}
	p.contentRefs[contentKey] = rel
	p.pathHashes[rel] = hash
	return rel, nil
}

func (p *Processor) recordFailure(entryURL, jsURL string, body []byte, mapStatus, mapURL, errText string) FileResult {
	rel, writeErr := p.writeGenerated("failures", jsURL, ".js", body)
	if writeErr != nil {
		errText += fmt.Sprintf("; write failure file: %v", writeErr)
		rel = ""
	}
	outputs := make([]string, 0, 1)
	if rel != "" {
		outputs = append(outputs, rel)
	}
	p.records = append(p.records, ManifestFile{
		EntryURL:        entryURL,
		JSURL:           jsURL,
		Status:          "failed",
		SourceMapURL:    mapURL,
		SourceMapStatus: mapStatus,
		Outputs:         outputs,
		Error:           errText,
	})
	return FileResult{
		AnalysisBody: body,
		Status:       "failed",
		Outputs:      outputs,
		Failed:       true,
		Error:        errText,
	}
}

func (p *Processor) Save() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	sort.Slice(p.records, func(i, j int) bool {
		if p.records[i].EntryURL != p.records[j].EntryURL {
			return p.records[i].EntryURL < p.records[j].EntryURL
		}
		return p.records[i].JSURL < p.records[j].JSURL
	})
	manifest := Manifest{Version: 1, Files: p.records}
	path := filepath.Join(p.auditDir, "manifest.json")
	tmpPath := path + ".tmp"
	file, err := os.Create(tmpPath)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(manifest); err != nil {
		_ = file.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return os.Rename(tmpPath, path)
}

func (p *Processor) checkWorker() error {
	if err := json.NewEncoder(p.stdin).Encode(workerRequest{Command: "ping"}); err != nil {
		return fmt.Errorf("start audit-prep worker: %w", err)
	}
	var response workerResponse
	if err := p.stdout.Decode(&response); err != nil {
		errText := "audit-prep worker stopped during startup"
		if !errors.Is(err, io.EOF) {
			errText = fmt.Sprintf("decode audit-prep startup response: %v", err)
		}
		if stderr := strings.TrimSpace(p.stderrString()); stderr != "" {
			errText += ": " + stderr
		}
		return errors.New(errText)
	}
	if !response.OK {
		if response.Error == "" {
			response.Error = "audit-prep worker failed to start"
		}
		return errors.New(response.Error)
	}
	majorText, _, _ := strings.Cut(response.NodeVersion, ".")
	major, err := strconv.Atoi(majorText)
	if err != nil || major < 18 {
		return errors.New(NodeVersionError)
	}
	return nil
}

func (p *Processor) latchWorkerFailure(errText string) {
	if p.workerErr == "" {
		p.workerErr = errText
	}
}

func (p *Processor) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	stdin := p.stdin
	cmd := p.cmd
	tempDir := p.tempDir
	p.mu.Unlock()

	_ = json.NewEncoder(stdin).Encode(workerRequest{Command: "shutdown"})
	_ = stdin.Close()
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()
	select {
	case err := <-done:
		_ = os.RemoveAll(tempDir)
		if err != nil && !strings.Contains(err.Error(), "signal: killed") {
			return err
		}
		return nil
	case <-time.After(2 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		_ = os.RemoveAll(tempDir)
		return nil
	}
}

type lockedBuilder struct {
	mu *sync.Mutex
	b  *strings.Builder
}

func (w lockedBuilder) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(data)
}

func (p *Processor) stderrString() string {
	p.stderrMu.Lock()
	defer p.stderrMu.Unlock()
	return p.stderr.String()
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
