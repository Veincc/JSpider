package store

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/Veincc/JSpider/internal/analyzer"
)

type Store struct {
	mu sync.Mutex

	jsAssets   map[string]*analyzer.JSAsset
	imports    []analyzer.DynamicImport
	routes     []analyzer.RouteChunk
	sourcemaps []analyzer.SourceMapInfo
	frameworks []analyzer.FrameworkDetect

	seenURLs      map[string]bool
	contentHashes map[string]string // hash -> first URL that had this content
	outDir        string
}

func New(outDir string) *Store {
	return &Store{
		jsAssets:      make(map[string]*analyzer.JSAsset),
		seenURLs:      make(map[string]bool),
		contentHashes: make(map[string]string),
		outDir:        outDir,
	}
}

// AddJS adds or updates a JS asset
func (s *Store) AddJS(asset *analyzer.JSAsset) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if existing, ok := s.jsAssets[asset.URL]; ok {
		s.jsAssets[asset.URL] = mergeJSAsset(existing, asset)
		s.seenURLs[asset.URL] = true
		return
	}

	s.jsAssets[asset.URL] = asset
	s.seenURLs[asset.URL] = true
}

func mergeJSAsset(existing, incoming *analyzer.JSAsset) *analyzer.JSAsset {
	merged := *existing

	// Do not allow confirmed to be downgraded by candidate/failed.
	if merged.Status != analyzer.StatusConfirmed || incoming.Status == analyzer.StatusConfirmed {
		merged.Status = incoming.Status
	}
	if merged.Confidence != analyzer.ConfHigh || incoming.Confidence == analyzer.ConfHigh {
		merged.Confidence = incoming.Confidence
	}
	if incoming.FromURL != "" {
		merged.FromURL = incoming.FromURL
	}
	if incoming.Type != "" && merged.Type == analyzer.TypeUnknownJS {
		merged.Type = incoming.Type
	}
	if incoming.Framework != "" {
		merged.Framework = incoming.Framework
	}
	if incoming.Source != "" && merged.Source == analyzer.SourceRegexCandidate {
		merged.Source = incoming.Source
	}
	if incoming.Depth < merged.Depth || merged.Depth == 0 {
		merged.Depth = incoming.Depth
	}
	if incoming.ContentType != "" {
		merged.ContentType = incoming.ContentType
	}
	if incoming.Size != 0 {
		merged.Size = incoming.Size
	}
	if incoming.Hash != "" {
		merged.Hash = incoming.Hash
	}
	if len(incoming.Reasons) > 0 {
		merged.Reasons = incoming.Reasons
	}

	return &merged
}

// HasSeen checks whether a URL has been processed
func (s *Store) HasSeen(url string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seenURLs[url]
}

// MarkSeen marks a URL as processed
func (s *Store) MarkSeen(url string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seenURLs[url] = true
}

// AddDynamicImport adds a dynamic import
func (s *Store) AddDynamicImport(imp analyzer.DynamicImport) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.imports = append(s.imports, imp)
}

// GetDynamicImports returns all dynamic imports
func (s *Store) GetDynamicImports() []analyzer.DynamicImport {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]analyzer.DynamicImport, len(s.imports))
	copy(result, s.imports)
	return result
}

// AddRoute adds a route mapping
func (s *Store) AddRoute(route analyzer.RouteChunk) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.routes = append(s.routes, route)
}

// AddSourcemap adds source map info (auto-deduplicates, keeps latest status per MapURL)
func (s *Store) AddSourcemap(sm analyzer.SourceMapInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.sourcemaps {
		if s.sourcemaps[i].MapURL == sm.MapURL && s.sourcemaps[i].FromJS == sm.FromJS {
			// Update existing entry (status may change from found to parsed)
			s.sourcemaps[i] = sm
			return
		}
	}
	s.sourcemaps = append(s.sourcemaps, sm)
}

// GetSourcemaps returns all source map info
func (s *Store) GetSourcemaps() []analyzer.SourceMapInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]analyzer.SourceMapInfo, len(s.sourcemaps))
	copy(result, s.sourcemaps)
	return result
}

// UpdateSourcemapStatus updates the status of a specific source map
func (s *Store) UpdateSourcemapStatus(mapURL string, status string, sourceCount int, hasContent bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.sourcemaps {
		if s.sourcemaps[i].MapURL == mapURL {
			s.sourcemaps[i].Status = status
			s.sourcemaps[i].SourceCount = sourceCount
			s.sourcemaps[i].HasSourcesContent = hasContent
			break
		}
	}
}

// AddFramework adds a framework detection result
func (s *Store) AddFramework(fw analyzer.FrameworkDetect) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.frameworks = append(s.frameworks, fw)
}

// JSCount returns the number of confirmed JS assets
func (s *Store) JSCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.jsAssets)
}

// GetConfirmedURLs returns the list of confirmed JS URLs
func (s *Store) GetConfirmedURLs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var urls []string
	for _, a := range s.jsAssets {
		if a.Status == analyzer.StatusConfirmed {
			urls = append(urls, a.URL)
		}
	}
	sort.Strings(urls)
	return urls
}

// GetCandidateURLs returns the list of candidate JS URLs
func (s *Store) GetCandidateURLs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var urls []string
	for _, a := range s.jsAssets {
		if a.Status == analyzer.StatusCandidate {
			urls = append(urls, a.URL)
		}
	}
	sort.Strings(urls)
	return urls
}

// HashContent computes the SHA256 hash of content
func HashContent(data []byte) string {
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h[:8])
}

// SaveAll saves all results to files (atomic write: write to temp file then rename)
func (s *Store) SaveAll() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Ensure output directory exists
	if err := os.MkdirAll(s.outDir, 0755); err != nil {
		return fmt.Errorf("Failed to create output directory: %w", err)
	}

	// js.txt — the single JS URL list (confirmed + candidates, deduped, sorted)
	var allJS []string
	seenJS := make(map[string]bool)
	for _, a := range s.jsAssets {
		if a.Status == analyzer.StatusConfirmed || a.Status == analyzer.StatusCandidate {
			if !seenJS[a.URL] {
				seenJS[a.URL] = true
				allJS = append(allJS, a.URL)
			}
		}
	}
	sort.Strings(allJS)
	if err := s.writeLinesAtomic("js.txt", allJS); err != nil {
		return err
	}

	// dynamic_imports.json
	if err := s.writeJSONAtomic("dynamic_imports.json", dedupImports(s.imports)); err != nil {
		return err
	}

	// route_chunk_map.json
	if err := s.writeJSONAtomic("route_chunk_map.json", dedupRoutes(s.routes)); err != nil {
		return err
	}

	// sourcemaps.txt (stable sort)
	var smLines []string
	for _, sm := range dedupSourcemaps(s.sourcemaps) {
		smLines = append(smLines, fmt.Sprintf("%s -> %s %s", sm.FromJS, sm.MapURL, sm.Status))
	}
	sort.Strings(smLines)
	if err := s.writeLinesAtomic("sourcemaps.txt", smLines); err != nil {
		return err
	}

	// framework_detect.json (stable sort)
	if err := s.writeJSONAtomic("framework_detect.json", dedupFrameworks(s.frameworks)); err != nil {
		return err
	}

	return nil
}

// writeLinesAtomic writes a text file atomically (write .tmp then rename)
func (s *Store) writeLinesAtomic(filename string, lines []string) error {
	tmpPath := s.outDir + "/" + filename + ".tmp"
	finalPath := s.outDir + "/" + filename

	f, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("Failed to create temp file %s: %w", filename, err)
	}
	for _, line := range lines {
		if _, err := f.WriteString(line + "\n"); err != nil {
			f.Close()
			os.Remove(tmpPath)
			return fmt.Errorf("Failed to write %s: %w", filename, err)
		}
	}
	if err := f.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("Failed to close file %s: %w", filename, err)
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("Failed to rename %s: %w", filename, err)
	}
	return nil
}

// writeJSONAtomic writes a JSON file atomically
func (s *Store) writeJSONAtomic(filename string, data interface{}) error {
	tmpPath := s.outDir + "/" + filename + ".tmp"
	finalPath := s.outDir + "/" + filename

	f, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("Failed to create temp file %s: %w", filename, err)
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(data); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("Failed to encode JSON %s: %w", filename, err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("Failed to close file %s: %w", filename, err)
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("Failed to rename %s: %w", filename, err)
	}
	return nil
}

// dedupSourcemaps deduplicates and stably sorts source maps
func dedupSourcemaps(sms []analyzer.SourceMapInfo) []analyzer.SourceMapInfo {
	seen := make(map[string]bool)
	var result []analyzer.SourceMapInfo
	for _, sm := range sms {
		key := sm.FromJS + "|" + sm.MapURL
		if !seen[key] {
			seen[key] = true
			result = append(result, sm)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].FromJS != result[j].FromJS {
			return result[i].FromJS < result[j].FromJS
		}
		return result[i].MapURL < result[j].MapURL
	})
	return result
}

// dedupFrameworks deduplicates and stably sorts framework detection results
func dedupFrameworks(fws []analyzer.FrameworkDetect) []analyzer.FrameworkDetect {
	seen := make(map[string]bool)
	var result []analyzer.FrameworkDetect
	for _, fw := range fws {
		key := fw.URL + "|" + fw.Framework
		if !seen[key] {
			seen[key] = true
			result = append(result, fw)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].URL != result[j].URL {
			return result[i].URL < result[j].URL
		}
		return result[i].Framework < result[j].Framework
	})
	return result
}

func dedupImports(imports []analyzer.DynamicImport) []analyzer.DynamicImport {
	seen := make(map[string]bool)
	var result []analyzer.DynamicImport
	for _, imp := range imports {
		key := imp.FromJS + "|" + imp.Raw + "|" + imp.ResolvedURL
		if !seen[key] {
			seen[key] = true
			result = append(result, imp)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].FromJS != result[j].FromJS {
			return result[i].FromJS < result[j].FromJS
		}
		return result[i].ResolvedURL < result[j].ResolvedURL
	})
	return result
}

func dedupRoutes(routes []analyzer.RouteChunk) []analyzer.RouteChunk {
	seen := make(map[string]bool)
	var result []analyzer.RouteChunk
	for _, r := range routes {
		key := r.Route + "|" + r.Component + "|" + r.LazyJS
		if !seen[key] {
			seen[key] = true
			result = append(result, r)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Route != result[j].Route {
			return result[i].Route < result[j].Route
		}
		return result[i].FromJS < result[j].FromJS
	})
	return result
}

// SaveRaw saves raw content to outDir/domain/ directory with automatic deduplication
func (s *Store) SaveRaw(domain, filename string, data []byte) error {
	s.mu.Lock()
	hash := HashContent(data)

	// Check if identical content already exists
	if _, exists := s.contentHashes[hash]; exists {
		s.mu.Unlock()
		// Content already exists, skipping save
		return nil
	}
	s.contentHashes[hash] = domain + "/" + filename
	s.mu.Unlock()

	dir := s.outDir + "/" + domain
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	path := dir + "/" + filename
	return os.WriteFile(path, data, 0644)
}

// IsDuplicateContent checks whether content already exists
func (s *Store) IsDuplicateContent(data []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	hash := HashContent(data)
	_, exists := s.contentHashes[hash]
	return exists
}

// NormalizeJSURLs deduplicates and normalizes a JS URL list
func NormalizeJSURLs(urls []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, u := range urls {
		nu := strings.TrimSpace(u)
		if nu == "" {
			continue
		}
		if !seen[nu] {
			seen[nu] = true
			result = append(result, nu)
		}
	}
	return result
}
