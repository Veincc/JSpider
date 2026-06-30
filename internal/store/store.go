package store

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/Veincc/JSpider/internal/analyzer"
	"github.com/Veincc/JSpider/internal/fileutil"
)

type Store struct {
	mu sync.Mutex

	jsAssets   map[string]*analyzer.JSAsset
	jsMappings map[string]map[string]map[string]struct{}
	outDir     string
}

type JSMapEntry struct {
	URL  string
	Path string
}

func New(outDir string) *Store {
	return &Store{
		jsAssets:   make(map[string]*analyzer.JSAsset),
		jsMappings: make(map[string]map[string]map[string]struct{}),
		outDir:     outDir,
	}
}

func (s *Store) AddJS(asset *analyzer.JSAsset) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if existing, ok := s.jsAssets[asset.URL]; ok {
		s.jsAssets[asset.URL] = mergeJSAsset(existing, asset)
		return
	}
	copy := *asset
	s.jsAssets[asset.URL] = &copy
}

func mergeJSAsset(existing, incoming *analyzer.JSAsset) *analyzer.JSAsset {
	merged := *existing
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
	if incoming.Source != "" && merged.Source == analyzer.SourceRegexCandidate {
		merged.Source = incoming.Source
	}
	if incoming.Depth < merged.Depth {
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
	return &merged
}

func (s *Store) GetConfirmedURLs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var urls []string
	for _, asset := range s.jsAssets {
		if asset.Status == analyzer.StatusConfirmed {
			urls = append(urls, asset.URL)
		}
	}
	sort.Strings(urls)
	return urls
}

func (s *Store) GetCandidateURLs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var urls []string
	for _, asset := range s.jsAssets {
		if asset.Status == analyzer.StatusCandidate {
			urls = append(urls, asset.URL)
		}
	}
	sort.Strings(urls)
	return urls
}

func (s *Store) RecordJSOutputs(site, sourceURL string, paths []string) {
	if site == "" || sourceURL == "" || len(paths) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.jsMappings[site] == nil {
		s.jsMappings[site] = make(map[string]map[string]struct{})
	}
	if s.jsMappings[site][sourceURL] == nil {
		s.jsMappings[site][sourceURL] = make(map[string]struct{})
	}
	for _, outputPath := range paths {
		if outputPath != "" {
			s.jsMappings[site][sourceURL][filepath.ToSlash(outputPath)] = struct{}{}
		}
	}
}

func (s *Store) JSMapEntries(site string) []JSMapEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	var entries []JSMapEntry
	for sourceURL, paths := range s.jsMappings[site] {
		for outputPath := range paths {
			entries = append(entries, JSMapEntry{URL: sourceURL, Path: outputPath})
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].URL != entries[j].URL {
			return entries[i].URL < entries[j].URL
		}
		return entries[i].Path < entries[j].Path
	})
	return entries
}

func (s *Store) WriteJSMap(site string) error {
	siteDir := filepath.Join(s.outDir, site)
	if err := os.MkdirAll(siteDir, 0755); err != nil {
		return err
	}
	var output bytes.Buffer
	for _, entry := range s.JSMapEntries(site) {
		output.WriteString(entry.URL)
		output.WriteByte('\t')
		output.WriteString(entry.Path)
		output.WriteByte('\n')
	}
	return fileutil.WriteFileAtomic(filepath.Join(siteDir, "js-map.txt"), output.Bytes(), 0600)
}
