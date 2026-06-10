package store

import (
	"crypto/sha256"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/Veincc/JSpider/internal/analyzer"
)

type Store struct {
	mu sync.Mutex

	jsAssets      map[string]*analyzer.JSAsset
	contentHashes map[string]string
	outDir        string
}

func New(outDir string) *Store {
	return &Store{
		jsAssets:      make(map[string]*analyzer.JSAsset),
		contentHashes: make(map[string]string),
		outDir:        outDir,
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

func (s *Store) SaveEntry(site string, data []byte) error {
	dir := filepath.Join(s.outDir, site)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "entry.html"), data, 0644)
}

func (s *Store) SaveJS(site, sourceURL string, data []byte) (string, bool, error) {
	hash := contentHash(data)
	key := site + "\x00" + hash

	s.mu.Lock()
	if existing, ok := s.contentHashes[key]; ok {
		s.mu.Unlock()
		return existing, false, nil
	}
	rel := filepath.ToSlash(filepath.Join(site, "js", artifactFilename(sourceURL, ".js")))
	s.contentHashes[key] = rel
	s.mu.Unlock()

	fullPath := filepath.Join(s.outDir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
		return "", false, err
	}
	if err := os.WriteFile(fullPath, data, 0644); err != nil {
		return "", false, err
	}
	return rel, true, nil
}

func contentHash(data []byte) string {
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum[:])
}

func artifactFilename(sourceURL, fallbackExt string) string {
	base := "script"
	if parsed, err := url.Parse(sourceURL); err == nil {
		if candidate := path.Base(parsed.Path); candidate != "" && candidate != "." && candidate != "/" {
			base = candidate
		}
	}
	ext := path.Ext(base)
	if ext == "" {
		ext = fallbackExt
	}
	stem := strings.TrimSuffix(base, path.Ext(base))
	stem = sanitizeName(stem)
	if stem == "" {
		stem = "script"
	}
	if len(stem) > 64 {
		stem = stem[:64]
	}
	sum := sha256.Sum256([]byte(sourceURL))
	return fmt.Sprintf("%s-%x%s", stem, sum[:4], ext)
}

func sanitizeName(value string) string {
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return strings.Trim(b.String(), "._")
}
