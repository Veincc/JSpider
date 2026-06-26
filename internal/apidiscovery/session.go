package apidiscovery

import (
	"bytes"
	"sort"
	"sync"
)

type sourceAnalysisState uint8

const (
	// sourceStatePending means the current source bytes have not been analyzed.
	sourceStatePending sourceAnalysisState = iota
	// sourceStateAnalyzing prevents concurrent AnalyzeSources calls from
	// analyzing the same source bytes twice.
	sourceStateAnalyzing
	// sourceStateAnalyzed means the current source version is reflected in static.
	sourceStateAnalyzed
)

type Session struct {
	mu sync.Mutex

	static       []StaticEndpoint
	runtime      []RuntimeRequest
	entryURLs    []string
	sources      map[string][]byte
	sourceStates map[string]sourceAnalysisState
	// sourceVersions changes every time AddSource replaces a URL's bytes.
	// AnalyzeSources uses it to discard stale analysis results if a source is
	// updated while jsluice is running outside the lock.
	sourceVersions map[string]uint64
}

func NewSession() *Session {
	return &Session{
		sources:        make(map[string][]byte),
		sourceStates:   make(map[string]sourceAnalysisState),
		sourceVersions: make(map[string]uint64),
	}
}

func (s *Session) AddEntryURL(entryURL string) {
	if s == nil || entryURL == "" {
		return
	}
	s.mu.Lock()
	for _, existing := range s.entryURLs {
		if existing == entryURL {
			s.mu.Unlock()
			return
		}
	}
	s.entryURLs = append(s.entryURLs, entryURL)
	s.mu.Unlock()
}

func (s *Session) AddStatic(endpoints []StaticEndpoint) {
	if s == nil || len(endpoints) == 0 {
		return
	}
	s.mu.Lock()
	s.static = append(s.static, endpoints...)
	s.mu.Unlock()
}

func (s *Session) AddRuntime(requests []RuntimeRequest) {
	if s == nil || len(requests) == 0 {
		return
	}
	s.mu.Lock()
	s.runtime = append(s.runtime, requests...)
	s.mu.Unlock()
}

func (s *Session) AddSource(sourceURL string, source []byte) {
	if s == nil || sourceURL == "" {
		return
	}
	s.mu.Lock()
	if s.sources == nil {
		s.sources = make(map[string][]byte)
	}
	if s.sourceStates == nil {
		s.sourceStates = make(map[string]sourceAnalysisState)
	}
	if s.sourceVersions == nil {
		s.sourceVersions = make(map[string]uint64)
	}
	if existing, ok := s.sources[sourceURL]; ok && bytes.Equal(existing, source) {
		s.mu.Unlock()
		return
	}
	// Replacing source bytes invalidates only the static endpoints that came
	// from this JavaScript URL; runtime evidence is kept independently.
	s.sources[sourceURL] = append([]byte(nil), source...)
	s.sourceVersions[sourceURL]++
	s.sourceStates[sourceURL] = sourceStatePending
	s.mu.Unlock()
}

func (s *Session) SourceCount() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sources)
}

func (s *Session) AnalyzeSources() error {
	if s == nil {
		return nil
	}

	s.mu.Lock()
	urls := make([]string, 0, len(s.sources))
	sources := make(map[string][]byte)
	versions := make(map[string]uint64)
	if s.sourceStates == nil {
		s.sourceStates = make(map[string]sourceAnalysisState)
	}
	if s.sourceVersions == nil {
		s.sourceVersions = make(map[string]uint64)
	}
	for sourceURL, source := range s.sources {
		if s.sourceStates[sourceURL] == sourceStateAnalyzed || s.sourceStates[sourceURL] == sourceStateAnalyzing {
			continue
		}
		// Mark in-progress before releasing the lock so parallel callers do not
		// enqueue the same source for duplicate analysis.
		s.sourceStates[sourceURL] = sourceStateAnalyzing
		urls = append(urls, sourceURL)
		sources[sourceURL] = append([]byte(nil), source...)
		versions[sourceURL] = s.sourceVersions[sourceURL]
	}
	s.mu.Unlock()
	sort.Strings(urls)

	for _, sourceURL := range urls {
		endpoints, err := AnalyzeJavaScript(sources[sourceURL], sourceURL)
		if err != nil {
			s.markSourcePendingIfCurrent(sourceURL, versions[sourceURL])
			return err
		}
		s.mu.Lock()
		// If AddSource replaced this URL while AnalyzeJavaScript was running,
		// discard the stale endpoints and leave the newer version pending.
		if s.sourceVersions[sourceURL] == versions[sourceURL] && s.sourceStates[sourceURL] == sourceStateAnalyzing {
			s.replaceStaticFromSourceLocked(sourceURL, endpoints)
			s.sourceStates[sourceURL] = sourceStateAnalyzed
		}
		s.mu.Unlock()
	}
	return nil
}

func (s *Session) markSourcePendingIfCurrent(sourceURL string, version uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sourceVersions[sourceURL] == version && s.sourceStates[sourceURL] == sourceStateAnalyzing {
		s.sourceStates[sourceURL] = sourceStatePending
	}
}

func (s *Session) replaceStaticFromSourceLocked(sourceURL string, endpoints []StaticEndpoint) {
	sanitizedSourceURL := SanitizeURL(sourceURL)
	if len(s.static) > 0 {
		filtered := s.static[:0]
		for _, endpoint := range s.static {
			if endpoint.SourceJSURL == sanitizedSourceURL {
				continue
			}
			filtered = append(filtered, endpoint)
		}
		s.static = filtered
	}
	s.static = append(s.static, endpoints...)
}

func (s *Session) Report() Report {
	if s == nil {
		return BuildReport(nil, nil)
	}
	s.mu.Lock()
	static := append([]StaticEndpoint(nil), s.static...)
	runtime := append([]RuntimeRequest(nil), s.runtime...)
	entryURLs := append([]string(nil), s.entryURLs...)
	s.mu.Unlock()
	return buildReport(static, runtime, entryURLs)
}
