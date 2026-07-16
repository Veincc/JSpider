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

type sourceKey struct {
	identity  SourceIdentity
	sourceURL string
}

type Session struct {
	mu sync.Mutex
	// cond coordinates callers so every concurrent AnalyzeSources invocation
	// observes the result of the single active execution instead of returning
	// while that execution is still in progress.
	cond               *sync.Cond
	analysisRunning    bool
	analysisGeneration uint64
	analysisCompleted  uint64
	analysisResults    map[uint64]error
	analysisWaiters    map[uint64]int
	analyzeSource      func([]byte, string) ([]StaticEndpoint, error)

	static           []StaticEndpoint
	runtime          []RuntimeRequest
	entryURLs        []string
	entryURLSet      map[string]struct{}
	sources          map[sourceKey][]byte
	sourceIdentities map[SourceIdentity]struct{}
	entryStats       map[string]SessionStats
	sourceStates     map[sourceKey]sourceAnalysisState
	sourceIndices    map[sourceKey]int
	identityIndices  map[SourceIdentity]int
	nextSourceIndex  int
	nextRuntimeIndex int
	// sourceVersions changes every time AddSource replaces a URL's bytes.
	// AnalyzeSources uses it to discard stale analysis results if a source is
	// updated while jsluice is running outside the lock.
	sourceVersions map[sourceKey]uint64
}

func NewSession() *Session {
	session := &Session{
		sources:          make(map[sourceKey][]byte),
		sourceIdentities: make(map[SourceIdentity]struct{}),
		entryStats:       make(map[string]SessionStats),
		entryURLSet:      make(map[string]struct{}),
		sourceStates:     make(map[sourceKey]sourceAnalysisState),
		sourceIndices:    make(map[sourceKey]int),
		identityIndices:  make(map[SourceIdentity]int),
		sourceVersions:   make(map[sourceKey]uint64),
		analysisResults:  make(map[uint64]error),
		analysisWaiters:  make(map[uint64]int),
		analyzeSource:    AnalyzeJavaScript,
	}
	session.cond = sync.NewCond(&session.mu)
	return session
}

func (s *Session) AddEntryURL(entryURL string) {
	if s == nil || entryURL == "" {
		return
	}
	s.mu.Lock()
	if s.entryURLSet == nil {
		s.entryURLSet = make(map[string]struct{})
	}
	if _, exists := s.entryURLSet[entryURL]; exists {
		s.mu.Unlock()
		return
	}
	s.entryURLSet[entryURL] = struct{}{}
	s.entryURLs = append(s.entryURLs, entryURL)
	s.mu.Unlock()
}

func (s *Session) AddStatic(endpoints []StaticEndpoint) {
	if s == nil || len(endpoints) == 0 {
		return
	}
	s.mu.Lock()
	cloned := cloneStaticEndpoints(endpoints)
	for index := range cloned {
		if !cloned[index].sourceIndexSet {
			cloned[index].SourceIndex = s.nextSourceIndex
			cloned[index].sourceIndexSet = true
			s.nextSourceIndex++
		}
	}
	s.static = append(s.static, cloned...)
	s.mu.Unlock()
}

func (s *Session) AddRuntime(requests []RuntimeRequest) {
	s.AddRuntimeForEntry("", requests)
}

// AddRuntimeForEntry associates collected browser requests with the entry
// that initiated discovery. Existing non-empty request identities win.
func (s *Session) AddRuntimeForEntry(entryURL string, requests []RuntimeRequest) {
	if s == nil || len(requests) == 0 {
		return
	}
	collected := cloneRuntimeRequests(requests)
	s.mu.Lock()
	if s.entryStats == nil {
		s.entryStats = make(map[string]SessionStats)
	}
	for i := range collected {
		collected[i].RuntimeIndex = s.nextRuntimeIndex
		collected[i].runtimeIndexSet = true
		s.nextRuntimeIndex++
		if collected[i].EntryURL == "" {
			collected[i].EntryURL = entryURL
		}
		if isRuntimeAPI(collected[i].ResourceType) && !collected[i].WebSocket && !collected[i].Preflight {
			stats := s.entryStats[collected[i].EntryURL]
			stats.Runtime++
			s.entryStats[collected[i].EntryURL] = stats
		}
	}
	s.runtime = append(s.runtime, collected...)
	s.mu.Unlock()
}

func (s *Session) AddSource(sourceURL string, source []byte) {
	s.AddSourceWithIdentity(SourceIdentity{FinalURL: sourceURL}, sourceURL, source)
}

// AddSourceWithIdentity records the complete fetch identity and an analysis
// unit URL. Units from one fetch share a stable source index, while identical
// final URLs reached from different entries remain separate provenance.
func (s *Session) AddSourceWithIdentity(identity SourceIdentity, sourceURL string, source []byte) {
	if s == nil || sourceURL == "" {
		return
	}
	s.mu.Lock()
	if s.sourceIdentities == nil {
		s.sourceIdentities = make(map[SourceIdentity]struct{})
	}
	if identity.FinalURL == "" {
		identity.FinalURL = sourceURL
	}
	if _, exists := s.sourceIdentities[identity]; !exists {
		s.sourceIdentities[identity] = struct{}{}
		if s.entryStats == nil {
			s.entryStats = make(map[string]SessionStats)
		}
		stats := s.entryStats[identity.EntryURL]
		stats.Sources++
		s.entryStats[identity.EntryURL] = stats
	}
	if s.sources == nil {
		s.sources = make(map[sourceKey][]byte)
	}
	if s.sourceStates == nil {
		s.sourceStates = make(map[sourceKey]sourceAnalysisState)
	}
	if s.sourceIndices == nil {
		s.sourceIndices = make(map[sourceKey]int)
	}
	if s.identityIndices == nil {
		s.identityIndices = make(map[SourceIdentity]int)
	}
	if s.sourceVersions == nil {
		s.sourceVersions = make(map[sourceKey]uint64)
	}
	key := sourceKey{identity: identity, sourceURL: sourceURL}
	if existing, ok := s.sources[key]; ok && bytes.Equal(existing, source) {
		s.mu.Unlock()
		return
	}
	if _, exists := s.sourceIndices[key]; !exists {
		sourceIndex, identityExists := s.identityIndices[identity]
		if !identityExists {
			sourceIndex = s.nextSourceIndex
			s.identityIndices[identity] = sourceIndex
			s.nextSourceIndex++
		}
		s.sourceIndices[key] = sourceIndex
	}
	// Replacing source bytes invalidates only the static endpoints that came
	// from this JavaScript URL; runtime evidence is kept independently.
	s.sources[key] = append([]byte(nil), source...)
	s.sourceVersions[key]++
	s.sourceStates[key] = sourceStatePending
	s.mu.Unlock()
}

// Stats returns a per-entry collection snapshot without running jsluice or
// building the final association report.
func (s *Session) Stats(entryURL string) SessionStats {
	if s == nil {
		return SessionStats{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.entryStats[entryURL]
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
	s.ensureAnalysisStateLocked()
	if s.analysisRunning {
		generation := s.analysisGeneration
		s.analysisWaiters[generation]++
		for s.analysisCompleted < generation {
			s.cond.Wait()
		}
		err := s.analysisResults[generation]
		s.analysisWaiters[generation]--
		if s.analysisWaiters[generation] == 0 {
			delete(s.analysisWaiters, generation)
			delete(s.analysisResults, generation)
		}
		s.mu.Unlock()
		return err
	}
	s.analysisRunning = true
	s.analysisGeneration++
	generation := s.analysisGeneration
	s.mu.Unlock()

	for {
		s.mu.Lock()
		keys, sources, versions := s.pendingSourceBatchLocked()
		s.mu.Unlock()
		if len(keys) == 0 {
			s.finishAnalysis(generation, nil)
			return nil
		}

		results := make(map[sourceKey][]StaticEndpoint, len(keys))
		for _, key := range keys {
			endpoints, err := s.analyzeSource(sources[key], key.sourceURL)
			if err != nil {
				s.rollbackSourceBatch(keys, versions)
				s.finishAnalysis(generation, err)
				return err
			}
			results[key] = endpoints
		}

		s.mu.Lock()
		for _, key := range keys {
			// If AddSource replaced this record while analysis ran, discard the
			// stale result and leave the new version pending for the next batch.
			if s.sourceVersions[key] == versions[key] && s.sourceStates[key] == sourceStateAnalyzing {
				s.replaceStaticFromSourceLocked(key, results[key])
				s.sourceStates[key] = sourceStateAnalyzed
			}
		}
		s.mu.Unlock()
	}
}

func (s *Session) ensureAnalysisStateLocked() {
	if s.cond == nil {
		s.cond = sync.NewCond(&s.mu)
	}
	if s.analysisResults == nil {
		s.analysisResults = make(map[uint64]error)
	}
	if s.analysisWaiters == nil {
		s.analysisWaiters = make(map[uint64]int)
	}
	if s.analyzeSource == nil {
		s.analyzeSource = AnalyzeJavaScript
	}
}

func (s *Session) pendingSourceBatchLocked() ([]sourceKey, map[sourceKey][]byte, map[sourceKey]uint64) {
	keys := make([]sourceKey, 0, len(s.sources))
	sources := make(map[sourceKey][]byte)
	versions := make(map[sourceKey]uint64)
	if s.sourceStates == nil {
		s.sourceStates = make(map[sourceKey]sourceAnalysisState)
	}
	if s.sourceVersions == nil {
		s.sourceVersions = make(map[sourceKey]uint64)
	}
	for key, source := range s.sources {
		if s.sourceStates[key] == sourceStateAnalyzed || s.sourceStates[key] == sourceStateAnalyzing {
			continue
		}
		// Mark in-progress before releasing the lock so parallel callers do not
		// enqueue the same source for duplicate analysis.
		s.sourceStates[key] = sourceStateAnalyzing
		keys = append(keys, key)
		sources[key] = append([]byte(nil), source...)
		versions[key] = s.sourceVersions[key]
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].sourceURL != keys[j].sourceURL {
			return keys[i].sourceURL < keys[j].sourceURL
		}
		if keys[i].identity.EntryURL != keys[j].identity.EntryURL {
			return keys[i].identity.EntryURL < keys[j].identity.EntryURL
		}
		if keys[i].identity.RequestedURL != keys[j].identity.RequestedURL {
			return keys[i].identity.RequestedURL < keys[j].identity.RequestedURL
		}
		if keys[i].identity.FinalURL != keys[j].identity.FinalURL {
			return keys[i].identity.FinalURL < keys[j].identity.FinalURL
		}
		return keys[i].identity.ContentHash < keys[j].identity.ContentHash
	})
	return keys, sources, versions
}

func (s *Session) rollbackSourceBatch(keys []sourceKey, versions map[sourceKey]uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, key := range keys {
		if s.sourceVersions[key] == versions[key] && s.sourceStates[key] == sourceStateAnalyzing {
			s.sourceStates[key] = sourceStatePending
		}
	}
}

func (s *Session) finishAnalysis(generation uint64, err error) {
	s.mu.Lock()
	s.analysisRunning = false
	s.analysisCompleted = generation
	if s.analysisWaiters[generation] > 0 {
		s.analysisResults[generation] = err
	}
	s.cond.Broadcast()
	s.mu.Unlock()
}

func (s *Session) replaceStaticFromSourceLocked(key sourceKey, endpoints []StaticEndpoint) {
	sourceIndex := s.sourceIndices[key]
	if len(s.static) > 0 {
		filtered := s.static[:0]
		for _, endpoint := range s.static {
			if endpoint.SourceIndex == sourceIndex && endpoint.SourceIdentity == key.identity && endpoint.SourceJSURL == key.sourceURL {
				continue
			}
			filtered = append(filtered, endpoint)
		}
		s.static = filtered
	}
	for index := range endpoints {
		endpoints[index].SourceIndex = sourceIndex
		endpoints[index].SourceIdentity = key.identity
		endpoints[index].sourceIndexSet = true
	}
	s.static = append(s.static, endpoints...)
}

func (s *Session) Report() Report {
	if s == nil {
		return BuildReport(nil, nil)
	}
	s.mu.Lock()
	static := cloneStaticEndpoints(s.static)
	runtime := cloneRuntimeRequests(s.runtime)
	entryURLs := append([]string(nil), s.entryURLs...)
	s.mu.Unlock()
	return buildReport(static, runtime, entryURLs)
}
