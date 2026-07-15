package apidiscovery

import (
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/Veincc/JSpider/internal/urlutil"
)

type normalizedPath struct {
	segments []string
}

type associationRecord struct {
	association  Association
	staticIndex  int
	runtimeIndex int
}

func BuildReport(static []StaticEndpoint, runtime []RuntimeRequest) Report {
	entryURLs := make([]string, 0, len(runtime))
	for _, request := range runtime {
		if request.EntryURL != "" {
			entryURLs = append(entryURLs, request.EntryURL)
		}
	}
	return buildReport(static, runtime, entryURLs)
}

func buildReport(static []StaticEndpoint, runtime []RuntimeRequest, entryURLs []string) Report {
	static = cloneStaticEndpoints(static)
	runtime = cloneRuntimeRequests(runtime)
	for i := range static {
		if !static[i].sourceIndexSet {
			static[i].SourceIndex = i
			static[i].sourceIndexSet = true
		}
		static[i].Version = Version
		ensureStaticCollections(&static[i])
	}
	for i := range runtime {
		if !runtime[i].runtimeIndexSet {
			runtime[i].RuntimeIndex = i
			runtime[i].runtimeIndexSet = true
		}
		runtime[i].Version = Version
		ensureRuntimeCollections(&runtime[i])
	}
	sortStaticEndpoints(static)
	sortRuntimeRequests(runtime)

	records := make([]associationRecord, 0)
	matchedStatic := make(map[int]bool)
	matchedRuntime := make(map[int]bool)
	runtimeIndex := newRuntimeAssociationIndex(runtime)
	for staticIndex := range static {
		for _, runtimeCandidate := range runtimeIndex.candidates(static[staticIndex]) {
			association, ok := associateOne(static[staticIndex], runtime[runtimeCandidate])
			if !ok {
				continue
			}
			records = append(records, associationRecord{
				association:  association,
				staticIndex:  staticIndex,
				runtimeIndex: runtimeCandidate,
			})
			matchedStatic[staticIndex] = true
			matchedRuntime[runtimeCandidate] = true
		}
	}
	sortAssociationRecords(records)
	associations := make([]Association, len(records))
	for index := range records {
		associations[index] = records[index].association
	}

	bases := buildBases(associations)
	endpoints := buildEndpoints(static, runtime, records, matchedStatic, matchedRuntime, bases, collectEntryOrigins(entryURLs))
	confirmed := 0
	for _, association := range associations {
		if association.Confidence == ConfidenceConfirmed {
			confirmed++
		}
	}

	return Report{
		StaticEndpoints: static,
		RuntimeRequests: runtime,
		Associations:    associations,
		Endpoints:       endpoints,
		Bases:           bases,
		Summary: Summary{
			Static:    len(static),
			Runtime:   countRuntimeAPIs(runtime),
			Matched:   len(associations),
			Confirmed: confirmed,
			Bases:     countConfirmedBases(bases),
		},
	}
}

func associateOne(static StaticEndpoint, runtime RuntimeRequest) (Association, bool) {
	if runtime.WebSocket || runtime.Preflight || !isRuntimeAPI(runtime.ResourceType) {
		return Association{}, false
	}
	staticMethod := strings.ToUpper(strings.TrimSpace(static.Method))
	runtimeMethod := strings.ToUpper(strings.TrimSpace(runtime.Method))
	if staticMethod != "" && runtimeMethod != "" && staticMethod != runtimeMethod {
		return Association{}, false
	}

	staticPath, ok := normalizeStaticPath(static.RawURL)
	if !ok {
		return Association{}, false
	}
	runtimeURL, err := url.Parse(runtime.URL)
	if err != nil || runtimeURL.Scheme == "" || runtimeURL.Host == "" {
		return Association{}, false
	}
	staticURL, err := url.Parse(strings.TrimSpace(static.RawURL))
	if err != nil {
		return Association{}, false
	}
	if staticURL.Host != "" {
		if !strings.EqualFold(staticURL.Host, runtimeURL.Host) {
			return Association{}, false
		}
		if staticURL.Scheme != "" && !strings.EqualFold(staticURL.Scheme, runtimeURL.Scheme) {
			return Association{}, false
		}
	} else if static.SourceIdentity.EntryURL != "" && runtime.EntryURL != static.SourceIdentity.EntryURL {
		return Association{}, false
	}
	runtimePath := normalizePath(runtimeURL.EscapedPath())
	// Match on whole path segments only. A suffix match can infer a gateway
	// prefix (/gw + /user/list), but must not let /user/list match /superuser/list.
	pathScore, prefixSegments, usedExpression, ok := matchPath(staticPath, runtimePath)
	if !ok {
		return Association{}, false
	}

	initiatorExact := containsString(runtime.Initiator.StackURLs, static.SourceJSURL) ||
		(runtime.Initiator.URL != "" && runtime.Initiator.URL == static.SourceJSURL)
	concreteSegments := 0
	for _, segment := range staticPath.segments {
		if segment != "EXPR" {
			concreteSegments++
		}
	}
	// One-segment paths such as /list are too generic for base inference unless
	// the runtime initiator proves they came from the same JavaScript source.
	if concreteSegments < 2 && !initiatorExact {
		return Association{}, false
	}

	score := pathScore
	evidence := []string{}
	if pathScore == 50 {
		evidence = append(evidence, "path_exact")
	} else {
		evidence = append(evidence, "path_suffix")
	}
	if staticMethod != "" && staticMethod == runtimeMethod {
		score += 20
		evidence = append(evidence, "method")
	}
	if initiatorExact {
		score += 30
		evidence = append(evidence, "initiator_exact")
	} else if sameFilename(static.SourceJSURL, append(runtime.Initiator.StackURLs, runtime.Initiator.URL)) {
		score += 10
		evidence = append(evidence, "initiator_filename")
	}
	if overlap := parameterOverlap(static.QueryParams, runtime.QueryParams); overlap > 0 {
		if overlap > 10 {
			overlap = 10
		}
		score += overlap
		evidence = append(evidence, "query_params")
	}
	if overlap := parameterOverlap(static.BodyParams, runtime.BodyParams); overlap > 0 {
		if overlap > 10 {
			overlap = 10
		}
		score += overlap
		evidence = append(evidence, "body_params")
	}
	runtimeOrigin := runtimeURL.Scheme + "://" + runtimeURL.Host
	if urlutil.GetOrigin(runtime.EntryURL) == runtimeOrigin {
		score += 5
		evidence = append(evidence, "entry_origin")
	}
	if usedExpression {
		score -= 5
		evidence = append(evidence, "expr_wildcard")
	}
	if score < 60 {
		return Association{}, false
	}

	prefix := ""
	if len(prefixSegments) > 0 {
		prefix = "/" + strings.Join(prefixSegments, "/")
	}
	confidence := ConfidenceCandidate
	if score >= 80 {
		confidence = ConfidenceConfirmed
	}
	method := runtimeMethod
	if method == "" {
		method = staticMethod
	}
	return Association{
		Version:        Version,
		SourceIndex:    static.SourceIndex,
		RuntimeIndex:   runtime.RuntimeIndex,
		SourceIdentity: static.SourceIdentity,
		EntryURL:       runtime.EntryURL,
		StaticRawURL:   static.RawURL,
		RuntimeURL:     runtime.URL,
		Method:         method,
		Score:          score,
		Confidence:     confidence,
		RuntimeOrigin:  runtimeOrigin,
		Prefix:         prefix,
		RuntimeBase:    runtimeOrigin + prefix,
		SourceJSURL:    static.SourceJSURL,
		InitiatorExact: initiatorExact,
		UsedExpression: usedExpression,
		Evidence:       evidence,
	}, true
}

func normalizeStaticPath(raw string) (normalizedPath, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return normalizedPath{}, false
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return normalizedPath{}, false
	}
	pathValue := parsed.EscapedPath()
	if pathValue == "" && parsed.Scheme == "" && parsed.Host == "" {
		pathValue = raw
		if index := strings.IndexAny(pathValue, "?#"); index >= 0 {
			pathValue = pathValue[:index]
		}
	}
	pathValue = strings.TrimPrefix(pathValue, "./")
	for strings.HasPrefix(pathValue, "../") {
		pathValue = strings.TrimPrefix(pathValue, "../")
	}
	if !strings.HasPrefix(pathValue, "/") {
		pathValue = "/" + pathValue
	}
	normalized := normalizePath(pathValue)
	return normalized, len(normalized.segments) > 0
}

func normalizePath(raw string) normalizedPath {
	parts := strings.Split(raw, "/")
	segments := make([]string, 0, len(parts))
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			continue
		}
		segments = append(segments, part)
	}
	return normalizedPath{segments: segments}
}

func matchPath(static, runtime normalizedPath) (int, []string, bool, bool) {
	if len(static.segments) == 0 || len(runtime.segments) < len(static.segments) {
		return 0, nil, false, false
	}
	offset := len(runtime.segments) - len(static.segments)
	usedExpression := false
	for _, segment := range static.segments {
		if segment == "EXPR" {
			usedExpression = true
			break
		}
	}
	if usedExpression && (static.segments[0] == "EXPR" || static.segments[len(static.segments)-1] == "EXPR") {
		return 0, nil, false, false
	}
	usedExpression = false
	for i, segment := range static.segments {
		runtimeSegment := runtime.segments[offset+i]
		if segment == "EXPR" {
			usedExpression = true
			continue
		}
		if segment != runtimeSegment {
			return 0, nil, false, false
		}
	}
	if offset == 0 {
		return 50, nil, usedExpression, true
	}
	return 45, append([]string(nil), runtime.segments[:offset]...), usedExpression, true
}

type runtimeAssociationIndex struct {
	exactAnyMethod      map[string][]int
	exactByMethod       map[string][]int
	exactWithoutMethod  map[string][]int
	expressionAnyMethod map[string][]int
	expressionByMethod  map[string][]int
	expressionNoMethod  map[string][]int
}

func newRuntimeAssociationIndex(runtime []RuntimeRequest) runtimeAssociationIndex {
	index := runtimeAssociationIndex{
		exactAnyMethod:      make(map[string][]int),
		exactByMethod:       make(map[string][]int),
		exactWithoutMethod:  make(map[string][]int),
		expressionAnyMethod: make(map[string][]int),
		expressionByMethod:  make(map[string][]int),
		expressionNoMethod:  make(map[string][]int),
	}
	for runtimeIndex, request := range runtime {
		parsed, err := url.Parse(request.URL)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			continue
		}
		pathValue := normalizePath(parsed.EscapedPath())
		if len(pathValue.segments) == 0 {
			continue
		}
		method := strings.ToUpper(strings.TrimSpace(request.Method))
		for start := range pathValue.segments {
			suffix := pathValue.segments[start:]
			exactKey := strings.Join(suffix, "\x1f")
			index.exactAnyMethod[exactKey] = append(index.exactAnyMethod[exactKey], runtimeIndex)
			if method == "" {
				index.exactWithoutMethod[exactKey] = append(index.exactWithoutMethod[exactKey], runtimeIndex)
			} else {
				key := method + "\x00" + exactKey
				index.exactByMethod[key] = append(index.exactByMethod[key], runtimeIndex)
			}

			// Expression candidates are keyed by their fixed prefix before the
			// first EXPR segment, the exact suffix length, and the final segment.
			// Generate each possible fixed-prefix length for this runtime suffix;
			// the paths are short and this avoids scanning every request sharing a
			// generic last segment.
			for prefixLength := 1; prefixLength < len(suffix); prefixLength++ {
				expressionKey := expressionAssociationKey(len(suffix), suffix[:prefixLength], suffix[len(suffix)-1])
				index.expressionAnyMethod[expressionKey] = append(index.expressionAnyMethod[expressionKey], runtimeIndex)
				if method == "" {
					index.expressionNoMethod[expressionKey] = append(index.expressionNoMethod[expressionKey], runtimeIndex)
				} else {
					key := method + "\x00" + expressionKey
					index.expressionByMethod[key] = append(index.expressionByMethod[key], runtimeIndex)
				}
			}
		}
	}
	return index
}

func (index runtimeAssociationIndex) candidates(static StaticEndpoint) []int {
	staticPath, ok := normalizeStaticPath(static.RawURL)
	if !ok || len(staticPath.segments) == 0 {
		return nil
	}
	method := strings.ToUpper(strings.TrimSpace(static.Method))
	firstExpression := -1
	for segmentIndex, segment := range staticPath.segments {
		if segment == "EXPR" {
			firstExpression = segmentIndex
			break
		}
	}
	if firstExpression < 0 {
		key := strings.Join(staticPath.segments, "\x1f")
		if method == "" {
			return index.exactAnyMethod[key]
		}
		return combineRuntimeCandidates(index.exactByMethod[method+"\x00"+key], index.exactWithoutMethod[key])
	}
	if firstExpression == 0 || staticPath.segments[len(staticPath.segments)-1] == "EXPR" {
		return nil
	}
	key := expressionAssociationKey(len(staticPath.segments), staticPath.segments[:firstExpression], staticPath.segments[len(staticPath.segments)-1])
	if method == "" {
		return index.expressionAnyMethod[key]
	}
	return combineRuntimeCandidates(index.expressionByMethod[method+"\x00"+key], index.expressionNoMethod[key])
}

func expressionAssociationKey(pathLength int, fixedPrefix []string, lastSegment string) string {
	return strconv.Itoa(pathLength) + "\x00" + strings.Join(fixedPrefix, "\x1f") + "\x00" + lastSegment
}

func combineRuntimeCandidates(first, second []int) []int {
	if len(first) == 0 {
		return second
	}
	if len(second) == 0 {
		return first
	}
	combined := make([]int, 0, len(first)+len(second))
	combined = append(combined, first...)
	combined = append(combined, second...)
	return combined
}

func buildBases(associations []Association) []RuntimeBase {
	type aggregate struct {
		origin      string
		prefix      string
		runtimeBase string
		pairs       []MatchedPair
		staticPaths map[string]bool
		singleHigh  bool
		totalScore  int
		entryURLs   map[string]bool
	}
	aggregates := make(map[string]*aggregate)
	for _, association := range associations {
		aggregateKey := association.RuntimeBase + "\x00" + association.EntryURL
		item := aggregates[aggregateKey]
		if item == nil {
			item = &aggregate{
				origin:      association.RuntimeOrigin,
				prefix:      association.Prefix,
				runtimeBase: association.RuntimeBase,
				staticPaths: make(map[string]bool),
				entryURLs:   make(map[string]bool),
			}
			aggregates[aggregateKey] = item
		}
		item.pairs = append(item.pairs, MatchedPair{
			StaticRawURL: association.StaticRawURL,
			RuntimeURL:   association.RuntimeURL,
			Score:        association.Score,
		})
		if association.EntryURL != "" {
			item.entryURLs[association.EntryURL] = true
		}
		// Count unique static interfaces, not query variants of the same path.
		item.staticPaths[staticInterfaceKey(association.StaticRawURL, association.Method)] = true
		item.totalScore += association.Score
		if association.Score >= 90 && association.InitiatorExact {
			item.singleHigh = true
		}
	}

	bases := make([]RuntimeBase, 0, len(aggregates))
	for _, item := range aggregates {
		sort.Slice(item.pairs, func(i, j int) bool {
			if item.pairs[i].StaticRawURL != item.pairs[j].StaticRawURL {
				return item.pairs[i].StaticRawURL < item.pairs[j].StaticRawURL
			}
			return item.pairs[i].RuntimeURL < item.pairs[j].RuntimeURL
		})
		confidence := ConfidenceCandidate
		if len(item.staticPaths) >= 2 || item.singleHigh {
			confidence = ConfidenceConfirmed
		}
		bases = append(bases, RuntimeBase{
			Version:       Version,
			Origin:        item.origin,
			Prefix:        item.prefix,
			RuntimeBase:   item.runtimeBase,
			Confidence:    confidence,
			EvidenceCount: len(item.pairs),
			MatchedPairs:  item.pairs,
			EntryURLs:     sortedStringSet(item.entryURLs),
			totalScore:    item.totalScore,
		})
	}
	sort.Slice(bases, func(i, j int) bool {
		if bases[i].Confidence != bases[j].Confidence {
			return bases[i].Confidence == ConfidenceConfirmed
		}
		if bases[i].EvidenceCount != bases[j].EvidenceCount {
			return bases[i].EvidenceCount > bases[j].EvidenceCount
		}
		leftScore := bases[i].totalScore
		rightScore := bases[j].totalScore
		if leftScore != rightScore {
			return leftScore > rightScore
		}
		if bases[i].RuntimeBase != bases[j].RuntimeBase {
			return bases[i].RuntimeBase < bases[j].RuntimeBase
		}
		return strings.Join(bases[i].EntryURLs, "\x00") < strings.Join(bases[j].EntryURLs, "\x00")
	})
	return bases
}

func buildEndpoints(static []StaticEndpoint, runtime []RuntimeRequest, associations []associationRecord, matchedStatic, matchedRuntime map[int]bool, bases []RuntimeBase, entryOrigins map[string]bool) []Endpoint {
	endpoints := make([]Endpoint, 0, len(associations)+len(static)+len(runtime))
	for _, record := range associations {
		association := record.association
		staticEndpoint := static[record.staticIndex]
		runtimeRequest := runtime[record.runtimeIndex]
		endpoints = append(endpoints, Endpoint{
			Version:            Version,
			SourceIndex:        staticEndpoint.SourceIndex,
			RuntimeIndex:       runtimeRequest.RuntimeIndex,
			SourceIdentity:     staticEndpoint.SourceIdentity,
			Kind:               EndpointMatched,
			RawURL:             association.StaticRawURL,
			ResolvedURL:        association.RuntimeURL,
			ResolvedCandidates: []string{},
			Method:             association.Method,
			Confidence:         association.Confidence,
			Score:              association.Score,
			SourceJSURLs:       nonEmptyStrings(staticEndpoint.SourceJSURL),
			RuntimeStatus:      runtimeRequest.StatusCode,
			RuntimeFailed:      runtimeRequest.Failed,
			QueryParams:        mergeParameters(staticEndpoint.QueryParams, runtimeRequest.QueryParams),
			BodyParams:         mergeParameters(staticEndpoint.BodyParams, runtimeRequest.BodyParams),
			Evidence:           cloneStrings(association.Evidence),
		})
	}

	confirmedBases := make([]RuntimeBase, 0)
	for _, base := range bases {
		if base.Confidence == ConfidenceConfirmed {
			confirmedBases = append(confirmedBases, base)
		}
	}
	for index, endpoint := range static {
		if matchedStatic[index] {
			continue
		}
		if !isReportableStaticOnly(endpoint, entryOrigins) {
			continue
		}
		candidates := resolveCandidates(endpoint, confirmedBases)
		endpoints = append(endpoints, Endpoint{
			Version:            Version,
			SourceIndex:        endpoint.SourceIndex,
			RuntimeIndex:       -1,
			SourceIdentity:     endpoint.SourceIdentity,
			Kind:               EndpointStaticOnly,
			RawURL:             endpoint.RawURL,
			ResolvedCandidates: candidates,
			Method:             endpoint.Method,
			Confidence:         ConfidenceCandidate,
			SourceJSURLs:       nonEmptyStrings(endpoint.SourceJSURL),
			QueryParams:        cloneParameters(endpoint.QueryParams),
			BodyParams:         cloneParameters(endpoint.BodyParams),
			Evidence:           []string{"static"},
		})
	}
	for index, request := range runtime {
		if matchedRuntime[index] || request.WebSocket || request.Preflight || !isRuntimeAPI(request.ResourceType) {
			continue
		}
		endpoints = append(endpoints, Endpoint{
			Version:            Version,
			SourceIndex:        -1,
			RuntimeIndex:       request.RuntimeIndex,
			Kind:               EndpointRuntimeOnly,
			ResolvedURL:        request.URL,
			ResolvedCandidates: []string{},
			Method:             request.Method,
			Confidence:         ConfidenceConfirmed,
			SourceJSURLs:       cloneStrings(request.Initiator.StackURLs),
			RuntimeStatus:      request.StatusCode,
			RuntimeFailed:      request.Failed,
			QueryParams:        cloneParameters(request.QueryParams),
			BodyParams:         cloneParameters(request.BodyParams),
			Evidence:           []string{"runtime"},
		})
	}
	sortEndpoints(endpoints)
	return endpoints
}

func resolveCandidates(endpoint StaticEndpoint, bases []RuntimeBase) []string {
	raw := endpoint.RawURL
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme != "" || parsed.Host != "" {
		return []string{}
	}
	staticPath, ok := normalizeStaticPath(raw)
	if !ok {
		return []string{}
	}
	suffix := strings.Join(staticPath.segments, "/")
	if suffix == "" || strings.Contains(suffix, "EXPR") {
		return []string{}
	}
	out := make([]string, 0, len(bases))
	seen := make(map[string]bool)
	for _, base := range bases {
		if endpoint.SourceIdentity.EntryURL != "" && !containsString(base.EntryURLs, endpoint.SourceIdentity.EntryURL) {
			continue
		}
		candidate := resolveAgainstBase(suffix, base)
		if !seen[candidate] {
			seen[candidate] = true
			out = append(out, candidate)
		}
	}
	if len(out) == 0 && endpoint.SourceIdentity.EntryURL != "" {
		base, baseErr := url.Parse(endpoint.SourceIdentity.EntryURL)
		if baseErr == nil && base.Scheme != "" && base.Host != "" {
			out = append(out, base.ResolveReference(parsed).String())
		}
	}
	return out
}

func sortedStringSet(values map[string]bool) []string {
	if len(values) == 0 {
		return []string{}
	}
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func resolveAgainstBase(staticPath string, base RuntimeBase) string {
	prefix := strings.Trim(base.Prefix, "/")
	if prefix != "" && hasSegmentPrefix(strings.Split(staticPath, "/"), strings.Split(prefix, "/")) {
		return strings.TrimSuffix(base.Origin, "/") + "/" + staticPath
	}
	return strings.TrimSuffix(base.RuntimeBase, "/") + "/" + staticPath
}

func hasSegmentPrefix(segments, prefix []string) bool {
	if len(prefix) == 0 || len(segments) < len(prefix) {
		return false
	}
	for index := range prefix {
		if segments[index] != prefix[index] {
			return false
		}
	}
	return true
}

func collectEntryOrigins(entryURLs []string) map[string]bool {
	origins := make(map[string]bool)
	for _, entryURL := range entryURLs {
		if origin := urlutil.GetOrigin(entryURL); origin != "" {
			origins[origin] = true
		}
	}
	return origins
}

func isReportableStaticOnly(endpoint StaticEndpoint, entryOrigins map[string]bool) bool {
	raw := strings.TrimSpace(endpoint.RawURL)
	if raw == "" || strings.HasPrefix(raw, "?") || strings.HasPrefix(raw, "#") {
		return false
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if parsed.Host != "" {
		origin := ""
		if parsed.Scheme != "" {
			origin = parsed.Scheme + "://" + parsed.Host
		}
		if (origin == "" || !entryOrigins[origin]) && strings.TrimSpace(endpoint.Method) == "" {
			return false
		}
	}
	switch strings.ToLower(path.Ext(parsed.Path)) {
	case ".htm", ".html", ".xhtml", ".pdf":
		return false
	}
	_, ok := normalizeStaticPath(raw)
	return ok
}

func staticInterfaceKey(raw, method string) string {
	normalized, ok := normalizeStaticPath(raw)
	if !ok {
		return strings.ToUpper(strings.TrimSpace(method)) + "\x00" + strings.TrimSpace(raw)
	}
	return strings.ToUpper(strings.TrimSpace(method)) + "\x00/" + strings.Join(normalized.segments, "/")
}

func isRuntimeAPI(resourceType string) bool {
	switch strings.ToLower(resourceType) {
	case "xhr", "fetch", "eventsource":
		return true
	default:
		return false
	}
}

func parameterOverlap(left, right []Parameter) int {
	rightNames := make(map[string]bool)
	for _, param := range right {
		rightNames[param.Name] = true
	}
	count := 0
	seen := make(map[string]bool)
	for _, param := range left {
		if rightNames[param.Name] && !seen[param.Name] {
			seen[param.Name] = true
			count++
		}
	}
	return count
}

func sameFilename(source string, initiators []string) bool {
	if source == "" {
		return false
	}
	sourceURL, err := url.Parse(source)
	if err != nil {
		return false
	}
	filename := path.Base(sourceURL.Path)
	if filename == "" || filename == "." || filename == "/" {
		return false
	}
	for _, candidate := range initiators {
		parsed, err := url.Parse(candidate)
		if err == nil && path.Base(parsed.Path) == filename {
			return true
		}
	}
	return false
}

func containsString(items []string, value string) bool {
	if value == "" {
		return false
	}
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}

func countConfirmedBases(bases []RuntimeBase) int {
	count := 0
	for _, base := range bases {
		if base.Confidence == ConfidenceConfirmed {
			count++
		}
	}
	return count
}

func countRuntimeAPIs(requests []RuntimeRequest) int {
	count := 0
	for _, request := range requests {
		if isRuntimeAPI(request.ResourceType) && !request.Preflight {
			count++
		}
	}
	return count
}

func ensureStaticCollections(endpoint *StaticEndpoint) {
	endpoint.RawURL = SanitizeURL(endpoint.RawURL)
	endpoint.Source = SanitizeSourceSnippet(endpoint.Source)
	endpoint.SourceJSURL = SanitizeURL(endpoint.SourceJSURL)
	endpoint.Headers = SanitizeHeaders(endpoint.Headers)
	if endpoint.QueryParams == nil {
		endpoint.QueryParams = []Parameter{}
	}
	if endpoint.BodyParams == nil {
		endpoint.BodyParams = []Parameter{}
	}
}

func ensureRuntimeCollections(request *RuntimeRequest) {
	request.URL = SanitizeURL(request.URL)
	request.EntryURL = SanitizeURL(request.EntryURL)
	request.DocumentURL = SanitizeURL(request.DocumentURL)
	request.RedirectFrom = SanitizeURL(request.RedirectFrom)
	request.RedirectTo = SanitizeURL(request.RedirectTo)
	request.Headers = SanitizeHeaders(request.Headers)
	request.Initiator.URL = SanitizeURL(request.Initiator.URL)
	for i := range request.Initiator.StackURLs {
		request.Initiator.StackURLs[i] = SanitizeURL(request.Initiator.StackURLs[i])
	}
	if request.QueryParams == nil {
		request.QueryParams = []Parameter{}
	}
	if request.BodyParams == nil {
		request.BodyParams = []Parameter{}
	}
	if request.Initiator.StackURLs == nil {
		request.Initiator.StackURLs = []string{}
	}
}

func mergeParameters(left, right []Parameter) []Parameter {
	out := append(append([]Parameter(nil), left...), right...)
	sortParameters(out)
	return deduplicateParameters(out)
}

func nonEmptyStrings(values ...string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func cloneStrings(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	return append([]string(nil), values...)
}

func cloneParameters(values []Parameter) []Parameter {
	if len(values) == 0 {
		return []Parameter{}
	}
	return append([]Parameter(nil), values...)
}

func sortStaticEndpoints(endpoints []StaticEndpoint) {
	sort.Slice(endpoints, func(i, j int) bool {
		if endpoints[i].RawURL != endpoints[j].RawURL {
			return endpoints[i].RawURL < endpoints[j].RawURL
		}
		if endpoints[i].Method != endpoints[j].Method {
			return endpoints[i].Method < endpoints[j].Method
		}
		if endpoints[i].SourceJSURL != endpoints[j].SourceJSURL {
			return endpoints[i].SourceJSURL < endpoints[j].SourceJSURL
		}
		if endpoints[i].Type != endpoints[j].Type {
			return endpoints[i].Type < endpoints[j].Type
		}
		return endpoints[i].SourceIndex < endpoints[j].SourceIndex
	})
}

func sortRuntimeRequests(requests []RuntimeRequest) {
	sort.Slice(requests, func(i, j int) bool {
		if requests[i].URL != requests[j].URL {
			return requests[i].URL < requests[j].URL
		}
		if requests[i].Method != requests[j].Method {
			return requests[i].Method < requests[j].Method
		}
		if requests[i].RequestID != requests[j].RequestID {
			return requests[i].RequestID < requests[j].RequestID
		}
		if requests[i].RedirectIndex != requests[j].RedirectIndex {
			return requests[i].RedirectIndex < requests[j].RedirectIndex
		}
		return requests[i].RuntimeIndex < requests[j].RuntimeIndex
	})
}

func sortAssociationRecords(records []associationRecord) {
	sort.Slice(records, func(i, j int) bool {
		left := records[i].association
		right := records[j].association
		if left.StaticRawURL != right.StaticRawURL {
			return left.StaticRawURL < right.StaticRawURL
		}
		if left.RuntimeURL != right.RuntimeURL {
			return left.RuntimeURL < right.RuntimeURL
		}
		if left.Score != right.Score {
			return left.Score > right.Score
		}
		if records[i].staticIndex != records[j].staticIndex {
			return records[i].staticIndex < records[j].staticIndex
		}
		return records[i].runtimeIndex < records[j].runtimeIndex
	})
}

func sortEndpoints(endpoints []Endpoint) {
	sort.Slice(endpoints, func(i, j int) bool {
		if endpoints[i].Kind != endpoints[j].Kind {
			return endpoints[i].Kind < endpoints[j].Kind
		}
		if endpoints[i].RawURL != endpoints[j].RawURL {
			return endpoints[i].RawURL < endpoints[j].RawURL
		}
		if endpoints[i].ResolvedURL != endpoints[j].ResolvedURL {
			return endpoints[i].ResolvedURL < endpoints[j].ResolvedURL
		}
		if endpoints[i].Method != endpoints[j].Method {
			return endpoints[i].Method < endpoints[j].Method
		}
		if endpoints[i].SourceIndex != endpoints[j].SourceIndex {
			return endpoints[i].SourceIndex < endpoints[j].SourceIndex
		}
		return endpoints[i].RuntimeIndex < endpoints[j].RuntimeIndex
	})
}
