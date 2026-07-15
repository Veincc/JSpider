package apidiscovery

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Veincc/JSpider/internal/fileutil"
)

func EndpointURLs(report Report, entryURLs []string) []string {
	seen := make(map[string]struct{})
	for _, endpoint := range report.Endpoints {
		for _, candidate := range preferredEndpointCandidates(endpoint, entryURLs) {
			if normalized, ok := normalizeEndpointURL(candidate); ok {
				seen[normalized] = struct{}{}
			}
		}
	}
	urls := make([]string, 0, len(seen))
	for value := range seen {
		urls = append(urls, value)
	}
	sort.Strings(urls)
	return urls
}

func preferredEndpointCandidates(endpoint Endpoint, entryURLs []string) []string {
	if value := strings.TrimSpace(endpoint.ResolvedURL); value != "" {
		return []string{value}
	}
	resolved := make([]string, 0, len(endpoint.ResolvedCandidates))
	for _, candidate := range endpoint.ResolvedCandidates {
		if strings.TrimSpace(candidate) != "" {
			resolved = append(resolved, candidate)
		}
	}
	if len(resolved) > 0 {
		return resolved
	}
	raw := strings.TrimSpace(endpoint.RawURL)
	if raw == "" || strings.HasPrefix(raw, "?") || strings.HasPrefix(raw, "#") {
		return nil
	}
	reference, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	if reference.Scheme != "" {
		return []string{raw}
	}
	if endpoint.SourceIdentity.EntryURL != "" {
		base, err := url.Parse(endpoint.SourceIdentity.EntryURL)
		if err == nil && base.Scheme != "" && base.Host != "" {
			return []string{base.ResolveReference(reference).String()}
		}
		return nil
	}
	var candidates []string
	for _, entryURL := range entryURLs {
		base, err := url.Parse(entryURL)
		if err != nil || base.Scheme == "" || base.Host == "" {
			continue
		}
		candidates = append(candidates, base.ResolveReference(reference).String())
	}
	return candidates
}

func normalizeEndpointURL(raw string) (string, bool) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" {
		return "", false
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https":
	default:
		return "", false
	}
	if strings.Contains(parsed.Path, "EXPR") {
		return "", false
	}
	parsed.Fragment = ""
	parsed.RawFragment = ""
	return parsed.String(), true
}

func WriteEndpointURLs(siteDir string, values []string) error {
	values = append([]string(nil), values...)
	sort.Strings(values)
	values = deduplicateStrings(values)
	var output bytes.Buffer
	for _, value := range values {
		output.WriteString(value)
		output.WriteByte('\n')
	}
	return fileutil.WriteFileAtomic(filepath.Join(siteDir, "endpoints.txt"), output.Bytes(), 0600)
}

func deduplicateStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := values[:1]
	for _, value := range values[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}

func WriteArtifacts(siteDir string, report Report) error {
	runtimeDir := filepath.Join(siteDir, "runtime")
	analysisDir := filepath.Join(siteDir, "analysis")
	// API artifacts can contain sensitive request data, so keep
	// output directories private even when the parent site directory is shared.
	if err := ensurePrivateDir(runtimeDir); err != nil {
		return fmt.Errorf("create runtime output directory: %w", err)
	}
	if err := ensurePrivateDir(analysisDir); err != nil {
		return fmt.Errorf("create analysis output directory: %w", err)
	}

	runtimeData, err := marshalJSONLines(report.RuntimeRequests)
	if err != nil {
		return fmt.Errorf("encode runtime requests: %w", err)
	}
	staticData, err := marshalJSONLines(report.StaticEndpoints)
	if err != nil {
		return fmt.Errorf("encode static endpoints: %w", err)
	}
	endpointsData, err := marshalJSONLines(report.Endpoints)
	if err != nil {
		return fmt.Errorf("encode endpoints: %w", err)
	}
	files := []struct {
		path string
		data []byte
	}{
		{filepath.Join(runtimeDir, "requests.jsonl"), runtimeData},
		{filepath.Join(analysisDir, "static-endpoints.jsonl"), staticData},
		{filepath.Join(analysisDir, "endpoints.jsonl"), endpointsData},
	}
	bases := struct {
		Version int           `json:"version"`
		Bases   []RuntimeBase `json:"bases"`
	}{Version: Version, Bases: report.Bases}
	basesData, err := json.Marshal(bases)
	if err != nil {
		return fmt.Errorf("encode runtime bases: %w", err)
	}
	basesData = append(basesData, '\n')
	files = append(files, struct {
		path string
		data []byte
	}{filepath.Join(analysisDir, "runtime-bases.json"), basesData})

	for _, file := range files {
		if err := fileutil.WriteFileAtomic(file.path, file.data, 0600); err != nil {
			return err
		}
	}
	return nil
}

func ensurePrivateDir(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	return os.Chmod(path, 0700)
}

func marshalJSONLines[T any](values []T) ([]byte, error) {
	var output bytes.Buffer
	for index, value := range values {
		encoded, err := json.Marshal(value)
		if err != nil {
			return nil, fmt.Errorf("encode JSONL item %d: %w", index, err)
		}
		output.Write(encoded)
		output.WriteByte('\n')
	}
	return output.Bytes(), nil
}
