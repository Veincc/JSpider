package apidiscovery

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Veincc/JSpider/internal/fileutil"
)

func WriteArtifacts(siteDir string, report Report) error {
	runtimeDir := filepath.Join(siteDir, "runtime")
	analysisDir := filepath.Join(siteDir, "analysis")
	// API artifacts can contain sanitized-but-sensitive structure, so keep
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
