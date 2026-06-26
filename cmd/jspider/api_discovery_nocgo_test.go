//go:build !cgo

package main

import (
	"strings"
	"testing"
)

func TestRunAPIDiscoveryRequiresCGOBuild(t *testing.T) {
	cfg := testConfig("https://example.com/", t.TempDir()+"/not-created")
	cfg.APIDiscovery = true

	err := run(cfg)
	if err == nil || !strings.Contains(err.Error(), "CGO-enabled build") {
		t.Fatalf("run() error = %v", err)
	}
}
