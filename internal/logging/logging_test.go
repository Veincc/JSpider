package logging

import (
	"bytes"
	"strings"
	"testing"
)

func TestNewWithWritersRoutesByLevel(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	log := NewWithWriters(false, &stdout, &stderr)

	log.Info("info %d", 1)
	log.Verbose("hidden")
	log.Warn("warning")
	log.LogError("fetch", "failed")

	if got := stdout.String(); !strings.Contains(got, "info 1") || strings.Contains(got, "hidden") {
		t.Fatalf("stdout = %q", got)
	}
	if got := stderr.String(); !strings.Contains(got, "[WARN] warning") || !strings.Contains(got, "[ERR] fetch: failed") {
		t.Fatalf("stderr = %q", got)
	}
}
