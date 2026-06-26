//go:build !cgo

package apidiscovery

import (
	"strings"
	"testing"
)

func TestNonCGOBuildReturnsClearError(t *testing.T) {
	err := CheckAvailable()
	if err == nil || !strings.Contains(err.Error(), "CGO-enabled build") {
		t.Fatalf("CheckAvailable() error = %v", err)
	}

	_, err = AnalyzeJavaScript([]byte(`fetch("/api")`), "https://example.com/app.js")
	if err == nil || !strings.Contains(err.Error(), "CGO-enabled build") {
		t.Fatalf("AnalyzeJavaScript() error = %v", err)
	}
}
