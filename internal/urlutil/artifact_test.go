package urlutil

import (
	"strings"
	"testing"
)

func TestArtifactFilename(t *testing.T) {
	got := ArtifactFilename("https://cdn.example/assets/app.min.js?v=1", ".js", "script")
	if !strings.HasPrefix(got, "app.min-") || !strings.HasSuffix(got, ".js") {
		t.Fatalf("ArtifactFilename() = %q", got)
	}
}

func TestSanitizePathPart(t *testing.T) {
	if got := SanitizePathPart("../src/app name.ts"); got != "src_app_name.ts" {
		t.Fatalf("SanitizePathPart() = %q", got)
	}
}
