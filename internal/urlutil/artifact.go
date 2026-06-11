package urlutil

import (
	"crypto/sha256"
	"fmt"
	"net/url"
	"path"
	"strings"
)

// ArtifactFilename creates a stable, safe filename for a downloaded URL.
func ArtifactFilename(sourceURL, fallbackExt, fallbackStem string) string {
	base := fallbackStem
	if parsed, err := url.Parse(sourceURL); err == nil {
		if candidate := path.Base(parsed.Path); candidate != "" && candidate != "." && candidate != "/" {
			base = candidate
		}
	}
	ext := path.Ext(base)
	if ext == "" {
		ext = fallbackExt
	}
	stem := SanitizePathPart(strings.TrimSuffix(base, path.Ext(base)))
	if stem == "" {
		stem = fallbackStem
	}
	if len(stem) > 64 {
		stem = stem[:64]
	}
	sum := sha256.Sum256([]byte(sourceURL))
	return fmt.Sprintf("%s-%x%s", stem, sum[:4], ext)
}

// SanitizePathPart replaces characters that are unsafe in generated paths.
func SanitizePathPart(value string) string {
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
