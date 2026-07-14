package urlutil

import (
	"mime"
	"net"
	"net/url"
	"path"
	"strings"
)

// Resolve resolves a relative path against a base URL to produce an absolute URL.
func Resolve(baseURL, rel string) (string, error) {
	if rel == "" {
		return "", nil
	}

	// Handle //cdn.example.com/a.js form
	if strings.HasPrefix(rel, "//") {
		u, err := url.Parse(baseURL)
		if err != nil {
			return "", err
		}
		return u.Scheme + ":" + rel, nil
	}

	base, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	ref, err := url.Parse(rel)
	if err != nil {
		return "", err
	}

	resolved := base.ResolveReference(ref)
	// Strip fragment
	resolved.Fragment = ""
	return resolved.String(), nil
}

// NormalizeURL normalizes a URL for deduplication comparison.
func NormalizeURL(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL, err
	}
	u.Fragment = ""
	return u.String(), nil
}

// IsSameOrigin checks whether two URLs share the same origin.
func IsSameOrigin(u1, u2 string) bool {
	parsed1, err := url.Parse(u1)
	if err != nil {
		return false
	}
	parsed2, err := url.Parse(u2)
	if err != nil {
		return false
	}
	return parsed1.Scheme == parsed2.Scheme && parsed1.Host == parsed2.Host
}

// GetOrigin returns the origin (scheme + host) of a URL.
func GetOrigin(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// GetHost returns the host of a URL.
func GetHost(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Host
}

// IsAllowedDomain checks whether a URL is in the allowed domain list.
func IsAllowedDomain(rawURL string, allowedDomains []string, sameOriginURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return false
	}

	// Check same origin
	if sameOriginURL != "" && IsSameOrigin(rawURL, sameOriginURL) {
		return true
	}

	// Check allowed CDN domains
	for _, d := range allowedDomains {
		domain := normalizeAllowedDomain(d)
		if domain == "" {
			continue
		}
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}

	return false
}

func normalizeAllowedDomain(domain string) string {
	d := strings.TrimSpace(strings.ToLower(domain))
	d = strings.TrimSuffix(d, "/")
	if d == "" {
		return ""
	}
	if strings.Contains(d, "://") {
		if u, err := url.Parse(d); err == nil {
			d = u.Hostname()
		}
	} else if host, _, err := net.SplitHostPort(d); err == nil {
		d = host
	}
	d = strings.Trim(d, ".")
	return d
}

// IsJSPath checks whether a URL path looks like a JS file.
func IsJSPath(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	p := strings.ToLower(u.Path)
	if strings.HasSuffix(p, ".js") || strings.HasSuffix(p, ".mjs") {
		return true
	}
	// Check for chunk patterns in query
	q := strings.ToLower(u.RawQuery)
	if strings.Contains(q, "chunk") || strings.Contains(q, "module") {
		return true
	}
	return false
}

// IsJSContentType checks whether a Content-Type indicates JS.
func IsJSContentType(ct string) bool {
	mediaType, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return false
	}
	switch strings.ToLower(mediaType) {
	case "application/javascript", "text/javascript",
		"application/ecmascript", "text/ecmascript",
		"application/x-javascript", "text/x-javascript",
		"application/js", "text/js":
		return true
	default:
		return false
	}
}

// SanitizeDomain returns the non-collision-aware directory base for a URL.
// Call OriginDirectoryNames when naming more than one input origin.
func SanitizeDomain(rawURL string) string {
	origin, err := CanonicalOrigin(rawURL)
	if err != nil {
		return "unknown"
	}
	base, err := originDirectoryBase(origin)
	if err != nil {
		return "unknown"
	}
	return base
}

// SanitizeFilename converts a URL to a safe filename.
func SanitizeFilename(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "unknown"
	}
	p := u.Path
	if p == "" || p == "/" {
		p = "/index"
	}
	if u.RawQuery != "" {
		p += "?" + u.RawQuery
	}
	// Replace special characters
	p = strings.ReplaceAll(p, "/", "_")
	p = strings.ReplaceAll(p, "\\", "_")
	p = strings.ReplaceAll(p, ":", "_")
	p = strings.ReplaceAll(p, "?", "_")
	p = strings.ReplaceAll(p, "&", "_")
	p = strings.ReplaceAll(p, "=", "_")
	p = strings.ReplaceAll(p, " ", "_")
	// Limit length
	if len(p) > 200 {
		p = p[:200]
	}
	return strings.TrimPrefix(p, "_")
}

// ExtractBasePath extracts the base path from a URL for relative path resolution.
func ExtractBasePath(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return path.Dir(u.Path)
}

// IsCSSResource checks whether a URL is a CSS resource.
func IsCSSResource(rawURL string) bool {
	lower := strings.ToLower(rawURL)
	return strings.HasSuffix(lower, ".css") || strings.Contains(lower, ".css?")
}

// ResolveJS resolves a JS URL discovered by static or dynamic analysis against a
// base URL. It handles bare relative paths (e.g. "assets/chunks/x.js") by treating
// them as ./-relative. It does not rewrite repeated path segments because those
// segments are legal and may identify distinct server resources.
//
// This is the recommended resolver for all JS URL discovery paths:
//   - analyzer regex imports, mapDeps, asset maps
//   - headless network / DOM / response extraction
//
// Rules:
//   - Absolute http/https URLs: return after fragment removal.
//   - Protocol-relative (//...): resolve against base origin.
//   - Absolute paths (/assets/x.js): resolve against origin.
//   - Explicit relative (./x.js, ../x.js): standard Resolve.
//   - Bare relative (assets/chunks/x.js): treat as ./-relative.
func ResolveJS(baseURL, raw string) (string, error) {
	if raw == "" {
		return "", nil
	}

	var resolved string

	switch {
	case strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://"):
		resolved = raw

	case strings.HasPrefix(raw, "//"):
		u, err := url.Parse(baseURL)
		if err != nil {
			return "", err
		}
		resolved = u.Scheme + ":" + raw

	case strings.HasPrefix(raw, "/"):
		// Absolute path — resolve against origin
		u, err := url.Parse(baseURL)
		if err != nil {
			return "", err
		}
		ref, err := url.Parse(raw)
		if err != nil {
			return "", err
		}
		u.Path = ref.Path
		u.RawPath = ref.RawPath
		u.RawQuery = ref.RawQuery
		u.Fragment = ""
		resolved = u.String()

	case strings.HasPrefix(raw, "./") || strings.HasPrefix(raw, "../"):
		// Explicit relative — standard resolution
		var err error
		resolved, err = Resolve(baseURL, raw)
		if err != nil {
			return "", err
		}

	default:
		// Bare relative path (e.g. "assets/chunks/x.js" or "chunks/x.js").
		// Treat as "./<path>" so it resolves relative to the base URL's directory.
		var err error
		resolved, err = Resolve(baseURL, "./"+raw)
		if err != nil {
			return "", err
		}
	}

	if u, err := url.Parse(resolved); err == nil {
		u.Fragment = ""
		resolved = u.String()
	}

	return resolved, nil
}

// DeduplicatePathSegments is retained for API compatibility. Repeated URL path
// segments are legal, so the function intentionally returns its input unchanged.
func DeduplicatePathSegments(rawURL string) string {
	return rawURL
}

// ShouldAttemptJSFetch determines whether a URL should be attempted as a JS fetch.
// For static sources, requires .js/.mjs extension or chunk/module query patterns.
// For dynamic sources (headless_network, headless_dom, headless_response), allows
// attempting the fetch even without a .js extension — FetchJS will confirm via
// HTTP 200 + Content-Type + looksLikeJS.
func ShouldAttemptJSFetch(rawURL string, fromDynamic bool) bool {
	if fromDynamic {
		// Dynamic sources: attempt fetch for any HTTP(S) URL that isn't obviously non-JS.
		// Skip obvious non-JS resources.
		lower := strings.ToLower(rawURL)
		if strings.HasSuffix(lower, ".css") || strings.Contains(lower, ".css?") {
			return false
		}
		if strings.HasSuffix(lower, ".html") || strings.HasSuffix(lower, ".htm") {
			return false
		}
		if strings.HasSuffix(lower, ".json") && !strings.Contains(lower, "chunk") && !strings.Contains(lower, "module") {
			return false
		}
		if strings.HasSuffix(lower, ".xml") || strings.HasSuffix(lower, ".svg") {
			return false
		}
		if strings.HasSuffix(lower, ".png") || strings.HasSuffix(lower, ".jpg") || strings.HasSuffix(lower, ".gif") || strings.HasSuffix(lower, ".woff") || strings.HasSuffix(lower, ".woff2") {
			return false
		}
		return true
	}
	// Static sources: strict check — must look like JS by path.
	return IsJSPath(rawURL)
}
