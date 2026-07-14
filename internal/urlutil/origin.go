package urlutil

import (
	"crypto/sha256"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

// CanonicalOrigin returns the normalized HTTP(S) origin for rawURL.
func CanonicalOrigin(rawURL string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return "", fmt.Errorf("parse URL: %w", err)
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("unsupported URL scheme %q", parsed.Scheme)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("URL is missing a host")
	}
	if strings.HasSuffix(parsed.Host, ":") {
		return "", fmt.Errorf("URL has an empty port")
	}

	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return "", fmt.Errorf("URL is missing a hostname")
	}
	isIPv6 := strings.Contains(host, ":")
	if ip := net.ParseIP(host); ip != nil {
		host = strings.ToLower(ip.String())
		isIPv6 = strings.Contains(host, ":")
	} else {
		if isIPv6 {
			return "", fmt.Errorf("invalid IPv6 hostname %q", host)
		}
		host, err = idna.Lookup.ToASCII(host)
		if err != nil {
			return "", fmt.Errorf("invalid IDNA hostname %q: %w", parsed.Hostname(), err)
		}
		host = strings.ToLower(host)
	}

	port := parsed.Port()
	if port != "" {
		numericPort, err := strconv.Atoi(port)
		if err != nil || numericPort < 1 || numericPort > 65535 {
			return "", fmt.Errorf("invalid port %q", port)
		}
		port = strconv.Itoa(numericPort)
		if (scheme == "http" && numericPort == 80) || (scheme == "https" && numericPort == 443) {
			port = ""
		}
	}

	authority := host
	if isIPv6 {
		authority = "[" + host + "]"
	}
	if port != "" {
		authority = net.JoinHostPort(host, port)
	}
	return scheme + "://" + authority, nil
}

// OriginDirectoryNames precomputes deterministic output directory names for
// every distinct canonical origin represented by rawURLs.
func OriginDirectoryNames(rawURLs []string) (map[string]string, error) {
	if len(rawURLs) == 0 {
		return nil, fmt.Errorf("no URLs provided")
	}

	bases := make(map[string]string)
	baseCounts := make(map[string]int)
	for _, rawURL := range rawURLs {
		origin, err := CanonicalOrigin(rawURL)
		if err != nil {
			return nil, fmt.Errorf("canonicalize %q: %w", rawURL, err)
		}
		if _, exists := bases[origin]; exists {
			continue
		}
		base, err := originDirectoryBase(origin)
		if err != nil {
			return nil, err
		}
		bases[origin] = base
		baseCounts[base]++
	}

	names := make(map[string]string, len(bases))
	for origin, base := range bases {
		if baseCounts[base] > 1 {
			sum := sha256.Sum256([]byte(origin))
			base = fmt.Sprintf("%s_%x", base, sum[:4])
		}
		names[origin] = base
	}
	return names, nil
}

func originDirectoryBase(origin string) (string, error) {
	parsed, err := url.Parse(origin)
	if err != nil {
		return "", fmt.Errorf("parse canonical origin %q: %w", origin, err)
	}
	base := sanitizeOriginHost(parsed.Hostname())
	if base == "" {
		return "", fmt.Errorf("canonical origin %q has no usable hostname", origin)
	}
	if port := parsed.Port(); port != "" {
		base += "_" + port
	}
	return base, nil
}

func sanitizeOriginHost(host string) string {
	var result strings.Builder
	for _, r := range strings.ToLower(host) {
		switch {
		case r >= 'a' && r <= 'z':
			result.WriteRune(r)
		case r >= '0' && r <= '9':
			result.WriteRune(r)
		default:
			result.WriteByte('_')
		}
	}
	return strings.Trim(result.String(), "_")
}
