package urlutil

import (
	"crypto/sha256"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

var originIDNA = idna.New(
	idna.MapForLookup(),
	idna.BidiRule(),
	idna.CheckHyphens(true),
	idna.CheckJoiners(true),
	idna.StrictDomainName(false),
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
		host, err = originIDNA.ToASCII(host)
		if err != nil {
			return "", fmt.Errorf("invalid IDNA hostname %q: %w", parsed.Hostname(), err)
		}
		host = strings.ToLower(host)
		if !isSupportedASCIIHostname(host) {
			return "", fmt.Errorf("invalid hostname %q", parsed.Hostname())
		}
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

	origins := make([]string, 0, len(bases))
	hashed := make(map[string]bool, len(bases))
	for origin, base := range bases {
		origins = append(origins, origin)
		hashed[origin] = baseCounts[base] > 1
	}
	sort.Strings(origins)

	for {
		names := make(map[string]string, len(origins))
		originsByName := make(map[string][]string, len(origins))
		for _, origin := range origins {
			name := bases[origin]
			if hashed[origin] {
				name = hashedOriginDirectory(name, origin)
			}
			names[origin] = name
			originsByName[name] = append(originsByName[name], origin)
		}

		finalNames := make([]string, 0, len(originsByName))
		for name := range originsByName {
			finalNames = append(finalNames, name)
		}
		sort.Strings(finalNames)

		collisionFound := false
		for _, name := range finalNames {
			collidingOrigins := originsByName[name]
			if len(collidingOrigins) < 2 {
				continue
			}
			collisionFound = true
			canResolve := false
			for _, origin := range collidingOrigins {
				if !hashed[origin] {
					hashed[origin] = true
					canResolve = true
				}
			}
			if !canResolve {
				return nil, fmt.Errorf("canonical origins %s still collide on directory %q after hashing", strings.Join(collidingOrigins, ", "), name)
			}
		}
		if !collisionFound {
			return names, nil
		}
	}
}

func hashedOriginDirectory(base, origin string) string {
	sum := sha256.Sum256([]byte(origin))
	return fmt.Sprintf("%s_%x", base, sum[:4])
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
		case r == '-' || r == '_':
			result.WriteRune(r)
		default:
			result.WriteByte('_')
		}
	}
	return strings.Trim(result.String(), "_")
}

func isSupportedASCIIHostname(host string) bool {
	for _, r := range host {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == '.':
		default:
			return false
		}
	}
	return true
}
