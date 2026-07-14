package urlutil

import (
	"crypto/sha256"
	"fmt"
	"reflect"
	"testing"
)

func TestCanonicalOrigin(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "lowercase and fold HTTP port", raw: "HTTP://EXAMPLE.COM:80/path?q=1#fragment", want: "http://example.com"},
		{name: "fold HTTPS port", raw: "https://Example.COM:443/path", want: "https://example.com"},
		{name: "retain non-default port", raw: "https://Example.COM:8443/path", want: "https://example.com:8443"},
		{name: "normalize leading-zero port", raw: "http://example.com:080/path", want: "http://example.com"},
		{name: "IDNA hostname", raw: "https://BÜCHER.example/path", want: "https://xn--bcher-kva.example"},
		{name: "IPv6 default port", raw: "HTTP://[2001:DB8::1]:80/path", want: "http://[2001:db8::1]"},
		{name: "IPv6 non-default port", raw: "https://[2001:DB8::1]:8443/path", want: "https://[2001:db8::1]:8443"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CanonicalOrigin(tt.raw)
			if err != nil {
				t.Fatalf("CanonicalOrigin(%q) error = %v", tt.raw, err)
			}
			if got != tt.want {
				t.Fatalf("CanonicalOrigin(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestCanonicalOriginRejectsInvalidAuthorities(t *testing.T) {
	for _, raw := range []string{
		"ftp://example.com",
		"https://",
		"https://example.com:",
		"https://example.com:0",
		"https://example.com:65536",
		"https://\u200d.example",
	} {
		t.Run(raw, func(t *testing.T) {
			if _, err := CanonicalOrigin(raw); err == nil {
				t.Fatalf("CanonicalOrigin(%q) returned no error", raw)
			}
		})
	}
}

func TestOriginDirectoryNamesDefaultAndNonDefaultPorts(t *testing.T) {
	names, err := OriginDirectoryNames([]string{
		"https://example.com:443/one",
		"https://port.example:8443/two",
		"http://[2001:db8::1]:8080/three",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"https://example.com":       "example_com",
		"https://port.example:8443": "port_example_8443",
		"http://[2001:db8::1]:8080": "2001_db8__1_8080",
	}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("OriginDirectoryNames() = %#v, want %#v", names, want)
	}
}

func TestOriginDirectoryNamesHashesEveryHTTPHTTPSCollision(t *testing.T) {
	raw := []string{"http://example.com/a", "https://example.com/b"}
	names, err := OriginDirectoryNames(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, origin := range []string{"http://example.com", "https://example.com"} {
		want := "example_com_" + originHash8(origin)
		if names[origin] != want {
			t.Fatalf("directory for %s = %q, want %q", origin, names[origin], want)
		}
	}
}

func TestOriginDirectoryNamesHashesEverySanitizedHostCollision(t *testing.T) {
	raw := []string{"https://a-b.example/one", "https://a.b.example/two"}
	names, err := OriginDirectoryNames(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, origin := range []string{"https://a-b.example", "https://a.b.example"} {
		want := "a_b_example_" + originHash8(origin)
		if names[origin] != want {
			t.Fatalf("directory for %s = %q, want %q", origin, names[origin], want)
		}
	}
}

func TestOriginDirectoryNamesAreOrderIndependent(t *testing.T) {
	forward := []string{
		"https://example.com/a",
		"http://example.com/b",
		"https://other.example:9443/c",
		"https://example.com/d",
	}
	reverse := []string{forward[3], forward[2], forward[1], forward[0]}

	first, err := OriginDirectoryNames(forward)
	if err != nil {
		t.Fatal(err)
	}
	second, err := OriginDirectoryNames(reverse)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("directory names depend on order: %#v vs %#v", first, second)
	}
}

func originHash8(origin string) string {
	sum := sha256.Sum256([]byte(origin))
	return fmt.Sprintf("%x", sum[:4])
}
