package urlutil

import "testing"

func FuzzResolveAndCanonicalOrigin(f *testing.F) {
	for _, seed := range []struct {
		base string
		ref  string
	}{
		{"https://Example.COM:443/app/index.html", "../assets/app.js#fragment"},
		{"http://[2001:db8::1]:80/root/", "//cdn.example.test/chunk.js"},
		{"https://bücher.example/path/", "./mod.js?token=raw"},
		{"not a URL", "%zz"},
	} {
		f.Add(seed.base, seed.ref)
	}

	f.Fuzz(func(t *testing.T, baseURL, reference string) {
		if len(baseURL) > 64*1024 || len(reference) > 64*1024 {
			t.Skip()
		}

		resolved, _ := Resolve(baseURL, reference)
		_, _ = ResolveJS(baseURL, reference)
		for _, candidate := range []string{baseURL, resolved} {
			origin, err := CanonicalOrigin(candidate)
			if err != nil {
				continue
			}
			roundTrip, err := CanonicalOrigin(origin + "/")
			if err != nil || roundTrip != origin {
				t.Fatalf("canonical origin is not idempotent: first=%q second=%q err=%v", origin, roundTrip, err)
			}
		}
	})
}
