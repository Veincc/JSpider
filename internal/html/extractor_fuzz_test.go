package html

import "testing"

func FuzzExtractEntryJS(f *testing.F) {
	for _, seed := range []struct {
		html string
		base string
	}{
		{`<script src="/assets/app.js"></script>`, "https://example.com/app/"},
		{`<base href="../static/"><script type="module">import("./entry.js")</script>`, "https://example.com/app/page"},
		{`<script src="&quot;><script src=//cdn.example.test/chunk.js>`, "https://example.com/"},
		{"\x00<html><script>import('/broken.js')", "http://[::1]:8080/"},
	} {
		f.Add(seed.html, seed.base)
	}

	extractor := NewExtractor()
	f.Fuzz(func(t *testing.T, document, baseURL string) {
		if len(document) > 1024*1024 || len(baseURL) > 64*1024 {
			t.Skip()
		}
		_ = extractor.ExtractEntryJS(document, baseURL)
		_ = extractor.ExtractModuleScripts(document, baseURL)
		_ = extractor.ExtractBaseHref(document)
	})
}
