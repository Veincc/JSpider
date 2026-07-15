package preprocess

import (
	"context"
	"testing"
)

func FuzzParseApplicationSourceMap(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(`{"version":3,"sources":["src/app.ts"],"sourcesContent":["export const app = 1"]}`),
		[]byte(`{"version":3,"sections":[{"offset":{"line":0,"column":0},"map":{"version":3,"sources":["src/a.ts"],"sourcesContent":["a()"]}}]}`),
		[]byte(`{"version":3,"sources":["../node_modules/pkg/index.js"],"sourcesContent":["vendor()"]}`),
		[]byte(`{"version":3,"sections":[{"offset":{"line":-1,"column":0},"url":"data:application/json,%7B%7D"}]}`),
		[]byte("\x00{not-json"),
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 2*1024*1024 {
			t.Skip()
		}
		recovery, status, err := parseApplicationSourcesContext(context.Background(), data)
		if err != nil {
			t.Fatalf("background source-map parse error = %v", err)
		}
		if status != "used" && status != "no_application_sources" {
			t.Fatalf("unexpected source-map status %q", status)
		}
		if recovery.SourceCount < len(recovery.Files) || recovery.ContentSize < 0 {
			t.Fatalf("invalid source-map accounting: %+v", recovery)
		}
	})
}
