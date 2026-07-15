package analyzer

import (
	"strings"
	"testing"

	"github.com/Veincc/JSpider/internal/logging"
)

var analyzerBenchmarkSink []JSAsset

func BenchmarkAnalyzerDiscoverJS(b *testing.B) {
	for _, size := range []int{100 * 1024, 1024 * 1024, 5 * 1024 * 1024} {
		b.Run(benchmarkSizeName(size), func(b *testing.B) {
			input := representativeJavaScript(size)
			if len(input) != size {
				b.Fatalf("benchmark input size = %d, want %d", len(input), size)
			}
			analyzer := NewAnalyzer(logging.New(false, ""))

			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				analyzerBenchmarkSink = analyzer.DiscoverJS(input, "https://example.com/assets/app.js")
			}
		})
	}
}

func benchmarkSizeName(size int) string {
	switch size {
	case 100 * 1024:
		return "100KiB"
	case 1024 * 1024:
		return "1MiB"
	case 5 * 1024 * 1024:
		return "5MiB"
	default:
		panic("unsupported analyzer benchmark size")
	}
}

func representativeJavaScript(size int) string {
	const block = `var api="/api/v1/items?limit=20";var route={path:"/items",component:function(){return import("./chunks/items.js")}};fetch("/api/v1/items");`
	var input strings.Builder
	input.Grow(size)
	for input.Len()+len(block) <= size {
		input.WriteString(block)
	}
	input.WriteString(strings.Repeat(" ", size-input.Len()))
	return input.String()
}
