package apidiscovery

import (
	"fmt"
	"strings"
	"testing"
)

func BenchmarkBuildReportAssociation1000(b *testing.B) {
	benchmarkBuildReportAssociation(b, 1000)
}

func BenchmarkBuildReportAssociation10000(b *testing.B) {
	benchmarkBuildReportAssociation(b, 10000)
}

func BenchmarkBuildReportExpressionCollisions1000(b *testing.B) {
	benchmarkBuildReportExpressionCollisions(b, 1000)
}

func BenchmarkBuildReportExpressionCollisions10000(b *testing.B) {
	benchmarkBuildReportExpressionCollisions(b, 10000)
}

func BenchmarkRuntimeAssociationIndexLongExactPath100(b *testing.B) {
	benchmarkRuntimeAssociationIndexLongExactPath(b, 100)
}

func BenchmarkRuntimeAssociationIndexLongExactPath1000(b *testing.B) {
	benchmarkRuntimeAssociationIndexLongExactPath(b, 1000)
}

func benchmarkBuildReportAssociation(b *testing.B, count int) {
	static := make([]StaticEndpoint, count)
	runtime := make([]RuntimeRequest, count)
	for index := 0; index < count; index++ {
		path := fmt.Sprintf("/api/%05d/users", index)
		static[index] = StaticEndpoint{RawURL: path, Method: "GET"}
		runtime[index] = RuntimeRequest{
			RequestID: fmt.Sprintf("request-%05d", index),
			URL:       "https://example.com/gateway" + path, Method: "GET", ResourceType: "Fetch",
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		report := BuildReport(static, runtime)
		if len(report.Associations) != count {
			b.Fatalf("associations = %d, want %d", len(report.Associations), count)
		}
	}
}

func benchmarkBuildReportExpressionCollisions(b *testing.B, count int) {
	static := make([]StaticEndpoint, count)
	runtime := make([]RuntimeRequest, count)
	for index := 0; index < count; index++ {
		static[index] = StaticEndpoint{
			RawURL: fmt.Sprintf("/api/EXPR/item-%05d/users", index), Method: "GET",
		}
		runtime[index] = RuntimeRequest{
			RequestID: fmt.Sprintf("request-%05d", index),
			URL:       fmt.Sprintf("https://example.com/gateway/api/value/item-%05d/users", index),
			Method:    "GET", ResourceType: "Fetch",
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		report := BuildReport(static, runtime)
		if len(report.Associations) != count {
			b.Fatalf("associations = %d, want %d", len(report.Associations), count)
		}
	}
}

func benchmarkRuntimeAssociationIndexLongExactPath(b *testing.B, segmentCount int) {
	segments := make([]string, segmentCount)
	for index := range segments {
		segments[index] = fmt.Sprintf("segment-%05d", index)
	}
	pathValue := "/" + strings.Join(segments, "/")
	static := []StaticEndpoint{{RawURL: pathValue, Method: "GET"}}
	runtime := []RuntimeRequest{{
		URL: "https://example.com/gateway" + pathValue, Method: "GET", ResourceType: "Fetch",
	}}
	b.ReportAllocs()
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		index := newRuntimeAssociationIndex(static, runtime)
		if candidates := index.candidates(static[0]); len(candidates) != 1 {
			b.Fatalf("candidates = %v, want one", candidates)
		}
	}
}
