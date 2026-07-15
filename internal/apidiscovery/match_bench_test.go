package apidiscovery

import (
	"fmt"
	"testing"
)

func BenchmarkBuildReportAssociation1000(b *testing.B) {
	benchmarkBuildReportAssociation(b, 1000)
}

func BenchmarkBuildReportAssociation10000(b *testing.B) {
	benchmarkBuildReportAssociation(b, 10000)
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
