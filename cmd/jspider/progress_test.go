package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Veincc/JSpider/internal/fetcher"
	"github.com/Veincc/JSpider/internal/logging"
)

func TestCrawlBatchStatsFormatsUniformAndMixedDepth(t *testing.T) {
	uniform := newCrawlBatchStats(1, []fetchReq{{depth: 2}, {depth: 2}})
	if got := uniform.depthLabel(); got != "2" {
		t.Fatalf("uniform depth = %q, want 2", got)
	}
	mixed := newCrawlBatchStats(2, []fetchReq{{depth: 3}, {depth: 1}, {depth: 2}})
	if got := mixed.depthLabel(); got != "1-3" {
		t.Fatalf("mixed depth = %q, want 1-3", got)
	}
}

func TestCrawlBatchStatsSeparatesFetchOutcomes(t *testing.T) {
	stats := newCrawlBatchStats(1, []fetchReq{{depth: 0}, {depth: 0}, {depth: 0}})
	stats.observeFetch(&fetcher.Result{IsJS: true})
	stats.observeFetch(&fetcher.Result{Err: &fetcher.ErrNotJavaScript{ContentType: "application/json"}})
	stats.observeFetch(&fetcher.Result{Err: errors.New("connection reset")})
	if stats.js != 1 || stats.nonJS != 1 || stats.failed != 1 {
		t.Fatalf("outcomes = %+v", stats)
	}
}

func TestCrawlBatchStatsLogsFixedSummary(t *testing.T) {
	var stdout bytes.Buffer
	log := logging.NewWithWriters(false, &stdout, nil)
	progress := newEntryProgress(1, 2, time.Now())
	stats := newCrawlBatchStats(3, []fetchReq{{depth: 1}, {depth: 1}})
	stats.js = 1
	stats.nonJS = 1
	stats.analyzed = 1
	stats.discovered = 7
	stats.next = 7
	stats.total = 9
	stats.log(log, progress, 1500*time.Millisecond)

	want := "[1/2] Batch 3: depth=1 attempted=2 js=1 non-js=1 failed=0 analyzed=1 discovered=7 next=7 total=9 elapsed=1.5s"
	if got := stdout.String(); !strings.Contains(got, want) || strings.Count(got, "Batch 3:") != 1 {
		t.Fatalf("batch log = %q, want one %q", got, want)
	}
}
