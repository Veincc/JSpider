package main

import (
	"fmt"
	"time"

	"github.com/Veincc/JSpider/internal/fetcher"
	"github.com/Veincc/JSpider/internal/logging"
)

type entryProgress struct {
	current     int
	total       int
	started     time.Time
	batchNumber int
	failed      int
}

func newEntryProgress(current, total int, started time.Time) *entryProgress {
	return &entryProgress{current: current, total: total, started: started}
}

func (p *entryProgress) prefix() string {
	return fmt.Sprintf("[%d/%d]", p.current, p.total)
}

type crawlBatchStats struct {
	number     int
	minDepth   int
	maxDepth   int
	attempted  int
	js         int
	nonJS      int
	failed     int
	analyzed   int
	discovered int
	next       int
	total      int
}

func newCrawlBatchStats(number int, batch []fetchReq) crawlBatchStats {
	stats := crawlBatchStats{number: number, attempted: len(batch)}
	if len(batch) == 0 {
		return stats
	}
	stats.minDepth, stats.maxDepth = batch[0].depth, batch[0].depth
	for _, item := range batch[1:] {
		if item.depth < stats.minDepth {
			stats.minDepth = item.depth
		}
		if item.depth > stats.maxDepth {
			stats.maxDepth = item.depth
		}
	}
	return stats
}

func (s *crawlBatchStats) observeFetch(result *fetcher.Result) {
	if result == nil {
		s.failed++
		return
	}
	if fetcher.IsNotJavaScript(result.Err) {
		s.nonJS++
		return
	}
	if result.Err != nil {
		s.failed++
		return
	}
	s.js++
}

func (s crawlBatchStats) depthLabel() string {
	if s.minDepth == s.maxDepth {
		return fmt.Sprintf("%d", s.minDepth)
	}
	return fmt.Sprintf("%d-%d", s.minDepth, s.maxDepth)
}

func formatElapsed(elapsed time.Duration) string {
	if elapsed < time.Second {
		return elapsed.Round(time.Millisecond).String()
	}
	return elapsed.Round(100 * time.Millisecond).String()
}

func (s crawlBatchStats) log(log *logging.Logger, progress *entryProgress, elapsed time.Duration) {
	log.Info("%s Batch %d: depth=%s attempted=%d js=%d non-js=%d failed=%d analyzed=%d discovered=%d next=%d total=%d elapsed=%s",
		progress.prefix(), s.number, s.depthLabel(), s.attempted, s.js, s.nonJS, s.failed,
		s.analyzed, s.discovered, s.next, s.total, formatElapsed(elapsed))
}
