package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"

	"github.com/Veincc/JSpider/internal/apidiscovery"
	"github.com/Veincc/JSpider/internal/logging"
)

// finalizeOutputs performs every independent close/write action it can. Site
// and action errors are joined only after all initialized origins have had a
// chance to finalize.
func finalizeOutputs(outDir string, sites map[string]*siteRuntime, apiEnabled bool, log *logging.Logger) error {
	origins := make([]string, 0, len(sites))
	for origin := range sites {
		origins = append(origins, origin)
	}
	sort.Strings(origins)

	var allErrors []error
	for _, origin := range origins {
		site := sites[origin]
		if site == nil {
			continue
		}
		var siteErrors []error
		if site.processor != nil {
			if err := site.processor.Close(); err != nil {
				siteErrors = append(siteErrors, fmt.Errorf("close JavaScript processor for %s: %w", site.directory, err))
			}
			site.processor = nil
		}
		if site.store == nil {
			siteErrors = append(siteErrors, fmt.Errorf("missing output store for %s", site.directory))
		} else if err := site.store.WriteJSMap(site.directory); err != nil {
			siteErrors = append(siteErrors, fmt.Errorf("write JavaScript map for %s: %w", site.directory, err))
		}

		if apiEnabled {
			session := site.apiSession
			if session == nil {
				siteErrors = append(siteErrors, fmt.Errorf("missing API discovery session for %s", site.directory))
			} else {
				// Analysis may fail after producing useful partial static results. Build
				// the report once regardless so independent runtime evidence is retained.
				if err := session.AnalyzeSources(); err != nil {
					siteErrors = append(siteErrors, fmt.Errorf("analyze discovered JavaScript APIs for %s: %w", site.directory, err))
				}
				report := session.Report()
				logAPIReport(log, site.directory, report)
				urls := apidiscovery.EndpointURLs(report, site.entryURLs)
				if err := apidiscovery.WriteEndpointURLs(filepath.Join(outDir, site.directory), urls); err != nil {
					siteErrors = append(siteErrors, fmt.Errorf("write endpoints for %s: %w", site.directory, err))
				}
			}
		}

		site.finalizeErr = errors.Join(siteErrors...)
		if site.finalizeErr != nil {
			allErrors = append(allErrors, site.finalizeErr)
		}
	}
	return errors.Join(allErrors...)
}

func logAPIReport(log *logging.Logger, site string, report apidiscovery.Report) {
	if log == nil {
		return
	}
	log.Info("[%s] API discovery: static=%d runtime=%d matched=%d confirmed=%d bases=%d",
		site, report.Summary.Static, report.Summary.Runtime,
		report.Summary.Matched, report.Summary.Confirmed, report.Summary.Bases)
	for _, association := range report.Associations {
		log.Verbose("  [api] match static=%s runtime=%s score=%d confidence=%s evidence=%v",
			association.StaticRawURL, association.RuntimeURL, association.Score,
			association.Confidence, association.Evidence)
	}
	for _, base := range report.Bases {
		if base.Confidence == apidiscovery.ConfidenceConfirmed {
			log.Info("Runtime base confirmed: %s (evidence=%d)", base.RuntimeBase, base.EvidenceCount)
		}
	}
}
