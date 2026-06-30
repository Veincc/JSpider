package main

import (
	"fmt"
	"path/filepath"
	"sort"

	"github.com/Veincc/JSpider/internal/apidiscovery"
	"github.com/Veincc/JSpider/internal/preprocess"
	"github.com/Veincc/JSpider/internal/store"
)

func finalizeOutputs(
	outDir string,
	s *store.Store,
	sites map[string]bool,
	processors map[string]*preprocess.Processor,
	apiSessions map[string]*apidiscovery.Session,
	siteEntryURLs map[string][]string,
	apiEnabled bool,
) error {
	orderedSites := make([]string, 0, len(sites))
	for site := range sites {
		orderedSites = append(orderedSites, site)
	}
	sort.Strings(orderedSites)

	for _, site := range orderedSites {
		if processor := processors[site]; processor != nil {
			if err := processor.Close(); err != nil {
				return fmt.Errorf("close JavaScript processor for %s: %w", site, err)
			}
			delete(processors, site)
		}
		if err := s.WriteJSMap(site); err != nil {
			return fmt.Errorf("write JavaScript map for %s: %w", site, err)
		}
		if !apiEnabled {
			continue
		}
		session := apiSessions[site]
		if session == nil {
			return fmt.Errorf("missing API discovery session for %s", site)
		}
		if err := session.AnalyzeSources(); err != nil {
			return fmt.Errorf("analyze discovered JavaScript APIs for %s: %w", site, err)
		}
		urls := apidiscovery.EndpointURLs(session.Report(), siteEntryURLs[site])
		if err := apidiscovery.WriteEndpointURLs(filepath.Join(outDir, site), urls); err != nil {
			return fmt.Errorf("write endpoints for %s: %w", site, err)
		}
	}
	return nil
}
