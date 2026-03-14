package vuln

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/hieuha/lazywp/internal/storage"
)

// VulnSource is the interface implemented by all vulnerability data providers.
// Uses storage.ItemType to avoid an import cycle with the client package.
type VulnSource interface {
	Name() string
	FetchBySlug(ctx context.Context, slug string, itemType storage.ItemType) ([]storage.Vulnerability, error)
	FetchRecent(ctx context.Context, limit int) ([]storage.Vulnerability, error)
}

// Aggregator queries multiple VulnSources and merges the results.
type Aggregator struct {
	sources []VulnSource
}

// NewAggregator creates an Aggregator with the given sources.
func NewAggregator(sources []VulnSource) *Aggregator {
	return &Aggregator{sources: sources}
}

// sourceResult holds the outcome of a single source fetch.
type sourceResult struct {
	name   string
	vulns  []storage.Vulnerability
	err    error
}

// FetchForSlug queries all sources in parallel for the given slug and item type.
// Returns merged deduplicated vulnerabilities sorted by CVSS descending, plus
// non-fatal warning strings for any sources that returned errors.
func (a *Aggregator) FetchForSlug(ctx context.Context, slug string, itemType storage.ItemType) ([]storage.Vulnerability, []string) {
	results := make(chan sourceResult, len(a.sources))

	var wg sync.WaitGroup
	for _, src := range a.sources {
		wg.Add(1)
		go func(s VulnSource) {
			defer wg.Done()
			vulns, err := s.FetchBySlug(ctx, slug, itemType)
			results <- sourceResult{name: s.Name(), vulns: vulns, err: err}
		}(src)
	}

	// Close channel once all goroutines finish
	go func() {
		wg.Wait()
		close(results)
	}()

	var allVulns [][]storage.Vulnerability
	var warnings []string

	for r := range results {
		if r.err != nil {
			warnings = append(warnings, fmt.Sprintf("%s: %v", r.name, r.err))
			continue
		}
		if len(r.vulns) > 0 {
			allVulns = append(allVulns, r.vulns)
		}
	}

	merged := Merge(allVulns...)
	return merged, warnings
}

// Merge deduplicates vulnerabilities across multiple source slices.
// Deduplication key is CVE ID (non-empty). For duplicates:
//   - Prefers WPScan for AffectedVersions and FixedIn fields.
//   - Prefers NVD for CVSS score (if WPScan score is 0).
// Results are sorted by CVSS descending.
func Merge(results ...[]storage.Vulnerability) []storage.Vulnerability {
	// Track by CVE ID; entries without a CVE are kept as-is (no dedup).
	byCVE := make(map[string]*storage.Vulnerability)
	var noCVE []storage.Vulnerability

	for _, slice := range results {
		for i := range slice {
			v := slice[i]
			if v.CVE == "" {
				noCVE = append(noCVE, v)
				continue
			}
			existing, found := byCVE[v.CVE]
			if !found {
				entry := v
				byCVE[v.CVE] = &entry
				continue
			}
			// Merge: prefer WPScan for version fields
			if v.Source == "wpscan" {
				if v.AffectedVersions != "" {
					existing.AffectedVersions = v.AffectedVersions
				}
				if v.FixedIn != "" {
					existing.FixedIn = v.FixedIn
				}
			}
			// Prefer NVD CVSS when existing score is zero
			if existing.CVSS == 0 && v.Source == "nvd" && v.CVSS > 0 {
				existing.CVSS = v.CVSS
			}
			// Use highest available CVSS
			if v.CVSS > existing.CVSS {
				existing.CVSS = v.CVSS
			}
			// Merge references (deduplicate)
			existing.References = mergeRefs(existing.References, v.References)
		}
	}

	// Assemble final slice
	merged := make([]storage.Vulnerability, 0, len(byCVE)+len(noCVE))
	for _, v := range byCVE {
		merged = append(merged, *v)
	}
	merged = append(merged, noCVE...)

	// Sort by CVSS descending
	sort.Slice(merged, func(i, j int) bool {
		return merged[i].CVSS > merged[j].CVSS
	})

	return merged
}

// mergeRefs combines two reference slices, removing duplicates.
func mergeRefs(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	for _, r := range a {
		seen[r] = true
	}
	out := append([]string(nil), a...)
	for _, r := range b {
		if r != "" && !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	return out
}
