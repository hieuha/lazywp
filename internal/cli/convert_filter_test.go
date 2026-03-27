package cli

import (
	"testing"

	"github.com/hieuha/lazywp/internal/exploit"
	"github.com/hieuha/lazywp/internal/scanner"
	"github.com/hieuha/lazywp/internal/storage"
)

// resetConvertFlags restores package-level filter vars to zero values after each test.
func resetConvertFlags(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		convertSlug = ""
		convertMinCVSS = 0
		convertMaxCVSS = 0
		convertCVE = ""
		convertStatus = ""
		convertVulnOnly = false
		convertSafeOnly = false
		convertExploitable = false
	})
}

func makeScanResult(slug, version string, cvss float64, cve string, vulnerable bool) ScanResult {
	r := ScanResult{
		Plugin:       scanner.ScannedPlugin{Slug: slug, Version: version},
		MaxCVSS:      cvss,
		IsVulnerable: vulnerable,
	}
	if cve != "" {
		r.Vulns = []storage.Vulnerability{{CVE: cve, CVSS: cvss}}
		r.ActiveVulns = 1
	}
	return r
}

func TestFilterScanResults_NoFilters(t *testing.T) {
	resetConvertFlags(t)
	results := []ScanResult{
		makeScanResult("plugin-a", "1.0", 7.5, "CVE-2024-001", true),
		makeScanResult("plugin-b", "2.0", 0, "", false),
	}
	got := filterScanResults(results)
	if len(got) != 2 {
		t.Errorf("no filters: expected 2 results, got %d", len(got))
	}
}

func TestFilterScanResults_SlugFilter(t *testing.T) {
	resetConvertFlags(t)
	convertSlug = "elementor"
	results := []ScanResult{
		makeScanResult("elementor-pro", "1.0", 8.0, "CVE-1", true),
		makeScanResult("akismet", "5.0", 0, "", false),
		makeScanResult("elementor", "3.0", 6.0, "CVE-2", true),
	}
	got := filterScanResults(results)
	if len(got) != 2 {
		t.Errorf("slug filter: expected 2, got %d", len(got))
	}
}

func TestFilterScanResults_SlugCaseInsensitive(t *testing.T) {
	resetConvertFlags(t)
	convertSlug = "ELEMENTOR"
	results := []ScanResult{
		makeScanResult("elementor-pro", "1.0", 8.0, "CVE-1", true),
	}
	got := filterScanResults(results)
	if len(got) != 1 {
		t.Errorf("slug filter case-insensitive: expected 1, got %d", len(got))
	}
}

func TestFilterScanResults_VulnOnly(t *testing.T) {
	resetConvertFlags(t)
	convertVulnOnly = true
	results := []ScanResult{
		makeScanResult("vuln-plugin", "1.0", 7.0, "CVE-1", true),
		makeScanResult("safe-plugin", "2.0", 0, "", false),
	}
	got := filterScanResults(results)
	if len(got) != 1 || got[0].Plugin.Slug != "vuln-plugin" {
		t.Errorf("vuln-only: expected 1 vulnerable result, got %d", len(got))
	}
}

func TestFilterScanResults_SafeOnly(t *testing.T) {
	resetConvertFlags(t)
	convertSafeOnly = true
	results := []ScanResult{
		makeScanResult("vuln-plugin", "1.0", 7.0, "CVE-1", true),
		makeScanResult("safe-plugin", "2.0", 0, "", false),
	}
	got := filterScanResults(results)
	if len(got) != 1 || got[0].Plugin.Slug != "safe-plugin" {
		t.Errorf("safe-only: expected 1 safe result, got %d", len(got))
	}
}

func TestFilterScanResults_StatusVulnerable(t *testing.T) {
	resetConvertFlags(t)
	convertStatus = "vulnerable"
	results := []ScanResult{
		makeScanResult("vuln", "1.0", 9.0, "CVE-1", true),
		makeScanResult("safe", "2.0", 0, "", false),
	}
	got := filterScanResults(results)
	if len(got) != 1 {
		t.Errorf("status=vulnerable: expected 1, got %d", len(got))
	}
}

func TestFilterScanResults_StatusSafe(t *testing.T) {
	resetConvertFlags(t)
	convertStatus = "safe"
	results := []ScanResult{
		makeScanResult("vuln", "1.0", 9.0, "CVE-1", true),
		makeScanResult("safe", "2.0", 0, "", false),
	}
	got := filterScanResults(results)
	if len(got) != 1 || got[0].Plugin.Slug != "safe" {
		t.Errorf("status=safe: expected 1 safe result, got %d", len(got))
	}
}

func TestFilterScanResults_MinCVSS(t *testing.T) {
	resetConvertFlags(t)
	convertMinCVSS = 7.0
	results := []ScanResult{
		makeScanResult("high", "1.0", 8.0, "CVE-1", true),
		makeScanResult("medium", "1.0", 5.0, "CVE-2", true),
		makeScanResult("safe", "2.0", 0, "", false),
	}
	got := filterScanResults(results)
	if len(got) != 1 || got[0].Plugin.Slug != "high" {
		t.Errorf("min-cvss=7.0: expected 1 result with cvss>=7.0, got %d", len(got))
	}
}

func TestFilterScanResults_MaxCVSS(t *testing.T) {
	resetConvertFlags(t)
	convertMaxCVSS = 6.0
	results := []ScanResult{
		makeScanResult("critical", "1.0", 9.5, "CVE-1", true),
		makeScanResult("medium", "1.0", 5.0, "CVE-2", true),
	}
	got := filterScanResults(results)
	if len(got) != 1 || got[0].Plugin.Slug != "medium" {
		t.Errorf("max-cvss=6.0: expected 1, got %d", len(got))
	}
}

func TestFilterScanResults_CVEFilter(t *testing.T) {
	resetConvertFlags(t)
	convertCVE = "2024-001"
	results := []ScanResult{
		makeScanResult("match", "1.0", 7.0, "CVE-2024-0010", true),
		makeScanResult("no-match", "1.0", 7.0, "CVE-2023-9999", true),
	}
	got := filterScanResults(results)
	if len(got) != 1 || got[0].Plugin.Slug != "match" {
		t.Errorf("cve filter: expected match, got %d", len(got))
	}
}

func TestFilterScanResults_Exploitable(t *testing.T) {
	resetConvertFlags(t)
	convertExploitable = true
	withPOC := ScanResult{
		Plugin:       scanner.ScannedPlugin{Slug: "has-poc"},
		IsVulnerable: true,
		ExploitData:  map[string]exploit.CVEInfo{"CVE-1": {HasPOC: true}},
	}
	withoutExploit := makeScanResult("no-exploit", "1.0", 7.0, "CVE-2", true)
	results := []ScanResult{withPOC, withoutExploit}
	got := filterScanResults(results)
	if len(got) != 1 || got[0].Plugin.Slug != "has-poc" {
		t.Errorf("exploitable filter: expected has-poc, got %d results", len(got))
	}
}

func TestFilterVulnResults_NoFilters(t *testing.T) {
	resetConvertFlags(t)
	results := []flatVuln{
		{Slug: "a", CVE: "CVE-1", CVSS: 7.0},
		{Slug: "b", CVE: "CVE-2", CVSS: 4.0},
	}
	got := filterVulnResults(results)
	if len(got) != 2 {
		t.Errorf("no filters: expected 2, got %d", len(got))
	}
}

func TestFilterVulnResults_SlugFilter(t *testing.T) {
	resetConvertFlags(t)
	convertSlug = "contact"
	results := []flatVuln{
		{Slug: "contact-form-7", CVE: "CVE-1", CVSS: 7.0},
		{Slug: "akismet", CVE: "CVE-2", CVSS: 5.0},
	}
	got := filterVulnResults(results)
	if len(got) != 1 || got[0].Slug != "contact-form-7" {
		t.Errorf("slug filter: expected contact-form-7, got %d results", len(got))
	}
}

func TestFilterVulnResults_MinCVSS(t *testing.T) {
	resetConvertFlags(t)
	convertMinCVSS = 8.0
	results := []flatVuln{
		{Slug: "a", CVSS: 9.0},
		{Slug: "b", CVSS: 5.0},
	}
	got := filterVulnResults(results)
	if len(got) != 1 || got[0].Slug != "a" {
		t.Errorf("min-cvss filter: expected 1 high-cvss result, got %d", len(got))
	}
}

func TestFilterVulnResults_MaxCVSS(t *testing.T) {
	resetConvertFlags(t)
	convertMaxCVSS = 6.0
	results := []flatVuln{
		{Slug: "a", CVSS: 9.0},
		{Slug: "b", CVSS: 5.0},
	}
	got := filterVulnResults(results)
	if len(got) != 1 || got[0].Slug != "b" {
		t.Errorf("max-cvss filter: expected 1 low-cvss result, got %d", len(got))
	}
}

func TestFilterVulnResults_CVEFilter(t *testing.T) {
	resetConvertFlags(t)
	convertCVE = "2024"
	results := []flatVuln{
		{Slug: "a", CVE: "CVE-2024-0001"},
		{Slug: "b", CVE: "CVE-2023-9999"},
	}
	got := filterVulnResults(results)
	if len(got) != 1 || got[0].Slug != "a" {
		t.Errorf("cve filter: expected 1 result for 2024, got %d", len(got))
	}
}

func TestCountUniqueVulnSlugs(t *testing.T) {
	tests := []struct {
		name    string
		results []flatVuln
		want    int
	}{
		{"empty", nil, 0},
		{"one slug two CVEs", []flatVuln{{Slug: "a", CVE: "CVE-1"}, {Slug: "a", CVE: "CVE-2"}}, 1},
		{"two distinct slugs", []flatVuln{{Slug: "a"}, {Slug: "b"}}, 2},
		{"three entries two slugs", []flatVuln{{Slug: "x"}, {Slug: "y"}, {Slug: "x"}}, 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := countUniqueVulnSlugs(tc.results); got != tc.want {
				t.Errorf("countUniqueVulnSlugs: got %d, want %d", got, tc.want)
			}
		})
	}
}
