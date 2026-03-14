package vuln

import (
	"context"
	"fmt"
	"testing"

	"github.com/hieuha/lazywp/internal/storage"
)

// mockVulnSource implements VulnSource for testing
type mockVulnSource struct {
	name     string
	vulns    []storage.Vulnerability
	fetchErr error
}

func (m *mockVulnSource) Name() string {
	return m.name
}

func (m *mockVulnSource) FetchBySlug(ctx context.Context, slug string, itemType storage.ItemType) ([]storage.Vulnerability, error) {
	if m.fetchErr != nil {
		return nil, m.fetchErr
	}
	return m.vulns, nil
}

func (m *mockVulnSource) FetchRecent(ctx context.Context, limit int) ([]storage.Vulnerability, error) {
	return m.vulns, nil
}

func TestMergeDedup(t *testing.T) {
	// Same CVE from 2 sources should be merged
	wpscanVulns := []storage.Vulnerability{
		{
			CVE:               "CVE-2024-1234",
			CVSS:              7.5,
			Source:            "wpscan",
			Title:             "Test Vuln",
			AffectedVersions:  "1.0-2.0",
			FixedIn:           "2.1",
			References:        []string{"https://example.com/1"},
		},
	}

	nvdVulns := []storage.Vulnerability{
		{
			CVE:        "CVE-2024-1234",
			CVSS:       8.0,
			Source:     "nvd",
			Title:      "Test Vuln",
			References: []string{"https://nvd.nist.gov/1"},
		},
	}

	merged := Merge(wpscanVulns, nvdVulns)

	if len(merged) != 1 {
		t.Errorf("Merge: got %d vulns, want 1", len(merged))
	}

	// Should have highest CVSS
	if merged[0].CVSS != 8.0 {
		t.Errorf("CVSS: got %.1f, want 8.0", merged[0].CVSS)
	}

	// Should keep wpscan version info
	if merged[0].AffectedVersions != "1.0-2.0" {
		t.Errorf("AffectedVersions: got %q, want 1.0-2.0", merged[0].AffectedVersions)
	}

	if merged[0].FixedIn != "2.1" {
		t.Errorf("FixedIn: got %q, want 2.1", merged[0].FixedIn)
	}
}

func TestMergePreferWPScan(t *testing.T) {
	// WPScan version info should be preferred
	wpscanVulns := []storage.Vulnerability{
		{
			CVE:               "CVE-2024-5678",
			CVSS:              6.0,
			Source:            "wpscan",
			AffectedVersions:  "1.0-3.0",
			FixedIn:           "3.1",
		},
	}

	nvdVulns := []storage.Vulnerability{
		{
			CVE:               "CVE-2024-5678",
			CVSS:              6.5,
			Source:            "nvd",
			AffectedVersions:  "1.5-2.5",
			FixedIn:           "2.6",
		},
	}

	merged := Merge(wpscanVulns, nvdVulns)

	if len(merged) != 1 {
		t.Errorf("Expected 1 merged entry, got %d", len(merged))
	}

	// Should prefer wpscan version fields
	if merged[0].AffectedVersions != "1.0-3.0" {
		t.Errorf("AffectedVersions: got %q, want 1.0-3.0", merged[0].AffectedVersions)
	}

	if merged[0].FixedIn != "3.1" {
		t.Errorf("FixedIn: got %q, want 3.1", merged[0].FixedIn)
	}
}

func TestMergePreferNVDCVSS(t *testing.T) {
	// NVD CVSS should be preferred when WPScan score is 0
	wpscanVulns := []storage.Vulnerability{
		{
			CVE:    "CVE-2024-9999",
			CVSS:   0, // No score from WPScan
			Source: "wpscan",
			Title:  "Test Vuln",
		},
	}

	nvdVulns := []storage.Vulnerability{
		{
			CVE:    "CVE-2024-9999",
			CVSS:   8.5,
			Source: "nvd",
			Title:  "Test Vuln",
		},
	}

	merged := Merge(wpscanVulns, nvdVulns)

	if merged[0].CVSS != 8.5 {
		t.Errorf("CVSS: got %.1f, want 8.5", merged[0].CVSS)
	}
}

func TestMergeSortByCVSS(t *testing.T) {
	// Should sort by CVSS descending
	vulns := []storage.Vulnerability{
		{CVE: "CVE-2024-LOW", CVSS: 3.0, Source: "nvd"},
		{CVE: "CVE-2024-HIGH", CVSS: 9.5, Source: "nvd"},
		{CVE: "CVE-2024-MEDIUM", CVSS: 6.0, Source: "nvd"},
	}

	merged := Merge(vulns)

	if len(merged) != 3 {
		t.Fatalf("Expected 3 vulns, got %d", len(merged))
	}

	if merged[0].CVSS != 9.5 {
		t.Errorf("First CVSS: got %.1f, want 9.5", merged[0].CVSS)
	}

	if merged[1].CVSS != 6.0 {
		t.Errorf("Second CVSS: got %.1f, want 6.0", merged[1].CVSS)
	}

	if merged[2].CVSS != 3.0 {
		t.Errorf("Third CVSS: got %.1f, want 3.0", merged[2].CVSS)
	}
}

func TestMergeNoCVE(t *testing.T) {
	// Entries without CVE ID should not be deduplicated
	vulns := [][]storage.Vulnerability{
		{
			{CVE: "", Title: "Unknown 1", CVSS: 5.0, Source: "source1"},
		},
		{
			{CVE: "", Title: "Unknown 2", CVSS: 5.0, Source: "source2"},
		},
	}

	merged := Merge(vulns...)

	// Should have 2 separate entries
	if len(merged) != 2 {
		t.Errorf("Expected 2 entries without CVE, got %d", len(merged))
	}
}

func TestAggregatorFetchForSlug(t *testing.T) {
	source1 := &mockVulnSource{
		name: "wpscan",
		vulns: []storage.Vulnerability{
			{CVE: "CVE-2024-1", CVSS: 7.0, Source: "wpscan", AffectedVersions: "1.0-2.0"},
		},
	}

	source2 := &mockVulnSource{
		name: "nvd",
		vulns: []storage.Vulnerability{
			{CVE: "CVE-2024-1", CVSS: 7.5, Source: "nvd"},
		},
	}

	agg := NewAggregator([]VulnSource{source1, source2})

	vulns, warnings := agg.FetchForSlug(context.Background(), "akismet", storage.ItemTypePlugin)

	if len(vulns) != 1 {
		t.Errorf("Expected 1 merged vuln, got %d", len(vulns))
	}

	if vulns[0].CVSS != 7.5 {
		t.Errorf("CVSS should be highest: got %.1f, want 7.5", vulns[0].CVSS)
	}

	if len(warnings) != 0 {
		t.Errorf("Expected no warnings, got %d", len(warnings))
	}
}

func TestAggregatorWithErrors(t *testing.T) {
	source1 := &mockVulnSource{
		name: "wpscan",
		vulns: []storage.Vulnerability{
			{CVE: "CVE-2024-1", CVSS: 7.0, Source: "wpscan"},
		},
	}

	source2 := &mockVulnSource{
		name:     "nvd",
		fetchErr: fmt.Errorf("network error"),
	}

	agg := NewAggregator([]VulnSource{source1, source2})

	vulns, warnings := agg.FetchForSlug(context.Background(), "test", storage.ItemTypePlugin)

	// Should still return results from source1
	if len(vulns) != 1 {
		t.Errorf("Expected 1 vuln despite error, got %d", len(vulns))
	}

	// Should have warning about nvd error
	if len(warnings) != 1 {
		t.Errorf("Expected 1 warning, got %d", len(warnings))
	}

	if len(warnings) > 0 && warnings[0] == "" {
		t.Error("Warning should contain error message")
	}
}

func TestAggregatorMultipleDifferentVulns(t *testing.T) {
	source1 := &mockVulnSource{
		name: "wpscan",
		vulns: []storage.Vulnerability{
			{CVE: "CVE-2024-1", CVSS: 7.0, Source: "wpscan"},
			{CVE: "CVE-2024-2", CVSS: 5.0, Source: "wpscan"},
		},
	}

	source2 := &mockVulnSource{
		name: "nvd",
		vulns: []storage.Vulnerability{
			{CVE: "CVE-2024-3", CVSS: 8.0, Source: "nvd"},
		},
	}

	agg := NewAggregator([]VulnSource{source1, source2})

	vulns, _ := agg.FetchForSlug(context.Background(), "test", storage.ItemTypePlugin)

	// Should have 3 unique CVEs
	if len(vulns) != 3 {
		t.Errorf("Expected 3 unique vulns, got %d", len(vulns))
	}

	// Should be sorted by CVSS descending (8.0, 7.0, 5.0)
	if vulns[0].CVSS != 8.0 || vulns[1].CVSS != 7.0 || vulns[2].CVSS != 5.0 {
		t.Errorf("Vulns not sorted by CVSS: %.1f, %.1f, %.1f", vulns[0].CVSS, vulns[1].CVSS, vulns[2].CVSS)
	}
}

func TestMergeReferences(t *testing.T) {
	vulns := []storage.Vulnerability{
		{
			CVE:        "CVE-2024-1",
			Source:     "wpscan",
			References: []string{"https://example.com/1", "https://example.com/2"},
		},
		{
			CVE:        "CVE-2024-1",
			Source:     "nvd",
			References: []string{"https://example.com/2", "https://nvd.com/1"},
		},
	}

	merged := Merge(vulns)

	if len(merged) != 1 {
		t.Fatalf("Expected 1 merged entry, got %d", len(merged))
	}

	// Should have deduplicated references (3 unique)
	if len(merged[0].References) != 3 {
		t.Errorf("Expected 3 unique references, got %d: %v", len(merged[0].References), merged[0].References)
	}
}
