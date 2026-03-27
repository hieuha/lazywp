package cli

import (
	"testing"

	"github.com/hieuha/lazywp/internal/exploit"
	"github.com/hieuha/lazywp/internal/scanner"
	"github.com/hieuha/lazywp/internal/storage"
)

func TestSeverityClass(t *testing.T) {
	tests := []struct {
		cvss float64
		want string
	}{
		{9.0, "critical"},
		{10.0, "critical"},
		{7.0, "high"},
		{8.9, "high"},
		{4.0, "medium"},
		{6.9, "medium"},
		{0.0, "low"},
		{3.9, "low"},
	}
	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			if got := severityClass(tc.cvss); got != tc.want {
				t.Errorf("severityClass(%.1f) = %q, want %q", tc.cvss, got, tc.want)
			}
		})
	}
}

func TestBuildReportData_Empty(t *testing.T) {
	rd := buildReportData("scan.json", nil)
	if rd.Total != 0 {
		t.Errorf("Total: got %d, want 0", rd.Total)
	}
	if rd.VulnCount != 0 {
		t.Errorf("VulnCount: got %d, want 0", rd.VulnCount)
	}
	if rd.SourceFile != "scan.json" {
		t.Errorf("SourceFile: got %q, want scan.json", rd.SourceFile)
	}
	if rd.HasExploit {
		t.Error("HasExploit should be false with no results")
	}
}

func TestBuildReportData_Counts(t *testing.T) {
	results := []ScanResult{
		{
			Plugin:       scanner.ScannedPlugin{Slug: "vuln-plugin"},
			IsVulnerable: true,
			Vulns: []storage.Vulnerability{
				{CVSS: 9.5},  // critical
				{CVSS: 7.5},  // high
				{CVSS: 5.0},  // medium
				{CVSS: 2.0},  // low
			},
		},
		{
			Plugin:       scanner.ScannedPlugin{Slug: "safe-plugin"},
			IsVulnerable: false,
		},
	}

	rd := buildReportData("scan.json", results)

	if rd.Total != 2 {
		t.Errorf("Total: got %d, want 2", rd.Total)
	}
	if rd.VulnCount != 1 {
		t.Errorf("VulnCount: got %d, want 1", rd.VulnCount)
	}
	if rd.SafeCount != 1 {
		t.Errorf("SafeCount: got %d, want 1", rd.SafeCount)
	}
	if rd.TotalCVEs != 4 {
		t.Errorf("TotalCVEs: got %d, want 4", rd.TotalCVEs)
	}
	if rd.Critical != 1 {
		t.Errorf("Critical: got %d, want 1", rd.Critical)
	}
	if rd.High != 1 {
		t.Errorf("High: got %d, want 1", rd.High)
	}
	if rd.Medium != 1 {
		t.Errorf("Medium: got %d, want 1", rd.Medium)
	}
	if rd.Low != 1 {
		t.Errorf("Low: got %d, want 1", rd.Low)
	}
}

func TestBuildReportData_ExploitCounts(t *testing.T) {
	results := []ScanResult{
		{
			Plugin:       scanner.ScannedPlugin{Slug: "plugin"},
			IsVulnerable: true,
			Vulns: []storage.Vulnerability{
				{CVE: "CVE-2024-0001"},
			},
			ExploitData: map[string]exploit.CVEInfo{
				"CVE-2024-0001": {HasPOC: true, IsKEV: true, HasNuclei: true},
			},
		},
	}

	rd := buildReportData("scan.json", results)

	if rd.POCCount != 1 {
		t.Errorf("POCCount: got %d, want 1", rd.POCCount)
	}
	if rd.KEVCount != 1 {
		t.Errorf("KEVCount: got %d, want 1", rd.KEVCount)
	}
	if rd.NucleiCount != 1 {
		t.Errorf("NucleiCount: got %d, want 1", rd.NucleiCount)
	}
	if !rd.HasExploit {
		t.Error("HasExploit should be true")
	}
}

func TestBuildReportData_VersionSet(t *testing.T) {
	rd := buildReportData("x.json", nil)
	if rd.Version != Version {
		t.Errorf("Version: got %q, want %q", rd.Version, Version)
	}
	if rd.Generated == "" {
		t.Error("Generated timestamp should not be empty")
	}
}
