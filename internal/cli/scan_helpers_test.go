package cli

import (
	"strings"
	"testing"

	"github.com/hieuha/lazywp/internal/exploit"
	"github.com/hieuha/lazywp/internal/scanner"
	"github.com/hieuha/lazywp/internal/storage"
)

func TestExtractSourceName(t *testing.T) {
	tests := []struct {
		warning string
		want    string
	}{
		{"wpscan: no api key configured", "wpscan"},
		{"nvd: http 401 unauthorized", "nvd"},
		{"wordfence: some error", "wordfence"},
		{"no colon here", ""},
		{"", ""},
		{":leading colon", ""},
	}
	for _, tc := range tests {
		t.Run(tc.warning, func(t *testing.T) {
			if got := extractSourceName(tc.warning); got != tc.want {
				t.Errorf("extractSourceName(%q) = %q, want %q", tc.warning, got, tc.want)
			}
		})
	}
}

func TestIsAPIKeyError(t *testing.T) {
	tests := []struct {
		warning string
		want    bool
	}{
		{"wpscan: no api key configured", true},
		{"nvd: no api keys configured", true},
		{"wordfence: http 401 unauthorized", true},
		{"source: http 403 forbidden", true},
		{"wpscan: http 500 internal error", false},
		{"regular timeout error", false},
		{"No API Key", true},   // case-insensitive
		{"HTTP 401", true},     // case-insensitive
	}
	for _, tc := range tests {
		t.Run(tc.warning, func(t *testing.T) {
			if got := isAPIKeyError(tc.warning); got != tc.want {
				t.Errorf("isAPIKeyError(%q) = %v, want %v", tc.warning, got, tc.want)
			}
		})
	}
}

func TestColorCVSS(t *testing.T) {
	tests := []struct {
		score        float64
		wantContains string
	}{
		{9.0, "9.0"},
		{9.5, "9.5"},
		{7.0, "7.0"},
		{8.9, "8.9"},
		{4.0, "4.0"},
		{6.9, "6.9"},
		{0.0, "0.0"},
		{3.9, "3.9"},
	}
	for _, tc := range tests {
		t.Run(tc.wantContains, func(t *testing.T) {
			got := colorCVSS(tc.score)
			if !strings.Contains(got, tc.wantContains) {
				t.Errorf("colorCVSS(%v) = %q, should contain %q", tc.score, got, tc.wantContains)
			}
			// Must contain ANSI reset
			if !strings.Contains(got, ansiReset) {
				t.Errorf("colorCVSS(%v) should contain ANSI reset code", tc.score)
			}
		})
	}

	// Critical (>=9.0) uses bold red
	got := colorCVSS(9.0)
	if !strings.Contains(got, ansiBoldRed) {
		t.Errorf("CVSS 9.0 should use bold red, got %q", got)
	}

	// High (7.0-8.9) uses red
	got = colorCVSS(7.5)
	if !strings.Contains(got, ansiRed) {
		t.Errorf("CVSS 7.5 should use red, got %q", got)
	}

	// Medium (4.0-6.9) uses yellow
	got = colorCVSS(5.0)
	if !strings.Contains(got, ansiYellow) {
		t.Errorf("CVSS 5.0 should use yellow, got %q", got)
	}

	// Low (<4.0) uses green
	got = colorCVSS(2.0)
	if !strings.Contains(got, ansiGreen) {
		t.Errorf("CVSS 2.0 should use green, got %q", got)
	}
}

func TestFlattenScanResults_Headers(t *testing.T) {
	headers, _ := flattenScanResults(nil)
	want := []string{"slug", "version", "status", "cve_count", "max_cvss", "update_to",
		"cve", "cvss", "type", "title", "min_affected_version", "max_affected_version", "fixed_in",
		"has_poc", "is_kev", "epss", "has_nuclei"}
	if len(headers) != len(want) {
		t.Fatalf("header count: got %d, want %d", len(headers), len(want))
	}
	for i, h := range want {
		if headers[i] != h {
			t.Errorf("header[%d]: got %q, want %q", i, headers[i], h)
		}
	}
}

func TestFlattenScanResults_SafePlugin(t *testing.T) {
	results := []ScanResult{
		{Plugin: scanner.ScannedPlugin{Slug: "akismet", Version: "5.0"}},
	}
	_, rows := flattenScanResults(results)
	if len(rows) != 1 {
		t.Fatalf("safe plugin: expected 1 row, got %d", len(rows))
	}
	if rows[0][0] != "akismet" {
		t.Errorf("slug: got %q, want akismet", rows[0][0])
	}
	if rows[0][2] != "safe" {
		t.Errorf("status: got %q, want safe", rows[0][2])
	}
}

func TestFlattenScanResults_VulnerablePlugin(t *testing.T) {
	results := []ScanResult{
		{
			Plugin:      scanner.ScannedPlugin{Slug: "bad-plugin", Version: "1.0"},
			ActiveVulns: 1,
			MaxCVSS:     8.5,
			MaxFixedIn:  "1.1",
			IsVulnerable: true,
			Vulns: []storage.Vulnerability{
				{CVE: "CVE-2024-1234", CVSS: 8.5, Type: "sqli", Title: "SQL Injection", FixedIn: "1.1"},
			},
		},
	}
	_, rows := flattenScanResults(results)
	if len(rows) != 1 {
		t.Fatalf("expected 1 row for 1 CVE, got %d", len(rows))
	}
	row := rows[0]
	if row[0] != "bad-plugin" {
		t.Errorf("slug: got %q", row[0])
	}
	if row[2] != "vulnerable" {
		t.Errorf("status: got %q, want vulnerable", row[2])
	}
	if row[6] != "CVE-2024-1234" {
		t.Errorf("cve: got %q", row[6])
	}
	if row[12] != "1.1" {
		t.Errorf("fixed_in: got %q, want 1.1", row[12])
	}
}

func TestFlattenScanResults_UnfixedVuln(t *testing.T) {
	results := []ScanResult{
		{
			Plugin:      scanner.ScannedPlugin{Slug: "plugin", Version: "1.0"},
			ActiveVulns: 1,
			IsVulnerable: true,
			Vulns: []storage.Vulnerability{
				{CVE: "CVE-2024-9999", CVSS: 9.8, FixedIn: ""},
			},
		},
	}
	_, rows := flattenScanResults(results)
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	// fixed_in column should be "unfixed" when empty
	if rows[0][12] != "unfixed" {
		t.Errorf("fixed_in: got %q, want unfixed", rows[0][12])
	}
}

func TestFlattenScanResults_WithExploitData(t *testing.T) {
	results := []ScanResult{
		{
			Plugin:      scanner.ScannedPlugin{Slug: "plugin", Version: "2.0"},
			ActiveVulns: 1,
			IsVulnerable: true,
			Vulns: []storage.Vulnerability{
				{CVE: "CVE-2024-0001", CVSS: 7.0, FixedIn: "2.1"},
			},
			ExploitData: map[string]exploit.CVEInfo{
				"CVE-2024-0001": {HasPOC: true, IsKEV: false, EPSS: 0.1234, HasNuclei: true},
			},
		},
	}
	_, rows := flattenScanResults(results)
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	if rows[0][13] != "true" {
		t.Errorf("has_poc: got %q, want true", rows[0][13])
	}
	if rows[0][14] != "false" {
		t.Errorf("is_kev: got %q, want false", rows[0][14])
	}
	if rows[0][16] != "true" {
		t.Errorf("has_nuclei: got %q, want true", rows[0][16])
	}
}

func TestFlattenScanResults_UnknownVersion(t *testing.T) {
	results := []ScanResult{
		{Plugin: scanner.ScannedPlugin{Slug: "plugin", Version: ""}},
	}
	_, rows := flattenScanResults(results)
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	if rows[0][1] != "unknown" {
		t.Errorf("version: got %q, want unknown", rows[0][1])
	}
}
