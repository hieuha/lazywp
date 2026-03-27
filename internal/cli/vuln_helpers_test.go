package cli

import (
	"testing"

	"github.com/hieuha/lazywp/internal/storage"
)

func TestTruncate(t *testing.T) {
	tests := []struct {
		s    string
		n    int
		want string
	}{
		{"hello", 10, "hello"},
		{"hello", 5, "hello"},
		{"hello world", 8, "hello..."},
		{"abcdef", 4, "a..."},
		{"", 5, ""},
		{"Unicode: 日本語テスト", 10, "Unicode..."},         // 15 runes, [:7]+"..." = "Unicode..."
		{"Unicode: 日本語テスト", 15, "Unicode: 日本語テスト"}, // exactly 15 runes, no truncation
	}
	for _, tc := range tests {
		t.Run(tc.s, func(t *testing.T) {
			if got := truncate(tc.s, tc.n); got != tc.want {
				t.Errorf("truncate(%q, %d) = %q, want %q", tc.s, tc.n, got, tc.want)
			}
		})
	}
}

func TestFlattenVulnRows_Headers(t *testing.T) {
	headers, _ := flattenVulnRows(nil)
	want := []string{"Slug", "CVE", "CVSS", "Type", "Title", "Affected Versions",
		"Min Affected", "Max Affected", "Fixed In", "Source"}
	if len(headers) != len(want) {
		t.Fatalf("header count: got %d, want %d", len(headers), len(want))
	}
	for i, h := range want {
		if headers[i] != h {
			t.Errorf("header[%d]: got %q, want %q", i, headers[i], h)
		}
	}
}

func TestFlattenVulnRows_Rows(t *testing.T) {
	flat := []flatVuln{
		{
			Slug:               "contact-form-7",
			CVE:                "CVE-2024-0001",
			CVSS:               8.5,
			Type:               "sqli",
			Title:              "SQL Injection",
			AffectedVersions:   "< 5.8",
			MinAffectedVersion: "5.0",
			MaxAffectedVersion: "5.7",
			FixedIn:            "5.8",
			Source:             "wordfence",
		},
	}
	headers, rows := flattenVulnRows(flat)
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	_ = headers
	row := rows[0]
	if row[0] != "contact-form-7" {
		t.Errorf("Slug: got %q", row[0])
	}
	if row[1] != "CVE-2024-0001" {
		t.Errorf("CVE: got %q", row[1])
	}
	if row[2] != "8.5" {
		t.Errorf("CVSS: got %q, want 8.5", row[2])
	}
	if row[8] != "5.8" {
		t.Errorf("FixedIn: got %q, want 5.8", row[8])
	}
	if row[9] != "wordfence" {
		t.Errorf("Source: got %q, want wordfence", row[9])
	}
}

func TestFlattenVulnRows_Empty(t *testing.T) {
	_, rows := flattenVulnRows(nil)
	if len(rows) != 0 {
		t.Errorf("empty input: expected 0 rows, got %d", len(rows))
	}
}

func TestUniqueMaxAffectedVersions(t *testing.T) {
	tests := []struct {
		name  string
		vulns []storage.Vulnerability
		want  int
	}{
		{"empty", nil, 0},
		{
			"skip empty version",
			[]storage.Vulnerability{{MaxAffectedVersion: ""}, {MaxAffectedVersion: "1.0"}},
			1,
		},
		{
			"skip wildcard",
			[]storage.Vulnerability{{MaxAffectedVersion: "*"}, {MaxAffectedVersion: "2.0"}},
			1,
		},
		{
			"deduplicate same version",
			[]storage.Vulnerability{{MaxAffectedVersion: "1.0"}, {MaxAffectedVersion: "1.0"}},
			1,
		},
		{
			"distinct versions",
			[]storage.Vulnerability{{MaxAffectedVersion: "1.0"}, {MaxAffectedVersion: "2.0"}},
			2,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := uniqueMaxAffectedVersions(tc.vulns)
			if len(got) != tc.want {
				t.Errorf("uniqueMaxAffectedVersions: got %d versions %v, want %d", len(got), got, tc.want)
			}
		})
	}
}

func TestUniqueMaxAffectedVersions_OrderPreserved(t *testing.T) {
	vulns := []storage.Vulnerability{
		{MaxAffectedVersion: "3.0"},
		{MaxAffectedVersion: "1.0"},
		{MaxAffectedVersion: "2.0"},
	}
	got := uniqueMaxAffectedVersions(vulns)
	if len(got) != 3 {
		t.Fatalf("expected 3 versions, got %d", len(got))
	}
	if got[0] != "3.0" || got[1] != "1.0" || got[2] != "2.0" {
		t.Errorf("order not preserved: got %v", got)
	}
}
