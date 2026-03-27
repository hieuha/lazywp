package client

import (
	"testing"
)

// Tests for matchesFilters and affectedVersionStr — pure functions with low coverage.

func TestMatchesFilters_NoFilters(t *testing.T) {
	wv := WordfenceVuln{Title: "SQL Injection", Slug: "my-plugin", CVSSRating: "high"}
	r := wfVulnRecord{}
	if !matchesFilters(wv, r, WordfenceFilters{}) {
		t.Error("empty filters should match everything")
	}
}

func TestMatchesFilters_SearchTitle(t *testing.T) {
	wv := WordfenceVuln{Title: "SQL Injection in WooCommerce", Slug: "woocommerce"}
	r := wfVulnRecord{}
	f := WordfenceFilters{Search: "woocommerce"}
	if !matchesFilters(wv, r, f) {
		t.Error("search by title substring should match")
	}
}

func TestMatchesFilters_SearchSlug(t *testing.T) {
	wv := WordfenceVuln{Title: "XSS Vulnerability", Slug: "akismet"}
	r := wfVulnRecord{}
	if !matchesFilters(wv, r, WordfenceFilters{Search: "akis"}) {
		t.Error("search by slug substring should match")
	}
}

func TestMatchesFilters_SearchNoMatch(t *testing.T) {
	wv := WordfenceVuln{Title: "XSS Vulnerability", Slug: "jetpack"}
	r := wfVulnRecord{}
	if matchesFilters(wv, r, WordfenceFilters{Search: "woocommerce"}) {
		t.Error("non-matching search should return false")
	}
}

func TestMatchesFilters_CVSSRatingMatch(t *testing.T) {
	wv := WordfenceVuln{CVSSRating: "critical"}
	r := wfVulnRecord{}
	if !matchesFilters(wv, r, WordfenceFilters{CVSSRating: "critical"}) {
		t.Error("matching CVSSRating should return true")
	}
}

func TestMatchesFilters_CVSSRatingCaseInsensitive(t *testing.T) {
	wv := WordfenceVuln{CVSSRating: "Critical"}
	r := wfVulnRecord{}
	if !matchesFilters(wv, r, WordfenceFilters{CVSSRating: "critical"}) {
		t.Error("CVSSRating match should be case-insensitive")
	}
}

func TestMatchesFilters_CVSSRatingNoMatch(t *testing.T) {
	wv := WordfenceVuln{CVSSRating: "medium"}
	r := wfVulnRecord{}
	if matchesFilters(wv, r, WordfenceFilters{CVSSRating: "critical"}) {
		t.Error("non-matching CVSSRating should return false")
	}
}

func TestMatchesFilters_CWETypeMatch(t *testing.T) {
	wv := WordfenceVuln{}
	r := wfVulnRecord{CWE: &wfCWE{ID: 89, Name: "SQL Injection"}}
	if !matchesFilters(wv, r, WordfenceFilters{CWEType: "sql"}) {
		t.Error("matching CWEType should return true")
	}
}

func TestMatchesFilters_CWETypeNoMatch(t *testing.T) {
	wv := WordfenceVuln{}
	r := wfVulnRecord{CWE: &wfCWE{ID: 79, Name: "Cross-Site Scripting"}}
	if matchesFilters(wv, r, WordfenceFilters{CWEType: "sql"}) {
		t.Error("non-matching CWEType should return false")
	}
}

func TestMatchesFilters_CWETypeFilterWithNilCWE(t *testing.T) {
	wv := WordfenceVuln{}
	r := wfVulnRecord{CWE: nil}
	// CWEType filter set but record has no CWE → should not match
	if matchesFilters(wv, r, WordfenceFilters{CWEType: "sqli"}) {
		t.Error("CWEType filter with nil CWE should return false")
	}
}

func TestMatchesFilters_YearMatch(t *testing.T) {
	pub := "2024-06-15"
	wv := WordfenceVuln{}
	r := wfVulnRecord{Published: &pub}
	if !matchesFilters(wv, r, WordfenceFilters{Year: 2024}) {
		t.Error("matching year should return true")
	}
}

func TestMatchesFilters_YearNoMatch(t *testing.T) {
	pub := "2024-06-15"
	wv := WordfenceVuln{}
	r := wfVulnRecord{Published: &pub}
	if matchesFilters(wv, r, WordfenceFilters{Year: 2023}) {
		t.Error("non-matching year should return false")
	}
}

func TestMatchesFilters_MonthMatch(t *testing.T) {
	pub := "2024-03-20"
	wv := WordfenceVuln{}
	r := wfVulnRecord{Published: &pub}
	if !matchesFilters(wv, r, WordfenceFilters{Month: 3}) {
		t.Error("matching month should return true")
	}
}

func TestMatchesFilters_MonthNoMatch(t *testing.T) {
	pub := "2024-03-20"
	wv := WordfenceVuln{}
	r := wfVulnRecord{Published: &pub}
	if matchesFilters(wv, r, WordfenceFilters{Month: 5}) {
		t.Error("non-matching month should return false")
	}
}

func TestMatchesFilters_DateFilterWithNilPublished(t *testing.T) {
	wv := WordfenceVuln{}
	r := wfVulnRecord{Published: nil}
	if matchesFilters(wv, r, WordfenceFilters{Year: 2024}) {
		t.Error("date filter with nil published should return false")
	}
}

// --- affectedVersionStr ---

func TestAffectedVersionStr_SingleRange(t *testing.T) {
	sw := []wfSoftware{
		{
			Slug:             "my-plugin",
			AffectedVersions: map[string]wfVersionRange{"* - 1.9.9": {}},
		},
	}
	got := affectedVersionStr(sw, "my-plugin")
	if got != "* - 1.9.9" {
		t.Errorf("want '* - 1.9.9', got %q", got)
	}
}

func TestAffectedVersionStr_MultipleRanges(t *testing.T) {
	sw := []wfSoftware{
		{
			Slug: "my-plugin",
			AffectedVersions: map[string]wfVersionRange{
				"1.0 - 1.5": {},
				"2.0 - 2.3": {},
			},
		},
	}
	got := affectedVersionStr(sw, "my-plugin")
	// Should be sorted and joined
	if got == "" {
		t.Error("expected non-empty affected version string")
	}
}

func TestAffectedVersionStr_NoMatch(t *testing.T) {
	sw := []wfSoftware{
		{Slug: "other-plugin", AffectedVersions: map[string]wfVersionRange{"* - 1.0": {}}},
	}
	got := affectedVersionStr(sw, "my-plugin")
	if got != "" {
		t.Errorf("want empty for non-matching slug, got %q", got)
	}
}

func TestAffectedVersionStr_EmptyVersions(t *testing.T) {
	sw := []wfSoftware{
		{Slug: "my-plugin", AffectedVersions: map[string]wfVersionRange{}},
	}
	got := affectedVersionStr(sw, "my-plugin")
	if got != "" {
		t.Errorf("want empty for no affected versions, got %q", got)
	}
}

func TestAffectedVersionStr_EmptySoftware(t *testing.T) {
	got := affectedVersionStr(nil, "my-plugin")
	if got != "" {
		t.Errorf("want empty for nil software, got %q", got)
	}
}
