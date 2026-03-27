package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	lazywphttp "github.com/hieuha/lazywp/internal/http"
)

func TestWordfenceClient_Name(t *testing.T) {
	wf := &WordfenceClient{}
	if wf.Name() != "wordfence" {
		t.Errorf("want 'wordfence', got %q", wf.Name())
	}
}

// buildWFFeed builds a minimal Wordfence feed body for testing.
func buildWFFeed(records map[string]wfVulnRecord) []byte {
	body, _ := json.Marshal(records)
	return body
}

func newWordfenceClient(t *testing.T, srv *httptest.Server) *WordfenceClient {
	t.Helper()
	return &WordfenceClient{
		http:       newTestHTTPClient(srv),
		keyRotator: lazywphttp.NewKeyRotator([]string{}),
		cache:      newTestCache(t),
	}
}

func makeWFRecord(id, title, slug, swType string, cvss float64, cve *string) wfVulnRecord {
	score := cvss
	rating := "medium"
	if cvss >= 9.0 {
		rating = "critical"
	} else if cvss >= 7.0 {
		rating = "high"
	}
	pub := "2024-01-15"
	return wfVulnRecord{
		ID:    id,
		Title: title,
		CVE:   cve,
		CVSS:  &wfCVSS{Score: score, Rating: rating},
		Software: []wfSoftware{
			{
				Type:            swType,
				Slug:            slug,
				Name:            slug + "-name",
				PatchedVersions: []string{"2.0.0"},
				AffectedVersions: map[string]wfVersionRange{
					"* - 1.9.9": {FromVersion: "*", FromInclusive: true, ToVersion: "1.9.9", ToInclusive: true},
				},
			},
		},
		References: []string{"https://wordfence.com/vuln/" + id},
		Published:  &pub,
	}
}

func TestWordfenceClient_FetchBySlug_ValidResponse(t *testing.T) {
	cve := "CVE-2024-1111"
	feed := map[string]wfVulnRecord{
		"vuln-001": makeWFRecord("vuln-001", "SQL Injection in akismet", "akismet", "plugin", 9.8, &cve),
		"vuln-002": makeWFRecord("vuln-002", "XSS in other-plugin", "other-plugin", "plugin", 6.5, nil),
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(buildWFFeed(feed)) //nolint:errcheck
	}))
	defer srv.Close()

	client := newWordfenceClient(t, srv)
	vulns, err := client.FetchBySlug(context.Background(), "akismet", Plugin)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vulns) != 1 {
		t.Fatalf("want 1 vuln for akismet, got %d", len(vulns))
	}
	if vulns[0].CVE != "CVE-2024-1111" {
		t.Errorf("want CVE-2024-1111, got %q", vulns[0].CVE)
	}
	if vulns[0].CVSS != 9.8 {
		t.Errorf("want CVSS=9.8, got %f", vulns[0].CVSS)
	}
	if vulns[0].Source != "wordfence" {
		t.Errorf("want source=wordfence, got %q", vulns[0].Source)
	}
	if vulns[0].FixedIn != "2.0.0" {
		t.Errorf("want FixedIn=2.0.0, got %q", vulns[0].FixedIn)
	}
}

func TestWordfenceClient_FetchBySlug_NoMatch(t *testing.T) {
	feed := map[string]wfVulnRecord{
		"vuln-003": makeWFRecord("vuln-003", "Vuln in other-plugin", "other-plugin", "plugin", 5.0, nil),
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(buildWFFeed(feed)) //nolint:errcheck
	}))
	defer srv.Close()

	client := newWordfenceClient(t, srv)
	vulns, err := client.FetchBySlug(context.Background(), "nonexistent-plugin", Plugin)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vulns) != 0 {
		t.Errorf("want 0 vulns for unknown slug, got %d", len(vulns))
	}
}

func TestWordfenceClient_FetchBySlug_TypeFilter(t *testing.T) {
	feed := map[string]wfVulnRecord{
		"vuln-p": makeWFRecord("vuln-p", "Plugin Vuln", "shared-slug", "plugin", 7.0, nil),
		"vuln-t": makeWFRecord("vuln-t", "Theme Vuln", "shared-slug", "theme", 6.0, nil),
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(buildWFFeed(feed)) //nolint:errcheck
	}))
	defer srv.Close()

	client := newWordfenceClient(t, srv)
	vulns, err := client.FetchBySlug(context.Background(), "shared-slug", Plugin)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Only the plugin vuln should match
	if len(vulns) != 1 {
		t.Fatalf("want 1 plugin vuln, got %d", len(vulns))
	}
	if vulns[0].Title != "Plugin Vuln" {
		t.Errorf("want Plugin Vuln, got %q", vulns[0].Title)
	}
}

func TestWordfenceClient_FetchBySlug_CacheHit(t *testing.T) {
	slug := "cached-wf-plugin"
	cachedVulns := []interface{}{
		map[string]interface{}{
			"cve": "CVE-2023-4444", "cvss": 8.0, "title": "Cached WF", "source": "wordfence",
		},
	}
	cacheData, _ := json.Marshal(cachedVulns)

	cache := newTestCache(t)
	cacheKey := "slug:" + slug + ":" + string(Plugin)
	_ = cache.Set("wordfence", cacheKey, cacheData)

	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := &WordfenceClient{
		http:       newTestHTTPClient(srv),
		keyRotator: lazywphttp.NewKeyRotator([]string{}),
		cache:      cache,
	}

	vulns, err := client.FetchBySlug(context.Background(), slug, Plugin)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if callCount != 0 {
		t.Errorf("server should not be called on cache hit, got %d calls", callCount)
	}
	if len(vulns) != 1 {
		t.Errorf("want 1 cached vuln, got %d", len(vulns))
	}
}

func TestWordfenceClient_FetchBySlug_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := newWordfenceClient(t, srv)
	_, err := client.FetchBySlug(context.Background(), "error-plugin", Plugin)
	if err == nil {
		t.Fatal("expected error for HTTP 500, got nil")
	}
}

func TestWordfenceClient_FetchRecent(t *testing.T) {
	pub1 := "2024-03-10"
	pub2 := "2024-01-05"
	feed := map[string]wfVulnRecord{
		"newer": makeWFRecord("newer", "Newer Vuln", "plugin-a", "plugin", 8.0, nil),
		"older": {
			ID: "older", Title: "Older Vuln",
			Software:  []wfSoftware{{Type: "plugin", Slug: "plugin-b"}},
			Published: &pub2,
		},
	}
	// Override Published on newer record
	r := feed["newer"]
	r.Published = &pub1
	feed["newer"] = r

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(buildWFFeed(feed)) //nolint:errcheck
	}))
	defer srv.Close()

	client := newWordfenceClient(t, srv)
	vulns, err := client.FetchRecent(context.Background(), 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vulns) != 2 {
		t.Errorf("want 2 vulns, got %d", len(vulns))
	}
}

func TestWordfenceClient_FetchRecent_Limit(t *testing.T) {
	feed := map[string]wfVulnRecord{
		"v1": makeWFRecord("v1", "Vuln 1", "p1", "plugin", 9.0, nil),
		"v2": makeWFRecord("v2", "Vuln 2", "p2", "plugin", 8.0, nil),
		"v3": makeWFRecord("v3", "Vuln 3", "p3", "plugin", 7.0, nil),
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(buildWFFeed(feed)) //nolint:errcheck
	}))
	defer srv.Close()

	client := newWordfenceClient(t, srv)
	vulns, err := client.FetchRecent(context.Background(), 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vulns) != 2 {
		t.Errorf("want 2 vulns after limit, got %d", len(vulns))
	}
}

func TestWordfenceClient_SearchVulns(t *testing.T) {
	feed := map[string]wfVulnRecord{
		"s1": makeWFRecord("s1", "SQL Injection in woo", "woocommerce", "plugin", 9.8, nil),
		"s2": makeWFRecord("s2", "XSS in jetpack", "jetpack", "plugin", 6.5, nil),
	}
	// Set CWE on s1 to SQL
	r := feed["s1"]
	r.CWE = &wfCWE{ID: 89, Name: "SQL Injection"}
	feed["s1"] = r

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(buildWFFeed(feed)) //nolint:errcheck
	}))
	defer srv.Close()

	client := newWordfenceClient(t, srv)
	results, err := client.SearchVulns(context.Background(), WordfenceFilters{Search: "woo"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("want 1 result for 'woo' search, got %d", len(results))
	}
	if results[0].Slug != "woocommerce" {
		t.Errorf("want slug=woocommerce, got %q", results[0].Slug)
	}
}

func TestWordfenceClient_SearchVulns_CVSSRating(t *testing.T) {
	feed := map[string]wfVulnRecord{
		"c1": makeWFRecord("c1", "Critical Vuln", "plugin-x", "plugin", 9.8, nil),
		"m1": makeWFRecord("m1", "Medium Vuln", "plugin-y", "plugin", 5.0, nil),
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(buildWFFeed(feed)) //nolint:errcheck
	}))
	defer srv.Close()

	client := newWordfenceClient(t, srv)
	results, err := client.SearchVulns(context.Background(), WordfenceFilters{CVSSRating: "critical"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("want 1 critical vuln, got %d", len(results))
	}
	if results[0].CVSSRating != "critical" {
		t.Errorf("want rating=critical, got %q", results[0].CVSSRating)
	}
}

// --- helper function unit tests ---

func TestCweToType_SQL(t *testing.T) {
	cwe := &wfCWE{ID: 89, Name: "SQL Injection"}
	if got := cweToType(cwe); got != "sqli" {
		t.Errorf("want sqli, got %q", got)
	}
}

func TestCweToType_XSS(t *testing.T) {
	cwe := &wfCWE{ID: 79, Name: "Cross-Site Scripting"}
	if got := cweToType(cwe); got != "xss" {
		t.Errorf("want xss, got %q", got)
	}
}

func TestCweToType_CSRF(t *testing.T) {
	cwe := &wfCWE{ID: 352, Name: "Cross-Site Request Forgery"}
	if got := cweToType(cwe); got != "csrf" {
		t.Errorf("want csrf, got %q", got)
	}
}

func TestCweToType_RCE(t *testing.T) {
	cwe := &wfCWE{ID: 94, Name: "Code Injection"}
	if got := cweToType(cwe); got != "rce" {
		t.Errorf("want rce, got %q", got)
	}
}

func TestCweToType_Nil(t *testing.T) {
	if got := cweToType(nil); got != "" {
		t.Errorf("want empty string for nil CWE, got %q", got)
	}
}

func TestCweToType_Unknown(t *testing.T) {
	cwe := &wfCWE{ID: 999, Name: "Some Unknown Weakness"}
	got := cweToType(cwe)
	if got != "CWE-999" {
		t.Errorf("want CWE-999, got %q", got)
	}
}

func TestMatchesSoftwareType(t *testing.T) {
	tests := []struct {
		swType   string
		itemType ItemType
		want     bool
	}{
		{"plugin", Plugin, true},
		{"theme", Plugin, false},
		{"plugin", Theme, false},
		{"theme", Theme, true},
	}
	for _, tc := range tests {
		got := matchesSoftwareType(tc.swType, tc.itemType)
		if got != tc.want {
			t.Errorf("matchesSoftwareType(%q, %v) = %v, want %v", tc.swType, tc.itemType, got, tc.want)
		}
	}
}

func TestCompareVersionParts(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "2.0.0", -1},
		{"2.0.0", "1.0.0", 1},
		{"1.0.0", "1.0.0", 0},
		{"1.10.0", "1.9.0", 1},
		{"1.0", "1.0.0", 0},
	}
	for _, tc := range tests {
		got := compareVersionParts(tc.a, tc.b)
		if got != tc.want {
			t.Errorf("compareVersionParts(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestStrVal(t *testing.T) {
	s := "hello"
	if got := strVal(&s); got != "hello" {
		t.Errorf("want hello, got %q", got)
	}
	if got := strVal(nil); got != "" {
		t.Errorf("want empty for nil, got %q", got)
	}
}

func TestFirstPatchedVersion(t *testing.T) {
	sw := []wfSoftware{
		{Slug: "my-plugin", PatchedVersions: []string{"1.2.3", "1.2.4"}},
	}
	got := firstPatchedVersion(sw, "my-plugin")
	if got != "1.2.3" {
		t.Errorf("want 1.2.3, got %q", got)
	}

	got = firstPatchedVersion(sw, "other-plugin")
	if got != "" {
		t.Errorf("want empty for non-matching slug, got %q", got)
	}
}

func TestMinMaxFromVersion(t *testing.T) {
	sw := []wfSoftware{
		{
			Slug: "myplugin",
			AffectedVersions: map[string]wfVersionRange{
				"1.0 - 2.5": {FromVersion: "1.0", ToVersion: "2.5"},
				"3.0 - 3.9": {FromVersion: "3.0", ToVersion: "3.9"},
			},
		},
	}

	min := minFromVersion(sw, "myplugin")
	if min != "1.0" {
		t.Errorf("want min=1.0, got %q", min)
	}

	max := maxToVersion(sw, "myplugin")
	if max != "3.9" {
		t.Errorf("want max=3.9, got %q", max)
	}
}
