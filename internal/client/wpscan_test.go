package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	lazywphttp "github.com/hieuha/lazywp/internal/http"
	"github.com/hieuha/lazywp/internal/vuln"
)

// newTestCache returns a vuln.Cache backed by a temp directory with a 1-hour TTL.
func newTestCache(t *testing.T) *vuln.Cache {
	t.Helper()
	return vuln.NewCache(t.TempDir(), time.Hour)
}

func TestWPScanClient_Name(t *testing.T) {
	w := &WPScanClient{}
	if w.Name() != "wpscan" {
		t.Errorf("want 'wpscan', got %q", w.Name())
	}
}

func TestWPScanClient_FetchRecent_NotSupported(t *testing.T) {
	w := &WPScanClient{}
	_, err := w.FetchRecent(context.Background(), 10)
	if err == nil {
		t.Fatal("expected error for unsupported FetchRecent, got nil")
	}
}

func TestWPScanClient_FetchBySlug_ValidResponse(t *testing.T) {
	slug := "akismet"
	wpscanBody := map[string]interface{}{
		slug: map[string]interface{}{
			"friendly_name":  "Akismet Anti-Spam",
			"latest_version": "5.3",
			"vulnerabilities": []map[string]interface{}{
				{
					"title":         "Akismet XSS",
					"created_at":    "2023-01-01T00:00:00.000Z",
					"cves":          []string{"CVE-2023-0001"},
					"cvss_score":    6.5,
					"cvss_vector":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
					"vuln_type":     "XSS",
					"references":    map[string]interface{}{"url": []string{"https://example.com/vuln"}},
					"fixed_in":      "5.3.1",
					"introduced_in": "4.0.0",
				},
			},
		},
	}
	body, _ := json.Marshal(wpscanBody)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify Authorization header is set
		if r.Header.Get("Authorization") == "" {
			http.Error(w, "missing auth", http.StatusUnauthorized)
			return
		}
		w.Header().Set("X-Requests-Remaining", "99")
		w.WriteHeader(http.StatusOK)
		w.Write(body) //nolint:errcheck
	}))
	defer srv.Close()

	keyRotator := lazywphttp.NewKeyRotator([]string{"test-api-key"})
	cache := newTestCache(t)
	client := &WPScanClient{
		http:       newTestHTTPClient(srv),
		keyRotator: keyRotator,
		cache:      cache,
	}

	vulns, err := client.FetchBySlug(context.Background(), slug, Plugin)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vulns) != 1 {
		t.Fatalf("want 1 vuln, got %d", len(vulns))
	}
	if vulns[0].CVE != "CVE-2023-0001" {
		t.Errorf("want CVE-2023-0001, got %q", vulns[0].CVE)
	}
	if vulns[0].CVSS != 6.5 {
		t.Errorf("want CVSS=6.5, got %f", vulns[0].CVSS)
	}
	if vulns[0].FixedIn != "5.3.1" {
		t.Errorf("want FixedIn=5.3.1, got %q", vulns[0].FixedIn)
	}
	if vulns[0].Source != "wpscan" {
		t.Errorf("want source=wpscan, got %q", vulns[0].Source)
	}
}

func TestWPScanClient_FetchBySlug_404_ReturnsEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	keyRotator := lazywphttp.NewKeyRotator([]string{"test-key"})
	client := &WPScanClient{
		http:       newTestHTTPClient(srv),
		keyRotator: keyRotator,
		cache:      newTestCache(t),
	}

	vulns, err := client.FetchBySlug(context.Background(), "missing-plugin", Plugin)
	if err != nil {
		t.Fatalf("404 should return nil error, got: %v", err)
	}
	if vulns != nil {
		t.Errorf("404 should return nil vulns, got %d", len(vulns))
	}
}

func TestWPScanClient_FetchBySlug_NoAPIKeys(t *testing.T) {
	// keyRotator.Next() fails before any HTTP call is made.
	keyRotator := lazywphttp.NewKeyRotator([]string{}) // no keys
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("HTTP call should not be made when no API keys are configured")
	}))
	defer srv.Close()

	client := &WPScanClient{
		http:       newTestHTTPClient(srv),
		keyRotator: keyRotator,
		cache:      newTestCache(t),
	}

	_, err := client.FetchBySlug(context.Background(), "some-plugin", Plugin)
	if err == nil {
		t.Fatal("expected error when no API keys configured, got nil")
	}
}

func TestWPScanClient_FetchBySlug_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	keyRotator := lazywphttp.NewKeyRotator([]string{"test-key"})
	client := &WPScanClient{
		http:       newTestHTTPClient(srv),
		keyRotator: keyRotator,
		cache:      newTestCache(t),
	}

	_, err := client.FetchBySlug(context.Background(), "some-plugin", Plugin)
	if err == nil {
		t.Fatal("expected error for HTTP 500, got nil")
	}
}

func TestWPScanClient_FetchBySlug_CacheHit(t *testing.T) {
	slug := "cached-plugin"
	cachedVulns := []interface{}{
		map[string]interface{}{
			"cve": "CVE-2024-9999", "cvss": 7.5, "title": "Cached Vuln", "source": "wpscan",
		},
	}
	cacheData, _ := json.Marshal(cachedVulns)

	cache := newTestCache(t)
	_ = cache.Set("wpscan", slug+":"+string(Plugin), cacheData)

	// Server should never be called on cache hit
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	keyRotator := lazywphttp.NewKeyRotator([]string{"test-key"})
	client := &WPScanClient{
		http:       newTestHTTPClient(srv),
		keyRotator: keyRotator,
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

func TestWPScanClient_FetchBySlug_QuotaUpdated(t *testing.T) {
	slug := "quota-plugin"
	body, _ := json.Marshal(map[string]interface{}{
		slug: map[string]interface{}{
			"friendly_name":   "Quota Plugin",
			"latest_version":  "1.0",
			"vulnerabilities": []interface{}{},
		},
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Requests-Remaining", "42")
		w.WriteHeader(http.StatusOK)
		w.Write(body) //nolint:errcheck
	}))
	defer srv.Close()

	keyRotator := lazywphttp.NewKeyRotator([]string{"quota-key"})
	client := &WPScanClient{
		http:       newTestHTTPClient(srv),
		keyRotator: keyRotator,
		cache:      newTestCache(t),
	}

	_, err := client.FetchBySlug(context.Background(), slug, Plugin)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Verify quota was updated — next call should still return the same key (42 > 0)
	key, err := keyRotator.Next()
	if err != nil {
		t.Fatalf("expected key to still be available: %v", err)
	}
	if key != "quota-key" {
		t.Errorf("want quota-key, got %q", key)
	}
}

// --- parseWPScanResponse unit tests ---

func TestParseWPScanResponse_SlugKey(t *testing.T) {
	slug := "my-plugin"
	raw := map[string]interface{}{
		slug: map[string]interface{}{
			"friendly_name":  "My Plugin",
			"latest_version": "2.0",
			"vulnerabilities": []map[string]interface{}{
				{
					"title":      "SQLi in my-plugin",
					"cves":       []string{"CVE-2024-0002"},
					"cvss_score": 9.8,
					"vuln_type":  "SQLI",
					"references": map[string]interface{}{"url": []string{}},
					"fixed_in":   "2.0.1",
				},
			},
		},
	}
	body, _ := json.Marshal(raw)
	vulns, err := parseWPScanResponse(body, slug, Plugin)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vulns) != 1 {
		t.Fatalf("want 1 vuln, got %d", len(vulns))
	}
	if vulns[0].CVE != "CVE-2024-0002" {
		t.Errorf("want CVE-2024-0002, got %q", vulns[0].CVE)
	}
}

func TestParseWPScanResponse_FallbackKey(t *testing.T) {
	// Response key does not match slug; should fall back to first key.
	raw := map[string]interface{}{
		"different-key": map[string]interface{}{
			"friendly_name":   "Other",
			"latest_version":  "1.0",
			"vulnerabilities": []interface{}{},
		},
	}
	body, _ := json.Marshal(raw)
	vulns, err := parseWPScanResponse(body, "no-match-slug", Plugin)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vulns == nil {
		t.Error("want empty slice, got nil")
	}
}

func TestParseWPScanResponse_NoCVE(t *testing.T) {
	slug := "nocve-plugin"
	raw := map[string]interface{}{
		slug: map[string]interface{}{
			"vulnerabilities": []map[string]interface{}{
				{
					"title":      "Auth Bypass",
					"cves":       []string{},
					"cvss_score": 8.1,
					"vuln_type":  "AUTH_BYPASS",
					"references": map[string]interface{}{"url": []string{}},
				},
			},
		},
	}
	body, _ := json.Marshal(raw)
	vulns, err := parseWPScanResponse(body, slug, Plugin)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vulns) != 1 {
		t.Fatalf("want 1 vuln, got %d", len(vulns))
	}
	if vulns[0].CVE != "" {
		t.Errorf("want empty CVE when cves=[]], got %q", vulns[0].CVE)
	}
}
