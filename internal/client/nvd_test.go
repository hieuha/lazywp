package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	lazywphttp "github.com/hieuha/lazywp/internal/http"
)

func TestNVDClient_Name(t *testing.T) {
	n := &NVDClient{}
	if n.Name() != "nvd" {
		t.Errorf("want 'nvd', got %q", n.Name())
	}
}

func makeNVDResponse(items []nvdVulnItem) nvdResponse {
	return nvdResponse{
		ResultsPerPage:  len(items),
		TotalResults:    len(items),
		Vulnerabilities: items,
	}
}

func makeNVDVulnItem(id, desc string, score float64) nvdVulnItem {
	return nvdVulnItem{
		CVE: nvdCVE{
			ID: id,
			Descriptions: []nvdDescription{
				{Lang: "en", Value: desc},
			},
			Metrics: nvdMetrics{
				CVSSMetricV31: []nvdCVSSEntry{
					{CVSSData: nvdCVSSData{BaseScore: score}},
				},
			},
		},
	}
}

func TestNVDClient_FetchBySlug_ValidResponse(t *testing.T) {
	resp := makeNVDResponse([]nvdVulnItem{
		makeNVDVulnItem("CVE-2024-1234", "SQL injection in wordpress akismet plugin", 7.5),
	})
	body, _ := json.Marshal(resp)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(body) //nolint:errcheck
	}))
	defer srv.Close()

	client := &NVDClient{
		http:       newTestHTTPClient(srv),
		keyRotator: lazywphttp.NewKeyRotator([]string{}),
		cache:      newTestCache(t),
	}

	vulns, err := client.FetchBySlug(context.Background(), "akismet", Plugin)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vulns) != 1 {
		t.Fatalf("want 1 vuln, got %d", len(vulns))
	}
	if vulns[0].CVE != "CVE-2024-1234" {
		t.Errorf("want CVE-2024-1234, got %q", vulns[0].CVE)
	}
	if vulns[0].CVSS != 7.5 {
		t.Errorf("want CVSS=7.5, got %f", vulns[0].CVSS)
	}
	if vulns[0].Source != "nvd" {
		t.Errorf("want source=nvd, got %q", vulns[0].Source)
	}
	if vulns[0].Title != "SQL injection in wordpress akismet plugin" {
		t.Errorf("unexpected title: %q", vulns[0].Title)
	}
}

func TestNVDClient_FetchBySlug_EmptyResults(t *testing.T) {
	resp := makeNVDResponse([]nvdVulnItem{})
	body, _ := json.Marshal(resp)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(body) //nolint:errcheck
	}))
	defer srv.Close()

	client := &NVDClient{
		http:       newTestHTTPClient(srv),
		keyRotator: lazywphttp.NewKeyRotator([]string{}),
		cache:      newTestCache(t),
	}

	vulns, err := client.FetchBySlug(context.Background(), "obscure-plugin", Plugin)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vulns) != 0 {
		t.Errorf("want 0 vulns for empty NVD response, got %d", len(vulns))
	}
}

func TestNVDClient_FetchBySlug_CacheHit(t *testing.T) {
	slug := "cached-nvd-plugin"
	cachedVulns := []interface{}{
		map[string]interface{}{
			"cve": "CVE-2023-5555", "cvss": 5.0, "title": "Cached NVD", "source": "nvd",
		},
	}
	cacheData, _ := json.Marshal(cachedVulns)

	cache := newTestCache(t)
	_ = cache.Set("nvd", slug+":"+string(Plugin), cacheData)

	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := &NVDClient{
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

func TestNVDClient_FetchBySlug_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := &NVDClient{
		http:       newTestHTTPClient(srv),
		keyRotator: lazywphttp.NewKeyRotator([]string{}),
		cache:      newTestCache(t),
	}

	_, err := client.FetchBySlug(context.Background(), "error-plugin", Plugin)
	if err == nil {
		t.Fatal("expected error for HTTP 500, got nil")
	}
}

func TestNVDClient_FetchBySlug_WithAPIKey(t *testing.T) {
	resp := makeNVDResponse([]nvdVulnItem{
		makeNVDVulnItem("CVE-2024-9999", "Test vuln with api key", 3.5),
	})
	body, _ := json.Marshal(resp)

	var receivedAPIKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAPIKey = r.Header.Get("apiKey")
		w.WriteHeader(http.StatusOK)
		w.Write(body) //nolint:errcheck
	}))
	defer srv.Close()

	client := &NVDClient{
		http:       newTestHTTPClient(srv),
		keyRotator: lazywphttp.NewKeyRotator([]string{"my-nvd-key"}),
		cache:      newTestCache(t),
	}

	_, err := client.FetchBySlug(context.Background(), "some-plugin", Plugin)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedAPIKey != "my-nvd-key" {
		t.Errorf("want apiKey header=my-nvd-key, got %q", receivedAPIKey)
	}
}

func TestNVDClient_FetchBySlug_NoKeyRotator(t *testing.T) {
	resp := makeNVDResponse([]nvdVulnItem{
		makeNVDVulnItem("CVE-2024-8888", "No key test", 2.0),
	})
	body, _ := json.Marshal(resp)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(body) //nolint:errcheck
	}))
	defer srv.Close()

	// nil keyRotator is valid — NVD API is free without a key (rate-limited).
	client := &NVDClient{
		http:       newTestHTTPClient(srv),
		keyRotator: nil,
		cache:      newTestCache(t),
	}

	vulns, err := client.FetchBySlug(context.Background(), "free-plugin", Plugin)
	if err != nil {
		t.Fatalf("unexpected error with nil keyRotator: %v", err)
	}
	if len(vulns) != 1 {
		t.Errorf("want 1 vuln, got %d", len(vulns))
	}
}

// --- helper function tests ---

func TestEnglishDescription_FirstEnglish(t *testing.T) {
	descs := []nvdDescription{
		{Lang: "es", Value: "Descripcion"},
		{Lang: "en", Value: "English description"},
	}
	got := englishDescription(descs)
	if got != "English description" {
		t.Errorf("want English description, got %q", got)
	}
}

func TestEnglishDescription_FallbackToFirst(t *testing.T) {
	descs := []nvdDescription{
		{Lang: "fr", Value: "Description française"},
	}
	got := englishDescription(descs)
	if got != "Description française" {
		t.Errorf("want fallback to first, got %q", got)
	}
}

func TestEnglishDescription_Empty(t *testing.T) {
	got := englishDescription(nil)
	if got != "" {
		t.Errorf("want empty string, got %q", got)
	}
}

func TestCVSSScore_V31Priority(t *testing.T) {
	metrics := nvdMetrics{
		CVSSMetricV31: []nvdCVSSEntry{{CVSSData: nvdCVSSData{BaseScore: 9.8}}},
		CVSSMetricV30: []nvdCVSSEntry{{CVSSData: nvdCVSSData{BaseScore: 8.5}}},
		CVSSMetricV2:  []nvdCVSSEntry{{CVSSData: nvdCVSSData{BaseScore: 7.0}}},
	}
	got := cvssScore(metrics)
	if got != 9.8 {
		t.Errorf("want V3.1 score=9.8, got %f", got)
	}
}

func TestCVSSScore_V30Fallback(t *testing.T) {
	metrics := nvdMetrics{
		CVSSMetricV30: []nvdCVSSEntry{{CVSSData: nvdCVSSData{BaseScore: 8.5}}},
		CVSSMetricV2:  []nvdCVSSEntry{{CVSSData: nvdCVSSData{BaseScore: 7.0}}},
	}
	got := cvssScore(metrics)
	if got != 8.5 {
		t.Errorf("want V3.0 score=8.5, got %f", got)
	}
}

func TestCVSSScore_V2Fallback(t *testing.T) {
	metrics := nvdMetrics{
		CVSSMetricV2: []nvdCVSSEntry{{CVSSData: nvdCVSSData{BaseScore: 6.5}}},
	}
	got := cvssScore(metrics)
	if got != 6.5 {
		t.Errorf("want V2 score=6.5, got %f", got)
	}
}

func TestCVSSScore_NoMetrics(t *testing.T) {
	got := cvssScore(nvdMetrics{})
	if got != 0 {
		t.Errorf("want 0 for no metrics, got %f", got)
	}
}
