package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	lazywphttp "github.com/hieuha/lazywp/internal/http"
)

func TestNVDClient_FetchRecent_ReturnsVulns(t *testing.T) {
	resp := makeNVDResponse([]nvdVulnItem{
		makeNVDVulnItem("CVE-2024-0001", "RCE in wordpress plugin-a", 9.8),
		makeNVDVulnItem("CVE-2024-0002", "XSS in wordpress plugin-b", 6.1),
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

	vulns, err := client.FetchRecent(context.Background(), 10)
	if err != nil {
		t.Fatalf("FetchRecent: %v", err)
	}
	if len(vulns) != 2 {
		t.Errorf("want 2 vulns, got %d", len(vulns))
	}
}

func TestNVDClient_FetchRecent_LimitApplied(t *testing.T) {
	resp := makeNVDResponse([]nvdVulnItem{
		makeNVDVulnItem("CVE-2024-1001", "Vuln 1", 9.0),
		makeNVDVulnItem("CVE-2024-1002", "Vuln 2", 8.0),
		makeNVDVulnItem("CVE-2024-1003", "Vuln 3", 7.0),
		makeNVDVulnItem("CVE-2024-1004", "Vuln 4", 6.0),
	})
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

	vulns, err := client.FetchRecent(context.Background(), 2)
	if err != nil {
		t.Fatalf("FetchRecent: %v", err)
	}
	if len(vulns) != 2 {
		t.Errorf("want 2 vulns after limit, got %d", len(vulns))
	}
}

func TestNVDClient_FetchRecent_ZeroLimit_ReturnsAll(t *testing.T) {
	resp := makeNVDResponse([]nvdVulnItem{
		makeNVDVulnItem("CVE-2024-2001", "Vuln A", 5.0),
		makeNVDVulnItem("CVE-2024-2002", "Vuln B", 4.0),
	})
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

	// limit=0 means no limit
	vulns, err := client.FetchRecent(context.Background(), 0)
	if err != nil {
		t.Fatalf("FetchRecent: %v", err)
	}
	if len(vulns) != 2 {
		t.Errorf("want 2 vulns with limit=0, got %d", len(vulns))
	}
}

func TestNVDClient_FetchRecent_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	client := &NVDClient{
		http:       newTestHTTPClient(srv),
		keyRotator: lazywphttp.NewKeyRotator([]string{}),
		cache:      newTestCache(t),
	}

	_, err := client.FetchRecent(context.Background(), 10)
	if err == nil {
		t.Fatal("expected error for HTTP 503, got nil")
	}
}
