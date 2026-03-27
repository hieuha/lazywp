package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	lazywphttp "github.com/hieuha/lazywp/internal/http"
)

func TestWordfenceClient_FetchVulnPlugins_Basic(t *testing.T) {
	feed := map[string]wfVulnRecord{
		"v1": makeWFRecord("v1", "SQLi in akismet", "akismet", "plugin", 9.8, nil),
		"v2": makeWFRecord("v2", "XSS in akismet", "akismet", "plugin", 7.0, nil),
		"v3": makeWFRecord("v3", "RCE in jetpack", "jetpack", "plugin", 9.0, nil),
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(buildWFFeed(feed)) //nolint:errcheck
	}))
	defer srv.Close()

	client := newWordfenceClient(t, srv)
	items, err := client.FetchVulnPlugins(context.Background(), WordfenceFilters{}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("want 2 items (akismet, jetpack), got %d", len(items))
	}
	// akismet has 2 vulns → sorted first
	if items[0].Slug != "akismet" {
		t.Errorf("want akismet first (most vulns), got %q", items[0].Slug)
	}
	if items[0].VulnCount != 2 {
		t.Errorf("akismet VulnCount = %d, want 2", items[0].VulnCount)
	}
}

func TestWordfenceClient_FetchVulnPlugins_Limit(t *testing.T) {
	feed := map[string]wfVulnRecord{
		"a1": makeWFRecord("a1", "Vuln in plugin-a", "plugin-a", "plugin", 9.0, nil),
		"b1": makeWFRecord("b1", "Vuln in plugin-b", "plugin-b", "plugin", 8.0, nil),
		"c1": makeWFRecord("c1", "Vuln in plugin-c", "plugin-c", "plugin", 7.0, nil),
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(buildWFFeed(feed)) //nolint:errcheck
	}))
	defer srv.Close()

	wf := newWordfenceClient(t, srv)
	items, err := wf.FetchVulnPlugins(context.Background(), WordfenceFilters{}, 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(items) != 2 {
		t.Errorf("want 2 items after limit, got %d", len(items))
	}
}

func TestWordfenceClient_FetchVulnPlugins_SkipsCore(t *testing.T) {
	coreRecord := wfVulnRecord{
		ID:    "core1",
		Title: "Core Vuln",
		Software: []wfSoftware{
			{Type: "core", Slug: "", Name: "WordPress Core"},
		},
	}
	feed := map[string]wfVulnRecord{
		"core1": coreRecord,
		"p1":    makeWFRecord("p1", "Plugin Vuln", "my-plugin", "plugin", 7.0, nil),
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(buildWFFeed(feed)) //nolint:errcheck
	}))
	defer srv.Close()

	wf := newWordfenceClient(t, srv)
	items, err := wf.FetchVulnPlugins(context.Background(), WordfenceFilters{}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, item := range items {
		if item.Slug == "" {
			t.Error("core entry (empty slug) should be skipped")
		}
	}
}

func TestWordfenceClient_FetchVulnPlugins_WithFilter(t *testing.T) {
	feed := map[string]wfVulnRecord{
		"h1": makeWFRecord("h1", "High Vuln", "plugin-h", "plugin", 8.5, nil),
		"m1": makeWFRecord("m1", "Medium Vuln", "plugin-m", "plugin", 5.0, nil),
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(buildWFFeed(feed)) //nolint:errcheck
	}))
	defer srv.Close()

	wf := newWordfenceClient(t, srv)
	items, err := wf.FetchVulnPlugins(context.Background(), WordfenceFilters{CVSSRating: "high"}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("want 1 high-rated item, got %d", len(items))
	}
	if items[0].Slug != "plugin-h" {
		t.Errorf("want plugin-h, got %q", items[0].Slug)
	}
}

func TestWordfenceClient_FetchVulnPlugins_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	wf := &WordfenceClient{
		http:       newTestHTTPClient(srv),
		keyRotator: lazywphttp.NewKeyRotator([]string{}),
		cache:      newTestCache(t),
	}
	_, err := wf.FetchVulnPlugins(context.Background(), WordfenceFilters{}, 0)
	if err == nil {
		t.Fatal("expected error for HTTP 500, got nil")
	}
}
