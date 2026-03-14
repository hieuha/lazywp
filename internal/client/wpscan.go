package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	lazywphttp "github.com/hieuha/lazywp/internal/http"
	"github.com/hieuha/lazywp/internal/storage"
	"github.com/hieuha/lazywp/internal/vuln"
)

const wpscanAPIBase = "https://wpscan.com/api/v3"

// WPScanClient fetches vulnerability data from the WPScan API.
type WPScanClient struct {
	http       *lazywphttp.Client
	keyRotator *lazywphttp.KeyRotator
	cache      *vuln.Cache
}

// NewWPScanClient creates a WPScanClient with the given dependencies.
func NewWPScanClient(httpClient *lazywphttp.Client, keyRotator *lazywphttp.KeyRotator, cache *vuln.Cache) *WPScanClient {
	return &WPScanClient{http: httpClient, keyRotator: keyRotator, cache: cache}
}

// Name identifies this source.
func (w *WPScanClient) Name() string { return "wpscan" }

// FetchRecent is not supported by WPScan; returns an error.
func (w *WPScanClient) FetchRecent(_ context.Context, _ int) ([]storage.Vulnerability, error) {
	return nil, fmt.Errorf("wpscan: FetchRecent not supported")
}

// FetchBySlug fetches vulnerabilities for a plugin or theme slug from WPScan API.
// Returns cached data if available. Handles 404 as empty (no error).
func (w *WPScanClient) FetchBySlug(ctx context.Context, slug string, itemType ItemType) ([]storage.Vulnerability, error) {
	cacheKey := slug + ":" + string(itemType)

	if data, ok := w.cache.Get(w.Name(), cacheKey); ok {
		return parseWPScanCached(data)
	}

	key, err := w.keyRotator.Next()
	if err != nil {
		return nil, fmt.Errorf("wpscan: no API key available: %w", err)
	}

	url := fmt.Sprintf("%s/%s/%s", wpscanAPIBase, itemType.Plural(), slug)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("wpscan: build request: %w", err)
	}
	req.Header.Set("Authorization", "Token token="+key)
	req.Header.Set("User-Agent", "lazywp-cli/1.0")

	resp, err := w.http.Do(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("wpscan: request %s: %w", slug, err)
	}
	defer resp.Body.Close()

	// Update quota from response header
	if remaining := resp.Header.Get("X-Requests-Remaining"); remaining != "" {
		if n, err := strconv.Atoi(remaining); err == nil {
			w.keyRotator.UpdateQuota(key, n)
		}
	}

	if resp.StatusCode == http.StatusNotFound {
		// 404 means no vulnerabilities; cache empty result
		_ = w.cache.Set(w.Name(), cacheKey, []byte("[]"))
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("wpscan: HTTP %d for %s", resp.StatusCode, slug)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("wpscan: read body: %w", err)
	}

	vulns, err := parseWPScanResponse(body, slug, itemType)
	if err != nil {
		return nil, err
	}

	// Cache raw vuln list as JSON
	if encoded, err := json.Marshal(vulns); err == nil {
		_ = w.cache.Set(w.Name(), cacheKey, encoded)
	}

	return vulns, nil
}

// wpscanVuln mirrors the WPScan API vulnerability structure.
type wpscanVuln struct {
	Title      string          `json:"title"`
	CreatedAt  string          `json:"created_at"`
	UpdatedAt  string          `json:"updated_at"`
	CVEs       []string        `json:"cves"`
	CVSSScore  float64         `json:"cvss_score"`
	CVSSVector string          `json:"cvss_vector"`
	Type       string          `json:"vuln_type"`
	References wpscanRefs      `json:"references"`
	FixedIn    string          `json:"fixed_in"`
	Introduced string          `json:"introduced_in"`
}

type wpscanRefs struct {
	URL []string `json:"url"`
}

// wpscanPluginResponse is the top-level WPScan API response for plugins/themes.
// The slug is the dynamic key at the top level.
type wpscanPluginResponse struct {
	FriendlyName    string       `json:"friendly_name"`
	LatestVersion   string       `json:"latest_version"`
	Vulnerabilities []wpscanVuln `json:"vulnerabilities"`
}

// parseWPScanCached decodes a previously cached []storage.Vulnerability JSON blob.
func parseWPScanCached(data []byte) ([]storage.Vulnerability, error) {
	var vulns []storage.Vulnerability
	if err := json.Unmarshal(data, &vulns); err != nil {
		return nil, fmt.Errorf("wpscan: decode cached data: %w", err)
	}
	return vulns, nil
}

// parseWPScanResponse extracts vulnerabilities from the raw WPScan API JSON body.
func parseWPScanResponse(body []byte, slug string, _ ItemType) ([]storage.Vulnerability, error) {
	// WPScan wraps the result under the slug key: { "slug": { "vulnerabilities": [...] } }
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("wpscan: parse response: %w", err)
	}

	// Find the entry — try slug first, then any key
	entry, ok := raw[slug]
	if !ok {
		for _, v := range raw {
			entry = v
			break
		}
	}
	if entry == nil {
		return nil, nil
	}

	var pluginData wpscanPluginResponse
	if err := json.Unmarshal(entry, &pluginData); err != nil {
		return nil, fmt.Errorf("wpscan: parse plugin data: %w", err)
	}

	vulns := make([]storage.Vulnerability, 0, len(pluginData.Vulnerabilities))
	for _, wv := range pluginData.Vulnerabilities {
		cve := ""
		if len(wv.CVEs) > 0 {
			cve = wv.CVEs[0]
		}
		v := storage.Vulnerability{
			CVE:              cve,
			CVSS:             wv.CVSSScore,
			Type:             wv.Type,
			Title:            wv.Title,
			Source:           "wpscan",
			AffectedVersions: wv.Introduced,
			FixedIn:          wv.FixedIn,
			References:       wv.References.URL,
		}
		vulns = append(vulns, v)
	}
	return vulns, nil
}
