package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	lazywphttp "github.com/hieuha/lazywp/internal/http"
	"github.com/hieuha/lazywp/internal/storage"
	"github.com/hieuha/lazywp/internal/vuln"
)

const nvdAPIBase = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// NVDClient fetches vulnerability data from the NVD/NIST CVE API 2.0.
type NVDClient struct {
	http       *lazywphttp.Client
	keyRotator *lazywphttp.KeyRotator
	cache      *vuln.Cache
}

// NewNVDClient creates an NVDClient with a KeyRotator for multi-key rotation.
func NewNVDClient(httpClient *lazywphttp.Client, keyRotator *lazywphttp.KeyRotator, cache *vuln.Cache) *NVDClient {
	return &NVDClient{http: httpClient, keyRotator: keyRotator, cache: cache}
}

// Name identifies this source.
func (n *NVDClient) Name() string { return "nvd" }

// FetchBySlug searches NVD for CVEs matching "wordpress {slug}".
// Results are cached per slug+itemType.
func (n *NVDClient) FetchBySlug(ctx context.Context, slug string, itemType ItemType) ([]storage.Vulnerability, error) {
	cacheKey := slug + ":" + string(itemType)
	if data, ok := n.cache.Get(n.Name(), cacheKey); ok {
		return parseNVDCached(data)
	}

	keyword := "wordpress " + slug
	vulns, err := n.queryNVD(ctx, url.Values{
		"keywordSearch": {keyword},
	})
	if err != nil {
		return nil, err
	}

	if encoded, err := json.Marshal(vulns); err == nil {
		_ = n.cache.Set(n.Name(), cacheKey, encoded)
	}
	return vulns, nil
}

// FetchRecent fetches CVEs published in the last 30 days related to wordpress plugins.
func (n *NVDClient) FetchRecent(ctx context.Context, limit int) ([]storage.Vulnerability, error) {
	pubStart := time.Now().UTC().Add(-30 * 24 * time.Hour).Format("2006-01-02T15:04:05.000")
	vulns, err := n.queryNVD(ctx, url.Values{
		"keywordSearch": {"wordpress plugin"},
		"pubStartDate":  {pubStart},
	})
	if err != nil {
		return nil, err
	}
	if limit > 0 && len(vulns) > limit {
		vulns = vulns[:limit]
	}
	return vulns, nil
}

// queryNVD executes a request to the NVD API with the given query parameters.
// On 403/429, marks the current key as exhausted and retries with the next key.
func (n *NVDClient) queryNVD(ctx context.Context, params url.Values) ([]storage.Vulnerability, error) {
	reqURL := nvdAPIBase + "?" + params.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("nvd: build request: %w", err)
	}
	var usedKey string
	if n.keyRotator != nil {
		if key, err := n.keyRotator.Next(); err == nil && key != "" {
			req.Header.Set("apiKey", key)
			usedKey = key
		}
	}
	req.Header.Set("User-Agent", "lazywp-cli/1.0")

	resp, err := n.http.Do(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("nvd: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		if usedKey != "" && n.keyRotator != nil {
			n.keyRotator.UpdateQuota(usedKey, 0)
			if !n.keyRotator.AllExhausted() {
				return n.queryNVD(ctx, params) // retry with next key
			}
		}
		return nil, fmt.Errorf("nvd: rate limited (HTTP %d) — all API keys exhausted", resp.StatusCode)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("nvd: HTTP %d", resp.StatusCode)
	}

	var nvdResp nvdResponse
	if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
		return nil, fmt.Errorf("nvd: decode response: %w", err)
	}

	return mapNVDVulns(nvdResp.Vulnerabilities), nil
}

// parseNVDCached decodes previously cached []storage.Vulnerability JSON.
func parseNVDCached(data []byte) ([]storage.Vulnerability, error) {
	var vulns []storage.Vulnerability
	if err := json.Unmarshal(data, &vulns); err != nil {
		return nil, fmt.Errorf("nvd: decode cached: %w", err)
	}
	return vulns, nil
}

// mapNVDVulns converts NVD API items to storage.Vulnerability slice.
func mapNVDVulns(items []nvdVulnItem) []storage.Vulnerability {
	vulns := make([]storage.Vulnerability, 0, len(items))
	for _, item := range items {
		cve := item.CVE
		title := englishDescription(cve.Descriptions)
		if title == "" {
			title = cve.ID
		}

		cvss := cvssScore(cve.Metrics)

		v := storage.Vulnerability{
			CVE:    cve.ID,
			CVSS:   cvss,
			Title:  title,
			Source: "nvd",
		}
		vulns = append(vulns, v)
	}
	return vulns
}

// englishDescription extracts the first English description text.
func englishDescription(descs []nvdDescription) string {
	for _, d := range descs {
		if d.Lang == "en" {
			return d.Value
		}
	}
	if len(descs) > 0 {
		return descs[0].Value
	}
	return ""
}

// cvssScore extracts the CVSS v3.1 base score, falling back to v2.
func cvssScore(metrics nvdMetrics) float64 {
	if len(metrics.CVSSMetricV31) > 0 {
		return metrics.CVSSMetricV31[0].CVSSData.BaseScore
	}
	if len(metrics.CVSSMetricV30) > 0 {
		return metrics.CVSSMetricV30[0].CVSSData.BaseScore
	}
	if len(metrics.CVSSMetricV2) > 0 {
		return metrics.CVSSMetricV2[0].CVSSData.BaseScore
	}
	return 0
}

// --- NVD API response types ---

type nvdResponse struct {
	ResultsPerPage int           `json:"resultsPerPage"`
	StartIndex     int           `json:"startIndex"`
	TotalResults   int           `json:"totalResults"`
	Vulnerabilities []nvdVulnItem `json:"vulnerabilities"`
}

type nvdVulnItem struct {
	CVE nvdCVE `json:"cve"`
}

type nvdCVE struct {
	ID           string           `json:"id"`
	Descriptions []nvdDescription `json:"descriptions"`
	Metrics      nvdMetrics       `json:"metrics"`
}

type nvdDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdMetrics struct {
	CVSSMetricV31 []nvdCVSSEntry `json:"cvssMetricV31"`
	CVSSMetricV30 []nvdCVSSEntry `json:"cvssMetricV30"`
	CVSSMetricV2  []nvdCVSSEntry `json:"cvssMetricV2"`
}

type nvdCVSSEntry struct {
	CVSSData nvdCVSSData `json:"cvssData"`
}

type nvdCVSSData struct {
	BaseScore float64 `json:"baseScore"`
}
