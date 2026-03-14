package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	lazywphttp "github.com/hieuha/lazywp/internal/http"
	"github.com/hieuha/lazywp/internal/storage"
	"github.com/hieuha/lazywp/internal/vuln"
)

const (
	wordfenceAPIBase    = "https://www.wordfence.com/api/intelligence/v3"
	wordfenceFeedPath   = "/vulnerabilities/production"
	wordfenceCacheKey   = "feed:production"
)

// WordfenceFilters holds optional filters applied client-side after fetching the feed.
type WordfenceFilters struct {
	CWEType    string // e.g. sqli, xss, rce (matched against CWE name, case-insensitive)
	CVSSRating string // critical, high, medium, low (matched against cvss.rating)
	Month      int    // 1-12 (matched against published date month)
	Year       int    // e.g. 2024 (matched against published date year)
	Search     string // substring match against title (case-insensitive)
}

// WordfenceVuln represents a parsed vulnerability entry from the Wordfence v3 API.
type WordfenceVuln struct {
	Title           string
	Slug            string
	SoftwareType    string // plugin, theme, core
	CVE             string
	CVSS            float64
	CVSSRating      string
	CWEName         string
	Type            string // vuln type derived from CWE
	AffectedVersion string // human-readable range from affected_versions
	PatchedVersion  string // first entry from patched_versions, if any
	Link            string // first reference URL
	Published       string // ISO date string
}

// VulnerableItem groups vulnerabilities by plugin/theme slug.
type VulnerableItem struct {
	Slug      string                   `json:"slug"`
	Name      string                   `json:"name"`
	VulnCount int                      `json:"vuln_count"`
	MaxCVSS   float64                  `json:"max_cvss"`
	Vulns     []storage.Vulnerability  `json:"vulns,omitempty"`
}

// WordfenceClient fetches vulnerability data from the Wordfence Intelligence v3 API.
type WordfenceClient struct {
	http       *lazywphttp.Client
	keyRotator *lazywphttp.KeyRotator
	cache      *vuln.Cache
}

// NewWordfenceClient creates a WordfenceClient with a KeyRotator for multi-key rotation.
func NewWordfenceClient(httpClient *lazywphttp.Client, keyRotator *lazywphttp.KeyRotator, cache *vuln.Cache) *WordfenceClient {
	return &WordfenceClient{http: httpClient, keyRotator: keyRotator, cache: cache}
}

// Name identifies this source.
func (wf *WordfenceClient) Name() string { return "wordfence" }

// --- v3 API response types ---

// wfVulnRecord mirrors the Wordfence v3 production feed record structure.
type wfVulnRecord struct {
	ID          string          `json:"id"`
	Title       string          `json:"title"`
	Description string          `json:"description"`
	CVE         *string         `json:"cve"`
	CVELink     *string         `json:"cve_link"`
	CVSS        *wfCVSS         `json:"cvss"`
	CWE         *wfCWE          `json:"cwe"`
	Software    []wfSoftware    `json:"software"`
	References  []string        `json:"references"`
	Published   *string         `json:"published"`
	Updated     *string         `json:"updated"`
	Researchers []string        `json:"researchers"`
	Informational *bool         `json:"informational"`
}

type wfCVSS struct {
	Vector string  `json:"vector"`
	Score  float64 `json:"score"`
	Rating string  `json:"rating"`
}

type wfCWE struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type wfSoftware struct {
	Type             string                     `json:"type"`
	Name             string                     `json:"name"`
	Slug             string                     `json:"slug"`
	AffectedVersions map[string]wfVersionRange  `json:"affected_versions"`
	Patched          bool                       `json:"patched"`
	PatchedVersions  []string                   `json:"patched_versions"`
	Remediation      string                     `json:"remediation"`
}

type wfVersionRange struct {
	FromVersion   string `json:"from_version"`
	FromInclusive bool   `json:"from_inclusive"`
	ToVersion     string `json:"to_version"`
	ToInclusive   bool   `json:"to_inclusive"`
}

// fetchFeed fetches the Wordfence production feed from the API.
// Returns the raw JSON body. On 429/401, marks the current key as exhausted and
// rotates to the next key if available.
func (wf *WordfenceClient) fetchFeed(ctx context.Context) ([]byte, error) {
	url := wordfenceAPIBase + wordfenceFeedPath

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("wordfence: build request: %w", err)
	}
	req.Header.Set("User-Agent", "lazywp-cli/1.0")

	var usedKey string
	if wf.keyRotator != nil {
		if key, err := wf.keyRotator.Next(); err == nil && key != "" {
			req.Header.Set("Authorization", "Bearer "+key)
			usedKey = key
		}
	}

	resp, err := wf.http.Do(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("wordfence: fetch feed: %w", err)
	}
	defer resp.Body.Close()

	// On rate limit or auth failure, mark key exhausted and retry with next key
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusUnauthorized {
		if usedKey != "" && wf.keyRotator != nil {
			wf.keyRotator.UpdateQuota(usedKey, 0)
			if !wf.keyRotator.AllExhausted() {
				return wf.fetchFeed(ctx) // retry with next key
			}
		}
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, fmt.Errorf("wordfence: API key required (401) — set wordfence_keys in config")
		}
		return nil, fmt.Errorf("wordfence: rate limited (429) — all API keys exhausted")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("wordfence: HTTP %d fetching feed", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("wordfence: read feed body: %w", err)
	}
	return body, nil
}

// loadFeed returns the parsed feed from cache or fetches it fresh.
func (wf *WordfenceClient) loadFeed(ctx context.Context) (map[string]wfVulnRecord, error) {
	if data, ok := wf.cache.Get(wf.Name(), wordfenceCacheKey); ok {
		var records map[string]wfVulnRecord
		if err := json.Unmarshal(data, &records); err == nil {
			return records, nil
		}
	}

	body, err := wf.fetchFeed(ctx)
	if err != nil {
		return nil, err
	}

	var records map[string]wfVulnRecord
	if err := json.Unmarshal(body, &records); err != nil {
		return nil, fmt.Errorf("wordfence: parse feed JSON: %w", err)
	}

	// Cache the raw body — re-parse on cache hit is cheap vs. re-fetch
	_ = wf.cache.Set(wf.Name(), wordfenceCacheKey, body)
	return records, nil
}

// FetchRecent fetches the full feed and returns the newest vulnerabilities up to limit.
func (wf *WordfenceClient) FetchRecent(ctx context.Context, limit int) ([]storage.Vulnerability, error) {
	records, err := wf.loadFeed(ctx)
	if err != nil {
		return nil, err
	}

	// Collect all, sort by published date desc
	all := make([]wfVulnRecord, 0, len(records))
	for _, r := range records {
		all = append(all, r)
	}
	sort.Slice(all, func(i, j int) bool {
		return publishedStr(all[i]) > publishedStr(all[j])
	})

	if limit > 0 && len(all) > limit {
		all = all[:limit]
	}

	vulns := make([]storage.Vulnerability, 0, len(all))
	for _, r := range all {
		vulns = append(vulns, recordToVuln(r, ""))
	}
	return vulns, nil
}

// FetchBySlug fetches vulnerabilities for a specific plugin/theme slug from the feed.
func (wf *WordfenceClient) FetchBySlug(ctx context.Context, slug string, itemType ItemType) ([]storage.Vulnerability, error) {
	cacheKey := "slug:" + slug + ":" + string(itemType)
	if data, ok := wf.cache.Get(wf.Name(), cacheKey); ok {
		var cached []storage.Vulnerability
		if err := json.Unmarshal(data, &cached); err == nil {
			return cached, nil
		}
	}

	records, err := wf.loadFeed(ctx)
	if err != nil {
		return nil, err
	}

	vulns := make([]storage.Vulnerability, 0)
	for _, r := range records {
		for _, sw := range r.Software {
			if sw.Slug == slug && matchesSoftwareType(sw.Type, itemType) {
				vulns = append(vulns, recordToVuln(r, sw.Slug))
				break
			}
		}
	}

	// Sort by CVSS desc
	sort.Slice(vulns, func(i, j int) bool {
		return vulns[i].CVSS > vulns[j].CVSS
	})

	if encoded, err := json.Marshal(vulns); err == nil {
		_ = wf.cache.Set(wf.Name(), cacheKey, encoded)
	}
	return vulns, nil
}

// SearchVulns returns vulnerabilities matching the given filters from the feed.
func (wf *WordfenceClient) SearchVulns(ctx context.Context, filters WordfenceFilters) ([]WordfenceVuln, error) {
	records, err := wf.loadFeed(ctx)
	if err != nil {
		return nil, err
	}

	var result []WordfenceVuln
	for _, r := range records {
		wv := recordToWordfenceVuln(r)
		if !matchesFilters(wv, r, filters) {
			continue
		}
		result = append(result, wv)
	}

	// Sort by CVSS desc
	sort.Slice(result, func(i, j int) bool {
		return result[i].CVSS > result[j].CVSS
	})
	return result, nil
}

// FetchVulnPlugins returns top N vulnerable plugins/themes grouped by slug.
func (wf *WordfenceClient) FetchVulnPlugins(ctx context.Context, filters WordfenceFilters, limit int) ([]VulnerableItem, error) {
	records, err := wf.loadFeed(ctx)
	if err != nil {
		return nil, err
	}

	bySlug := make(map[string]*VulnerableItem)
	for _, r := range records {
		wv := recordToWordfenceVuln(r)
		if !matchesFilters(wv, r, filters) {
			continue
		}
		for _, sw := range r.Software {
			if sw.Type == "core" {
				continue
			}
			slug := sw.Slug
			if slug == "" {
				continue
			}
			item, ok := bySlug[slug]
			if !ok {
				item = &VulnerableItem{Slug: slug, Name: sw.Name}
				bySlug[slug] = item
			}
			item.VulnCount++
			v := recordToVuln(r, slug)
			if v.CVSS > item.MaxCVSS {
				item.MaxCVSS = v.CVSS
			}
			item.Vulns = append(item.Vulns, v)
		}
	}

	items := make([]VulnerableItem, 0, len(bySlug))
	for _, v := range bySlug {
		items = append(items, *v)
	}

	// Sort by vuln count desc, then MaxCVSS desc
	sort.Slice(items, func(i, j int) bool {
		if items[i].VulnCount != items[j].VulnCount {
			return items[i].VulnCount > items[j].VulnCount
		}
		return items[i].MaxCVSS > items[j].MaxCVSS
	})

	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	return items, nil
}

// --- helpers ---

// recordToVuln converts a wfVulnRecord to storage.Vulnerability.
func recordToVuln(r wfVulnRecord, slug string) storage.Vulnerability {
	cve := ""
	if r.CVE != nil {
		cve = *r.CVE
	}
	cvss := 0.0
	if r.CVSS != nil {
		cvss = r.CVSS.Score
	}
	vulnType := cweToType(r.CWE)
	fixedIn := firstPatchedVersion(r.Software, slug)
	affectedVer := affectedVersionStr(r.Software, slug)

	return storage.Vulnerability{
		CVE:              cve,
		CVSS:             cvss,
		Type:             vulnType,
		Title:            r.Title,
		Source:           "wordfence",
		AffectedVersions: affectedVer,
		FixedIn:          fixedIn,
		References:       r.References,
	}
}

// recordToWordfenceVuln converts a wfVulnRecord to WordfenceVuln.
func recordToWordfenceVuln(r wfVulnRecord) WordfenceVuln {
	wv := WordfenceVuln{
		Title:     r.Title,
		Published: strVal(r.Published),
		Type:      cweToType(r.CWE),
	}
	if r.CVE != nil {
		wv.CVE = *r.CVE
	}
	if r.CVSS != nil {
		wv.CVSS = r.CVSS.Score
		wv.CVSSRating = r.CVSS.Rating
	}
	if r.CWE != nil {
		wv.CWEName = r.CWE.Name
	}
	if len(r.References) > 0 {
		wv.Link = r.References[0]
	}
	// Use first non-core software entry for slug/type
	for _, sw := range r.Software {
		if sw.Type == "core" {
			continue
		}
		wv.Slug = sw.Slug
		wv.SoftwareType = sw.Type
		wv.AffectedVersion = softwareAffectedVersionStr(sw)
		if len(sw.PatchedVersions) > 0 {
			wv.PatchedVersion = sw.PatchedVersions[0]
		}
		break
	}
	return wv
}

// matchesFilters returns true if wv/record matches all non-zero filter fields.
func matchesFilters(wv WordfenceVuln, r wfVulnRecord, f WordfenceFilters) bool {
	if f.Search != "" && !strings.Contains(strings.ToLower(wv.Title), strings.ToLower(f.Search)) &&
		!strings.Contains(strings.ToLower(wv.Slug), strings.ToLower(f.Search)) {
		return false
	}
	if f.CVSSRating != "" && !strings.EqualFold(wv.CVSSRating, f.CVSSRating) {
		return false
	}
	if f.CWEType != "" && r.CWE != nil {
		if !strings.Contains(strings.ToLower(r.CWE.Name), strings.ToLower(f.CWEType)) &&
			!strings.Contains(strings.ToLower(cweToType(r.CWE)), strings.ToLower(f.CWEType)) {
			return false
		}
	} else if f.CWEType != "" {
		return false
	}
	if f.Month > 0 || f.Year > 0 {
		pub := strVal(r.Published)
		if pub == "" {
			return false
		}
		t, err := time.Parse("2006-01-02", pub[:10])
		if err != nil {
			return false
		}
		if f.Year > 0 && t.Year() != f.Year {
			return false
		}
		if f.Month > 0 && int(t.Month()) != f.Month {
			return false
		}
	}
	return true
}

// matchesSoftwareType checks if a software type string matches an ItemType.
func matchesSoftwareType(swType string, it ItemType) bool {
	switch it {
	case storage.ItemTypePlugin:
		return swType == "plugin"
	case storage.ItemTypeTheme:
		return swType == "theme"
	default:
		return true
	}
}

// cweToType maps a CWE entry to a short type label used by the app.
func cweToType(cwe *wfCWE) string {
	if cwe == nil {
		return ""
	}
	name := strings.ToLower(cwe.Name)
	switch {
	case strings.Contains(name, "sql"):
		return "sqli"
	case strings.Contains(name, "cross-site scripting") || strings.Contains(name, "xss"):
		return "xss"
	case strings.Contains(name, "cross-site request forgery") || strings.Contains(name, "csrf"):
		return "csrf"
	case strings.Contains(name, "remote code execution") || strings.Contains(name, "code injection"):
		return "rce"
	case strings.Contains(name, "local file inclusion") || strings.Contains(name, "path traversal"):
		return "lfi"
	case strings.Contains(name, "server-side request forgery") || strings.Contains(name, "ssrf"):
		return "ssrf"
	case strings.Contains(name, "insecure direct object"):
		return "idor"
	case strings.Contains(name, "privilege escalation") || strings.Contains(name, "authorization"):
		return "privesc"
	case strings.Contains(name, "upload"):
		return "file-upload"
	default:
		return "CWE-" + strconv.Itoa(cwe.ID)
	}
}

// firstPatchedVersion returns the first patched version for the matching software entry.
func firstPatchedVersion(software []wfSoftware, slug string) string {
	for _, sw := range software {
		if slug != "" && sw.Slug != slug {
			continue
		}
		if len(sw.PatchedVersions) > 0 {
			return sw.PatchedVersions[0]
		}
	}
	return ""
}

// affectedVersionStr returns a human-readable affected version range for a slug.
func affectedVersionStr(software []wfSoftware, slug string) string {
	for _, sw := range software {
		if slug != "" && sw.Slug != slug {
			continue
		}
		return softwareAffectedVersionStr(sw)
	}
	return ""
}

// softwareAffectedVersionStr builds a human-readable version range string.
func softwareAffectedVersionStr(sw wfSoftware) string {
	if len(sw.AffectedVersions) == 0 {
		return ""
	}
	// Collect the range keys (e.g. "* - 1.0.0") and join them
	keys := make([]string, 0, len(sw.AffectedVersions))
	for k := range sw.AffectedVersions {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}

// publishedStr returns the published date string for sorting; empty string sorts last.
func publishedStr(r wfVulnRecord) string {
	if r.Published == nil {
		return ""
	}
	return *r.Published
}

// strVal dereferences a *string safely.
func strVal(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
