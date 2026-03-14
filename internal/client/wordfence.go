package client

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	lazywphttp "github.com/hieuha/lazywp/internal/http"
	"github.com/hieuha/lazywp/internal/storage"
	"github.com/hieuha/lazywp/internal/vuln"
)

const (
	wordfenceFeedURL   = "https://www.wordfence.com/feed/"
	wordfenceSearchURL = "https://www.wordfence.com/threat-intel/vulnerabilities/search"
)

var cveRegex = regexp.MustCompile(`CVE-\d{4}-\d{4,}`)

// WordfenceFilters holds optional search filters for vulnerability queries.
type WordfenceFilters struct {
	CWEType    string // sqli, xss, directory-traversal, lfi, rce, csrf, ssrf, idor
	CVSSRating string // critical, high, medium, low
	Month      int    // 1-12
	Year       int    // 2020-2026
	Search     string
}

// WordfenceVuln represents a single vulnerability entry from Wordfence.
type WordfenceVuln struct {
	Title           string
	Slug            string
	CVE             string
	CVSS            float64
	Type            string
	AffectedVersion string
	PatchedVersion  string
	Link            string
}

// VulnerableItem groups vulnerabilities by plugin/theme slug.
type VulnerableItem struct {
	Slug      string
	Name      string
	VulnCount int
	MaxCVSS   float64
	Vulns     []storage.Vulnerability
}

// WordfenceClient fetches vulnerability data from Wordfence.
type WordfenceClient struct {
	http  *lazywphttp.Client
	cache *vuln.Cache
}

// NewWordfenceClient creates a WordfenceClient.
func NewWordfenceClient(httpClient *lazywphttp.Client, cache *vuln.Cache) *WordfenceClient {
	return &WordfenceClient{http: httpClient, cache: cache}
}

// Name identifies this source.
func (wf *WordfenceClient) Name() string { return "wordfence" }

// FetchRecent fetches the Wordfence RSS feed and extracts CVE IDs as vulnerabilities.
func (wf *WordfenceClient) FetchRecent(ctx context.Context, limit int) ([]storage.Vulnerability, error) {
	body, err := wf.http.GetBody(ctx, wordfenceFeedURL)
	if err != nil {
		return nil, fmt.Errorf("wordfence: fetch feed: %w", err)
	}

	cves := cveRegex.FindAllString(string(body), -1)

	// Deduplicate CVE IDs
	seen := make(map[string]bool, len(cves))
	vulns := make([]storage.Vulnerability, 0, len(cves))
	for _, cve := range cves {
		if seen[cve] {
			continue
		}
		seen[cve] = true
		vulns = append(vulns, storage.Vulnerability{
			CVE:    cve,
			Source: "wordfence",
			Title:  cve,
		})
	}

	if limit > 0 && len(vulns) > limit {
		vulns = vulns[:limit]
	}
	return vulns, nil
}

// FetchBySlug fetches recent Wordfence vulnerabilities and filters by slug.
func (wf *WordfenceClient) FetchBySlug(ctx context.Context, slug string, itemType ItemType) ([]storage.Vulnerability, error) {
	cacheKey := slug + ":" + string(itemType)
	if data, ok := wf.cache.Get(wf.Name(), cacheKey); ok {
		var cached []storage.Vulnerability
		if err := json.Unmarshal(data, &cached); err == nil {
			return cached, nil
		}
	}

	wfVulns, err := wf.SearchVulns(ctx, WordfenceFilters{Search: slug})
	if err != nil {
		return nil, err
	}

	vulns := make([]storage.Vulnerability, 0)
	for _, wv := range wfVulns {
		if wv.Slug != slug {
			continue
		}
		vulns = append(vulns, storage.Vulnerability{
			CVE:    wv.CVE,
			CVSS:   wv.CVSS,
			Type:   wv.Type,
			Title:  wv.Title,
			Source: "wordfence",
			FixedIn: wv.PatchedVersion,
			References: []string{wv.Link},
		})
	}

	if encoded, err := json.Marshal(vulns); err == nil {
		_ = wf.cache.Set(wf.Name(), cacheKey, encoded)
	}
	return vulns, nil
}

// SearchVulns scrapes the Wordfence vulnerability search page with optional filters.
// Uses simple string/regex parsing — best-effort HTML extraction.
func (wf *WordfenceClient) SearchVulns(ctx context.Context, filters WordfenceFilters) ([]WordfenceVuln, error) {
	params := buildWordfenceParams(filters)
	reqURL := wordfenceSearchURL
	if params != "" {
		reqURL += "?" + params
	}

	body, err := wf.http.GetBody(ctx, reqURL)
	if err != nil {
		return nil, fmt.Errorf("wordfence: search request: %w", err)
	}

	return parseWordfenceHTML(string(body)), nil
}

// FetchVulnPlugins searches Wordfence for vulnerable plugins/themes grouped by slug,
// returning the top N items sorted by vuln count and max CVSS.
// Falls back to RSS feed if HTML scraping returns no results (JS-rendered pages).
func (wf *WordfenceClient) FetchVulnPlugins(ctx context.Context, filters WordfenceFilters, limit int) ([]VulnerableItem, error) {
	wfVulns, err := wf.SearchVulns(ctx, filters)
	if err != nil {
		return nil, err
	}

	// Wordfence search pages are JS-rendered; fall back to RSS feed
	if len(wfVulns) == 0 {
		rssVulns, rssErr := wf.FetchRecent(ctx, 100)
		if rssErr != nil {
			return nil, fmt.Errorf("wordfence: RSS fallback: %w", rssErr)
		}
		for _, v := range rssVulns {
			wfVulns = append(wfVulns, WordfenceVuln{
				CVE:   v.CVE,
				Title: v.Title,
				CVSS:  v.CVSS,
			})
		}
	}

	bySlug := make(map[string]*VulnerableItem)
	for _, wv := range wfVulns {
		slug := wv.Slug
		if slug == "" {
			slug = slugFromTitle(wv.Title)
		}
		item, ok := bySlug[slug]
		if !ok {
			item = &VulnerableItem{Slug: slug, Name: wv.Title}
			bySlug[slug] = item
		}
		item.VulnCount++
		if wv.CVSS > item.MaxCVSS {
			item.MaxCVSS = wv.CVSS
		}
		item.Vulns = append(item.Vulns, storage.Vulnerability{
			CVE:    wv.CVE,
			CVSS:   wv.CVSS,
			Type:   wv.Type,
			Title:  wv.Title,
			Source: "wordfence",
			FixedIn: wv.PatchedVersion,
			References: []string{wv.Link},
		})
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

// buildWordfenceParams converts WordfenceFilters to a URL query string.
func buildWordfenceParams(f WordfenceFilters) string {
	var parts []string
	if f.Search != "" {
		parts = append(parts, "q="+urlEncode(f.Search))
	}
	if f.CWEType != "" {
		parts = append(parts, "cwe="+urlEncode(f.CWEType))
	}
	if f.CVSSRating != "" {
		parts = append(parts, "cvss="+urlEncode(f.CVSSRating))
	}
	if f.Month > 0 {
		parts = append(parts, "month="+strconv.Itoa(f.Month))
	}
	if f.Year > 0 {
		parts = append(parts, "year="+strconv.Itoa(f.Year))
	}
	return strings.Join(parts, "&")
}

// urlEncode performs minimal percent-encoding for query parameter values.
func urlEncode(s string) string {
	s = strings.ReplaceAll(s, " ", "+")
	s = strings.ReplaceAll(s, "&", "%26")
	s = strings.ReplaceAll(s, "=", "%3D")
	return s
}

// parseWordfenceHTML extracts vulnerability entries from Wordfence HTML.
// Uses regex/string parsing — best-effort, no external HTML library.
func parseWordfenceHTML(html string) []WordfenceVuln {
	var vulns []WordfenceVuln

	// Extract CVE IDs from the page
	cves := cveRegex.FindAllString(html, -1)
	seen := make(map[string]bool)

	for _, cve := range cves {
		if seen[cve] {
			continue
		}
		seen[cve] = true

		wv := WordfenceVuln{CVE: cve, Title: cve}

		// Try to find a CVSS score near this CVE mention
		if score := extractCVSSNear(html, cve); score > 0 {
			wv.CVSS = score
		}

		// Try to extract a title near the CVE
		if title := extractTitleNear(html, cve); title != "" {
			wv.Title = title
		}

		// Try to extract a slug
		wv.Slug = extractSlugNear(html, cve)

		// Try to extract a link
		wv.Link = extractLinkNear(html, cve)

		vulns = append(vulns, wv)
	}

	return vulns
}

var (
	cvssNearRegex  = regexp.MustCompile(`(?i)cvss[^0-9]*([0-9]+\.[0-9]+)`)
	linkRegex      = regexp.MustCompile(`href="(https://www\.wordfence\.com/[^"]+)"`)
	slugRegex      = regexp.MustCompile(`/plugins/([a-z0-9\-]+)`)
	titleTagRegex  = regexp.MustCompile(`(?i)<(?:h[1-6]|title|td)[^>]*>([^<]{10,120})</(?:h[1-6]|title|td)>`)
)

// extractCVSSNear finds a CVSS score in the 300-char window around cveID in html.
func extractCVSSNear(html, cveID string) float64 {
	idx := strings.Index(html, cveID)
	if idx < 0 {
		return 0
	}
	start := idx - 150
	if start < 0 {
		start = 0
	}
	end := idx + 150
	if end > len(html) {
		end = len(html)
	}
	window := html[start:end]
	m := cvssNearRegex.FindStringSubmatch(window)
	if m == nil {
		return 0
	}
	score, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0
	}
	return score
}

// extractTitleNear finds the nearest heading or table cell text around cveID.
func extractTitleNear(html, cveID string) string {
	idx := strings.Index(html, cveID)
	if idx < 0 {
		return ""
	}
	start := idx - 400
	if start < 0 {
		start = 0
	}
	end := idx + 400
	if end > len(html) {
		end = len(html)
	}
	window := html[start:end]
	m := titleTagRegex.FindStringSubmatch(window)
	if m == nil {
		return ""
	}
	return strings.TrimSpace(m[1])
}

// extractSlugNear finds a WordPress plugin slug in the 500-char window around cveID.
func extractSlugNear(html, cveID string) string {
	idx := strings.Index(html, cveID)
	if idx < 0 {
		return ""
	}
	start := idx - 250
	if start < 0 {
		start = 0
	}
	end := idx + 250
	if end > len(html) {
		end = len(html)
	}
	window := html[start:end]
	m := slugRegex.FindStringSubmatch(window)
	if m == nil {
		return ""
	}
	return m[1]
}

// extractLinkNear finds a Wordfence URL in the 500-char window around cveID.
func extractLinkNear(html, cveID string) string {
	idx := strings.Index(html, cveID)
	if idx < 0 {
		return ""
	}
	start := idx - 250
	if start < 0 {
		start = 0
	}
	end := idx + 250
	if end > len(html) {
		end = len(html)
	}
	window := html[start:end]
	m := linkRegex.FindStringSubmatch(window)
	if m == nil {
		return ""
	}
	return m[1]
}

// slugFromTitle derives a best-effort slug from a vulnerability title.
func slugFromTitle(title string) string {
	lower := strings.ToLower(title)
	// Remove common prefixes like "WordPress Plugin " or "WordPress Theme "
	for _, prefix := range []string{"wordpress plugin ", "wordpress theme ", "wordpress "} {
		if strings.HasPrefix(lower, prefix) {
			lower = lower[len(prefix):]
			break
		}
	}
	// Keep only alphanumeric and spaces, convert spaces to dashes
	var b strings.Builder
	for _, r := range lower {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		} else if r == ' ' || r == '-' {
			b.WriteRune('-')
		}
	}
	slug := strings.Trim(b.String(), "-")
	// Collapse repeated dashes
	for strings.Contains(slug, "--") {
		slug = strings.ReplaceAll(slug, "--", "-")
	}
	return slug
}
