package client

import (
	"context"
	"encoding/json"
	"fmt"
	"math"

	lazywphttp "github.com/hieuha/lazywp/internal/http"
)

const (
	wpAPIBase      = "https://api.wordpress.org"
	wpDownloadBase = "https://downloads.wordpress.org"
	maxPerPage     = 250
)

// WordPressClient fetches plugin/theme info from WordPress.org API.
type WordPressClient struct {
	http     *lazywphttp.Client
	itemType ItemType
}

// NewWordPressClient creates a client for the given item type.
func NewWordPressClient(httpClient *lazywphttp.Client, itemType ItemType) *WordPressClient {
	return &WordPressClient{http: httpClient, itemType: itemType}
}

// GetInfo fetches metadata for a single plugin or theme by slug.
func (wc *WordPressClient) GetInfo(ctx context.Context, slug string) (*ItemInfo, error) {
	url := wc.infoURL(slug)
	resp, err := wc.http.Get(ctx, url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return nil, fmt.Errorf("%s not found: %s", wc.itemType, slug)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("WP API returned %d for %s", resp.StatusCode, slug)
	}

	var info ItemInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("parse %s info: %w", wc.itemType, err)
	}
	info.Type = wc.itemType
	info.DecodeNames()
	return &info, nil
}

// GetVersions returns available versions for a slug (excluding trunk/dev).
func (wc *WordPressClient) GetVersions(ctx context.Context, slug string) (map[string]string, error) {
	info, err := wc.GetInfo(ctx, slug)
	if err != nil {
		return nil, err
	}
	versions := make(map[string]string)
	for v, url := range info.Versions {
		if v == "trunk" || v == "" {
			continue
		}
		versions[v] = url
	}
	return versions, nil
}

// Browse fetches plugins/themes by category (popular, new, trending, featured).
func (wc *WordPressClient) Browse(ctx context.Context, category string, count int) ([]ItemInfo, error) {
	pages := int(math.Ceil(float64(count) / float64(maxPerPage)))
	var all []ItemInfo

	for page := 1; page <= pages; page++ {
		perPage := maxPerPage
		if remaining := count - len(all); remaining < maxPerPage {
			perPage = remaining
		}

		url := fmt.Sprintf("%s/%s/info/1.2/?action=query_%s&request[browse]=%s&request[per_page]=%d&request[page]=%d",
			wpAPIBase, wc.itemType.Plural(), wc.itemType.Plural(), category, perPage, page)

		body, err := wc.http.GetBody(ctx, url)
		if err != nil {
			return all, fmt.Errorf("browse page %d: %w", page, err)
		}

		var br BrowseResponse
		if err := json.Unmarshal(body, &br); err != nil {
			return all, fmt.Errorf("parse browse response: %w", err)
		}

		items := br.Items()
		for i := range items {
			items[i].Type = wc.itemType
			items[i].DecodeNames()
		}
		all = append(all, items...)

		if len(all) >= count || page >= br.Info.Pages {
			break
		}
	}

	if len(all) > count {
		all = all[:count]
	}
	return all, nil
}

// Search finds plugins/themes matching a keyword query.
func (wc *WordPressClient) Search(ctx context.Context, query string, count int) ([]ItemInfo, error) {
	pages := int(math.Ceil(float64(count) / float64(maxPerPage)))
	var all []ItemInfo

	for page := 1; page <= pages; page++ {
		perPage := maxPerPage
		if remaining := count - len(all); remaining < maxPerPage {
			perPage = remaining
		}

		url := fmt.Sprintf("%s/%s/info/1.2/?action=query_%s&request[search]=%s&request[per_page]=%d&request[page]=%d",
			wpAPIBase, wc.itemType.Plural(), wc.itemType.Plural(), query, perPage, page)

		body, err := wc.http.GetBody(ctx, url)
		if err != nil {
			return all, fmt.Errorf("search page %d: %w", page, err)
		}

		var br BrowseResponse
		if err := json.Unmarshal(body, &br); err != nil {
			return all, fmt.Errorf("parse search response: %w", err)
		}

		items := br.Items()
		for i := range items {
			items[i].Type = wc.itemType
			items[i].DecodeNames()
		}
		all = append(all, items...)

		if len(all) >= count || page >= br.Info.Pages {
			break
		}
	}

	if len(all) > count {
		all = all[:count]
	}
	return all, nil
}

// DownloadURL builds the download URL for a plugin/theme.
func (wc *WordPressClient) DownloadURL(slug, version string) string {
	if version == "" {
		return fmt.Sprintf("%s/%s/%s.zip", wpDownloadBase, wc.itemType, slug)
	}
	return fmt.Sprintf("%s/%s/%s.%s.zip", wpDownloadBase, wc.itemType, slug, version)
}

// infoURL builds the info API URL for a slug.
func (wc *WordPressClient) infoURL(slug string) string {
	switch wc.itemType {
	case Theme:
		return fmt.Sprintf("%s/themes/info/1.2/%s", wpAPIBase, slug)
	default:
		return fmt.Sprintf("%s/plugins/info/1.0/%s.json", wpAPIBase, slug)
	}
}
