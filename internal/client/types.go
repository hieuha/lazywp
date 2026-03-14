package client

import (
	"encoding/json"
	"fmt"

	"github.com/hieuha/lazywp/internal/storage"
)

// ItemType is an alias for storage.ItemType so that both client and vuln
// packages share the same underlying type without an import cycle.
type ItemType = storage.ItemType

// Plugin and Theme re-export the storage constants under the client package
// for backward compatibility with existing callers.
const (
	Plugin ItemType = storage.ItemTypePlugin
	Theme  ItemType = storage.ItemTypeTheme
)

// ItemTypeFromString delegates to storage.ItemTypeFromString.
func ItemTypeFromString(s string) (ItemType, error) {
	return storage.ItemTypeFromString(s)
}

// ItemInfo holds metadata for a WordPress plugin or theme.
type ItemInfo struct {
	Slug                string            `json:"slug"`
	Name                string            `json:"name"`
	Version             string            `json:"version"`
	Author              string            `json:"author"`
	DownloadLink        string            `json:"download_link"`
	ActiveInstallations int               `json:"active_installations"`
	Downloaded          int               `json:"downloaded"`
	Rating              float64           `json:"rating"`
	TestedUpTo          string            `json:"tested"`
	RequiresPHP         FlexString        `json:"requires_php"`
	LastUpdated         string            `json:"last_updated"`
	Versions            map[string]string `json:"versions"`
	Homepage            string            `json:"homepage"`
	Type                ItemType          `json:"-"`
}

// BrowseResponse represents paginated browse/search results.
type BrowseResponse struct {
	Info    PageInfo        `json:"info"`
	Plugins []ItemInfo      `json:"plugins,omitempty"`
	Themes  []ItemInfo      `json:"themes,omitempty"`
}

// Items returns the items list regardless of type.
func (br *BrowseResponse) Items() []ItemInfo {
	if len(br.Plugins) > 0 {
		return br.Plugins
	}
	return br.Themes
}

// PageInfo holds pagination metadata.
type PageInfo struct {
	Page    int `json:"page"`
	Pages   int `json:"pages"`
	Results int `json:"results"`
}

// FlexString handles WordPress API fields that can be string or bool (e.g. requires_php: false).
type FlexString string

func (fs *FlexString) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		*fs = FlexString(s)
		return nil
	}
	var b bool
	if err := json.Unmarshal(data, &b); err == nil {
		*fs = FlexString(fmt.Sprintf("%v", b))
		return nil
	}
	*fs = ""
	return nil
}
