package storage

import "fmt"

// ItemType represents a WordPress plugin or theme.
// Defined here (in storage) so both client and vuln packages can reference it
// without creating an import cycle.
type ItemType string

const (
	ItemTypePlugin ItemType = "plugin"
	ItemTypeTheme  ItemType = "theme"
)

// ItemTypeFromString parses a string into ItemType.
func ItemTypeFromString(s string) (ItemType, error) {
	switch s {
	case "plugin":
		return ItemTypePlugin, nil
	case "theme":
		return ItemTypeTheme, nil
	default:
		return "", fmt.Errorf("invalid item type %q: must be 'plugin' or 'theme'", s)
	}
}

// Plural returns the plural form (plugins/themes) used in URL construction.
func (t ItemType) Plural() string {
	return string(t) + "s"
}
