package storage

import "testing"

func TestItemTypeFromString(t *testing.T) {
	tests := []struct {
		input string
		want  ItemType
	}{
		{"plugin", ItemTypePlugin},
		{"theme", ItemTypeTheme},
	}
	for _, tt := range tests {
		got, err := ItemTypeFromString(tt.input)
		if err != nil {
			t.Errorf("ItemTypeFromString(%q) error: %v", tt.input, err)
		}
		if got != tt.want {
			t.Errorf("ItemTypeFromString(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestItemTypeFromString_Invalid(t *testing.T) {
	_, err := ItemTypeFromString("invalid")
	if err == nil {
		t.Error("expected error for invalid input")
	}
}

func TestItemType_Plural(t *testing.T) {
	if ItemTypePlugin.Plural() != "plugins" {
		t.Errorf("plugin plural: got %q", ItemTypePlugin.Plural())
	}
	if ItemTypeTheme.Plural() != "themes" {
		t.Errorf("theme plural: got %q", ItemTypeTheme.Plural())
	}
}
