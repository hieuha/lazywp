package client

import (
	"testing"
)

func TestItemTypeFromString_Plugin(t *testing.T) {
	got, err := ItemTypeFromString("plugin")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != Plugin {
		t.Errorf("want Plugin, got %v", got)
	}
}

func TestItemTypeFromString_Theme(t *testing.T) {
	got, err := ItemTypeFromString("theme")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != Theme {
		t.Errorf("want Theme, got %v", got)
	}
}

func TestItemTypeFromString_Invalid(t *testing.T) {
	_, err := ItemTypeFromString("unknown")
	if err == nil {
		t.Fatal("expected error for invalid type, got nil")
	}
}

func TestItemTypeFromString_Empty(t *testing.T) {
	_, err := ItemTypeFromString("")
	if err == nil {
		t.Fatal("expected error for empty string, got nil")
	}
}

func TestItemTypeFromString_CaseSensitive(t *testing.T) {
	// "Plugin" (capital P) should not match — function is case-sensitive
	_, err := ItemTypeFromString("Plugin")
	if err == nil {
		t.Fatal("expected error for 'Plugin' (capital P), got nil")
	}
}
