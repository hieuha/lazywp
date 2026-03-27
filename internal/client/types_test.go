package client

import (
	"encoding/json"
	"testing"
)

// --- FlexVersions ---

func TestFlexVersions_Object(t *testing.T) {
	input := `{"1.0":"https://downloads.wordpress.org/plugin-1.0.zip","2.0":"https://downloads.wordpress.org/plugin-2.0.zip"}`
	var fv FlexVersions
	if err := json.Unmarshal([]byte(input), &fv); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fv) != 2 {
		t.Errorf("want 2 entries, got %d", len(fv))
	}
	if fv["1.0"] != "https://downloads.wordpress.org/plugin-1.0.zip" {
		t.Errorf("unexpected value for key 1.0: %s", fv["1.0"])
	}
}

func TestFlexVersions_EmptyArray(t *testing.T) {
	var fv FlexVersions
	if err := json.Unmarshal([]byte(`[]`), &fv); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fv != nil {
		t.Errorf("want nil map for empty array, got %v", fv)
	}
}

func TestFlexVersions_NonEmptyArray(t *testing.T) {
	// WordPress sometimes returns arrays of strings; should not error, just be nil.
	var fv FlexVersions
	if err := json.Unmarshal([]byte(`["1.0","2.0"]`), &fv); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fv != nil {
		t.Errorf("want nil map for non-string-map array, got %v", fv)
	}
}

// --- FlexString ---

func TestFlexString_String(t *testing.T) {
	var fs FlexString
	if err := json.Unmarshal([]byte(`"5.6"`), &fs); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(fs) != "5.6" {
		t.Errorf("want '5.6', got %q", fs)
	}
}

func TestFlexString_BoolFalse(t *testing.T) {
	var fs FlexString
	if err := json.Unmarshal([]byte(`false`), &fs); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(fs) != "false" {
		t.Errorf("want 'false', got %q", fs)
	}
}

func TestFlexString_BoolTrue(t *testing.T) {
	var fs FlexString
	if err := json.Unmarshal([]byte(`true`), &fs); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(fs) != "true" {
		t.Errorf("want 'true', got %q", fs)
	}
}

func TestFlexString_Null(t *testing.T) {
	var fs FlexString
	if err := json.Unmarshal([]byte(`null`), &fs); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(fs) != "" {
		t.Errorf("want empty string for null, got %q", fs)
	}
}

func TestFlexString_EmptyString(t *testing.T) {
	var fs FlexString
	if err := json.Unmarshal([]byte(`""`), &fs); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(fs) != "" {
		t.Errorf("want empty string, got %q", fs)
	}
}

// --- DecodeNames ---

func TestDecodeNames_HTMLEntities(t *testing.T) {
	info := &ItemInfo{
		Name:   "Plugin &amp; Theme &lt;test&gt;",
		Author: "Author &quot;Name&quot;",
	}
	info.DecodeNames()
	if info.Name != `Plugin & Theme <test>` {
		t.Errorf("unexpected Name: %q", info.Name)
	}
	if info.Author != `Author "Name"` {
		t.Errorf("unexpected Author: %q", info.Author)
	}
}

func TestDecodeNames_NoEntities(t *testing.T) {
	info := &ItemInfo{Name: "Simple Plugin", Author: "John Doe"}
	info.DecodeNames()
	if info.Name != "Simple Plugin" || info.Author != "John Doe" {
		t.Errorf("values should be unchanged: name=%q author=%q", info.Name, info.Author)
	}
}

// --- BrowseResponse.Items ---

func TestBrowseResponse_Items_Plugins(t *testing.T) {
	br := &BrowseResponse{
		Plugins: []ItemInfo{{Slug: "akismet"}, {Slug: "jetpack"}},
		Themes:  []ItemInfo{{Slug: "twentytwentyone"}},
	}
	items := br.Items()
	if len(items) != 2 {
		t.Fatalf("want 2 items (plugins), got %d", len(items))
	}
	if items[0].Slug != "akismet" {
		t.Errorf("unexpected first item: %s", items[0].Slug)
	}
}

func TestBrowseResponse_Items_Themes(t *testing.T) {
	br := &BrowseResponse{
		Plugins: nil,
		Themes:  []ItemInfo{{Slug: "twentytwentyone"}, {Slug: "astra"}},
	}
	items := br.Items()
	if len(items) != 2 {
		t.Fatalf("want 2 items (themes), got %d", len(items))
	}
	if items[0].Slug != "twentytwentyone" {
		t.Errorf("unexpected first item: %s", items[0].Slug)
	}
}

func TestBrowseResponse_Items_Empty(t *testing.T) {
	br := &BrowseResponse{}
	items := br.Items()
	if len(items) != 0 {
		t.Errorf("want 0 items, got %d", len(items))
	}
}

// --- ItemInfo full JSON round-trip ---

func TestItemInfo_JSONUnmarshal_FlexFields(t *testing.T) {
	raw := `{
		"slug": "woocommerce",
		"name": "WooCommerce &amp; Co",
		"version": "8.0.0",
		"tested": "6.4",
		"requires_php": false,
		"versions": {"8.0.0": "https://downloads.wordpress.org/woocommerce.8.0.0.zip"}
	}`
	var info ItemInfo
	if err := json.Unmarshal([]byte(raw), &info); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if string(info.TestedUpTo) != "6.4" {
		t.Errorf("want TestedUpTo=6.4, got %q", info.TestedUpTo)
	}
	if string(info.RequiresPHP) != "false" {
		t.Errorf("want RequiresPHP=false, got %q", info.RequiresPHP)
	}
	if info.Versions["8.0.0"] == "" {
		t.Error("want Versions map populated")
	}
}
