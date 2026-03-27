package watch

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/hieuha/lazywp/internal/storage"
)

func TestLoadState_NotExist(t *testing.T) {
	state, err := LoadState(filepath.Join(t.TempDir(), "missing.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(state) != 0 {
		t.Errorf("expected empty state, got %d entries", len(state))
	}
}

func TestLoadState_Valid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	want := WatchState{
		"akismet": {Version: "5.0", CVEs: []string{"CVE-2024-1"}},
	}
	data, _ := json.Marshal(want)
	os.WriteFile(path, data, 0644)

	got, err := LoadState(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got["akismet"].Version != "5.0" {
		t.Errorf("version: got %q, want 5.0", got["akismet"].Version)
	}
	if len(got["akismet"].CVEs) != 1 {
		t.Errorf("CVEs count: got %d, want 1", len(got["akismet"].CVEs))
	}
}

func TestLoadState_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	os.WriteFile(path, []byte("{bad"), 0644)

	_, err := LoadState(path)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestSaveState_AtomicWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	state := WatchState{
		"hello": {Version: "1.0", CVEs: []string{"CVE-2024-99"}},
	}
	if err := SaveState(path, state); err != nil {
		t.Fatalf("SaveState failed: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read saved file: %v", err)
	}

	var loaded WatchState
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("unmarshal saved state: %v", err)
	}
	if loaded["hello"].Version != "1.0" {
		t.Errorf("version: got %q, want 1.0", loaded["hello"].Version)
	}
}

func TestSaveState_CreatesDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "dir")
	path := filepath.Join(dir, "state.json")

	state := WatchState{"test": {Version: "2.0"}}
	if err := SaveState(path, state); err != nil {
		t.Fatalf("SaveState failed: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("file not created: %v", err)
	}
}

func TestDiffSlug_NewVersion(t *testing.T) {
	old := SlugState{Version: "1.0", CVEs: []string{}}
	changes := DiffSlug("test", old, "2.0", nil)

	if len(changes) != 1 {
		t.Fatalf("expected 1 change, got %d", len(changes))
	}
	if changes[0].Type != "new_version" {
		t.Errorf("type: got %q, want new_version", changes[0].Type)
	}
	if changes[0].OldVersion != "1.0" || changes[0].NewVersion != "2.0" {
		t.Errorf("versions: got %q->%q, want 1.0->2.0", changes[0].OldVersion, changes[0].NewVersion)
	}
}

func TestDiffSlug_NewCVE(t *testing.T) {
	old := SlugState{Version: "1.0", CVEs: []string{"CVE-2024-1"}}
	vulns := []storage.Vulnerability{
		{CVE: "CVE-2024-1", CVSS: 5.0},
		{CVE: "CVE-2024-2", CVSS: 9.0, Title: "Critical bug"},
	}
	changes := DiffSlug("test", old, "1.0", vulns)

	if len(changes) != 1 {
		t.Fatalf("expected 1 change, got %d", len(changes))
	}
	if changes[0].Type != "new_cve" {
		t.Errorf("type: got %q, want new_cve", changes[0].Type)
	}
	if changes[0].CVE != "CVE-2024-2" {
		t.Errorf("CVE: got %q, want CVE-2024-2", changes[0].CVE)
	}
}

func TestDiffSlug_FirstRun(t *testing.T) {
	old := SlugState{} // empty — first run
	vulns := []storage.Vulnerability{
		{CVE: "CVE-2024-1"},
	}
	changes := DiffSlug("test", old, "1.0", vulns)

	if len(changes) != 0 {
		t.Errorf("expected no changes on first run, got %d", len(changes))
	}
}

func TestDiffSlug_NoCVESkipped(t *testing.T) {
	old := SlugState{Version: "1.0", CVEs: []string{}}
	vulns := []storage.Vulnerability{
		{CVE: "", Title: "No CVE ID"},
	}
	changes := DiffSlug("test", old, "1.0", vulns)

	if len(changes) != 0 {
		t.Errorf("expected 0 changes for empty CVE, got %d", len(changes))
	}
}

func TestDiffSlug_NoChange(t *testing.T) {
	old := SlugState{Version: "1.0", CVEs: []string{"CVE-2024-1"}}
	vulns := []storage.Vulnerability{{CVE: "CVE-2024-1"}}
	changes := DiffSlug("test", old, "1.0", vulns)

	if len(changes) != 0 {
		t.Errorf("expected 0 changes, got %d", len(changes))
	}
}

func TestReset(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	os.WriteFile(path, []byte("{}"), 0644)

	if err := Reset(path); err != nil {
		t.Fatalf("Reset failed: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("file should be deleted after Reset")
	}
}

func TestReset_NonExistent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.json")
	if err := Reset(path); err != nil {
		t.Fatalf("Reset on missing file should not error: %v", err)
	}
}
