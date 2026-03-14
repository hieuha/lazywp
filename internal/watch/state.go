package watch

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/hieuha/lazywp/internal/storage"
)

// SlugState tracks last-known version and CVEs for a single slug.
type SlugState struct {
	Version   string    `json:"version"`
	CVEs      []string  `json:"cves"`
	LastCheck time.Time `json:"last_check"`
}

// WatchState is the full state file: map[slug]SlugState.
type WatchState map[string]SlugState

// Change represents a detected difference between runs.
type Change struct {
	Slug       string  `json:"slug"`
	Type       string  `json:"type"` // "new_version" or "new_cve"
	OldVersion string  `json:"old_version,omitempty"`
	NewVersion string  `json:"new_version,omitempty"`
	CVE        string  `json:"cve,omitempty"`
	CVSS       float64 `json:"cvss,omitempty"`
	Title      string  `json:"title,omitempty"`
}

// LoadState reads the state file from disk. Returns empty state if file doesn't exist.
func LoadState(path string) (WatchState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return make(WatchState), nil
		}
		return nil, fmt.Errorf("read state file: %w", err)
	}

	var state WatchState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("parse state file: %w", err)
	}
	return state, nil
}

// SaveState writes the state to disk with indented JSON.
func SaveState(path string, state WatchState) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}

	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write state file: %w", err)
	}
	return nil
}

// DiffSlug compares old state against new version and CVE list, returning detected changes.
func DiffSlug(slug string, old SlugState, newVersion string, newVulns []storage.Vulnerability) []Change {
	var changes []Change

	// Detect version change (skip on first run when old version is empty).
	if old.Version != "" && newVersion != "" && old.Version != newVersion {
		changes = append(changes, Change{
			Slug:       slug,
			Type:       "new_version",
			OldVersion: old.Version,
			NewVersion: newVersion,
		})
	}

	// Build set of known CVEs for fast lookup.
	known := make(map[string]bool, len(old.CVEs))
	for _, cve := range old.CVEs {
		known[cve] = true
	}

	// Detect new CVEs (skip entries without CVE ID).
	for _, v := range newVulns {
		if v.CVE == "" {
			continue
		}
		if !known[v.CVE] {
			// Only report as new if this isn't the first run for this slug.
			if len(old.CVEs) > 0 || old.Version != "" {
				changes = append(changes, Change{
					Slug:  slug,
					Type:  "new_cve",
					CVE:   v.CVE,
					CVSS:  v.CVSS,
					Title: v.Title,
				})
			}
		}
	}

	return changes
}

// Reset deletes the state file. No error if file doesn't exist.
func Reset(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove state file: %w", err)
	}
	return nil
}
