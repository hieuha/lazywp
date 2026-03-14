package downloader

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

const stateFileName = ".lazywp-state.json"

// DownloadState tracks progress of an in-flight download for resume support.
type DownloadState struct {
	Slug            string    `json:"slug"`
	Version         string    `json:"version"`
	Type            string    `json:"type"`
	DownloadURL     string    `json:"download_url"`
	BytesDownloaded int64     `json:"bytes_downloaded"`
	TotalBytes      int64     `json:"total_bytes"`
	StartedAt       time.Time `json:"started_at"`
	LastUpdated     time.Time `json:"last_updated"`
}

// SaveState writes a download state file to the given directory.
func SaveState(dir string, state *DownloadState) error {
	state.LastUpdated = time.Now()
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, stateFileName), data, 0644)
}

// LoadState reads the download state from dir. Returns nil, nil if the state file does not exist.
func LoadState(dir string) (*DownloadState, error) {
	data, err := os.ReadFile(filepath.Join(dir, stateFileName))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var state DownloadState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	return &state, nil
}

// ClearState removes the download state file from dir.
// It is a no-op if the file does not exist.
func ClearState(dir string) error {
	err := os.Remove(filepath.Join(dir, stateFileName))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
