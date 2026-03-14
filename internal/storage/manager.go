package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Manager handles download directory structure and metadata I/O.
type Manager struct {
	baseDir string
	mu      sync.Mutex // protects index and error log writes
}

// NewManager creates a storage manager for the given base directory.
func NewManager(baseDir string) *Manager {
	return &Manager{baseDir: baseDir}
}

// BaseDir returns the storage base directory.
func (m *Manager) BaseDir() string {
	return m.baseDir
}

// EnsureStructure creates the required directory structure.
func (m *Manager) EnsureStructure() error {
	dirs := []string{
		filepath.Join(m.baseDir, "plugins"),
		filepath.Join(m.baseDir, "themes"),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0755); err != nil {
			return fmt.Errorf("create dir %s: %w", d, err)
		}
	}
	// Create empty index.json if missing
	indexPath := filepath.Join(m.baseDir, "index.json")
	if _, err := os.Stat(indexPath); os.IsNotExist(err) {
		if err := os.WriteFile(indexPath, []byte("[]"), 0644); err != nil {
			return fmt.Errorf("create index: %w", err)
		}
	}
	return nil
}

// ItemDir returns the directory path for a specific item version.
func (m *Manager) ItemDir(itemType, slug, version string) string {
	return filepath.Join(m.baseDir, itemType+"s", slug, version)
}

// WriteMetadata writes metadata.json for a downloaded item.
func (m *Manager) WriteMetadata(meta *Metadata) error {
	dir := m.ItemDir(meta.Type, meta.Slug, meta.Version)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create metadata dir: %w", err)
	}
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}
	return os.WriteFile(filepath.Join(dir, "metadata.json"), data, 0644)
}

// ReadMetadata reads metadata.json for a specific item.
func (m *Manager) ReadMetadata(itemType, slug, version string) (*Metadata, error) {
	path := filepath.Join(m.ItemDir(itemType, slug, version), "metadata.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var meta Metadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("parse metadata: %w", err)
	}
	return &meta, nil
}

// Exists checks if an item version has already been downloaded.
func (m *Manager) Exists(itemType, slug, version string) bool {
	metaPath := filepath.Join(m.ItemDir(itemType, slug, version), "metadata.json")
	_, err := os.Stat(metaPath)
	return err == nil
}

// UpdateIndex appends an entry to the download index.
func (m *Manager) UpdateIndex(entry IndexEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	entries, _ := m.ReadIndex() // ignore error, start fresh if corrupt
	entries = append(entries, entry)
	return m.writeJSON(filepath.Join(m.baseDir, "index.json"), entries)
}

// ReadIndex reads all entries from the download index.
func (m *Manager) ReadIndex() ([]IndexEntry, error) {
	data, err := os.ReadFile(filepath.Join(m.baseDir, "index.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var entries []IndexEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("parse index: %w", err)
	}
	return entries, nil
}

// LogError appends an error entry to errors.json.
func (m *Manager) LogError(entry ErrorEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	entry.Timestamp = time.Now()
	var entries []ErrorEntry
	data, err := os.ReadFile(filepath.Join(m.baseDir, "errors.json"))
	if err == nil {
		_ = json.Unmarshal(data, &entries) // ignore parse errors
	}
	entries = append(entries, entry)
	return m.writeJSON(filepath.Join(m.baseDir, "errors.json"), entries)
}

func (m *Manager) writeJSON(path string, v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
