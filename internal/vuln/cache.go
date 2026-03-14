package vuln

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Cache is a file-based cache with TTL for vulnerability data.
// Files are stored as {baseDir}/{source}/{sha256(key)}.json
type Cache struct {
	baseDir    string
	defaultTTL time.Duration
	disabled   bool
}

// NewCache creates a Cache that stores files under baseDir with the given TTL.
func NewCache(baseDir string, ttl time.Duration) *Cache {
	return &Cache{baseDir: baseDir, defaultTTL: ttl}
}

// keyToFilename converts a cache key to a SHA-256 hex filename.
func (c *Cache) keyToFilename(source, key string) string {
	sum := sha256.Sum256([]byte(key))
	return filepath.Join(c.baseDir, source, fmt.Sprintf("%x.json", sum))
}

// SetDisabled toggles cache reads. When disabled, Get always returns miss
// but Set still writes (so fresh API data is cached for future use).
func (c *Cache) SetDisabled(disabled bool) { c.disabled = disabled }

// Get retrieves cached data for (source, key) if it exists and is within TTL.
// Returns (data, true) on hit, (nil, false) on miss or expiry.
func (c *Cache) Get(source, key string) ([]byte, bool) {
	if c.disabled {
		return nil, false
	}
	path := c.keyToFilename(source, key)
	info, err := os.Stat(path)
	if err != nil {
		return nil, false
	}
	if time.Since(info.ModTime()) > c.defaultTTL {
		return nil, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	return data, true
}

// Set writes data to the cache for (source, key).
func (c *Cache) Set(source, key string, data []byte) error {
	path := c.keyToFilename(source, key)
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("cache mkdir %s: %w", dir, err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("cache write %s: %w", path, err)
	}
	return nil
}

// Invalidate removes the cached file for (source, key).
func (c *Cache) Invalidate(source, key string) error {
	path := c.keyToFilename(source, key)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("cache invalidate %s: %w", path, err)
	}
	return nil
}

// ClearSource removes all cached files for a given source.
func (c *Cache) ClearSource(source string) (int, error) {
	dir := filepath.Join(c.baseDir, source)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("cache read dir %s: %w", dir, err)
	}
	count := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if err := os.Remove(filepath.Join(dir, e.Name())); err == nil {
			count++
		}
	}
	return count, nil
}

// ClearAll removes all cached files across all sources.
func (c *Cache) ClearAll() (int, error) {
	entries, err := os.ReadDir(c.baseDir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("cache read base dir: %w", err)
	}
	total := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		n, err := c.ClearSource(e.Name())
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

// BaseDir returns the cache base directory path.
func (c *Cache) BaseDir() string { return c.baseDir }

// CacheInfo holds metadata about a cached source.
type CacheInfo struct {
	Source    string
	CachedAt time.Time
	Age      time.Duration
	Expired  bool
	FileSize int64
}

// Info returns cache metadata for a specific (source, key) entry.
// Returns nil if not cached.
func (c *Cache) Info(source, key string) *CacheInfo {
	path := c.keyToFilename(source, key)
	info, err := os.Stat(path)
	if err != nil {
		return nil
	}
	age := time.Since(info.ModTime())
	return &CacheInfo{
		Source:    source,
		CachedAt: info.ModTime(),
		Age:      age,
		Expired:  age > c.defaultTTL,
		FileSize: info.Size(),
	}
}

// SourceInfo returns cache info for a source's main feed entry.
func (c *Cache) SourceInfo(source string) *CacheInfo {
	dir := filepath.Join(c.baseDir, source)
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) == 0 {
		return nil
	}
	// Find the most recent file
	var newest os.FileInfo
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		if newest == nil || fi.ModTime().After(newest.ModTime()) {
			newest = fi
		}
	}
	if newest == nil {
		return nil
	}
	age := time.Since(newest.ModTime())
	return &CacheInfo{
		Source:    source,
		CachedAt: newest.ModTime(),
		Age:      age,
		Expired:  age > c.defaultTTL,
		FileSize: newest.Size(),
	}
}
