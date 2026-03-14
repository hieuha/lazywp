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

// Get retrieves cached data for (source, key) if it exists and is within TTL.
// Returns (data, true) on hit, (nil, false) on miss or expiry.
func (c *Cache) Get(source, key string) ([]byte, bool) {
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
