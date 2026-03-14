package http

import (
	"fmt"
	"sync"
)

// KeyRotator manages API key rotation with quota tracking.
type KeyRotator struct {
	mu        sync.Mutex
	keys      []string
	remaining map[string]int // key -> remaining quota (-1 = unknown)
	index     int
}

// NewKeyRotator creates a rotator for the given API keys.
func NewKeyRotator(keys []string) *KeyRotator {
	remaining := make(map[string]int, len(keys))
	for _, k := range keys {
		remaining[k] = -1 // unknown quota
	}
	return &KeyRotator{
		keys:      keys,
		remaining: remaining,
	}
}

// Next returns the next available API key using round-robin, skipping exhausted keys.
func (kr *KeyRotator) Next() (string, error) {
	kr.mu.Lock()
	defer kr.mu.Unlock()

	if len(kr.keys) == 0 {
		return "", fmt.Errorf("no API keys configured")
	}

	for i := 0; i < len(kr.keys); i++ {
		idx := (kr.index + i) % len(kr.keys)
		key := kr.keys[idx]
		if kr.remaining[key] != 0 { // -1 (unknown) or > 0
			kr.index = idx + 1
			return key, nil
		}
	}
	return "", fmt.Errorf("all API keys exhausted")
}

// UpdateQuota updates the remaining quota for a key (from response headers).
func (kr *KeyRotator) UpdateQuota(key string, remaining int) {
	kr.mu.Lock()
	defer kr.mu.Unlock()
	kr.remaining[key] = remaining
}

// AllKeys returns a copy of all configured API keys.
func (kr *KeyRotator) AllKeys() []string {
	kr.mu.Lock()
	defer kr.mu.Unlock()
	out := make([]string, len(kr.keys))
	copy(out, kr.keys)
	return out
}

// AllExhausted returns true if all keys have zero remaining quota.
func (kr *KeyRotator) AllExhausted() bool {
	kr.mu.Lock()
	defer kr.mu.Unlock()
	for _, r := range kr.remaining {
		if r != 0 {
			return false
		}
	}
	return true
}
