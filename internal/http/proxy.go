package http

import (
	"fmt"
	"math/rand"
	"net/url"
	"sync"
)

// ProxyStrategy defines how proxies are selected.
type ProxyStrategy string

const (
	StrategyRoundRobin ProxyStrategy = "round-robin"
	StrategyFailover   ProxyStrategy = "failover"
	StrategyRandom     ProxyStrategy = "random"
)

// ProxyRotator cycles through proxy URLs using a configurable strategy.
type ProxyRotator struct {
	mu       sync.Mutex
	proxies  []*url.URL
	strategy ProxyStrategy
	index    int
	failed   map[int]bool
}

// NewProxyRotator creates a proxy rotator from URL strings.
// Use "direct" for no-proxy entry.
func NewProxyRotator(proxyURLs []string, strategy ProxyStrategy) (*ProxyRotator, error) {
	var proxies []*url.URL
	for _, raw := range proxyURLs {
		if raw == "direct" {
			proxies = append(proxies, nil) // nil = direct connection
			continue
		}
		u, err := url.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL %q: %w", raw, err)
		}
		proxies = append(proxies, u)
	}
	return &ProxyRotator{
		proxies:  proxies,
		strategy: strategy,
		failed:   make(map[int]bool),
	}, nil
}

// Next returns the next proxy URL. Returns nil for direct connection.
func (pr *ProxyRotator) Next() (*url.URL, error) {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	if len(pr.proxies) == 0 {
		return nil, nil // direct
	}

	switch pr.strategy {
	case StrategyRandom:
		idx := rand.Intn(len(pr.proxies))
		return pr.proxies[idx], nil

	case StrategyFailover:
		for i := 0; i < len(pr.proxies); i++ {
			idx := (pr.index + i) % len(pr.proxies)
			if !pr.failed[idx] {
				return pr.proxies[idx], nil
			}
		}
		// All failed — reset and try first
		pr.failed = make(map[int]bool)
		return pr.proxies[0], nil

	default: // round-robin
		idx := pr.index % len(pr.proxies)
		pr.index++
		return pr.proxies[idx], nil
	}
}

// MarkFailed marks a proxy as failed (for failover strategy).
func (pr *ProxyRotator) MarkFailed(proxy *url.URL) {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	for i, p := range pr.proxies {
		if p != nil && proxy != nil && p.String() == proxy.String() {
			pr.failed[i] = true
			pr.index = i + 1
			return
		}
	}
}
