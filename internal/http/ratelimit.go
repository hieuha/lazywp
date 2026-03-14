package http

import (
	"context"
	"sync"

	"golang.org/x/time/rate"
)

// RateLimiter enforces per-domain request rate limits using token buckets.
type RateLimiter struct {
	mu       sync.Mutex
	limiters map[string]*rate.Limiter
	defaults map[string]float64
}

// NewRateLimiter creates a rate limiter with per-domain rates (requests/second).
func NewRateLimiter(rates map[string]float64) *RateLimiter {
	return &RateLimiter{
		limiters: make(map[string]*rate.Limiter),
		defaults: rates,
	}
}

// Wait blocks until the rate limit allows a request for the given domain.
func (rl *RateLimiter) Wait(ctx context.Context, domain string) error {
	rl.mu.Lock()
	lim, ok := rl.limiters[domain]
	if !ok {
		rps := 10.0 // default: 10 req/s
		if r, exists := rl.defaults[domain]; exists {
			rps = r
		}
		lim = rate.NewLimiter(rate.Limit(rps), int(rps)+1)
		rl.limiters[domain] = lim
	}
	rl.mu.Unlock()
	return lim.Wait(ctx)
}
