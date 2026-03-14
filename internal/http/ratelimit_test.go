package http

import (
	"context"
	"testing"
	"time"
)

func TestWaitPasses(t *testing.T) {
	rates := map[string]float64{
		"api.example.com": 10.0, // 10 req/s
	}
	rl := NewRateLimiter(rates)

	ctx := context.Background()

	// First request should not block
	err := rl.Wait(ctx, "api.example.com")
	if err != nil {
		t.Fatalf("Wait failed: %v", err)
	}

	// Additional requests within rate should not block
	for i := 0; i < 5; i++ {
		err := rl.Wait(ctx, "api.example.com")
		if err != nil {
			t.Fatalf("Wait iteration %d failed: %v", i, err)
		}
	}
}

func TestPerDomainIsolation(t *testing.T) {
	rates := map[string]float64{
		"api1.example.com": 10.0,
		"api2.example.com": 5.0,
	}
	rl := NewRateLimiter(rates)

	ctx := context.Background()

	// Calls to api1 should not affect api2
	for i := 0; i < 3; i++ {
		err := rl.Wait(ctx, "api1.example.com")
		if err != nil {
			t.Fatalf("Wait on api1 iteration %d failed: %v", i, err)
		}
	}

	// api2 should work independently
	for i := 0; i < 3; i++ {
		err := rl.Wait(ctx, "api2.example.com")
		if err != nil {
			t.Fatalf("Wait on api2 iteration %d failed: %v", i, err)
		}
	}
}

func TestUnknownDomain(t *testing.T) {
	rates := map[string]float64{
		"api1.example.com": 10.0,
	}
	rl := NewRateLimiter(rates)

	ctx := context.Background()

	// Unknown domain should use default rate (10 req/s)
	err := rl.Wait(ctx, "unknown.example.com")
	if err != nil {
		t.Fatalf("Wait on unknown domain failed: %v", err)
	}
}

func TestCancelledContext(t *testing.T) {
	rates := map[string]float64{
		"api.example.com": 0.1, // Very slow rate to ensure blocking
	}
	rl := NewRateLimiter(rates)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	// First wait should succeed
	err := rl.Wait(ctx, "api.example.com")
	if err != nil {
		t.Fatalf("First Wait failed: %v", err)
	}

	// Second wait will block due to rate limit and should be cancelled
	err = rl.Wait(ctx, "api.example.com")
	if err == nil {
		t.Error("Wait should fail with cancelled context")
	}
}

func TestMultipleDomains(t *testing.T) {
	rates := map[string]float64{
		"api1.example.com": 5.0,
		"api2.example.com": 5.0,
		"api3.example.com": 5.0,
	}
	rl := NewRateLimiter(rates)

	ctx := context.Background()

	// Interleaved requests to different domains should not interfere
	domains := []string{"api1.example.com", "api2.example.com", "api3.example.com"}
	for round := 0; round < 3; round++ {
		for _, domain := range domains {
			err := rl.Wait(ctx, domain)
			if err != nil {
				t.Fatalf("Wait on %s round %d failed: %v", domain, round, err)
			}
		}
	}
}

func TestDefaultRate(t *testing.T) {
	rl := NewRateLimiter(map[string]float64{})

	ctx := context.Background()

	// Domain not in config should use default rate
	err := rl.Wait(ctx, "unconfirmed.example.com")
	if err != nil {
		t.Fatalf("Wait on unconfigured domain failed: %v", err)
	}
}
