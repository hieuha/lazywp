package http

import (
	"testing"
)

func TestRoundRobinProxy(t *testing.T) {
	proxyURLs := []string{"http://proxy1.com:8080", "http://proxy2.com:8080", "http://proxy3.com:8080"}
	pr, err := NewProxyRotator(proxyURLs, StrategyRoundRobin)
	if err != nil {
		t.Fatalf("NewProxyRotator failed: %v", err)
	}

	// Should cycle through proxies
	proxy1, err := pr.Next()
	if err != nil {
		t.Fatalf("First Next failed: %v", err)
	}

	proxy2, err := pr.Next()
	if err != nil {
		t.Fatalf("Second Next failed: %v", err)
	}

	proxy3, err := pr.Next()
	if err != nil {
		t.Fatalf("Third Next failed: %v", err)
	}

	// Verify we got proxies in sequence
	if proxy1 == nil || proxy1.String() != "http://proxy1.com:8080" {
		t.Errorf("First proxy: got %v, want http://proxy1.com:8080", proxy1)
	}

	if proxy2 == nil || proxy2.String() != "http://proxy2.com:8080" {
		t.Errorf("Second proxy: got %v, want http://proxy2.com:8080", proxy2)
	}

	if proxy3 == nil || proxy3.String() != "http://proxy3.com:8080" {
		t.Errorf("Third proxy: got %v, want http://proxy3.com:8080", proxy3)
	}
}

func TestFailoverProxy(t *testing.T) {
	proxyURLs := []string{"http://proxy1.com:8080", "http://proxy2.com:8080"}
	pr, err := NewProxyRotator(proxyURLs, StrategyFailover)
	if err != nil {
		t.Fatalf("NewProxyRotator failed: %v", err)
	}

	// Get first proxy
	proxy1, err := pr.Next()
	if err != nil {
		t.Fatalf("First Next failed: %v", err)
	}

	// Mark it as failed
	pr.MarkFailed(proxy1)

	// Next call should return proxy2 (not proxy1)
	proxy2, err := pr.Next()
	if err != nil {
		t.Fatalf("Second Next failed: %v", err)
	}

	if proxy1.String() == proxy2.String() {
		t.Error("Failed proxy should be skipped")
	}
}

func TestRandomProxy(t *testing.T) {
	proxyURLs := []string{"http://proxy1.com:8080", "http://proxy2.com:8080", "http://proxy3.com:8080"}
	pr, err := NewProxyRotator(proxyURLs, StrategyRandom)
	if err != nil {
		t.Fatalf("NewProxyRotator failed: %v", err)
	}

	// Call Next multiple times and verify it returns valid proxies
	for i := 0; i < 10; i++ {
		proxy, err := pr.Next()
		if err != nil {
			t.Fatalf("Next iteration %d failed: %v", i, err)
		}

		if proxy == nil {
			t.Error("Random strategy should return a proxy")
		}

		// Verify proxy is one of the configured ones
		valid := false
		for _, url := range proxyURLs {
			if proxy.String() == url {
				valid = true
				break
			}
		}

		if !valid {
			t.Errorf("Random returned invalid proxy: %v", proxy)
		}
	}
}

func TestDirectConnection(t *testing.T) {
	proxyURLs := []string{"direct", "http://proxy.com:8080"}
	pr, err := NewProxyRotator(proxyURLs, StrategyRoundRobin)
	if err != nil {
		t.Fatalf("NewProxyRotator failed: %v", err)
	}

	// First call should return nil (direct)
	proxy1, err := pr.Next()
	if err != nil {
		t.Fatalf("First Next failed: %v", err)
	}

	if proxy1 != nil {
		t.Error("Expected nil for direct connection")
	}

	// Second call should return actual proxy
	proxy2, err := pr.Next()
	if err != nil {
		t.Fatalf("Second Next failed: %v", err)
	}

	if proxy2 == nil {
		t.Error("Expected proxy URL, got nil")
	}
}

func TestValidProxyParsing(t *testing.T) {
	// Test that valid URLs are parsed correctly
	proxyURLs := []string{"http://proxy.com:8080", "https://secure-proxy.com:3128"}
	pr, err := NewProxyRotator(proxyURLs, StrategyRoundRobin)

	if err != nil {
		t.Fatalf("Should not fail with valid proxy URLs: %v", err)
	}

	if pr == nil {
		t.Error("ProxyRotator should be created")
	}
}

func TestEmptyProxies(t *testing.T) {
	pr, err := NewProxyRotator([]string{}, StrategyRoundRobin)
	if err != nil {
		t.Fatalf("NewProxyRotator failed: %v", err)
	}

	// Should return nil for empty list
	proxy, err := pr.Next()
	if err != nil {
		t.Fatalf("Next failed: %v", err)
	}

	if proxy != nil {
		t.Error("Expected nil for empty proxy list")
	}
}

func TestMarkFailedReset(t *testing.T) {
	proxyURLs := []string{"http://proxy1.com:8080", "http://proxy2.com:8080"}
	pr, err := NewProxyRotator(proxyURLs, StrategyFailover)
	if err != nil {
		t.Fatalf("NewProxyRotator failed: %v", err)
	}

	proxy1, _ := pr.Next()
	pr.MarkFailed(proxy1)

	proxy2, _ := pr.Next()
	pr.MarkFailed(proxy2)

	// Both failed — next call should reset and return proxy1
	proxy3, err := pr.Next()
	if err != nil {
		t.Fatalf("Next after both failed: %v", err)
	}

	// Should return first proxy after reset
	if proxy3 == nil || proxy3.String() != "http://proxy1.com:8080" {
		t.Errorf("Expected proxy1 after reset, got %v", proxy3)
	}
}

func TestMarkFailedNil(t *testing.T) {
	proxyURLs := []string{"direct", "http://proxy.com:8080"}
	pr, err := NewProxyRotator(proxyURLs, StrategyFailover)
	if err != nil {
		t.Fatalf("NewProxyRotator failed: %v", err)
	}

	// Mark nil as failed (should handle gracefully)
	pr.MarkFailed(nil)

	// Next should still work
	proxy, err := pr.Next()
	if err != nil {
		t.Fatalf("Next after MarkFailed(nil): %v", err)
	}

	// First element is nil (direct), should return that
	if proxy != nil {
		t.Error("Expected nil for direct connection")
	}
}

func TestSingleProxy(t *testing.T) {
	proxyURLs := []string{"http://only-proxy.com:8080"}
	pr, err := NewProxyRotator(proxyURLs, StrategyRoundRobin)
	if err != nil {
		t.Fatalf("NewProxyRotator failed: %v", err)
	}

	// Should return same proxy repeatedly
	for i := 0; i < 5; i++ {
		proxy, err := pr.Next()
		if err != nil {
			t.Fatalf("Next iteration %d failed: %v", i, err)
		}

		if proxy == nil || proxy.String() != "http://only-proxy.com:8080" {
			t.Errorf("Expected only-proxy.com, got %v", proxy)
		}
	}
}
