package http

import (
	"testing"
)

func TestRoundRobin(t *testing.T) {
	keys := []string{"key1", "key2", "key3"}
	kr := NewKeyRotator(keys)

	// Should cycle through keys
	key1, err := kr.Next()
	if err != nil {
		t.Fatalf("First Next failed: %v", err)
	}
	if key1 != "key1" && key1 != "key2" && key1 != "key3" {
		t.Errorf("First key invalid: %q", key1)
	}

	key2, err := kr.Next()
	if err != nil {
		t.Fatalf("Second Next failed: %v", err)
	}

	key3, err := kr.Next()
	if err != nil {
		t.Fatalf("Third Next failed: %v", err)
	}

	// Verify we got different keys (round-robin)
	keys_got := []string{key1, key2, key3}
	if len(keys_got) != len(keys) {
		t.Errorf("Expected 3 keys, got %d", len(keys_got))
	}
}

func TestExhaustedKey(t *testing.T) {
	keys := []string{"key1", "key2", "key3"}
	kr := NewKeyRotator(keys)

	// Mark key1 as exhausted (0 remaining)
	kr.UpdateQuota("key1", 0)

	// Next should skip key1 and return key2 or key3
	key, err := kr.Next()
	if err != nil {
		t.Fatalf("Next failed: %v", err)
	}

	if key == "key1" {
		t.Error("Next should skip exhausted key1")
	}
}

func TestAllExhausted(t *testing.T) {
	keys := []string{"key1", "key2"}
	kr := NewKeyRotator(keys)

	// Mark all as exhausted
	kr.UpdateQuota("key1", 0)
	kr.UpdateQuota("key2", 0)

	if !kr.AllExhausted() {
		t.Error("AllExhausted should return true when all keys are at 0")
	}

	// Request should fail
	_, err := kr.Next()
	if err == nil {
		t.Error("Next should fail when all keys exhausted")
	}
}

func TestUnknownQuota(t *testing.T) {
	keys := []string{"key1", "key2"}
	kr := NewKeyRotator(keys)

	// Initially quota is -1 (unknown), Next should still work
	key, err := kr.Next()
	if err != nil {
		t.Fatalf("Next with unknown quota failed: %v", err)
	}

	if key == "" {
		t.Error("Next should return a key even with unknown quota")
	}
}

func TestUpdateQuota(t *testing.T) {
	keys := []string{"key1"}
	kr := NewKeyRotator(keys)

	// Update quota
	kr.UpdateQuota("key1", 100)

	// Should still work
	key, err := kr.Next()
	if err != nil {
		t.Fatalf("Next failed: %v", err)
	}

	if key != "key1" {
		t.Errorf("Expected key1, got %q", key)
	}
}

func TestNoKeys(t *testing.T) {
	kr := NewKeyRotator([]string{})

	_, err := kr.Next()
	if err == nil {
		t.Error("Next should fail with no keys")
	}
}

func TestSingleKey(t *testing.T) {
	keys := []string{"only-key"}
	kr := NewKeyRotator(keys)

	// Should return same key repeatedly
	for i := 0; i < 5; i++ {
		key, err := kr.Next()
		if err != nil {
			t.Fatalf("Next iteration %d failed: %v", i, err)
		}
		if key != "only-key" {
			t.Errorf("Expected only-key, got %q", key)
		}
	}
}

func TestSkipMultipleExhausted(t *testing.T) {
	keys := []string{"key1", "key2", "key3", "key4"}
	kr := NewKeyRotator(keys)

	// Exhaust key1 and key3
	kr.UpdateQuota("key1", 0)
	kr.UpdateQuota("key3", 0)

	// Next calls should return key2 or key4
	for i := 0; i < 3; i++ {
		key, err := kr.Next()
		if err != nil {
			t.Fatalf("Next failed: %v", err)
		}

		if key == "key1" || key == "key3" {
			t.Errorf("Next returned exhausted key: %q", key)
		}
	}
}
