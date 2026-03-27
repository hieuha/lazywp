package cli

import "testing"

func TestRedactKeys_Empty(t *testing.T) {
	if got := redactKeys(nil); got != nil {
		t.Errorf("redactKeys(nil): got %v, want nil", got)
	}
	if got := redactKeys([]string{}); got != nil {
		t.Errorf("redactKeys([]): got %v, want nil", got)
	}
}

func TestRedactKeys_Single(t *testing.T) {
	keys := []string{"super-secret-key-abc123"}
	got := redactKeys(keys)
	if len(got) != 1 {
		t.Fatalf("expected 1 result, got %d", len(got))
	}
	if got[0] != "[redacted]" {
		t.Errorf("got %q, want [redacted]", got[0])
	}
}

func TestRedactKeys_Multiple(t *testing.T) {
	keys := []string{"key1", "key2", "key3"}
	got := redactKeys(keys)
	if len(got) != len(keys) {
		t.Fatalf("length mismatch: got %d, want %d", len(got), len(keys))
	}
	for i, v := range got {
		if v != "[redacted]" {
			t.Errorf("keys[%d]: got %q, want [redacted]", i, v)
		}
	}
}

func TestRedactKeys_DoesNotMutateInput(t *testing.T) {
	original := []string{"my-api-key"}
	_ = redactKeys(original)
	if original[0] != "my-api-key" {
		t.Error("redactKeys must not mutate the input slice")
	}
}
