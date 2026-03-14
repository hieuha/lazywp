package scanner

import "testing"

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.0", "1.0.1", -1},
		{"1.0.1", "1.0.0", 1},
		{"2.0", "1.9.9", 1},
		{"1.9.9", "2.0", -1},
		{"1.0", "1.0.0", 0},
		{"3.20.0", "3.21.0", -1},
		{"6.1.2", "6.1.5", -1},
		{"5.3.1", "5.3.1", 0},
		{"10.0", "9.99", 1},
	}

	for _, tt := range tests {
		got := CompareVersions(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestIsVulnerable(t *testing.T) {
	tests := []struct {
		current, fixedIn string
		want             bool
	}{
		{"6.1.2", "6.1.5", true},   // current < fixedIn
		{"6.1.5", "6.1.5", false},  // current == fixedIn
		{"6.2.0", "6.1.5", false},  // current > fixedIn
		{"1.0.0", "", true},        // empty fixedIn = always vulnerable
		{"1.0.0", "unfixed", true}, // unfixed = always vulnerable
		{"1.0.0", "Unfixed", true}, // case-insensitive
	}

	for _, tt := range tests {
		got := IsVulnerable(tt.current, tt.fixedIn)
		if got != tt.want {
			t.Errorf("IsVulnerable(%q, %q) = %v, want %v", tt.current, tt.fixedIn, got, tt.want)
		}
	}
}
