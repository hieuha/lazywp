package cli

import "testing"

func TestCvssToSARIFLevel(t *testing.T) {
	tests := []struct {
		cvss float64
		want string
	}{
		{9.0, "error"},
		{9.8, "error"},
		{7.0, "error"},
		{8.9, "error"},
		{4.0, "warning"},
		{6.9, "warning"},
		{0.0, "note"},
		{3.9, "note"},
	}
	for _, tc := range tests {
		t.Run("", func(t *testing.T) {
			if got := cvssToSARIFLevel(tc.cvss); got != tc.want {
				t.Errorf("cvssToSARIFLevel(%.1f) = %q, want %q", tc.cvss, got, tc.want)
			}
		})
	}
}

func TestFixedLabel(t *testing.T) {
	tests := []struct {
		s    string
		want string
	}{
		{"", "unfixed"},
		{"1.2.3", "1.2.3"},
		{"2.0", "2.0"},
	}
	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			if got := fixedLabel(tc.s); got != tc.want {
				t.Errorf("fixedLabel(%q) = %q, want %q", tc.s, got, tc.want)
			}
		})
	}
}
