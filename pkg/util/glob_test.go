package util

import "testing"

func TestMatch(t *testing.T) {
	tests := []struct {
		pattern string
		value   string
		want    bool
	}{
		{"github.com", "github.com", true},
		{"github.com", "GitHub.com", false},
		{"*.example.net", "api.example.net", true},
		{"*.example.net", "example.net", false},
		{"*", "team/dev", true},
		{"team/*", "team/dev", true},
		{"team-*", "team-alpha", true},
		{"team-*", "group-beta", false},
		{"a?c", "abc", true},
		{"a?c", "ac", false},
		{"", "github.com", false},
		{"*", "", false},
	}

	for _, tt := range tests {
		if got := Match(tt.pattern, tt.value); got != tt.want {
			t.Fatalf("Match(%q, %q) = %v, want %v", tt.pattern, tt.value, got, tt.want)
		}
	}
}
