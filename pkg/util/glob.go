package util

import "strings"

// Match reports whether value matches pattern. Unlike path.Match, '*' spans any
// characters including '/', so it suits hostnames, namespaces, and cluster
// names. '*' matches any run (including empty); '?' matches a single byte.
// Empty pattern or value never matches.
func Match(pattern, value string) bool {
	pattern = strings.TrimSpace(pattern)
	value = strings.TrimSpace(value)
	if pattern == "" || value == "" {
		return false
	}

	px, vx := 0, 0
	star, starMatch := -1, 0
	for vx < len(value) {
		switch {
		case px < len(pattern) && (pattern[px] == '?' || pattern[px] == value[vx]):
			px++
			vx++
		case px < len(pattern) && pattern[px] == '*':
			star, starMatch = px, vx
			px++
		case star != -1:
			px = star + 1
			starMatch++
			vx = starMatch
		default:
			return false
		}
	}
	for px < len(pattern) && pattern[px] == '*' {
		px++
	}
	return px == len(pattern)
}
