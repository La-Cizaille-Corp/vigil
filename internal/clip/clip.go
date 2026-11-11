// Package clip shortens text without cutting a character in two, so that what
// Vigil shows, stores or sends stays valid UTF-8. Limits on what users and
// sources write count characters (Text, Prefix, Fits); Bytes is for the size
// budget of a message sent elsewhere.
package clip

import "unicode/utf8"

// Prefix returns the first n characters of s.
func Prefix(s string, n int) string {
	if n <= 0 {
		return ""
	}
	count := 0
	for i := range s {
		if count == n {
			return s[:i]
		}
		count++
	}
	return s
}

// Text returns s cut to n characters, the last one "…" when s was longer.
func Text(s string, n int) string {
	if Fits(s, n) {
		return s
	}
	if n <= 0 {
		return ""
	}
	return Prefix(s, n-1) + "…"
}

// Bytes returns s cut to at most n bytes, then "…" when it was longer.
func Bytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := max(n, 0)
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

// Fits reports whether s has at most n characters.
func Fits(s string, n int) bool {
	return utf8.RuneCountInString(s) <= n
}
