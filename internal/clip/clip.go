// Package clip shortens text without cutting a character in two, so that what
// Vigil shows, stores or sends stays valid UTF-8. Limits on what users and
// sources write count characters (Text, Prefix, Fits, Excerpt); Bytes is for
// the size budget of a message sent elsewhere.
package clip

import (
	"strings"
	"unicode/utf8"
)

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

// Excerpt returns s cut to n characters as Text does, and ends with "…" a
// text that stops before the end of its sentence: feeds cut their summaries
// mid-word ("… that 1,122 public"), and the reader should see it is cut.
func Excerpt(s string, n int) string {
	s = strings.TrimRight(s, " \t\r\n\u200b")
	if !Fits(s, n) {
		return Text(s, n)
	}
	if r, _ := utf8.DecodeLastRuneInString(s); s != "" && !strings.ContainsRune(".!?…»\")]", r) {
		return s + "…"
	}
	return s
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
