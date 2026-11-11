package clip

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestClip(t *testing.T) {
	for _, c := range []struct {
		s, prefix, text string
		n               int
	}{
		{"abc", "abc", "abc", 3},
		{"abcd", "abc", "ab…", 3},
		{"éèêë", "éèê", "éè…", 3},
		{"日本語です", "日本", "日…", 2},
		{"abc", "", "", 0},
		{"", "", "", 2},
	} {
		if got := Prefix(c.s, c.n); got != c.prefix {
			t.Errorf("Prefix(%q, %d) = %q, want %q", c.s, c.n, got, c.prefix)
		}
		if got := Text(c.s, c.n); got != c.text {
			t.Errorf("Text(%q, %d) = %q, want %q", c.s, c.n, got, c.text)
		}
	}
	if !Fits("éé", 2) || Fits("ééé", 2) {
		t.Error("Fits counts bytes, not characters")
	}
}

// A byte budget never cuts a character in two.
func TestBytes(t *testing.T) {
	long := strings.Repeat("a", 299) + "é et la suite"
	got := Bytes(long, 300)
	if !utf8.ValidString(got) || got != strings.Repeat("a", 299)+"…" {
		t.Errorf("Bytes = %q", got)
	}
	if Bytes("court", 300) != "court" || Bytes("é", 0) != "…" {
		t.Error("Bytes changed a short text, or failed on an empty budget")
	}
}
