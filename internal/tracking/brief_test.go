package tracking

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// A summary taken from a description without a sentence end in its first 300
// bytes was cut there, possibly in the middle of a character.
func TestBriefStaysValidUTF8(t *testing.T) {
	got := brief("a" + strings.Repeat("é", 400))
	if !utf8.ValidString(got) || utf8.RuneCountInString(got) != 300 || !strings.HasSuffix(got, "…") {
		t.Errorf("brief = %q", got)
	}
	if got := brief("Première phrase. La suite."); got != "Première phrase." {
		t.Errorf("first sentence: %q", got)
	}
}
