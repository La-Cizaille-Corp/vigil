package chattext

import (
	"strings"
	"testing"
)

func TestText(t *testing.T) {
	got := Text("x <!channel> <https://evil.example/fix|Correctif>\n@here [Patch](https://evil) ![](https://evil/p.png)")
	for _, bad := range []string{"<!", "<https", "\n", "@here", "](https"} {
		if strings.Contains(got, bad) {
			t.Errorf("%q survives in %q", bad, got)
		}
	}
	if Text("Log4Shell dans log4j-core 2.14.1") != "Log4Shell dans log4j-core 2.14.1" {
		t.Error("plain text changed")
	}
	// The mention stays readable: only an invisible character is inserted.
	if m := Text("@here"); m != "@"+zwsp+"here" {
		t.Errorf("mention = %q", m)
	}
	if c := Cell("a|b"); c != `a\|b` {
		t.Errorf("cell = %q", c)
	}
	if u := URL("https://example.org/a b(c)"); u != "https://example.org/a%20b%28c%29" {
		t.Errorf("url = %q", u)
	}
}

// A line break or another control character cannot cut a Markdown link.
func TestURLControlCharacters(t *testing.T) {
	for in, want := range map[string]string{
		"https://evil.example/a\n@channel please": "https://evil.example/a%0A@channel%20please",
		"https://e.example/a\r\tb\x00c\x7fd":      "https://e.example/a%0D%09b%00c%7Fd",
		"https://e.example/[x]<y>":                "https://e.example/%5Bx%5D%3Cy%3E",
		"https://e.example/été?q=1&r=%41":         "https://e.example/été?q=1&r=%41",
	} {
		if got := URL(in); got != want {
			t.Errorf("URL(%q) = %q, want %q", in, got, want)
		}
	}
}
