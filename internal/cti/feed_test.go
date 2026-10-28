package cti

import "testing"

func TestCleanText(t *testing.T) {
	for in, want := range map[string]string{
		"<p>Séance à 9h&nbsp;30</p>":        "Séance à 9h 30",
		"jeudi 22 octobre à 9h&amp;nbsp;30": "jeudi 22 octobre à 9h 30",
		"&lt;b&gt;gras&lt;/b&gt; &amp; co":  "gras & co",
		// escaped three times: no markup may survive the last decoding
		"&amp;amp;lt;!channel&amp;amp;gt; alerte": "alerte",
	} {
		if got := cleanText(in); got != want {
			t.Errorf("cleanText(%q) = %q, want %q", in, got, want)
		}
	}
}
