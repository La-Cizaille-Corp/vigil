package cti

import (
	"reflect"
	"testing"
)

const rss = `<?xml version="1.0" encoding="ISO-8859-1"?>
<rss version="2.0"><channel>
<item><title>Ransomware hits French hospital</title><link>https://example.org/a</link>
<guid>a</guid><pubDate>Mon, 26 Oct 2026 10:00:00 +0000</pubDate>
<description>&lt;p&gt;Attack on a &lt;b&gt;h&#xF4;pital&lt;/b&gt; in France.&lt;/p&gt;</description></item>
<item><title>Bad link</title><link>javascript:alert(1)</link><guid>b</guid></item>
</channel></rss>`

const atom = `<feed xmlns="http://www.w3.org/2005/Atom">
<entry><id>urn:1</id><title>Bank targeted</title><link rel="alternate" href="https://example.org/b"/>
<updated>2026-10-25T08:00:00Z</updated><summary>Phishing against a German bank</summary></entry>
</feed>`

func TestParseRSS(t *testing.T) {
	items, err := Parse([]byte(rss))
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("got %d items", len(items))
	}
	if items[0].Summary != "Attack on a hôpital in France." {
		t.Errorf("summary not cleaned: %q", items[0].Summary)
	}
	if items[1].Link != "" {
		t.Errorf("javascript link kept: %q", items[1].Link)
	}
	countries, sectors := Classify(items[0], "", nil)
	if !reflect.DeepEqual(countries, []string{"FR"}) || !reflect.DeepEqual(sectors, []string{"health"}) {
		t.Errorf("classify = %v %v", countries, sectors)
	}
}

func TestParseAtom(t *testing.T) {
	items, err := Parse([]byte(atom))
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Link != "https://example.org/b" || items[0].Published.IsZero() {
		t.Fatalf("unexpected items: %+v", items)
	}
	countries, sectors := Classify(items[0], "EU", []string{"digital"})
	if !reflect.DeepEqual(countries, []string{"DE", "EU"}) || !reflect.DeepEqual(sectors, []string{"digital", "finance"}) {
		t.Errorf("classify = %v %v", countries, sectors)
	}
}

func TestParseDate(t *testing.T) {
	for _, s := range []string{
		"Mon, 26 Oct 26 12:00:00 +0000",   // CISA
		"Wed, 21 Oct 2026 00:00:00 +0000", // CERT-FR
		"Mon, 26 Oct 2026 23:20:39 GMT",   // BleepingComputer
		"2026-10-25T08:00:00Z",            // Atom
	} {
		if d := parseDate(s); d.Year() != 2026 {
			t.Errorf("parseDate(%q) = %v", s, d)
		}
	}
}

func TestClassifyWholeWords(t *testing.T) {
	// "Ukraine" must not match inside another word, "uk" must not match "Ukraine".
	countries, _ := Classify(Item{Title: "Ukrainian CERT warns"}, "", nil)
	if !reflect.DeepEqual(countries, []string{"UA"}) {
		t.Errorf("countries = %v", countries)
	}
}
