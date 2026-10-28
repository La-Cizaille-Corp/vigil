package cti

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/store"
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
	tags := Classify(items[0], store.Feed{})
	if !reflect.DeepEqual(tags.Countries, []string{"FR"}) || !reflect.DeepEqual(tags.Sectors, []string{"health"}) {
		t.Errorf("classify = %+v", tags)
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
	tags := Classify(items[0], store.Feed{Country: "EU", Sectors: "digital"})
	if !reflect.DeepEqual(tags.Countries, []string{"DE", "EU"}) || !reflect.DeepEqual(tags.Sectors, []string{"digital", "finance"}) {
		t.Errorf("classify = %+v", tags)
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
	tags := Classify(Item{Title: "Ukrainian CERT warns"}, store.Feed{})
	if !reflect.DeepEqual(tags.Countries, []string{"UA"}) {
		t.Errorf("countries = %v", tags.Countries)
	}
}

func TestClassifyRegulations(t *testing.T) {
	for title, want := range map[string][]string{
		"La Commission précise l'application de NIS2 et du Cyber Resilience Act": {"cra", "gdpr", "nis2"},
		"EDPB adopts guidelines":                      {"gdpr"}, // from the feed
		"ESAs publish DORA incident reporting RTS":    {"dora", "gdpr"},
		"Nouvelle version du référentiel SecNumCloud": {"gdpr", "secnumcloud"},
		"Cracking the code of ransomware":             {"gdpr"}, // "cra" inside a word is ignored
	} {
		tags := Classify(Item{Title: title}, store.Feed{Regulations: "gdpr"})
		if !reflect.DeepEqual(tags.Regulations, want) {
			t.Errorf("%q: %v, want %v", title, tags.Regulations, want)
		}
	}
}

// A feed cannot flood the database nor pin an item at the top with a date in
// the future.
func TestParseLimits(t *testing.T) {
	var b strings.Builder
	b.WriteString(`<rss><channel>`)
	for i := range maxFeedItems + 10 {
		fmt.Fprintf(&b, `<item><guid>%d</guid><title>t</title><pubDate>Mon, 26 Oct 2026 10:00:00 +0000</pubDate></item>`, i)
	}
	fmt.Fprintf(&b, `<item><guid>future</guid><title>f</title><link>https://example.org/%s</link><pubDate>Fri, 01 Jan 2100 00:00:00 +0000</pubDate></item>`,
		strings.Repeat("a", maxLinkLen))
	b.WriteString(`</channel></rss>`)
	items, err := Parse([]byte(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != maxFeedItems {
		t.Errorf("%d items kept, want %d", len(items), maxFeedItems)
	}
	for _, it := range items {
		if it.Published.After(time.Now().Add(25 * time.Hour)) {
			t.Errorf("future date kept: %v", it.Published)
		}
		if it.GUID == "future" && it.Link != "" {
			t.Error("oversized link kept")
		}
	}
}
