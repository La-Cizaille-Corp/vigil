package cti

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/netsafe"
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
	items, err := parseFeed([]byte(rss))
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
	tags := classify(items[0], store.Feed{})
	if !reflect.DeepEqual(tags.Countries, []string{"FR"}) || !reflect.DeepEqual(tags.Sectors, []string{"health"}) {
		t.Errorf("classify = %+v", tags)
	}
}

func TestParseAtom(t *testing.T) {
	items, err := parseFeed([]byte(atom))
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Link != "https://example.org/b" || items[0].Published.IsZero() {
		t.Fatalf("unexpected items: %+v", items)
	}
	tags := classify(items[0], store.Feed{Country: "EU", Sectors: "digital"})
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
	tags := classify(feedItem{Title: "Ukrainian CERT warns"}, store.Feed{})
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
		tags := classify(feedItem{Title: title}, store.Feed{Regulations: "gdpr"})
		if !reflect.DeepEqual(tags.Regulations, want) {
			t.Errorf("%q: %v, want %v", title, tags.Regulations, want)
		}
	}
}

// A link that would cut the Markdown link of the digest, or hide its host
// behind credentials, is not stored; the item is kept without it.
func TestParseDropsUnsafeLinks(t *testing.T) {
	feed := "<rss><channel>" +
		"<item><guid>1</guid><title>Correctif urgent</title><link>https://evil.example/a\n@channel please read</link></item>" +
		"<item><guid>2</guid><title>Avis</title><link>https://www.cert.example@evil.example/</link></item>" +
		"<item><guid>3</guid><title>Bulletin</title><link> https://example.org/c </link></item>" +
		"</channel></rss>"
	items, err := parseFeed([]byte(feed))
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 3 {
		t.Fatalf("got %d items", len(items))
	}
	for i, want := range []string{"", "", "https://example.org/c"} {
		if items[i].Link != want {
			t.Errorf("item %d: link %q, want %q", i+1, items[i].Link, want)
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
		strings.Repeat("a", netsafe.MaxURLLen))
	b.WriteString(`</channel></rss>`)
	items, err := parseFeed([]byte(b.String()))
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

// C1 of the 0.5.0 review: a feed is decoded one entry at a time, and no
// further than maxFeedEntries. 8 MiB of empty items used to cost about
// 2.3 GiB of allocations (450 MiB live) for the 500 items kept.
func TestParseStopsAfterMaxEntries(t *testing.T) {
	for _, f := range []struct{ open, entry, close string }{
		{"<rss><channel>", "<item/>", "</channel></rss>"},
		{`<feed xmlns="http://www.w3.org/2005/Atom">`, "<entry/>", "</feed>"},
		{"<rss><channel>", "<x:item/>", "</channel></rss>"}, // any prefix is an item for encoding/xml
	} {
		var b bytes.Buffer
		b.WriteString(f.open)
		for b.Len()+len(f.entry)+len(f.close) <= maxFeedBytes {
			b.WriteString(f.entry)
		}
		b.WriteString(f.close)
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		items, err := parseFeed(b.Bytes())
		runtime.ReadMemStats(&after)
		if err != nil || len(items) != maxFeedItems {
			t.Errorf("%s: %d items, %v", f.entry, len(items), err)
		}
		if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 32<<20 {
			t.Errorf("%s: %d MiB allocated to read %d bytes", f.entry, allocated>>20, b.Len())
		}
	}
	// What follows the last entry read is not read: not even cut short.
	feed := "<rss><channel>" + strings.Repeat("<item><guid>g</guid><title>t</title></item>", maxFeedEntries) + "<item><title>coupé"
	if items, err := parseFeed([]byte(feed)); err != nil || len(items) != maxFeedItems {
		t.Errorf("entries past the bound: %d items, %v", len(items), err)
	}
}

// C12 of the 0.5.0 review: the items of RSS 1.0 are children of the root,
// not of the channel; they used to be dropped without an error.
func TestParseRSS10(t *testing.T) {
	const rdf = `<?xml version="1.0"?>
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns="http://purl.org/rss/1.0/" xmlns:dc="http://purl.org/dc/elements/1.1/">
 <channel rdf:about="https://example.org/"><title>Exemple</title><link>https://example.org/</link>
  <items><rdf:Seq><rdf:li resource="https://example.org/1"/></rdf:Seq></items></channel>
 <item rdf:about="https://example.org/1"><title>Premier avis</title><link>https://example.org/1</link>
  <dc:date>2026-11-01T10:00:00Z</dc:date></item>
</rdf:RDF>`
	items, err := parseFeed([]byte(rdf))
	if err != nil || len(items) != 1 {
		t.Fatalf("%d items, %v", len(items), err)
	}
	if it := items[0]; it.Title != "Premier avis" || it.Link != "https://example.org/1" || it.GUID != "https://example.org/1" ||
		!it.Published.Equal(time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("item = %+v", it)
	}
}

// newFeedCollector returns a store whose only feed is served by h, and a
// collector of it.
func newFeedCollector(t *testing.T, h http.HandlerFunc) (*store.Store, *Collector) {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "cti.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	feeds, _ := st.ListFeeds(ctx)
	for _, f := range feeds {
		if err := st.DeleteFeed(ctx, f.ID); err != nil {
			t.Fatal(err)
		}
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	if _, err := st.CreateFeed(ctx, store.Feed{Name: "x", URL: srv.URL, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	return st, &Collector{Store: st, HTTP: srv.Client(), Log: slog.New(slog.DiscardHandler)}
}

// S8 of the code audit: one collection at a time. A second request is
// refused at once instead of waiting for the first one, then collecting
// everything again.
func TestRunIsExclusive(t *testing.T) {
	var calls atomic.Int32
	fetched, release := make(chan struct{}, 10), make(chan struct{})
	st, c := newFeedCollector(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		fetched <- struct{}{}
		<-release
		w.Write([]byte(`<rss><channel></channel></rss>`))
	})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock) // before the feed server closes
	ctx := context.Background()
	if err := st.SetSetting(ctx, SettingNewsPerDay, "24"); err != nil {
		t.Fatal(err)
	}

	first := make(chan error, 1)
	go func() { _, err := c.Run(ctx); first <- err }()
	select {
	case <-fetched:
	case <-time.After(10 * time.Second):
		t.Fatal("the first collection did not start")
	}
	if !c.Running() {
		t.Error("Running() = false during a collection")
	}
	second := make(chan error, 1)
	go func() { _, err := c.Run(ctx); second <- err }()
	select {
	case err := <-second:
		if !errors.Is(err, ErrRunning) {
			t.Errorf("second collection: %v, want ErrRunning", err)
		}
		second = nil
	case <-time.After(2 * time.Second):
		t.Error("the second collection waits for the first one")
	}
	if second == nil {
		if err := c.RunIfDue(ctx); err != nil {
			t.Errorf("scheduled collection during a manual one: %v", err)
		}
	}
	unblock()
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if second != nil { // queued behind the first one: let it end
		<-second
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("%d collections, want 1", n)
	}
	if c.Running() {
		t.Error("Running() = true after the collection")
	}
}

// The feeds are collected as often as the setting says, read each time.
func TestRunIfDue(t *testing.T) {
	ctx := context.Background()
	var calls atomic.Int32
	st, c := newFeedCollector(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Write([]byte(`<rss><channel></channel></rss>`))
	})
	set := func(perDay string) {
		t.Helper()
		if err := st.SetSetting(ctx, SettingNewsPerDay, perDay); err != nil {
			t.Fatal(err)
		}
	}
	runIfDue := func() {
		t.Helper()
		if err := c.RunIfDue(ctx); err != nil {
			t.Fatal(err)
		}
	}

	if n, _ := NewsPerDay(ctx, st); n != defaultNewsPerDay {
		t.Errorf("default frequency = %d", n)
	}
	set("3")
	if n, _ := NewsPerDay(ctx, st); n != defaultNewsPerDay {
		t.Errorf("unknown frequency = %d", n)
	}
	set("0")
	runIfDue()
	if n := calls.Load(); n != 0 {
		t.Errorf("collected on demand only: %d calls", n)
	}
	set("24")
	runIfDue() // never collected yet
	runIfDue() // the hour has not passed
	if n := calls.Load(); n != 1 {
		t.Errorf("once an hour: %d calls", n)
	}
	c.last = time.Now().Add(-61 * time.Minute)
	runIfDue()
	if n := calls.Load(); n != 2 {
		t.Errorf("after an hour: %d calls", n)
	}
	set("1") // lowered: the day has not passed
	runIfDue()
	if n := calls.Load(); n != 2 {
		t.Errorf("once a day: %d calls", n)
	}
}
