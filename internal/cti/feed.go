// Package cti collects threat-intelligence news from RSS/Atom feeds and tags
// items by sector and country.
package cti

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/clip"
	"github.com/La-Cizaille-Corp/vigil/internal/limit"
	"github.com/La-Cizaille-Corp/vigil/internal/netsafe"
)

const maxFeedBytes = 8 << 20

// feedItem is one normalised feed entry.
type feedItem struct {
	GUID      string
	Title     string
	Link      string
	Summary   string
	Published time.Time
}

// fetch downloads and parses a feed.
func fetch(ctx context.Context, client *http.Client, url, userAgent string) ([]feedItem, error) {
	// The URL of a feed may carry an access key: errors leave it out.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, netsafe.WithoutURL(err)
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/rss+xml, application/atom+xml, application/xml, text/xml")
	resp, err := client.Do(req)
	if err != nil {
		return nil, netsafe.WithoutURL(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("réponse HTTP %d", resp.StatusCode)
	}
	body, err := limit.Read(resp.Body, maxFeedBytes)
	if err != nil {
		return nil, err
	}
	return parseFeed(body)
}

// rssItem is an item of RSS 2.0, or of RSS 1.0 (RDF), whose items are
// children of the root rather than of the channel.
type rssItem struct {
	GUID        string `xml:"guid"`
	Title       string `xml:"title"`
	Link        string `xml:"link"`
	Description string `xml:"description"`
	PubDate     string `xml:"pubDate"`
	Date        string `xml:"http://purl.org/dc/elements/1.1/ date"`
}

func (it rssItem) item() feedItem {
	return feedItem{
		GUID:      firstNonEmpty(it.GUID, it.Link, it.Title),
		Title:     it.Title,
		Link:      it.Link,
		Summary:   it.Description,
		Published: parseDate(firstNonEmpty(it.PubDate, it.Date)),
	}
}

// atomEntry is an entry of Atom.
type atomEntry struct {
	ID    string `xml:"id"`
	Title string `xml:"title"`
	Links []struct {
		Href string `xml:"href,attr"`
		Rel  string `xml:"rel,attr"`
	} `xml:"link"`
	Summary   string `xml:"summary"`
	Content   string `xml:"content"`
	Published string `xml:"published"`
	Updated   string `xml:"updated"`
}

func (e atomEntry) item() feedItem {
	link := ""
	for _, l := range e.Links {
		if l.Rel == "" || l.Rel == "alternate" {
			link = l.Href
			break
		}
	}
	return feedItem{
		GUID:      firstNonEmpty(e.ID, link, e.Title),
		Title:     e.Title,
		Link:      link,
		Summary:   firstNonEmpty(e.Summary, e.Content),
		Published: parseDate(firstNonEmpty(e.Published, e.Updated)),
	}
}

// maxFeedEntries bounds the entries decoded from one document; the rest of
// it is not read. SECURITY: decoding the whole document before keeping
// maxFeedItems let 8 MiB of empty <item/> make a million structures, about
// half a gibibyte for each collection (revue 0.5.0, C1).
const maxFeedEntries = 2000

// parseFeed reads RSS 2.0, RSS 1.0 (RDF) or Atom, one entry at a time, at most
// maxFeedEntries of them. encoding/xml never resolves external entities, so
// XXE is not possible.
func parseFeed(data []byte) ([]feedItem, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = false
	dec.CharsetReader = charsetReader
	var items []feedItem
	root, depth := "", 0
	for depth > 0 || root == "" {
		tok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("flux illisible : %w", err)
		}
		switch t := tok.(type) {
		case xml.EndElement:
			depth--
		case xml.StartElement:
			if root == "" {
				if root = t.Name.Local; root != "rss" && root != "RDF" && root != "feed" {
					return nil, errors.New("format de flux inconnu (RSS ou Atom attendu)")
				}
				depth++
				continue
			}
			// An item or an entry is decoded whole, its end element with it;
			// the decoder goes into any other element (the channel of RSS 2.0).
			var it interface{ item() feedItem }
			switch {
			case root == "feed" && t.Name.Local == "entry":
				it = &atomEntry{}
			case root != "feed" && t.Name.Local == "item":
				it = &rssItem{}
			default:
				depth++
				continue
			}
			if err := dec.DecodeElement(it, &t); err != nil {
				return nil, fmt.Errorf("flux illisible : %w", err)
			}
			if items = append(items, it.item()); len(items) == maxFeedEntries {
				depth = 0 // the rest of the feed is left unread
			}
		}
	}

	now := time.Now().UTC()
	for i := range items {
		it := &items[i]
		it.Title = clip.Text(cleanText(it.Title), 500)
		it.Summary = clip.Text(cleanText(it.Summary), 2000)
		it.GUID = clip.Text(strings.TrimSpace(it.GUID), 500)
		// SECURITY: only keep plain http(s) links. A javascript: URL would be
		// neutralised by html/template anyway, but a line break inside the
		// link would cut the Markdown link of the digest and let the rest of
		// it ping a whole channel: such links are not stored.
		it.Link, _ = netsafe.WebURL(it.Link)
		// A date in the future would keep an item at the top of every list
		// and out of the retention purge.
		if it.Published.IsZero() || it.Published.After(now.Add(24*time.Hour)) {
			it.Published = now
		}
	}
	// SECURITY: a hostile or broken feed cannot flood the database.
	if len(items) > maxFeedItems {
		sort.SliceStable(items, func(i, j int) bool { return items[i].Published.After(items[j].Published) })
		items = items[:maxFeedItems]
	}
	return items, nil
}

// maxFeedItems bounds what one fetch of a feed may store.
const maxFeedItems = 500

var tagRe = regexp.MustCompile(`<[^>]*>`)

// cleanText turns HTML content into plain text that templates escape again
// on output. Some feeds escape their HTML twice ("&amp;nbsp;"), so entities
// are decoded until stable, and tags removed once more after the last pass.
func cleanText(s string) string {
	for range 3 {
		s = tagRe.ReplaceAllString(s, " ")
		u := html.UnescapeString(s)
		if u == s {
			break
		}
		s = u
	}
	s = tagRe.ReplaceAllString(s, " ")
	return strings.Join(strings.Fields(s), " ")
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}

var dateLayouts = []string{
	time.RFC1123Z, time.RFC1123, time.RFC3339, time.RFC3339Nano,
	"Mon, 02 Jan 06 15:04:05 -0700", "Mon, 02 Jan 06 15:04:05 MST", // two-digit years (CISA)
	"Mon, 2 Jan 2006 15:04:05 -0700", "Mon, 2 Jan 2006 15:04:05 MST", "2006-01-02T15:04:05Z0700", "2006-01-02",
}

func parseDate(s string) time.Time {
	s = strings.TrimSpace(s)
	for _, l := range dateLayouts {
		if t, err := time.Parse(l, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}
