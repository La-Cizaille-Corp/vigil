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
	"strings"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/netsafe"
)

const maxFeedBytes = 8 << 20

// Item is one normalised feed entry.
type Item struct {
	GUID      string
	Title     string
	Link      string
	Summary   string
	Published time.Time
}

// Fetch downloads and parses a feed.
func Fetch(ctx context.Context, client *http.Client, url, userAgent string) ([]Item, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/rss+xml, application/atom+xml, application/xml, text/xml")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	body, err := netsafe.ReadLimited(resp.Body, maxFeedBytes)
	if err != nil {
		return nil, err
	}
	return Parse(body)
}

// Parse reads RSS 2.0 or Atom. encoding/xml never resolves external
// entities, so XXE is not possible.
func Parse(data []byte) ([]Item, error) {
	var doc struct {
		XMLName xml.Name
		Channel struct {
			Items []struct {
				GUID        string `xml:"guid"`
				Title       string `xml:"title"`
				Link        string `xml:"link"`
				Description string `xml:"description"`
				PubDate     string `xml:"pubDate"`
				Date        string `xml:"http://purl.org/dc/elements/1.1/ date"`
			} `xml:"item"`
		} `xml:"channel"`
		Entries []struct {
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
		} `xml:"entry"`
	}
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = false
	dec.CharsetReader = charsetReader
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("parse feed: %w", err)
	}

	var items []Item
	switch doc.XMLName.Local {
	case "rss", "RDF":
		for _, it := range doc.Channel.Items {
			items = append(items, Item{
				GUID:      firstNonEmpty(it.GUID, it.Link, it.Title),
				Title:     it.Title,
				Link:      it.Link,
				Summary:   it.Description,
				Published: parseDate(firstNonEmpty(it.PubDate, it.Date)),
			})
		}
	case "feed":
		for _, e := range doc.Entries {
			link := ""
			for _, l := range e.Links {
				if l.Rel == "" || l.Rel == "alternate" {
					link = l.Href
					break
				}
			}
			items = append(items, Item{
				GUID:      firstNonEmpty(e.ID, link, e.Title),
				Title:     e.Title,
				Link:      link,
				Summary:   firstNonEmpty(e.Summary, e.Content),
				Published: parseDate(firstNonEmpty(e.Published, e.Updated)),
			})
		}
	default:
		return nil, errors.New("format de flux inconnu (RSS ou Atom attendu)")
	}

	for i := range items {
		it := &items[i]
		it.Title = truncate(cleanText(it.Title), 500)
		it.Summary = truncate(cleanText(it.Summary), 2000)
		it.GUID = truncate(strings.TrimSpace(it.GUID), 500)
		it.Link = strings.TrimSpace(it.Link)
		// SECURITY: only keep http(s) links; a javascript: URL would be
		// neutralised by html/template anyway, but we do not store it.
		if !strings.HasPrefix(it.Link, "https://") && !strings.HasPrefix(it.Link, "http://") {
			it.Link = ""
		}
		if it.Published.IsZero() {
			it.Published = time.Now().UTC()
		}
	}
	return items, nil
}

var tagRe = regexp.MustCompile(`<[^>]*>`)

// cleanText removes markup and collapses whitespace; the result is plain text
// that templates escape again on output.
func cleanText(s string) string {
	s = tagRe.ReplaceAllString(s, " ")
	s = html.UnescapeString(s)
	return strings.Join(strings.Fields(s), " ")
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
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
