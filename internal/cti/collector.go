package cti

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/store"
)

// Setting keys holding the watched countries and sectors (comma-separated).
const (
	SettingCountries = "cti_countries"
	SettingSectors   = "cti_sectors"
)

// Retention of CTI items.
const Retention = 180 * 24 * time.Hour

// Collector fetches every enabled feed.
type Collector struct {
	Store     *store.Store
	HTTP      *http.Client // must come from netsafe.NewClient: feed URLs are user input
	UserAgent string
	Log       *slog.Logger

	mu sync.Mutex
}

// Run fetches all enabled feeds and returns the number of new items.
// A failing feed is recorded and skipped.
func (c *Collector) Run(ctx context.Context) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	feeds, err := c.Store.ListFeeds(ctx)
	if err != nil {
		return 0, err
	}
	total := 0
	for _, f := range feeds {
		if !f.Enabled {
			continue
		}
		n, fetchErr := c.collect(ctx, f)
		if fetchErr != nil {
			c.Log.Warn("flux CTI en erreur", "feed", f.Name, "err", fetchErr)
		}
		if err := c.Store.RecordFeedFetch(ctx, f.ID, fetchErr); err != nil {
			return total, err
		}
		total += n
	}
	if err := c.Store.PurgeCTIItems(ctx, time.Now().Add(-Retention)); err != nil {
		return total, err
	}
	c.Log.Info("cti done", "new_items", total)
	return total, nil
}

func (c *Collector) collect(ctx context.Context, f store.Feed) (int, error) {
	items, err := Fetch(ctx, c.HTTP, f.URL, c.UserAgent)
	if err != nil {
		return 0, err
	}
	cutoff := time.Now().Add(-Retention)
	n := 0
	for _, it := range items {
		if it.GUID == "" || it.Title == "" || it.Published.Before(cutoff) {
			continue
		}
		countries, sectors := Classify(it, f.Country, splitNonEmpty(f.Sectors))
		isNew, err := c.Store.InsertCTIItem(ctx, f.ID, store.CTIItem{
			GUID: it.GUID, Title: it.Title, Link: it.Link, Summary: it.Summary,
			Published: it.Published, Countries: countries, Sectors: sectors,
		})
		if err != nil {
			return n, err
		}
		if isNew {
			n++
		}
	}
	return n, nil
}

// WatchedFilter returns the filter built from the watched countries and sectors.
func WatchedFilter(ctx context.Context, st *store.Store) (store.CTIFilter, error) {
	countries, err := st.Setting(ctx, SettingCountries)
	if err != nil {
		return store.CTIFilter{}, err
	}
	sectors, err := st.Setting(ctx, SettingSectors)
	if err != nil {
		return store.CTIFilter{}, err
	}
	return store.CTIFilter{Countries: splitNonEmpty(countries), Sectors: splitNonEmpty(sectors)}, nil
}

// SaveWatched stores the watched countries and sectors, ignoring unknown values.
func SaveWatched(ctx context.Context, st *store.Store, countries, sectors []string) error {
	keep := func(tags []Tag, values []string) string {
		var out []string
		for _, v := range values {
			if Known(tags, v) {
				out = append(out, v)
			}
		}
		return strings.Join(out, ",")
	}
	if err := st.SetSetting(ctx, SettingCountries, keep(Countries, countries)); err != nil {
		return err
	}
	return st.SetSetting(ctx, SettingSectors, keep(Sectors, sectors))
}
