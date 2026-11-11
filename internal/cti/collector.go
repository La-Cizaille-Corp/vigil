package cti

import (
	"context"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/store"
)

// Setting keys holding the watched countries and sectors (comma-separated).
const (
	SettingCountries   = "cti_countries"
	SettingSectors     = "cti_sectors"
	SettingRegulations = "cti_regulations"
	// SettingNewsPerDay is how many times a day the feeds are collected.
	SettingNewsPerDay = "cti_news_per_day"
)

// DefaultNewsPerDay is the frequency of the collection when it was not chosen.
const DefaultNewsPerDay = 4

// NewsFrequencies are the times a day the feeds can be collected; 0 is on
// demand only.
var NewsFrequencies = []int{0, 1, 2, 4, 6, 12, 24}

// NewsPerDay returns how many times a day the feeds are collected.
func NewsPerDay(ctx context.Context, st *store.Store) (int, error) {
	v, err := st.Setting(ctx, SettingNewsPerDay)
	if err != nil {
		return 0, err
	}
	n, err := strconv.Atoi(v)
	if err != nil || !slices.Contains(NewsFrequencies, n) {
		return DefaultNewsPerDay, nil
	}
	return n, nil
}

// Retention of CTI items.
const Retention = 180 * 24 * time.Hour

// Collector fetches every enabled feed.
type Collector struct {
	Store     *store.Store
	HTTP      *http.Client // must come from netsafe.NewClient: feed URLs are user input
	UserAgent string
	Log       *slog.Logger

	mu   sync.Mutex
	last time.Time // start of the last collection
}

// RunIfDue collects the feeds when the time between two collections has
// passed, according to the setting read each time: it can change at any moment.
func (c *Collector) RunIfDue(ctx context.Context) error {
	perDay, err := NewsPerDay(ctx, c.Store)
	if err != nil || perDay == 0 {
		return err
	}
	c.mu.Lock()
	last := c.last
	c.mu.Unlock()
	if !last.IsZero() && time.Since(last) < 24*time.Hour/time.Duration(perDay) {
		return nil
	}
	_, err = c.Run(ctx)
	return err
}

// Run fetches all enabled feeds and returns the number of new items.
// A failing feed is recorded and skipped.
func (c *Collector) Run(ctx context.Context) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.last = time.Now()

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
		tags := Classify(it, f)
		isNew, err := c.Store.InsertCTIItem(ctx, f.ID, store.CTIItem{
			GUID: it.GUID, Title: it.Title, Link: it.Link, Summary: it.Summary, Published: it.Published,
			Countries: tags.Countries, Sectors: tags.Sectors, Regulations: tags.Regulations,
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

// WatchedRegulations returns the filter of the regulatory watch: items tagged
// with one of the watched regulations, or with any regulation when none is
// selected. Countries and sectors do not apply: a regulation concerns everyone
// it covers.
func WatchedRegulations(ctx context.Context, st *store.Store) (store.CTIFilter, error) {
	regs, err := st.Setting(ctx, SettingRegulations)
	if err != nil {
		return store.CTIFilter{}, err
	}
	f := store.CTIFilter{Regulations: splitNonEmpty(regs)}
	f.AnyRegulation = len(f.Regulations) == 0
	return f, nil
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

// SaveWatched stores the watched countries, sectors and regulations, ignoring
// unknown values and duplicates: the stored filter is the default view of the
// news page (see KnownOnly).
func SaveWatched(ctx context.Context, st *store.Store, countries, sectors, regulations []string) error {
	keep := func(tags []Tag, values []string) string { return strings.Join(KnownOnly(tags, values), ",") }
	if err := st.SetSetting(ctx, SettingCountries, keep(Countries, countries)); err != nil {
		return err
	}
	if err := st.SetSetting(ctx, SettingRegulations, keep(Regulations, regulations)); err != nil {
		return err
	}
	return st.SetSetting(ctx, SettingSectors, keep(Sectors, sectors))
}
