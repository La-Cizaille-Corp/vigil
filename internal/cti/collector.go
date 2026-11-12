package cti

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/choice"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
)

// Setting keys holding the watched countries and sectors (comma-separated).
const (
	SettingCountries   = "cti_countries"
	settingSectors     = "cti_sectors"
	settingRegulations = "cti_regulations"
	// SettingNewsPerDay is how many times a day the feeds are collected.
	SettingNewsPerDay = "cti_news_per_day"
)

// defaultNewsPerDay is the frequency of the collection when it was not chosen.
const defaultNewsPerDay = 4

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
		return defaultNewsPerDay, nil
	}
	return n, nil
}

// retention of CTI items.
const retention = 180 * 24 * time.Hour

// Collector fetches every enabled feed.
type Collector struct {
	Store     *store.Store
	HTTP      *http.Client // must come from netsafe.NewClient: feed URLs are user input
	UserAgent string
	Log       *slog.Logger

	mu      sync.Mutex // held for a whole collection
	last    time.Time  // start of the last collection, under mu
	running atomic.Bool
}

// ErrRunning is returned when a collection is already in progress.
var ErrRunning = errors.New("une collecte des flux est déjà en cours")

// RunIfDue collects the feeds when the time between two collections has
// passed, according to the setting read each time: it can change at any
// moment. A collection in progress is the one due: it returns nil.
func (c *Collector) RunIfDue(ctx context.Context) error {
	perDay, err := NewsPerDay(ctx, c.Store)
	if err != nil || perDay == 0 {
		return err
	}
	_, err = c.run(ctx, 24*time.Hour/time.Duration(perDay))
	if errors.Is(err, ErrRunning) {
		return nil
	}
	return err
}

// Run fetches all enabled feeds and returns the number of new items.
// A failing feed is recorded and skipped. It returns ErrRunning, without
// waiting, when a collection is already in progress.
func (c *Collector) Run(ctx context.Context) (int, error) { return c.run(ctx, 0) }

// Running reports whether a collection is in progress.
func (c *Collector) Running() bool { return c.running.Load() }

// run collects the feeds, unless the last collection started less than every
// ago (every > 0).
func (c *Collector) run(ctx context.Context, every time.Duration) (int, error) {
	// SECURITY: one collection at a time. Each manual request used to wait for
	// the previous one, then run a whole collection of its own (10 minutes at
	// most each): repeated clicks piled up goroutines and outgoing requests.
	if !c.mu.TryLock() {
		return 0, ErrRunning
	}
	defer c.mu.Unlock()
	if every > 0 && !c.last.IsZero() && time.Since(c.last) < every {
		return 0, nil
	}
	c.running.Store(true)
	defer c.running.Store(false)
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
			c.Log.Warn("cti feed failed", "feed", f.Name, "err", fetchErr)
		}
		if err := c.Store.RecordFeedFetch(ctx, f.ID, fetchErr); err != nil {
			return total, err
		}
		total += n
	}
	purged, err := c.Store.PurgeCTIItems(ctx, time.Now().Add(-retention))
	if err != nil {
		return total, err
	}
	c.Log.Info("cti done", "new_items", total, "purged", purged)
	return total, nil
}

func (c *Collector) collect(ctx context.Context, f store.Feed) (int, error) {
	items, err := fetch(ctx, c.HTTP, f.URL, c.UserAgent)
	if err != nil {
		return 0, err
	}
	cutoff := time.Now().Add(-retention)
	n := 0
	for _, it := range items {
		if it.GUID == "" || it.Title == "" || it.Published.Before(cutoff) {
			continue
		}
		tags := classify(it, f)
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
	regs, err := st.Setting(ctx, settingRegulations)
	if err != nil {
		return store.CTIFilter{}, err
	}
	f := store.CTIFilter{Regulations: store.SplitList(regs)}
	f.AnyRegulation = len(f.Regulations) == 0
	return f, nil
}

// WatchedFilter returns the filter built from the watched countries and sectors.
func WatchedFilter(ctx context.Context, st *store.Store) (store.CTIFilter, error) {
	countries, err := st.Setting(ctx, SettingCountries)
	if err != nil {
		return store.CTIFilter{}, err
	}
	sectors, err := st.Setting(ctx, settingSectors)
	if err != nil {
		return store.CTIFilter{}, err
	}
	return store.CTIFilter{Countries: store.SplitList(countries), Sectors: store.SplitList(sectors)}, nil
}

// SaveWatched stores the watched countries, sectors and regulations, ignoring
// unknown values and duplicates: the stored filter is the default view of the
// news page (see choice.KnownOnly).
func SaveWatched(ctx context.Context, st *store.Store, countries, sectors, regulations []string) error {
	keep := func(opts []choice.Option, values []string) string {
		return strings.Join(choice.KnownOnly(opts, values), ",")
	}
	if err := st.SetSetting(ctx, SettingCountries, keep(Countries, countries)); err != nil {
		return err
	}
	if err := st.SetSetting(ctx, settingRegulations, keep(Regulations, regulations)); err != nil {
		return err
	}
	return st.SetSetting(ctx, settingSectors, keep(Sectors, sectors))
}
