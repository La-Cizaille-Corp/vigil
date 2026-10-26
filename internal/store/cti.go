package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Feed is a CTI RSS/Atom source.
type Feed struct {
	ID          int64
	Name        string
	URL         string
	Country     string
	Sectors     string
	Enabled     bool
	LastFetched time.Time
	LastError   string
}

// CTIItem is one news item from a feed.
type CTIItem struct {
	ID        int64
	FeedName  string
	GUID      string
	Title     string
	Link      string
	Summary   string
	Published time.Time
	Countries []string
	Sectors   []string
}

// CTIFilter selects items. An empty list means "any".
type CTIFilter struct {
	Countries []string
	Sectors   []string
	Since     time.Time
	Limit     int
}

// ListFeeds returns every feed.
func (s *Store) ListFeeds(ctx context.Context) ([]Feed, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, url, country, sectors, enabled, last_fetched, last_error
		FROM cti_feeds ORDER BY name COLLATE NOCASE`)
	if err != nil {
		return nil, fmt.Errorf("list feeds: %w", err)
	}
	defer rows.Close()
	var out []Feed
	for rows.Next() {
		var f Feed
		var fetched string
		if err := rows.Scan(&f.ID, &f.Name, &f.URL, &f.Country, &f.Sectors, &f.Enabled, &fetched, &f.LastError); err != nil {
			return nil, err
		}
		f.LastFetched = parseTime(fetched)
		out = append(out, f)
	}
	return out, rows.Err()
}

// CreateFeed adds a feed.
func (s *Store) CreateFeed(ctx context.Context, f Feed) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO cti_feeds (name, url, country, sectors, enabled) VALUES (?, ?, ?, ?, ?)`,
		f.Name, f.URL, f.Country, f.Sectors, f.Enabled)
	if err != nil {
		return 0, fmt.Errorf("create feed: %w", err)
	}
	return res.LastInsertId()
}

// SetFeedEnabled turns a feed on or off.
func (s *Store) SetFeedEnabled(ctx context.Context, id int64, enabled bool) error {
	return expectRow(s.db.ExecContext(ctx, `UPDATE cti_feeds SET enabled = ? WHERE id = ?`, enabled, id))
}

// DeleteFeed removes a feed and its items.
func (s *Store) DeleteFeed(ctx context.Context, id int64) error {
	return expectRow(s.db.ExecContext(ctx, `DELETE FROM cti_feeds WHERE id = ?`, id))
}

// RecordFeedFetch stores the outcome of a fetch.
func (s *Store) RecordFeedFetch(ctx context.Context, id int64, fetchErr error) error {
	msg := ""
	if fetchErr != nil {
		msg = truncateString(fetchErr.Error(), 300)
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE cti_feeds SET last_fetched = ?, last_error = ? WHERE id = ?`, now(), msg, id)
	return err
}

// InsertCTIItem stores an item unless the feed already has it; it reports
// whether the item is new.
func (s *Store) InsertCTIItem(ctx context.Context, feedID int64, it CTIItem) (bool, error) {
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO cti_items (feed_id, guid, title, link, summary, published, countries, sectors, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (feed_id, guid) DO NOTHING`,
		feedID, it.GUID, it.Title, it.Link, it.Summary, formatTime(it.Published),
		joinTags(it.Countries), joinTags(it.Sectors), now())
	if err != nil {
		return false, fmt.Errorf("insert cti item: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ListCTIItems returns items matching f, most recent first.
func (s *Store) ListCTIItems(ctx context.Context, f CTIFilter) ([]CTIItem, error) {
	var where []string
	var args []any
	// Tags are stored as ",FR,US," so that LIKE '%,FR,%' matches exactly one tag.
	anyTag := func(column string, values []string) {
		if len(values) == 0 {
			return
		}
		var ors []string
		for _, v := range values {
			ors = append(ors, column+" LIKE ?")
			args = append(args, "%,"+v+",%")
		}
		where = append(where, "("+strings.Join(ors, " OR ")+")")
	}
	anyTag("i.countries", f.Countries)
	anyTag("i.sectors", f.Sectors)
	if !f.Since.IsZero() {
		where = append(where, "i.created_at >= ?")
		args = append(args, formatTime(f.Since))
	}
	q := `SELECT i.id, fd.name, i.guid, i.title, i.link, i.summary, i.published, i.countries, i.sectors
		FROM cti_items i JOIN cti_feeds fd ON fd.id = i.feed_id`
	if len(where) > 0 {
		// #nosec G202 -- only fixed column expressions are joined; values are parameters.
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY i.published DESC, i.id DESC LIMIT ?"
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list cti items: %w", err)
	}
	defer rows.Close()
	var out []CTIItem
	for rows.Next() {
		var it CTIItem
		var published, countries, sectors string
		if err := rows.Scan(&it.ID, &it.FeedName, &it.GUID, &it.Title, &it.Link, &it.Summary,
			&published, &countries, &sectors); err != nil {
			return nil, err
		}
		it.Published = parseTime(published)
		it.Countries, it.Sectors = splitTags(countries), splitTags(sectors)
		out = append(out, it)
	}
	return out, rows.Err()
}

// PurgeCTIItems deletes items older than before, to keep the database small.
func (s *Store) PurgeCTIItems(ctx context.Context, before time.Time) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM cti_items WHERE published < ?`, formatTime(before))
	return err
}

// Setting returns a setting value, or "" when unset.
func (s *Store) Setting(ctx context.Context, key string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

// SetSetting stores a setting value.
func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO settings (key, value) VALUES (?, ?)
		ON CONFLICT (key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

func joinTags(tags []string) string {
	if len(tags) == 0 {
		return ""
	}
	return "," + strings.Join(tags, ",") + ","
}

func splitTags(s string) []string {
	var out []string
	for _, t := range strings.Split(s, ",") {
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

func expectRow(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func truncateString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
