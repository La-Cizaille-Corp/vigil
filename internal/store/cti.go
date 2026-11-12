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
	Regulations string // comma-separated, applied to every item
	Enabled     bool
	LastFetched time.Time
	LastError   string
}

// CTIItem is one news item from a feed.
type CTIItem struct {
	ID          int64
	FeedName    string
	GUID        string
	Title       string
	Link        string
	Summary     string
	Published   time.Time
	Countries   []string
	Sectors     []string
	Regulations []string
	Concerns    []string // cited CVE identifiers that affect the inventory (open findings)
}

// CTIFilter selects items. An empty list means "any".
type CTIFilter struct {
	Countries     []string
	Sectors       []string
	Regulations   []string
	AnyRegulation bool // only items tagged with at least one regulation
	Concerning    bool // only items citing a vulnerability of an open finding
	Since         time.Time
	Limit         int
}

// selectFeed reads the columns of a Feed (see scanFeed).
const selectFeed = `SELECT id, name, url, country, sectors, regulations, enabled, last_fetched, last_error FROM cti_feeds `

// scanFeed reads a row of selectFeed; no row is ErrNotFound.
func scanFeed(row scanner) (Feed, error) {
	var f Feed
	var fetched string
	err := row.Scan(&f.ID, &f.Name, &f.URL, &f.Country, &f.Sectors, &f.Regulations, &f.Enabled, &fetched, &f.LastError)
	if errors.Is(err, sql.ErrNoRows) {
		return f, ErrNotFound
	}
	f.LastFetched = parseTime(fetched)
	return f, err
}

// ListFeeds returns every feed.
func (s *Store) ListFeeds(ctx context.Context) ([]Feed, error) {
	return collect(ctx, s.q(ctx), "list feeds", scanFeed, selectFeed+`ORDER BY name COLLATE NOCASE`)
}

// Feed returns one feed, ErrNotFound if none has this id.
func (s *Store) Feed(ctx context.Context, id int64) (Feed, error) {
	f, err := scanFeed(s.q(ctx).QueryRowContext(ctx, selectFeed+`WHERE id = ?`, id))
	if err != nil {
		return f, fmt.Errorf("feed %d: %w", id, err)
	}
	return f, nil
}

// CreateFeed adds a feed; ErrExists when another feed has the same URL.
func (s *Store) CreateFeed(ctx context.Context, f Feed) (int64, error) {
	res, err := s.q(ctx).ExecContext(ctx,
		`INSERT INTO cti_feeds (name, url, country, sectors, regulations, enabled) VALUES (?, ?, ?, ?, ?, ?)`,
		f.Name, f.URL, f.Country, f.Sectors, f.Regulations, f.Enabled)
	if err != nil {
		return 0, fmt.Errorf("create feed: %w", mapUnique(err))
	}
	id, err := res.LastInsertId()
	return id, wrap("create feed", err)
}

// SetFeedEnabled turns a feed on or off.
func (s *Store) SetFeedEnabled(ctx context.Context, id int64, enabled bool) error {
	return wrap("set feed enabled", expectRow(s.q(ctx).ExecContext(ctx, `UPDATE cti_feeds SET enabled = ? WHERE id = ?`, enabled, id)))
}

// DeleteFeed removes a feed and its items.
func (s *Store) DeleteFeed(ctx context.Context, id int64) error {
	return wrap("delete feed", expectRow(s.q(ctx).ExecContext(ctx, `DELETE FROM cti_feeds WHERE id = ?`, id)))
}

// RecordFeedFetch stores the outcome of a fetch.
func (s *Store) RecordFeedFetch(ctx context.Context, id int64, fetchErr error) error {
	_, err := s.q(ctx).ExecContext(ctx,
		`UPDATE cti_feeds SET last_fetched = ?, last_error = ? WHERE id = ?`, now(), errText(fetchErr), id)
	return wrap("record feed fetch", err)
}

// InsertCTIItem stores an item unless the feed already has it, or another feed
// has the same article; it reports whether the item is new.
func (s *Store) InsertCTIItem(ctx context.Context, feedID int64, it CTIItem) (bool, error) {
	created := false
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			INSERT INTO cti_items (feed_id, guid, title, link, summary, published, countries, sectors, regulations, created_at)
			SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
			WHERE ? = '' OR NOT EXISTS (SELECT 1 FROM cti_items WHERE link = ?)
			ON CONFLICT (feed_id, guid) DO NOTHING`,
			feedID, it.GUID, it.Title, it.Link, it.Summary, formatTime(it.Published),
			joinTags(it.Countries), joinTags(it.Sectors), joinTags(it.Regulations), now(), it.Link, it.Link)
		if err := expectRow(res, err); errors.Is(err, ErrNotFound) {
			return nil // already known
		} else if err != nil {
			return err
		}
		created = true
		id, err := res.LastInsertId()
		if err != nil {
			return err
		}
		return insertMentions(ctx, tx, id, it.Title+" "+it.Summary)
	})
	if err != nil {
		return false, fmt.Errorf("insert cti item: %w", err)
	}
	return created, nil
}

// maxMentions bounds the identifiers kept per item (bulletins list dozens).
const maxMentions = 100

// extractCVEs returns the distinct CVE identifiers cited in text (CVE-YYYY-N
// with 4 to 7 digits, any case), upper case, in order of appearance.
func extractCVEs(text string) []string {
	var out []string
	seen := map[string]bool{}
	upper := strings.ToUpper(text)
	for i := 0; len(out) < maxMentions; {
		j := strings.Index(upper[i:], "CVE-")
		if j < 0 {
			break
		}
		start := i + j
		i = start + 4
		if start > 0 && isWordByte(upper[start-1]) {
			continue
		}
		year := digits(upper[i:])
		if year != 4 || i+year >= len(upper) || upper[i+year] != '-' {
			continue
		}
		seq := digits(upper[i+year+1:])
		end := i + year + 1 + seq
		if seq < 4 || seq > 7 || (end < len(upper) && isWordByte(upper[end])) {
			continue
		}
		if id := upper[start:end]; !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
		i = end
	}
	return out
}

// digits counts the ASCII digits at the start of s.
func digits(s string) int {
	n := 0
	for n < len(s) && s[n] >= '0' && s[n] <= '9' {
		n++
	}
	return n
}

func isWordByte(b byte) bool {
	return b == '_' || (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

func insertMentions(ctx context.Context, q querier, itemID int64, text string) error {
	for _, cve := range extractCVEs(text) {
		if _, err := q.ExecContext(ctx,
			`INSERT OR IGNORE INTO cti_mentions (item_id, cve) VALUES (?, ?)`, itemID, cve); err != nil {
			return err
		}
	}
	return nil
}

// backfillMentions indexes the CVE identifiers of news collected before
// migration 9.
func backfillMentions(ctx context.Context, conn *sql.Conn) error {
	items, err := collect(ctx, conn, "backfill mentions", func(row scanner) (CTIItem, error) {
		var it CTIItem
		err := row.Scan(&it.ID, &it.Summary)
		return it, err
	}, `SELECT id, title || ' ' || summary FROM cti_items`)
	if err != nil {
		return err
	}
	for _, it := range items {
		if err := insertMentions(ctx, conn, it.ID, it.Summary); err != nil {
			return fmt.Errorf("backfill mentions: %w", err)
		}
	}
	return nil
}

// ListMentions returns the most recent news citing any of the identifiers.
func (s *Store) ListMentions(ctx context.Context, ids []string, limit int) ([]CTIItem, error) {
	var cves []string
	for _, id := range ids {
		if strings.HasPrefix(strings.ToUpper(id), "CVE-") {
			cves = append(cves, strings.ToUpper(id))
		}
	}
	if len(cves) == 0 {
		return nil, nil
	}
	where, args := inClause(nil, nil, "m.cve", cves)
	args = append(args, limit)
	// #nosec G202 -- where[0] is "m.cve IN (?, ...)": the values are parameters.
	return collect(ctx, s.q(ctx), "mentions", func(row scanner) (CTIItem, error) {
		var it CTIItem
		var published string
		err := row.Scan(&it.ID, &it.FeedName, &it.Title, &it.Link, &published)
		it.Published = parseTime(published)
		return it, err
	}, `
		SELECT DISTINCT i.id, fd.name, i.title, i.link, i.published
		FROM cti_mentions m JOIN cti_items i ON i.id = m.item_id JOIN cti_feeds fd ON fd.id = i.feed_id
		WHERE `+where[0]+`
		ORDER BY i.published DESC LIMIT ?`, args...)
}

// MaxCTIItems is the most items a list of the watch reads, the most recent
// ones; without a Limit, it reads defaultCTIItems.
const (
	MaxCTIItems     = 500
	defaultCTIItems = 200
)

// ListCTIItems returns items matching f, most recent first. News are the same
// for everyone; whether one concerns the inventory depends on the scope.
func (s *Store) ListCTIItems(ctx context.Context, sc Scope, f CTIFilter) ([]CTIItem, error) {
	with, where, args := ctiQuery(sc, f)
	// #nosec G202 -- with and where are fixed expressions (ctiQuery); the values are parameters.
	q := with + `SELECT i.id, fd.name, i.guid, i.title, i.link, i.summary, i.published, i.countries, i.sectors, i.regulations,
		       COALESCE((SELECT group_concat(m.cve) FROM cti_mentions m WHERE m.item_id = i.id AND m.cve IN (SELECT cve FROM open_cves)), '')
		FROM cti_items i JOIN cti_feeds fd ON fd.id = i.feed_id` + where + " ORDER BY i.published DESC, i.id DESC LIMIT ?"
	limit := f.Limit
	if limit <= 0 || limit > MaxCTIItems {
		limit = defaultCTIItems
	}
	return collect(ctx, s.q(ctx), "list cti items", scanCTIItem, q, append(args, limit)...)
}

// CountCTIItems returns how many items match f, Limit aside: the count of a
// view of the watch, however many of them it lists.
func (s *Store) CountCTIItems(ctx context.Context, sc Scope, f CTIFilter) (int, error) {
	with, where, args := ctiQuery(sc, f)
	var n int
	// #nosec G202 -- with and where are fixed expressions (ctiQuery); the values are parameters.
	err := s.q(ctx).QueryRowContext(ctx, with+`SELECT COUNT(*) FROM cti_items i JOIN cti_feeds fd ON fd.id = i.feed_id`+where, args...).Scan(&n)
	return n, wrap("count cti items", err)
}

// ctiQuery is what selects the items matching f: the WITH clause of the open
// CVEs of the scope, the WHERE clause ("" for none) and their arguments, in
// that order. ListCTIItems and CountCTIItems read the same items by it.
func ctiQuery(sc Scope, f CTIFilter) (with, where string, args []any) {
	var conds []string
	with, args = openCVEs(sc) // first in the query, so are its arguments
	anyTag := func(column string, values []string) {
		if len(values) == 0 {
			return
		}
		var ors []string
		for _, v := range values {
			cond, arg := hasTag(column, v)
			ors = append(ors, cond)
			args = append(args, arg)
		}
		conds = append(conds, "("+strings.Join(ors, " OR ")+")")
	}
	anyTag("i.countries", f.Countries)
	anyTag("i.sectors", f.Sectors)
	anyTag("i.regulations", f.Regulations)
	if f.AnyRegulation {
		conds = append(conds, "i.regulations <> ''")
	}
	if !f.Since.IsZero() {
		conds = append(conds, "i.created_at >= ?")
		args = append(args, formatTime(f.Since))
	}
	if f.Concerning {
		conds = append(conds, "EXISTS (SELECT 1 FROM cti_mentions m WHERE m.item_id = i.id AND m.cve IN (SELECT cve FROM open_cves))")
	}
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ")
	}
	return with, where, args
}

// scanCTIItem reads a row of ListCTIItems.
func scanCTIItem(row scanner) (CTIItem, error) {
	var it CTIItem
	var published, countries, sectors, regulations, concerns string
	if err := row.Scan(&it.ID, &it.FeedName, &it.GUID, &it.Title, &it.Link, &it.Summary,
		&published, &countries, &sectors, &regulations, &concerns); err != nil {
		return it, err
	}
	if concerns != "" {
		it.Concerns = strings.Split(concerns, ",")
	}
	it.Published = parseTime(published)
	it.Countries, it.Sectors, it.Regulations = SplitList(countries), SplitList(sectors), SplitList(regulations)
	return it, nil
}

// PurgeCTIItems deletes items older than before, to keep the database small;
// it returns how many were deleted.
func (s *Store) PurgeCTIItems(ctx context.Context, before time.Time) (int, error) {
	n, err := purge(ctx, s.q(ctx), `DELETE FROM cti_items WHERE published < ?`, before)
	return n, wrap("purge cti items", err)
}

// UpdateFeedTags replaces the tags a feed applies to its items.
func (s *Store) UpdateFeedTags(ctx context.Context, id int64, country, sectors, regulations string) error {
	return wrap("update feed tags", expectRow(s.q(ctx).ExecContext(ctx,
		`UPDATE cti_feeds SET country = ?, sectors = ?, regulations = ? WHERE id = ?`, country, sectors, regulations, id)))
}

// ListFeedItems returns the items of a feed with what tagging reads: their title
// and summary.
func (s *Store) ListFeedItems(ctx context.Context, feedID int64) ([]CTIItem, error) {
	return collect(ctx, s.q(ctx), "feed items", func(row scanner) (CTIItem, error) {
		var it CTIItem
		err := row.Scan(&it.ID, &it.Title, &it.Summary)
		return it, err
	}, `SELECT id, title, summary FROM cti_items WHERE feed_id = ?`, feedID)
}

// SetCTIItemTags replaces the tags of an item.
func (s *Store) SetCTIItemTags(ctx context.Context, id int64, countries, sectors, regulations []string) error {
	_, err := s.q(ctx).ExecContext(ctx, `UPDATE cti_items SET countries = ?, sectors = ?, regulations = ? WHERE id = ?`,
		joinTags(countries), joinTags(sectors), joinTags(regulations), id)
	return wrap("set cti item tags", err)
}
