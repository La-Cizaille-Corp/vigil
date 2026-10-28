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

// ListFeeds returns every feed.
func (s *Store) ListFeeds(ctx context.Context) ([]Feed, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, url, country, sectors, regulations, enabled, last_fetched, last_error
		FROM cti_feeds ORDER BY name COLLATE NOCASE`)
	if err != nil {
		return nil, fmt.Errorf("list feeds: %w", err)
	}
	defer rows.Close()
	var out []Feed
	for rows.Next() {
		var f Feed
		var fetched string
		if err := rows.Scan(&f.ID, &f.Name, &f.URL, &f.Country, &f.Sectors, &f.Regulations, &f.Enabled, &fetched, &f.LastError); err != nil {
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
		`INSERT INTO cti_feeds (name, url, country, sectors, regulations, enabled) VALUES (?, ?, ?, ?, ?, ?)`,
		f.Name, f.URL, f.Country, f.Sectors, f.Regulations, f.Enabled)
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
	created := false
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			INSERT INTO cti_items (feed_id, guid, title, link, summary, published, countries, sectors, regulations, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (feed_id, guid) DO NOTHING`,
			feedID, it.GUID, it.Title, it.Link, it.Summary, formatTime(it.Published),
			joinTags(it.Countries), joinTags(it.Sectors), joinTags(it.Regulations), now())
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return nil
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

// ExtractCVEs returns the distinct CVE identifiers cited in text (CVE-YYYY-N
// with 4 to 7 digits, any case), upper case, in order of appearance.
func ExtractCVEs(text string) []string {
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

func insertMentions(ctx context.Context, tx interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}, itemID int64, text string) error {
	for _, cve := range ExtractCVEs(text) {
		if _, err := tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO cti_mentions (item_id, cve) VALUES (?, ?)`, itemID, cve); err != nil {
			return err
		}
	}
	return nil
}

// backfillMentions indexes the CVE identifiers of news collected before
// migration 9.
func backfillMentions(ctx context.Context, conn *sql.Conn) error {
	rows, err := conn.QueryContext(ctx, `SELECT id, title || ' ' || summary FROM cti_items`)
	if err != nil {
		return err
	}
	texts := map[int64]string{}
	for rows.Next() {
		var id int64
		var text string
		if err := rows.Scan(&id, &text); err != nil {
			_ = rows.Close() // the scan error is the one to report
			return err
		}
		texts[id] = text
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for id, text := range texts {
		if err := insertMentions(ctx, conn, id, text); err != nil {
			return err
		}
	}
	return nil
}

// openCVEs selects the CVE identifiers (id or alias) of open findings.
const openCVEs = `
	SELECT v.id FROM findings f JOIN vulnerabilities v ON v.id = f.vuln_id
	WHERE f.status IN ` + openStatuses + ` AND v.id LIKE 'CVE-%'
	UNION
	SELECT j.value FROM findings f JOIN vulnerabilities v ON v.id = f.vuln_id, json_each(v.aliases) j
	WHERE f.status IN ` + openStatuses + ` AND j.value LIKE 'CVE-%'`

// MentionsOf returns the most recent news citing any of the identifiers.
func (s *Store) MentionsOf(ctx context.Context, ids []string, limit int) ([]CTIItem, error) {
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
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT i.id, fd.name, i.title, i.link, i.published
		FROM cti_mentions m JOIN cti_items i ON i.id = m.item_id JOIN cti_feeds fd ON fd.id = i.feed_id
		WHERE `+where[0]+`
		ORDER BY i.published DESC LIMIT ?`, args...)
	if err != nil {
		return nil, fmt.Errorf("mentions: %w", err)
	}
	defer rows.Close()
	var out []CTIItem
	for rows.Next() {
		var it CTIItem
		var published string
		if err := rows.Scan(&it.ID, &it.FeedName, &it.Title, &it.Link, &published); err != nil {
			return nil, err
		}
		it.Published = parseTime(published)
		out = append(out, it)
	}
	return out, rows.Err()
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
	anyTag("i.regulations", f.Regulations)
	if f.AnyRegulation {
		where = append(where, "i.regulations <> ''")
	}
	if !f.Since.IsZero() {
		where = append(where, "i.created_at >= ?")
		args = append(args, formatTime(f.Since))
	}
	if f.Concerning {
		where = append(where, "EXISTS (SELECT 1 FROM cti_mentions m WHERE m.item_id = i.id AND m.cve IN ("+openCVEs+"))")
	}
	q := `SELECT i.id, fd.name, i.guid, i.title, i.link, i.summary, i.published, i.countries, i.sectors, i.regulations,
		       COALESCE((SELECT group_concat(m.cve) FROM cti_mentions m WHERE m.item_id = i.id AND m.cve IN (` + openCVEs + `)), '')
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
		var published, countries, sectors, regulations, concerns string
		if err := rows.Scan(&it.ID, &it.FeedName, &it.GUID, &it.Title, &it.Link, &it.Summary,
			&published, &countries, &sectors, &regulations, &concerns); err != nil {
			return nil, err
		}
		if concerns != "" {
			it.Concerns = strings.Split(concerns, ",")
		}
		it.Published = parseTime(published)
		it.Countries, it.Sectors, it.Regulations = splitTags(countries), splitTags(sectors), splitTags(regulations)
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

// UpdateFeedTags replaces the tags a feed applies to its items.
func (s *Store) UpdateFeedTags(ctx context.Context, id int64, country, sectors, regulations string) error {
	return expectRow(s.db.ExecContext(ctx,
		`UPDATE cti_feeds SET country = ?, sectors = ?, regulations = ? WHERE id = ?`, country, sectors, regulations, id))
}

// FeedItems returns the items of a feed, with their tags.
func (s *Store) FeedItems(ctx context.Context, feedID int64) ([]CTIItem, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, title, summary FROM cti_items WHERE feed_id = ?`, feedID)
	if err != nil {
		return nil, fmt.Errorf("feed items: %w", err)
	}
	defer rows.Close()
	var out []CTIItem
	for rows.Next() {
		var it CTIItem
		if err := rows.Scan(&it.ID, &it.Title, &it.Summary); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// SetCTIItemTags replaces the tags of an item.
func (s *Store) SetCTIItemTags(ctx context.Context, id int64, countries, sectors, regulations []string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE cti_items SET countries = ?, sectors = ?, regulations = ? WHERE id = ?`,
		joinTags(countries), joinTags(sectors), joinTags(regulations), id)
	return err
}
