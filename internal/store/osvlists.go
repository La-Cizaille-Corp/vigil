package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// OSVList is what the synchronisation keeps of the advisories OSV reports for
// a query read in full (A90): Advisories is written and read by it alone.
type OSVList struct {
	Query      string    // the query, as the synchronisation writes it
	ReadAt     time.Time // the last full read
	Advisories string
}

// OSVList returns the list kept for a query, or ErrNotFound.
func (s *Store) OSVList(ctx context.Context, query string) (OSVList, error) {
	l := OSVList{Query: query}
	var readAt string
	err := s.q(ctx).QueryRowContext(ctx, `SELECT read_at, advisories FROM osv_lists WHERE query = ?`, query).
		Scan(&readAt, &l.Advisories)
	if errors.Is(err, sql.ErrNoRows) {
		return l, ErrNotFound
	}
	l.ReadAt = parseTime(readAt)
	return l, wrap("osv list", err)
}

// SaveOSVList keeps the list of a query, in place of the one before.
func (s *Store) SaveOSVList(ctx context.Context, l OSVList) error {
	_, err := s.q(ctx).ExecContext(ctx, `
		INSERT INTO osv_lists (query, read_at, advisories) VALUES (?, ?, ?)
		ON CONFLICT (query) DO UPDATE SET read_at = excluded.read_at, advisories = excluded.advisories`,
		l.Query, formatTime(l.ReadAt), l.Advisories)
	return wrap("save osv list", err)
}

// PurgeOSVLists drops the lists read in full before a time, and returns how
// many went: those of a version no longer asked, and those due a full read.
func (s *Store) PurgeOSVLists(ctx context.Context, before time.Time) (int, error) {
	n, err := purge(ctx, s.q(ctx), `DELETE FROM osv_lists WHERE read_at < ?`, before)
	return n, wrap("purge osv lists", err)
}
