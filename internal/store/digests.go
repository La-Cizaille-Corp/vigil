package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Digest is a generated summary report.
type Digest struct {
	ID        int64
	Since     time.Time
	CreatedAt time.Time
	Markdown  string
	HTML      string
}

// CreateDigest stores a digest and returns its id.
func (s *Store) CreateDigest(ctx context.Context, d Digest) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO digests (since, created_at, markdown, html) VALUES (?, ?, ?, ?)`,
		formatTime(d.Since), formatTime(d.CreatedAt), d.Markdown, d.HTML)
	if err != nil {
		return 0, fmt.Errorf("create digest: %w", err)
	}
	id, err := res.LastInsertId()
	return id, wrap("create digest", err)
}

// Digest returns one digest of the scope: ErrNotFound outside of it.
func (s *Store) Digest(ctx context.Context, sc Scope, id int64) (Digest, error) {
	var d Digest
	var since, created string
	err := s.db.QueryRowContext(ctx,
		`SELECT id, since, created_at, markdown, html FROM digests WHERE id = ? AND `+sc.digestCond(), id).
		Scan(&d.ID, &since, &created, &d.Markdown, &d.HTML)
	if errors.Is(err, sql.ErrNoRows) {
		return d, ErrNotFound
	}
	d.Since, d.CreatedAt = parseTime(since), parseTime(created)
	return d, wrap("digest", err)
}

// ListDigests returns the digests of the scope without their content, most
// recent first.
func (s *Store) ListDigests(ctx context.Context, sc Scope) ([]Digest, error) {
	// #nosec G202 -- digestCond is a fixed expression.
	return collect(ctx, s.db, "list digests", func(row scanner) (Digest, error) {
		var d Digest
		var since, created string
		err := row.Scan(&d.ID, &since, &created)
		d.Since, d.CreatedAt = parseTime(since), parseTime(created)
		return d, err
	}, `SELECT id, since, created_at FROM digests WHERE `+sc.digestCond()+` ORDER BY id DESC`)
}

// LastDigestTime returns when the latest digest was produced, or zero.
func (s *Store) LastDigestTime(ctx context.Context) (time.Time, error) {
	var created sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT MAX(created_at) FROM digests`).Scan(&created)
	if err != nil || !created.Valid {
		return time.Time{}, wrap("last digest time", err)
	}
	return parseTime(created.String), nil
}
