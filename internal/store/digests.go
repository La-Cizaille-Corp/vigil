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
	return res.LastInsertId()
}

// Digest returns one digest.
func (s *Store) Digest(ctx context.Context, id int64) (Digest, error) {
	var d Digest
	var since, created string
	err := s.db.QueryRowContext(ctx,
		`SELECT id, since, created_at, markdown, html FROM digests WHERE id = ?`, id).
		Scan(&d.ID, &since, &created, &d.Markdown, &d.HTML)
	if errors.Is(err, sql.ErrNoRows) {
		return d, ErrNotFound
	}
	d.Since, d.CreatedAt = parseTime(since), parseTime(created)
	return d, err
}

// ListDigests returns digests without their content, most recent first.
func (s *Store) ListDigests(ctx context.Context) ([]Digest, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, since, created_at FROM digests ORDER BY id DESC`)
	if err != nil {
		return nil, fmt.Errorf("list digests: %w", err)
	}
	defer rows.Close()
	var out []Digest
	for rows.Next() {
		var d Digest
		var since, created string
		if err := rows.Scan(&d.ID, &since, &created); err != nil {
			return nil, err
		}
		d.Since, d.CreatedAt = parseTime(since), parseTime(created)
		out = append(out, d)
	}
	return out, rows.Err()
}

// LastDigestTime returns when the latest digest was produced, or zero.
func (s *Store) LastDigestTime(ctx context.Context) (time.Time, error) {
	var created sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT MAX(created_at) FROM digests`).Scan(&created)
	if err != nil || !created.Valid {
		return time.Time{}, err
	}
	return parseTime(created.String), nil
}
