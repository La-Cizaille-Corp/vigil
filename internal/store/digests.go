package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Digest is a generated summary report, of the whole inventory or of a group.
type Digest struct {
	ID        int64
	Since     time.Time
	CreatedAt time.Time
	Markdown  string
	HTML      string
	Group     int64  // the group it covers, 0 for the whole inventory (A68)
	GroupName string // read with it, "" for the whole inventory
}

// CreateDigest stores a digest and returns its id.
func (s *Store) CreateDigest(ctx context.Context, d Digest) (int64, error) {
	res, err := s.q(ctx).ExecContext(ctx,
		`INSERT INTO digests (since, created_at, markdown, html, group_id) VALUES (?, ?, ?, ?, ?)`,
		formatTime(d.Since), formatTime(d.CreatedAt), d.Markdown, d.HTML, nullID(d.Group))
	if err != nil {
		return 0, fmt.Errorf("create digest: %w", err)
	}
	id, err := res.LastInsertId()
	return id, wrap("create digest", err)
}

// digestFrom reads the digests with the name of their group.
const digestFrom = ` FROM digests d LEFT JOIN asset_groups g ON g.id = d.group_id `

// Digest returns one digest of the scope: ErrNotFound outside of it.
func (s *Store) Digest(ctx context.Context, sc Scope, id int64) (Digest, error) {
	var d Digest
	var since, created string
	cond, args := sc.groupCond("d.group_id")
	// #nosec G202 -- cond is a fixed expression of Scope.groupCond; the values are parameters.
	err := s.q(ctx).QueryRowContext(ctx,
		`SELECT d.id, d.since, d.created_at, d.markdown, d.html, COALESCE(d.group_id, 0), COALESCE(g.name, '')`+digestFrom+
			`WHERE d.id = ? AND `+cond, append([]any{id}, args...)...).
		Scan(&d.ID, &since, &created, &d.Markdown, &d.HTML, &d.Group, &d.GroupName)
	if errors.Is(err, sql.ErrNoRows) {
		return d, ErrNotFound
	}
	d.Since, d.CreatedAt = parseTime(since), parseTime(created)
	return d, wrap("digest", err)
}

// ListDigests returns the digests of the scope without their content, most
// recent first.
func (s *Store) ListDigests(ctx context.Context, sc Scope) ([]Digest, error) {
	cond, args := sc.groupCond("d.group_id")
	// #nosec G202 -- cond is a fixed expression of Scope.groupCond; the values are parameters.
	return collect(ctx, s.q(ctx), "list digests", func(row scanner) (Digest, error) {
		var d Digest
		var since, created string
		err := row.Scan(&d.ID, &since, &created, &d.Group, &d.GroupName)
		d.Since, d.CreatedAt = parseTime(since), parseTime(created)
		return d, err
	}, `SELECT d.id, d.since, d.created_at, COALESCE(d.group_id, 0), COALESCE(g.name, '')`+digestFrom+
		`WHERE `+cond+` ORDER BY d.id DESC`, args...)
}

// LastDigestTime returns when the latest digest of a group (0: of the whole
// inventory) was produced, or zero: each one covers the period since its
// own previous one.
func (s *Store) LastDigestTime(ctx context.Context, group int64) (time.Time, error) {
	var created sql.NullString
	err := s.q(ctx).QueryRowContext(ctx, `SELECT MAX(created_at) FROM digests WHERE COALESCE(group_id, 0) = ?`, group).Scan(&created)
	if err != nil || !created.Valid {
		return time.Time{}, wrap("last digest time", err)
	}
	return parseTime(created.String), nil
}
