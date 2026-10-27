package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// APIToken authorizes SBOM uploads for a single project.
type APIToken struct {
	ID         int64
	Name       string
	Project    string
	CreatedAt  time.Time
	LastUsedAt time.Time
}

// ListAPITokens returns every token (without secrets).
func (s *Store) ListAPITokens(ctx context.Context) ([]APIToken, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, project, created_at, last_used_at FROM api_tokens ORDER BY project, name`)
	if err != nil {
		return nil, fmt.Errorf("list api tokens: %w", err)
	}
	defer rows.Close()
	var out []APIToken
	for rows.Next() {
		var t APIToken
		var created, used string
		if err := rows.Scan(&t.ID, &t.Name, &t.Project, &created, &used); err != nil {
			return nil, err
		}
		t.CreatedAt, t.LastUsedAt = parseTime(created), parseTime(used)
		out = append(out, t)
	}
	return out, rows.Err()
}

// CreateAPIToken stores a token by the hash of its secret.
func (s *Store) CreateAPIToken(ctx context.Context, t APIToken, tokenHash string, createdBy int64) (int64, error) {
	var uid any
	if createdBy != 0 {
		uid = createdBy
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO api_tokens (name, project, token_hash, created_by, created_at) VALUES (?, ?, ?, ?, ?)`,
		t.Name, t.Project, tokenHash, uid, now())
	if err != nil {
		return 0, fmt.Errorf("create api token: %w", err)
	}
	return res.LastInsertId()
}

// APITokenByHash finds a token and records its use.
func (s *Store) APITokenByHash(ctx context.Context, tokenHash string) (APIToken, error) {
	var t APIToken
	var created string
	err := s.db.QueryRowContext(ctx,
		`SELECT id, name, project, created_at FROM api_tokens WHERE token_hash = ?`, tokenHash).
		Scan(&t.ID, &t.Name, &t.Project, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return t, ErrNotFound
	}
	if err != nil {
		return t, fmt.Errorf("api token: %w", err)
	}
	t.CreatedAt = parseTime(created)
	if _, err := s.db.ExecContext(ctx, `UPDATE api_tokens SET last_used_at = ? WHERE id = ?`, now(), t.ID); err != nil {
		return t, fmt.Errorf("touch api token: %w", err)
	}
	return t, nil
}

// DeleteAPIToken revokes a token.
func (s *Store) DeleteAPIToken(ctx context.Context, id int64) error {
	return expectRow(s.db.ExecContext(ctx, `DELETE FROM api_tokens WHERE id = ?`, id))
}
