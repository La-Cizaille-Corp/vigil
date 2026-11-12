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
	CreatedBy  string // name of the account that created it, "" if unknown (listed only)
	Suspended  bool   // that account is disabled: the token is refused (listed only)
	CreatedAt  time.Time
	LastUsedAt time.Time
}

// ListAPITokens returns every token (without secrets).
func (s *Store) ListAPITokens(ctx context.Context) ([]APIToken, error) {
	return collect(ctx, s.q(ctx), "list api tokens", func(row scanner) (APIToken, error) {
		var t APIToken
		var created, used string
		err := row.Scan(&t.ID, &t.Name, &t.Project, &t.CreatedBy, &t.Suspended, &created, &used)
		t.CreatedAt, t.LastUsedAt = parseTime(created), parseTime(used)
		return t, err
	}, `
		SELECT t.id, t.name, t.project, COALESCE(u.username, ''), COALESCE(u.disabled_at, '') <> '',
			t.created_at, t.last_used_at
		FROM api_tokens t LEFT JOIN users u ON u.id = t.created_by ORDER BY t.project, t.name`)
}

// CreateAPIToken stores a token by the hash of its secret.
func (s *Store) CreateAPIToken(ctx context.Context, t APIToken, tokenHash string, createdBy int64) (int64, error) {
	res, err := s.q(ctx).ExecContext(ctx,
		`INSERT INTO api_tokens (name, project, token_hash, created_by, created_at) VALUES (?, ?, ?, ?, ?)`,
		t.Name, t.Project, tokenHash, nullID(createdBy), now())
	if err != nil {
		return 0, fmt.Errorf("create api token: %w", err)
	}
	id, err := res.LastInsertId()
	return id, wrap("create api token", err)
}

// APITokenByHash finds a token and records its use. SECURITY: a token is
// refused (ErrNotFound) while the account that created it is disabled, as
// that account's sessions are, and works again once it is enabled. A token
// whose creator is unknown keeps working.
func (s *Store) APITokenByHash(ctx context.Context, tokenHash string) (APIToken, error) {
	var t APIToken
	var created string
	err := s.q(ctx).QueryRowContext(ctx, `
		SELECT t.id, t.name, t.project, t.created_at
		FROM api_tokens t LEFT JOIN users u ON u.id = t.created_by
		WHERE t.token_hash = ? AND COALESCE(u.disabled_at, '') = ''`, tokenHash).
		Scan(&t.ID, &t.Name, &t.Project, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return t, ErrNotFound
	}
	if err != nil {
		return t, fmt.Errorf("api token: %w", err)
	}
	t.CreatedAt = parseTime(created)
	if _, err := s.q(ctx).ExecContext(ctx, `UPDATE api_tokens SET last_used_at = ? WHERE id = ?`, now(), t.ID); err != nil {
		return t, fmt.Errorf("touch api token: %w", err)
	}
	return t, nil
}

// DeleteAPIToken revokes a token.
func (s *Store) DeleteAPIToken(ctx context.Context, id int64) error {
	return wrap("delete api token", expectRow(s.q(ctx).ExecContext(ctx, `DELETE FROM api_tokens WHERE id = ?`, id)))
}
