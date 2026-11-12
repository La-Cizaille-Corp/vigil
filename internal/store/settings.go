package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// Setting returns a setting value, or "" when unset.
func (s *Store) Setting(ctx context.Context, key string) (string, error) {
	var v string
	err := s.q(ctx).QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, wrap("setting "+key, err)
}

// SetSetting stores a setting value.
func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.q(ctx).ExecContext(ctx, `
		INSERT INTO settings (key, value) VALUES (?, ?)
		ON CONFLICT (key) DO UPDATE SET value = excluded.value`, key, value)
	return wrap("set setting "+key, err)
}

// TOTP policies: who must use a second factor.
const (
	TOTPOptional = ""
	TOTPAdmins   = "admin"
	TOTPEveryone = "all"
)

const totpPolicyKey = "totp_required"

// TOTPPolicy returns who must use a second factor.
func (s *Store) TOTPPolicy(ctx context.Context) (string, error) {
	return s.Setting(ctx, totpPolicyKey)
}

// SetTOTPPolicy sets who must use a second factor.
func (s *Store) SetTOTPPolicy(ctx context.Context, policy string) error {
	switch policy {
	case TOTPOptional, TOTPAdmins, TOTPEveryone:
		return s.SetSetting(ctx, totpPolicyKey, policy)
	}
	return fmt.Errorf("unknown second factor policy %q", policy)
}
