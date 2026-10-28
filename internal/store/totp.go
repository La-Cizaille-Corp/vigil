package store

import (
	"context"
	"fmt"
)

// UserTOTP returns the active and pending TOTP secrets of a user and the last
// accepted time step.
func (s *Store) UserTOTP(ctx context.Context, userID int64) (secret, pending string, lastStep int64, err error) {
	err = s.db.QueryRowContext(ctx,
		`SELECT totp_secret, totp_pending, totp_last_step FROM users WHERE id = ?`, userID).
		Scan(&secret, &pending, &lastStep)
	if err != nil {
		err = fmt.Errorf("user totp: %w", err)
	}
	return
}

// SetTOTPPending stores a secret awaiting confirmation by a first valid code.
func (s *Store) SetTOTPPending(ctx context.Context, userID int64, secret string) error {
	return expectRow(s.db.ExecContext(ctx, `UPDATE users SET totp_pending = ? WHERE id = ?`, secret, userID))
}

// EnableTOTP activates the pending secret.
func (s *Store) EnableTOTP(ctx context.Context, userID, step int64) error {
	return expectRow(s.db.ExecContext(ctx, `
		UPDATE users SET totp_secret = totp_pending, totp_pending = '', totp_last_step = ?
		WHERE id = ? AND totp_pending <> ''`, step, userID))
}

// DisableTOTP removes the second factor of a user.
func (s *Store) DisableTOTP(ctx context.Context, userID int64) error {
	return expectRow(s.db.ExecContext(ctx,
		`UPDATE users SET totp_secret = '', totp_pending = '', totp_last_step = 0 WHERE id = ?`, userID))
}

// DisableTOTPByName is the CLI recovery path for a lost authenticator; it
// also ends the user's sessions.
func (s *Store) DisableTOTPByName(ctx context.Context, username string) error {
	a, err := s.AccountByName(ctx, username)
	if err != nil {
		return err
	}
	return s.ResetTOTP(ctx, a.ID)
}

// UseTOTPStep consumes a time step; it reports false when that step (or a
// later one) was already used, so a code cannot be replayed, even concurrently.
func (s *Store) UseTOTPStep(ctx context.Context, userID, step int64) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE users SET totp_last_step = ? WHERE id = ? AND totp_last_step < ?`, step, userID, step)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}
