package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Account is a user as listed for administration.
type Account struct {
	ID        int64
	Username  string
	Role      string
	TOTP      bool // second factor enabled
	Disabled  bool
	CreatedAt time.Time
}

// ErrLastAdmin is returned when a change would leave no active administrator.
var ErrLastAdmin = errors.New("last active administrator")

// otherAdmin is true when an active administrator other than the updated
// row exists; it is evaluated inside the UPDATE, so two concurrent changes
// cannot both remove the last one.
const otherAdmin = `EXISTS (SELECT 1 FROM users o WHERE o.role = 'admin' AND o.disabled_at = '' AND o.id <> users.id)`

// ListAccounts returns every user, active ones first, by name.
func (s *Store) ListAccounts(ctx context.Context) ([]Account, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, username, role, totp_secret <> '', disabled_at <> '', created_at
		FROM users ORDER BY disabled_at <> '', username COLLATE NOCASE`)
	if err != nil {
		return nil, fmt.Errorf("list accounts: %w", err)
	}
	defer rows.Close()
	var out []Account
	for rows.Next() {
		var a Account
		var created string
		if err := rows.Scan(&a.ID, &a.Username, &a.Role, &a.TOTP, &a.Disabled, &created); err != nil {
			return nil, err
		}
		a.CreatedAt = parseTime(created)
		out = append(out, a)
	}
	return out, rows.Err()
}

// AccountByID returns one user, disabled or not.
func (s *Store) AccountByID(ctx context.Context, id int64) (Account, error) {
	return accountByID(ctx, s.db, id)
}

// rowQuerier is a *sql.DB or a *sql.Tx: with a single connection, a query
// made inside a transaction must go through it.
type rowQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func accountByID(ctx context.Context, q rowQuerier, id int64) (Account, error) {
	var a Account
	var created string
	err := q.QueryRowContext(ctx, `
		SELECT id, username, role, totp_secret <> '', disabled_at <> '', created_at FROM users WHERE id = ?`, id).
		Scan(&a.ID, &a.Username, &a.Role, &a.TOTP, &a.Disabled, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return a, ErrNotFound
	}
	a.CreatedAt = parseTime(created)
	return a, err
}

// AccountByName returns one user by name, disabled or not.
func (s *Store) AccountByName(ctx context.Context, username string) (Account, error) {
	var id int64
	err := s.db.QueryRowContext(ctx, `SELECT id FROM users WHERE username = ?`, username).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return Account{}, ErrNotFound
	}
	if err != nil {
		return Account{}, err
	}
	return s.AccountByID(ctx, id)
}

// CreateFirstAdmin creates the first administrator in a single statement, so
// that two concurrent first-run forms cannot both succeed: ErrNotFound when
// an account already exists.
func (s *Store) CreateFirstAdmin(ctx context.Context, username, passwordHash string) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO users (username, password_hash, role, created_at)
		SELECT ?, ?, 'admin', ? WHERE NOT EXISTS (SELECT 1 FROM users)`, username, passwordHash, now())
	if err != nil {
		return 0, fmt.Errorf("create first admin: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return 0, ErrNotFound
	}
	return res.LastInsertId()
}

// SetRole changes the role of an active user. The role is read at every
// request, so the change applies to open sessions at once.
func (s *Store) SetRole(ctx context.Context, id int64, role string) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE users SET role = ?
		WHERE id = ? AND disabled_at = '' AND (role <> 'admin' OR ? = 'admin' OR `+otherAdmin+`)`, role, id, role)
	return accountChanged(ctx, s.db, id, res, err)
}

// SetDisabled disables a user, ending its sessions, or enables it again.
func (s *Store) SetDisabled(ctx context.Context, id int64, disabled bool) error {
	if !disabled {
		res, err := s.db.ExecContext(ctx, `UPDATE users SET disabled_at = '' WHERE id = ?`, id)
		return expectRow(res, err)
	}
	return s.inTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			UPDATE users SET disabled_at = ?
			WHERE id = ? AND disabled_at = '' AND (role <> 'admin' OR `+otherAdmin+`)`, now(), id)
		if err := accountChanged(ctx, tx, id, res, err); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, id)
		return err
	})
}

// ResetPassword replaces the password of a user and ends its sessions.
func (s *Store) ResetPassword(ctx context.Context, id int64, passwordHash string) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if err := expectRow(tx.ExecContext(ctx, `UPDATE users SET password_hash = ? WHERE id = ?`, passwordHash, id)); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, id)
		return err
	})
}

// ResetTOTP removes the second factor of a user who lost it, and ends the
// user's sessions.
func (s *Store) ResetTOTP(ctx context.Context, id int64) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if err := expectRow(tx.ExecContext(ctx,
			`UPDATE users SET totp_secret = '', totp_pending = '', totp_last_step = 0 WHERE id = ?`, id)); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, id)
		return err
	})
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

// PurgeAudit deletes the audit entries older than before; it returns how
// many were deleted.
func (s *Store) PurgeAudit(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM audit_log WHERE created_at < ?`, formatTime(before))
	if err != nil {
		return 0, fmt.Errorf("purge audit log: %w", err)
	}
	return res.RowsAffected()
}

// accountChanged explains an UPDATE of a user that changed nothing: unknown
// or disabled user (ErrNotFound), or last active administrator.
func accountChanged(ctx context.Context, q rowQuerier, id int64, res sql.Result, err error) error {
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return nil
	}
	a, err := accountByID(ctx, q, id)
	if err != nil {
		return err
	}
	if a.Role == "admin" && !a.Disabled {
		return ErrLastAdmin
	}
	return ErrNotFound
}
