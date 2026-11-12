package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// ErrLastAdmin is returned when a change would leave no active administrator.
var ErrLastAdmin = errors.New("last active administrator")

// otherAdmin is true when an active administrator other than the updated
// row exists; it is evaluated inside the UPDATE, so two concurrent changes
// cannot both remove the last one.
const otherAdmin = `EXISTS (SELECT 1 FROM users o WHERE o.role = 'admin' AND o.disabled_at = '' AND o.id <> users.id)`

// ListUsers returns every user, active ones first, by name.
func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	return collect(ctx, s.db, "list users", func(row scanner) (User, error) { return scanUser(row) },
		selectUser+`ORDER BY disabled_at <> '', username COLLATE NOCASE`)
}

// User returns one user, disabled or not.
func (s *Store) User(ctx context.Context, id int64) (User, error) {
	return userByID(ctx, s.db, id)
}

func userByID(ctx context.Context, q querier, id int64) (User, error) {
	u, err := scanUser(q.QueryRowContext(ctx, selectUser+`WHERE id = ?`, id))
	if err != nil && !errors.Is(err, ErrNotFound) {
		return u, fmt.Errorf("user %d: %w", id, err)
	}
	return u, err
}

// AnyUserByName returns one user by its exact name, disabled or not, in a
// single query whether it exists or not (see the failed sign-in). To sign in,
// UserByName keeps the disabled ones out.
func (s *Store) AnyUserByName(ctx context.Context, username string) (User, error) {
	u, err := scanUser(s.db.QueryRowContext(ctx, selectUser+`WHERE username = ?`, username))
	if err != nil && !errors.Is(err, ErrNotFound) {
		return u, fmt.Errorf("user by name: %w", err)
	}
	return u, err
}

// CreateFirstAdmin creates the first administrator in a single statement, so
// that two concurrent first-run forms cannot both succeed: ErrNotFound when
// an account already exists.
func (s *Store) CreateFirstAdmin(ctx context.Context, username, passwordHash string) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO users (username, password_hash, role, created_at)
		SELECT ?, ?, 'admin', ? WHERE NOT EXISTS (SELECT 1 FROM users)`, username, passwordHash, now())
	if err := expectRow(res, err); err != nil {
		return 0, wrap("create first admin", err)
	}
	id, err := res.LastInsertId()
	return id, wrap("create first admin", err)
}

// SetRole changes the role of an active user. The role is read at every
// request, so the change applies to open sessions at once.
func (s *Store) SetRole(ctx context.Context, id int64, role string) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE users SET role = ?
		WHERE id = ? AND disabled_at = '' AND (role <> 'admin' OR ? = 'admin' OR `+otherAdmin+`)`, role, id, role)
	return wrap("set role", accountChanged(ctx, s.db, id, res, err))
}

// SetDisabled disables a user, ending its sessions, or enables it again.
func (s *Store) SetDisabled(ctx context.Context, id int64, disabled bool) error {
	if !disabled {
		return wrap("enable account", expectRow(s.db.ExecContext(ctx, `UPDATE users SET disabled_at = '' WHERE id = ?`, id)))
	}
	return wrap("disable account", s.inTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			UPDATE users SET disabled_at = ?
			WHERE id = ? AND disabled_at = '' AND (role <> 'admin' OR `+otherAdmin+`)`, now(), id)
		if err := accountChanged(ctx, tx, id, res, err); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, id)
		return err
	}))
}

// ResetPassword replaces the password of a user and ends its sessions.
func (s *Store) ResetPassword(ctx context.Context, id int64, passwordHash string) error {
	return wrap("reset password", s.inTx(ctx, func(tx *sql.Tx) error {
		if err := expectRow(tx.ExecContext(ctx, `UPDATE users SET password_hash = ? WHERE id = ?`, passwordHash, id)); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, id)
		return err
	}))
}

// ResetTOTP removes the second factor of a user who lost it, and ends the
// user's sessions.
func (s *Store) ResetTOTP(ctx context.Context, id int64) error {
	return wrap("reset totp", s.inTx(ctx, func(tx *sql.Tx) error {
		if err := expectRow(tx.ExecContext(ctx,
			`UPDATE users SET totp_secret = '', totp_pending = '', totp_last_step = 0 WHERE id = ?`, id)); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, id)
		return err
	}))
}

// ResetAllTOTP removes the second factor of every account that has one, or
// is enrolling, and ends their sessions. After a leak of the database or of a
// backup, the secrets it held become worthless once everyone has enrolled
// again. It returns the number of accounts reset.
func (s *Store) ResetAllTOTP(ctx context.Context) (int, error) {
	var n int
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		const enrolled = `totp_secret <> '' OR totp_pending <> ''`
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE `+enrolled+`)`); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx,
			`UPDATE users SET totp_secret = '', totp_pending = '', totp_last_step = 0 WHERE `+enrolled)
		if err != nil {
			return err
		}
		affected, err := res.RowsAffected()
		n = int(affected)
		return err
	})
	return n, wrap("reset every totp", err)
}

// accountChanged explains an UPDATE of a user that changed nothing: unknown
// or disabled user (ErrNotFound), or last active administrator.
func accountChanged(ctx context.Context, q querier, id int64, res sql.Result, err error) error {
	if err := expectRow(res, err); !errors.Is(err, ErrNotFound) {
		return err
	}
	u, err := userByID(ctx, q, id)
	if err != nil {
		return err
	}
	if u.Role == "admin" && !u.Disabled {
		return ErrLastAdmin
	}
	return ErrNotFound
}
