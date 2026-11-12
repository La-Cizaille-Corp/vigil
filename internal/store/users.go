package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// User is an account.
type User struct {
	ID           int64
	Username     string
	PasswordHash string // read by UserByName only, to sign in
	Role         string
	TOTP         bool // second factor enabled
	Disabled     bool
	CreatedAt    time.Time
}

// userColumns are those of a User but its password hash (see scanUser).
const (
	userColumns = `id, username, role, totp_secret <> '', disabled_at <> '', created_at`
	selectUser  = `SELECT ` + userColumns + ` FROM users `
)

// scanUser reads the columns of userColumns, then extra ones if given; no row
// is ErrNotFound.
func scanUser(row scanner, extra ...any) (User, error) {
	var u User
	var created string
	err := row.Scan(append([]any{&u.ID, &u.Username, &u.Role, &u.TOTP, &u.Disabled, &created}, extra...)...)
	if errors.Is(err, sql.ErrNoRows) {
		return u, ErrNotFound
	}
	u.CreatedAt = parseTime(created)
	return u, err
}

// Session is an authenticated browser session with its user.
type Session struct {
	User      User
	CSRFToken string
}

// CountUsers returns the number of accounts.
func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.q(ctx).QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, wrap("count users", err)
}

// CreateUser inserts a user; passwordHash must already be hashed. A name that
// differs from an existing one only by case is refused (ErrExists): « Alice »
// and « alice » would be confused in the history and the audit log. Names are
// compared in Go, as SQLite's NOCASE only folds ASCII letters; the check and
// the insert share a transaction, so concurrent creations cannot both pass.
// Accounts that already overlap are kept.
func (s *Store) CreateUser(ctx context.Context, username, passwordHash, role string) (int64, error) {
	var id int64
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		names, err := collect(ctx, tx, "user names", value[string], `SELECT username FROM users`)
		if err != nil {
			return err
		}
		for _, name := range names {
			if strings.EqualFold(name, username) {
				return ErrExists
			}
		}
		res, err := tx.ExecContext(ctx,
			`INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)`,
			username, passwordHash, role, now())
		if err != nil {
			return err
		}
		id, err = res.LastInsertId()
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("create user: %w", err)
	}
	return id, nil
}

// UserByName looks up an active user by username, with its password hash; a
// disabled one is ErrNotFound, so that it cannot sign in.
func (s *Store) UserByName(ctx context.Context, username string) (User, error) {
	var hash string
	u, err := scanUser(s.q(ctx).QueryRowContext(ctx,
		`SELECT `+userColumns+`, password_hash FROM users WHERE username = ? AND disabled_at = ''`, username), &hash)
	u.PasswordHash = hash
	if errors.Is(err, ErrNotFound) {
		return u, err
	}
	return u, wrap("user by name", err)
}

// CreateSession stores a session identified by the hash of its token.
func (s *Store) CreateSession(ctx context.Context, tokenHash string, userID int64, csrf string, expires time.Time) error {
	_, err := s.q(ctx).ExecContext(ctx,
		`INSERT INTO sessions (token_hash, user_id, csrf_token, expires_at) VALUES (?, ?, ?, ?)`,
		tokenHash, userID, csrf, formatTime(expires))
	return wrap("create session", err)
}

// Session returns a non-expired session.
func (s *Store) Session(ctx context.Context, tokenHash string) (Session, error) {
	var sess Session
	var err error
	sess.User, err = scanUser(s.q(ctx).QueryRowContext(ctx, `
		SELECT `+userColumns+`, s.csrf_token
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = ? AND s.expires_at > ? AND u.disabled_at = ''`, tokenHash, now()), &sess.CSRFToken)
	if errors.Is(err, ErrNotFound) {
		return sess, err
	}
	return sess, wrap("session", err)
}

// DeleteSession removes a session (logout).
func (s *Store) DeleteSession(ctx context.Context, tokenHash string) error {
	_, err := s.q(ctx).ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, tokenHash)
	return wrap("delete session", err)
}

// DeleteOtherSessions ends every session of a user except the current one.
func (s *Store) DeleteOtherSessions(ctx context.Context, userID int64, keepHash string) error {
	_, err := s.q(ctx).ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ? AND token_hash <> ?`, userID, keepHash)
	return wrap("delete other sessions", err)
}

// DeleteExpiredSessions purges stale sessions.
func (s *Store) DeleteExpiredSessions(ctx context.Context) error {
	_, err := s.q(ctx).ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, now())
	return wrap("delete expired sessions", err)
}

// SetPassword replaces the password hash of a user, who changes it: the
// caller ends the user's other sessions (ResetPassword ends them all).
func (s *Store) SetPassword(ctx context.Context, userID int64, passwordHash string) error {
	return wrap("set password", expectRow(s.q(ctx).ExecContext(ctx, `UPDATE users SET password_hash = ? WHERE id = ?`, passwordHash, userID)))
}

// Audit records a security-relevant action. userID 0 means the system.
func (s *Store) Audit(ctx context.Context, userID int64, action, detail string) error {
	_, err := s.q(ctx).ExecContext(ctx,
		`INSERT INTO audit_log (user_id, action, detail, created_at) VALUES (?, ?, ?, ?)`,
		nullID(userID), action, detail, now())
	return wrap("audit", err)
}

// AuditEntry is one line of the audit log.
type AuditEntry struct {
	Username  string // empty for the command line or the system
	Action    string
	Detail    string
	CreatedAt time.Time
}

// ListAudit returns the most recent audit entries, newest first.
func (s *Store) ListAudit(ctx context.Context, limit int) ([]AuditEntry, error) {
	return collect(ctx, s.q(ctx), "list audit", func(row scanner) (AuditEntry, error) {
		var e AuditEntry
		var created string
		err := row.Scan(&e.Username, &e.Action, &e.Detail, &created)
		e.CreatedAt = parseTime(created)
		return e, err
	}, `
		SELECT COALESCE(u.username, ''), l.action, l.detail, l.created_at
		FROM audit_log l LEFT JOIN users u ON u.id = l.user_id
		ORDER BY l.id DESC LIMIT ?`, limit)
}

// PurgeAudit deletes the audit entries older than before; it returns how
// many were deleted.
func (s *Store) PurgeAudit(ctx context.Context, before time.Time) (int, error) {
	n, err := purge(ctx, s.q(ctx), `DELETE FROM audit_log WHERE created_at < ?`, before)
	return n, wrap("purge audit log", err)
}
