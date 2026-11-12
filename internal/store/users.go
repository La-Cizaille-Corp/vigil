package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// User is an account able to sign in.
type User struct {
	ID           int64
	Username     string
	PasswordHash string
	Role         string
	TOTP         bool // second factor enabled (set on sessions)
}

// Session is an authenticated browser session with its user.
type Session struct {
	User      User
	CSRFToken string
	ExpiresAt time.Time
}

// CountUsers returns the number of accounts.
func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// CreateUser inserts a user; passwordHash must already be hashed. A name that
// differs from an existing one only by case is refused (ErrExists): « Alice »
// and « alice » would be confused in the history and the audit log. Names are
// compared in Go, as SQLite's NOCASE only folds ASCII letters; the check and
// the insert share a transaction, so concurrent creations cannot both pass,
// and the same name inserted meanwhile by another process (vigil user add)
// is ErrExists too. Accounts that already overlap are kept.
func (s *Store) CreateUser(ctx context.Context, username, passwordHash, role string) (int64, error) {
	var id int64
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT username FROM users`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				return err
			}
			if strings.EqualFold(name, username) {
				return ErrExists
			}
		}
		if err := rows.Err(); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx,
			`INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)`,
			username, passwordHash, role, now())
		if err != nil {
			return mapUnique(err)
		}
		id, err = res.LastInsertId()
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("create user: %w", err)
	}
	return id, nil
}

// UserByName looks up an active user by username; a disabled one is
// ErrNotFound, so that it cannot sign in.
func (s *Store) UserByName(ctx context.Context, username string) (User, error) {
	var u User
	err := s.db.QueryRowContext(ctx,
		`SELECT id, username, password_hash, role FROM users WHERE username = ? AND disabled_at = ''`, username).
		Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role)
	if errors.Is(err, sql.ErrNoRows) {
		return u, ErrNotFound
	}
	return u, err
}

// CreateSession stores a session identified by the hash of its token.
func (s *Store) CreateSession(ctx context.Context, tokenHash string, userID int64, csrf string, expires time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions (token_hash, user_id, csrf_token, expires_at) VALUES (?, ?, ?, ?)`,
		tokenHash, userID, csrf, formatTime(expires))
	return err
}

// SessionByHash returns a non-expired session.
func (s *Store) SessionByHash(ctx context.Context, tokenHash string) (Session, error) {
	var sess Session
	var expires string
	err := s.db.QueryRowContext(ctx, `
		SELECT u.id, u.username, u.role, u.totp_secret <> '', s.csrf_token, s.expires_at
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = ? AND s.expires_at > ? AND u.disabled_at = ''`, tokenHash, now()).
		Scan(&sess.User.ID, &sess.User.Username, &sess.User.Role, &sess.User.TOTP, &sess.CSRFToken, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return sess, ErrNotFound
	}
	sess.ExpiresAt = parseTime(expires)
	return sess, err
}

// DeleteSession removes a session (logout).
func (s *Store) DeleteSession(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, tokenHash)
	return err
}

// DeleteOtherSessions ends every session of a user except the current one.
func (s *Store) DeleteOtherSessions(ctx context.Context, userID int64, keepHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ? AND token_hash <> ?`, userID, keepHash)
	return err
}

// DeleteExpiredSessions purges stale sessions.
func (s *Store) DeleteExpiredSessions(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, now())
	return err
}

// AuditDetail writes the detail of an audit entry, the one format of new
// entries (older ones keep the forms they were written in): key=value pairs
// in the order given, keys and values alternating as in log/slog ("id", 12,
// "role", "analyst" gives id=12 role=analyst). SECURITY: a value that is
// empty or holds a space, a quote, an equals sign, a character that is not
// printable or invalid UTF-8 is quoted in Go syntax (name="Équipe sécu",
// text="a\nb"), so that a typed value can neither add a field nor start
// another line of a log.
func AuditDetail(kv ...any) string {
	var b strings.Builder
	for i := 0; i < len(kv); i += 2 {
		if i > 0 {
			b.WriteByte(' ')
		}
		value := ""
		if i+1 < len(kv) {
			value = fmt.Sprint(kv[i+1])
		}
		if value == "" || strings.ContainsFunc(value, func(r rune) bool {
			return r == ' ' || r == '"' || r == '=' || r == utf8.RuneError || !unicode.IsPrint(r)
		}) {
			value = strconv.Quote(value)
		}
		fmt.Fprintf(&b, "%v=%s", kv[i], value)
	}
	return b.String()
}

// Audit records a security-relevant action, its detail written by
// AuditDetail. userID 0 means the system.
func (s *Store) Audit(ctx context.Context, userID int64, action, detail string) error {
	var uid any
	if userID != 0 {
		uid = userID
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO audit_log (user_id, action, detail, created_at) VALUES (?, ?, ?, ?)`,
		uid, action, detail, now())
	return err
}

// SetPassword replaces the password hash of a user.
func (s *Store) SetPassword(ctx context.Context, userID int64, passwordHash string) error {
	return expectRow(s.db.ExecContext(ctx, `UPDATE users SET password_hash = ? WHERE id = ?`, passwordHash, userID))
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
	rows, err := s.db.QueryContext(ctx, `
		SELECT COALESCE(u.username, ''), l.action, l.detail, l.created_at
		FROM audit_log l LEFT JOIN users u ON u.id = l.user_id
		ORDER BY l.id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list audit: %w", err)
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var created string
		if err := rows.Scan(&e.Username, &e.Action, &e.Detail, &created); err != nil {
			return nil, err
		}
		e.CreatedAt = parseTime(created)
		out = append(out, e)
	}
	return out, rows.Err()
}
