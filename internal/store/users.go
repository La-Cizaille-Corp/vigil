package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
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
	Access       Access
}

// Access is what an account sees (A68): every asset, or only those of its
// groups. The zero value is a restricted account without a group, which sees
// nothing: an access is always chosen.
type Access struct {
	All    bool
	Groups []int64 // the groups of a restricted account, in order
}

// Restricted reports whether the account sees the assets of its groups only.
// An administrator sees everything whatever its access: it manages the
// accounts, and could grant itself any group.
func (u User) Restricted() bool { return u.Role != "admin" && !u.Access.All }

// Scope is the part of the inventory the account may see and change: the
// same for both, as the role of each page says who may change anything.
func (u User) Scope() Scope {
	if !u.Restricted() {
		return Everything
	}
	return InGroups(u.Access.Groups...)
}

// AuditAccess is the audit detail of an access (see AuditDetail):
// access=all, or access=groups and the names of its groups among groups,
// those of no group left out as SetUserAccess leaves them out.
func AuditAccess(access Access, groups []Group) []any {
	if access.All {
		return []any{"access", "all"}
	}
	var names []string
	for _, g := range groups {
		if slices.Contains(access.Groups, g.ID) {
			names = append(names, g.Name)
		}
	}
	return []any{"access", "groups", "groups", strings.Join(names, ",")}
}

// userColumns are those of a User but its password hash (see scanUser), on
// the table users, not aliased.
const (
	userColumns = `users.id, users.username, users.role, users.totp_secret <> '', users.disabled_at <> '', users.created_at,
		users.access = 'all', COALESCE((SELECT group_concat(ug.group_id) FROM user_groups ug WHERE ug.user_id = users.id), '')`
	selectUser = `SELECT ` + userColumns + ` FROM users `
)

// scanUser reads the columns of userColumns, then extra ones if given; no row
// is ErrNotFound.
func scanUser(row scanner, extra ...any) (User, error) {
	var u User
	var created, groups string
	err := row.Scan(append([]any{&u.ID, &u.Username, &u.Role, &u.TOTP, &u.Disabled, &created, &u.Access.All, &groups}, extra...)...)
	if errors.Is(err, sql.ErrNoRows) {
		return u, ErrNotFound
	}
	u.CreatedAt = parseTime(created)
	for _, g := range splitTags(groups) {
		id, perr := strconv.ParseInt(g, 10, 64)
		if perr != nil {
			return u, fmt.Errorf("group of user %d: %w", u.ID, perr)
		}
		u.Access.Groups = append(u.Access.Groups, id)
	}
	slices.Sort(u.Access.Groups)
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

// CreateUser inserts a user with its access; passwordHash must already be
// hashed. A name that differs from an existing one only by case is refused
// (ErrExists, see nameTaken): « Alice » and « alice » would be confused in the
// history and the audit log. The check and the insert share a transaction, so
// concurrent creations cannot both pass, and the same name inserted meanwhile
// by another process (vigil user add) is ErrExists too. Accounts that already
// overlap are kept.
func (s *Store) CreateUser(ctx context.Context, username, passwordHash, role string, access Access) (int64, error) {
	var id int64
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		if err := nameTaken(ctx, tx, username, `SELECT username FROM users`); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx,
			`INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)`,
			username, passwordHash, role, now())
		if err != nil {
			return mapUnique(err)
		}
		if id, err = res.LastInsertId(); err != nil {
			return err
		}
		return setAccess(ctx, tx, id, access)
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
		FROM sessions s JOIN users ON users.id = s.user_id
		WHERE s.token_hash = ? AND s.expires_at > ? AND users.disabled_at = ''`, tokenHash, now()), &sess.CSRFToken)
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
