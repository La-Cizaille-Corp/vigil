// Package store owns the SQLite database: connection, migrations and every
// SQL query of the application. All queries are parameterised.
package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/clip"

	"modernc.org/sqlite" // pure Go driver, no CGO
	sqlite3 "modernc.org/sqlite/lib"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// ErrNotFound is returned when a requested row does not exist.
var ErrNotFound = errors.New("not found")

// ErrExists is returned when a new row would duplicate an existing one, such
// as a user name differing from another only by case.
var ErrExists = errors.New("already exists")

// mapUnique turns a violated uniqueness constraint (UNIQUE or PRIMARY KEY)
// into ErrExists, so that the caller can tell a duplicate from a failure;
// any other error is returned as it is.
func mapUnique(err error) error {
	var e *sqlite.Error
	if errors.As(err, &e) && (e.Code() == sqlite3.SQLITE_CONSTRAINT_UNIQUE || e.Code() == sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY) {
		return ErrExists
	}
	return err
}

// mapForeignKey turns a reference to a row that does not exist, such as the
// group of a channel, into ErrNotFound; any other error is returned as it is.
func mapForeignKey(err error) error {
	var e *sqlite.Error
	if errors.As(err, &e) && e.Code() == sqlite3.SQLITE_CONSTRAINT_FOREIGNKEY {
		return ErrNotFound
	}
	return err
}

// Store wraps the database handle.
type Store struct {
	db            *sql.DB
	upgradeBackup string // copy written before the last schema upgrade, if any
}

// ErrNewerSchema is returned when the database was written by a more recent
// version of Vigil: running older code on it could lose or corrupt data.
var ErrNewerSchema = errors.New("base de données plus récente que cette version de Vigil")

// Open opens (or creates) the database at path and applies pending migrations.
func Open(ctx context.Context, path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create data directory: %w", err)
	}
	// SECURITY: create the file with owner-only permissions before SQLite does.
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) // #nosec G304 -- path chosen by the operator
	if err != nil {
		return nil, fmt.Errorf("create database file: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("create database file: %w", err)
	}
	// A file created by an older version or copied by hand may be readable by
	// others; WAL and SHM files inherit its mode. No effect on Windows, where
	// the folder's access rights apply.
	if info, err := os.Stat(path); err == nil && info.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(path, 0o600); err != nil {
			return nil, fmt.Errorf("restrict database file: %w", err)
		}
	}

	// Temporary data stays in memory: no temporary file to write, as the file
	// system of the container is read-only (see deploy/docker-compose.yml).
	dsn := path + "?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=temp_store(2)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	// A single connection keeps SQLite locking trivial; load is low for this tool.
	db.SetMaxOpenConns(1)

	s := &Store{db: db}
	if err := s.migrate(ctx, path); err != nil {
		_ = db.Close() // the migration error is the one to report
		return nil, err
	}
	return s, nil
}

// Close releases the database.
func (s *Store) Close() error { return s.db.Close() }

// migration is one embedded schema change, applied once and never edited
// after a release (TestMigrationsFrozen guards this).
type migration struct {
	version int
	name    string
	body    string
}

func migrations() ([]migration, error) {
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return nil, fmt.Errorf("read migrations: %w", err)
	}
	var list []migration
	for _, e := range entries {
		prefix, _, ok := strings.Cut(e.Name(), "_")
		if !ok {
			return nil, fmt.Errorf("migration %q: name must be NNN_description.sql", e.Name())
		}
		version, err := strconv.Atoi(prefix)
		if err != nil {
			return nil, fmt.Errorf("migration %q: %w", e.Name(), err)
		}
		body, err := migrationsFS.ReadFile("migrations/" + e.Name())
		if err != nil {
			return nil, fmt.Errorf("read migration %q: %w", e.Name(), err)
		}
		list = append(list, migration{version: version, name: e.Name(), body: string(body)})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].version < list[j].version })
	return list, nil
}

// LatestSchema is the schema version this binary brings a database to.
func LatestSchema() int {
	list, err := migrations()
	if err != nil || len(list) == 0 {
		return 0
	}
	return list[len(list)-1].version
}

// SchemaVersion returns the schema version of the open database.
func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	return schemaVersion(ctx, s.q(ctx))
}

// schemaVersion reads the highest applied migration.
func schemaVersion(ctx context.Context, q querier) (int, error) {
	var v int
	err := q.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&v)
	return v, wrap("schema version", err)
}

// UpgradeBackup returns the copy of the database written before the schema
// upgrade done by Open, or "" if none was needed.
func (s *Store) UpgradeBackup() string { return s.upgradeBackup }

// migrate brings the schema up to date. Data survives upgrades because
// migrations only ever add to the schema or transform rows in place, each in
// a transaction; before the first pending one, a consistent copy of an
// existing database is written next to it.
func (s *Store) migrate(ctx context.Context, path string) error {
	if _, err := s.db.ExecContext(ctx,
		`CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY)`); err != nil {
		return fmt.Errorf("create migrations table: %w", err)
	}
	list, err := migrations()
	if err != nil {
		return err
	}
	current, err := s.SchemaVersion(ctx)
	if err != nil {
		return err
	}
	if latest := list[len(list)-1].version; current > latest {
		// SECURITY: older code on a newer schema could silently lose data.
		return fmt.Errorf("%w : %s est au schéma %d, cette version gère jusqu'au schéma %d ; "+
			"installez une version à jour de Vigil, ou restaurez la copie .bak écrite avant la mise à jour",
			ErrNewerSchema, path, current, latest)
	}
	versions, err := collect(ctx, s.db, "read applied migrations", value[int], `SELECT version FROM schema_migrations`)
	if err != nil {
		return err
	}
	applied := map[int]bool{}
	for _, v := range versions {
		applied[v] = true
	}

	for _, m := range list {
		if applied[m.version] {
			continue
		}
		if current > 0 && s.upgradeBackup == "" {
			if err := s.backupBeforeUpgrade(ctx, path, current); err != nil {
				return err
			}
		}
		if err := s.apply(ctx, m); err != nil {
			return fmt.Errorf("apply migration %q: %w", m.name, err)
		}
	}
	return nil
}

// backupBeforeUpgrade writes <db>.schema-<N>.<UTC time>.bak. Without it, a
// failed or unwanted upgrade could only be undone from the operator's backups.
func (s *Store) backupBeforeUpgrade(ctx context.Context, path string, current int) error {
	dest := fmt.Sprintf("%s.schema-%d.%s.bak", path, current, time.Now().UTC().Format(stampLayout))
	if err := backup(ctx, s.db, dest); err != nil {
		return fmt.Errorf("copie de sécurité avant mise à jour du schéma (espace disque, droits ?) : %w", err)
	}
	s.upgradeBackup = dest
	// A copy that cannot be deleted only stays behind: the upgrade goes on.
	_ = pruneUpgradeBackups(path, keepUpgradeBackups)
	return nil
}

// keepUpgradeBackups is how many copies taken before a schema upgrade are
// kept next to the database: each holds every secret of the database.
const keepUpgradeBackups = 3

// apply runs one migration in a transaction. Another process (vigil sync
// while vigil serve starts) may have applied it meanwhile: the check is
// repeated inside the transaction, which holds the write lock from the start.
func (s *Store) apply(ctx context.Context, m migration) error {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return err
	}
	err = func() error {
		var done int
		if err := conn.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, m.version).Scan(&done); err != nil || done > 0 {
			return err
		}
		if _, err := conn.ExecContext(ctx, m.body); err != nil {
			return err
		}
		if hook := afterMigration[m.version]; hook != nil {
			if err := hook(ctx, conn); err != nil {
				return err
			}
		}
		_, err := conn.ExecContext(ctx, `INSERT INTO schema_migrations (version) VALUES (?)`, m.version)
		return err
	}()
	if err != nil {
		_, _ = conn.ExecContext(ctx, `ROLLBACK`) // the migration error is the one to report
		return err
	}
	_, err = conn.ExecContext(ctx, `COMMIT`)
	return err
}

// afterMigration holds data transformations that SQL alone cannot express,
// run in the same transaction as the migration of the same version (the
// "Go step" announced by the comments of migration 009 is backfillMentions).
var afterMigration = map[int]func(context.Context, *sql.Conn) error{
	9: backfillMentions,
}

// txKey marks a context that carries a transaction of InTx.
type txKey struct{}

// InTx runs fn in a transaction: every call of the store made with the
// context fn receives joins it, and an error of fn undoes them all. The
// synchronisation groups the writes of an asset this way (A57).
//
// Inside fn, call the store with that context only, and read nothing from
// the network: the transaction holds the only connection to the database,
// that any other call waits for.
func (s *Store) InTx(ctx context.Context, fn func(context.Context) error) error {
	if _, ok := ctx.Value(txKey{}).(*sql.Tx); ok {
		return fn(ctx) // already inside one: part of it
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	if err := fn(context.WithValue(ctx, txKey{}, tx)); err != nil {
		_ = tx.Rollback() // fn's error is the one to report
		return err
	}
	return wrap("commit", tx.Commit())
}

// q returns where the statements made with ctx go: the transaction it
// carries (see InTx), or the database.
func (s *Store) q(ctx context.Context) querier {
	if tx, ok := ctx.Value(txKey{}).(*sql.Tx); ok {
		return tx
	}
	return s.db
}

// inTx runs fn in a transaction, or in that of InTx when ctx carries one.
func (s *Store) inTx(ctx context.Context, fn func(*sql.Tx) error) error {
	return s.InTx(ctx, func(ctx context.Context) error {
		return fn(ctx.Value(txKey{}).(*sql.Tx))
	})
}

// scanner is a row to read: a *sql.Row or the current row of *sql.Rows.
type scanner interface {
	Scan(dest ...any) error
}

// querier runs statements: a *sql.DB, *sql.Tx or *sql.Conn. With a single
// connection, a statement made inside a transaction must go through it.
type querier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// collect runs a query and reads each row with scan. It reads and closes every
// row before returning, so that the next statement of a transaction finds the
// connection free. Its errors start with label.
func collect[T any](ctx context.Context, q querier, label string, scan func(scanner) (T, error), query string, args ...any) ([]T, error) {
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	defer rows.Close() // after a failure; a no-op once closed below
	var out []T
	for rows.Next() {
		v, err := scan(rows)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", label, err)
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	return out, nil
}

// value reads a row of a single column, for collect.
func value[T any](row scanner) (T, error) {
	var v T
	err := row.Scan(&v)
	return v, err
}

// count is a key and a number of rows, as GROUP BY gives them.
type count struct {
	key string
	n   int
}

func scanCount(row scanner) (count, error) {
	var c count
	err := row.Scan(&c.key, &c.n)
	return c, err
}

// expectRow turns a statement that changed no row into ErrNotFound.
func expectRow(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// purge runs a DELETE of the rows older than before, the one parameter of
// query, and returns how many went.
func purge(ctx context.Context, q querier, query string, before time.Time) (int, error) {
	res, err := q.ExecContext(ctx, query, formatTime(before))
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// wrap prefixes a failure with what was being done; nil stays nil.
func wrap(label string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", label, err)
}

// nullID stores the user 0 (the system, the command line) as NULL.
func nullID(id int64) any {
	if id == 0 {
		return nil
	}
	return id
}

// maxErrorText bounds a failure kept with a feed or a channel, in characters.
const maxErrorText = 300

// errText is a failure as kept with a feed or a channel, "" for none.
func errText(err error) string {
	if err == nil {
		return ""
	}
	return clip.Text(err.Error(), maxErrorText)
}

// nonNil keeps a list stored as JSON an array, never null.
func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// inClause adds "column IN (?, ?...)" for a non-empty list.
func inClause[T any](where []string, args []any, column string, values []T) ([]string, []any) {
	if len(values) == 0 {
		return where, args
	}
	marks := strings.TrimSuffix(strings.Repeat("?, ", len(values)), ", ")
	for _, v := range values {
		args = append(args, v)
	}
	return append(where, column+" IN ("+marks+")"), args
}

// nameTaken returns ErrExists when the names read by query hold name at the
// case of its letters: « Alice » and « alice », « Équipe » and « équipe »
// would be confused. They are compared in Go (strings.EqualFold), as SQLite's
// NOCASE only folds ASCII letters.
func nameTaken(ctx context.Context, q querier, name, query string, args ...any) error {
	names, err := collect(ctx, q, "names", value[string], query, args...)
	if err != nil {
		return err
	}
	if slices.ContainsFunc(names, func(n string) bool { return strings.EqualFold(n, name) }) {
		return ErrExists
	}
	return nil
}

// likeEscaper protects LIKE wildcards in user search terms.
var likeEscaper = strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`)

// joinTags stores a list of tags as ",FR,US,", so that hasTag can find one of
// them with a single LIKE.
func joinTags(tags []string) string {
	if len(tags) == 0 {
		return ""
	}
	return "," + strings.Join(tags, ",") + ","
}

// SplitList reads a list stored between commas (joinTags, or "fr,de" for the
// tags of a feed): its items, spaces around each removed, empty ones dropped.
// Every comma-separated list of Vigil is read here: tags, groups of an account,
// countries, sectors and regulations.
func SplitList(s string) []string {
	var out []string
	for _, t := range strings.Split(s, ",") {
		if t = strings.TrimSpace(t); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// hasTag is the condition "the list stored in column (see joinTags) holds
// tag", and its argument.
// SECURITY: the LIKE wildcards of tag are escaped, so that "pci_dss" or a
// user's tag never matches another one.
func hasTag(column, tag string) (cond string, arg any) {
	return column + ` LIKE ? ESCAPE '\'`, "%," + likeEscaper.Replace(tag) + ",%"
}

// now returns the current time as stored in the database.
func now() string { return formatTime(time.Now()) }

func formatTime(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func parseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return t
}

// day is the date of t as compared with the deadlines: 'YYYY-MM-DD', in UTC.
func day(t time.Time) string { return t.UTC().Format(time.DateOnly) }

// stampLayout dates the backup files, in UTC: it sorts chronologically.
const stampLayout = "20060102-150405"
