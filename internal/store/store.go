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
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure Go driver, no CGO
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// ErrNotFound is returned when a requested row does not exist.
var ErrNotFound = errors.New("not found")

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

	dsn := path + "?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
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
	var v int
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&v)
	return v, err
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
		return fmt.Errorf("read schema version: %w", err)
	}
	if latest := list[len(list)-1].version; current > latest {
		// SECURITY: older code on a newer schema could silently lose data.
		return fmt.Errorf("%w : %s est au schéma %d, cette version gère jusqu'au schéma %d ; "+
			"installez une version à jour de Vigil, ou restaurez la copie .bak écrite avant la mise à jour",
			ErrNewerSchema, path, current, latest)
	}
	applied := map[int]bool{}
	rows, err := s.db.QueryContext(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return fmt.Errorf("read applied migrations: %w", err)
	}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			_ = rows.Close() // the scan error is the one to report
			return fmt.Errorf("read applied migrations: %w", err)
		}
		applied[v] = true
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("read applied migrations: %w", err)
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
	dest := fmt.Sprintf("%s.schema-%d.%s.bak", path, current, time.Now().UTC().Format("20060102-150405"))
	if err := s.Backup(ctx, dest); err != nil {
		return fmt.Errorf("copie de sécurité avant mise à jour du schéma (espace disque, droits ?) : %w", err)
	}
	s.upgradeBackup = dest
	return nil
}

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
// run in the same transaction as the migration of the same version.
var afterMigration = map[int]func(context.Context, *sql.Conn) error{
	9: backfillMentions,
}

func (s *Store) inTx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback() // fn's error is the one to report
		return err
	}
	return tx.Commit()
}

// now returns the current time as stored in the database.
func now() string { return formatTime(time.Now()) }

func formatTime(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func parseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return t
}
