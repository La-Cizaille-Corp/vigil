package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Backup writes a consistent copy of the database to dest with VACUUM INTO,
// which SQLite guarantees to be a transactionally consistent snapshot even
// while the server writes. The copy is then checked with integrity_check.
// Copying vigil.db with a file tool while it is open is NOT safe: recent
// transactions live in the -wal file.
func (s *Store) Backup(ctx context.Context, dest string) error {
	return backup(ctx, s.db, dest)
}

// BackupFile copies the database at src to dest without opening it as a
// Store: no migration runs, so a backup taken with a newer binary before an
// upgrade is a copy of the database as the running version left it.
func BackupFile(ctx context.Context, src, dest string) error {
	if _, err := os.Stat(src); err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(src)+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	defer db.Close()
	return backup(ctx, db, dest)
}

func backup(ctx context.Context, db *sql.DB, dest string) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return fmt.Errorf("backup directory: %w", err)
	}
	// VACUUM INTO refuses an existing non-empty file; write next to the
	// destination then rename, so a failed backup never replaces a good one.
	tmp := dest + ".tmp"
	_ = os.Remove(tmp) // leftover of an interrupted backup
	// SECURITY: the backup holds the same secrets as the database: owner only.
	f, err := os.OpenFile(tmp, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- path chosen by the operator
	if err != nil {
		return fmt.Errorf("backup file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("backup file: %w", err)
	}
	if _, err := db.ExecContext(ctx, `VACUUM INTO ?`, tmp); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("backup: %w", err)
	}
	if err := CheckIntegrity(ctx, tmp); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("backup: %w", err)
	}
	return nil
}

// CheckIntegrity opens a database file read-only and runs integrity_check.
func CheckIntegrity(ctx context.Context, path string) error {
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?mode=ro")
	if err != nil {
		return fmt.Errorf("integrity check: %w", err)
	}
	defer db.Close()
	var result string
	if err := db.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&result); err != nil {
		return fmt.Errorf("integrity check: %w", err)
	}
	if result != "ok" {
		return fmt.Errorf("integrity check of %s failed: %s", path, result)
	}
	return nil
}

// FileSchema returns the schema version of a database file without changing
// it (0 for a file that Vigil never initialised).
func FileSchema(ctx context.Context, path string) (int, error) {
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?mode=ro")
	if err != nil {
		return 0, fmt.Errorf("schema version: %w", err)
	}
	defer db.Close()
	var exists int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'`).Scan(&exists); err != nil || exists == 0 {
		return 0, err
	}
	var v int
	err = db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&v)
	return v, err
}

// backupPrefix and backupSuffix name the files written by RotateBackups, so
// that rotation never deletes anything else in the directory.
const (
	backupPrefix = "vigil-"
	backupSuffix = ".db"
)

// BackupName returns the file name of a scheduled backup taken at t.
func BackupName(t time.Time) string {
	return backupPrefix + t.UTC().Format("20060102-150405") + backupSuffix
}

// isBackupName reports whether name is exactly a BackupName.
func isBackupName(name string) bool {
	stamp, ok := strings.CutPrefix(name, backupPrefix)
	if !ok {
		return false
	}
	if stamp, ok = strings.CutSuffix(stamp, backupSuffix); !ok {
		return false
	}
	_, err := time.Parse("20060102-150405", stamp)
	return err == nil
}

// BackupTo writes a timestamped backup in dir and keeps only the newest keep
// scheduled backups (keep <= 0 keeps everything).
func (s *Store) BackupTo(ctx context.Context, dir string, keep int) (string, error) {
	dest := filepath.Join(dir, BackupName(time.Now()))
	if err := s.Backup(ctx, dest); err != nil {
		return "", err
	}
	return dest, RotateBackups(dir, keep)
}

// RotateBackups deletes the oldest scheduled backups beyond keep.
func RotateBackups(dir string, keep int) error {
	if keep <= 0 {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("rotate backups: %w", err)
	}
	var names []string
	var errs []error
	for _, e := range entries {
		n := e.Name()
		if !e.Type().IsRegular() {
			continue
		}
		// Only names written by BackupName: a copy made by hand
		// ("vigil-avant-maj.db") is neither counted nor deleted.
		if isBackupName(n) {
			names = append(names, n)
		}
		// A backup interrupted by a crash leaves its temporary file, a full
		// copy of the database: removed once clearly abandoned.
		if tmp, ok := strings.CutSuffix(n, ".tmp"); ok && isBackupName(tmp) {
			if info, err := e.Info(); err == nil && time.Since(info.ModTime()) > time.Hour {
				errs = append(errs, os.Remove(filepath.Join(dir, n)))
			}
		}
	}
	sort.Strings(names) // timestamps sort chronologically
	for len(names) > keep {
		if err := os.Remove(filepath.Join(dir, names[0])); err != nil {
			errs = append(errs, err)
		}
		names = names[1:]
	}
	return errors.Join(errs...)
}
