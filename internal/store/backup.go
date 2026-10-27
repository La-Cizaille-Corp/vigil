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
	if _, err := s.db.ExecContext(ctx, `VACUUM INTO ?`, tmp); err != nil {
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
	for _, e := range entries {
		n := e.Name()
		if e.Type().IsRegular() && strings.HasPrefix(n, backupPrefix) && strings.HasSuffix(n, backupSuffix) {
			names = append(names, n)
		}
	}
	sort.Strings(names) // timestamps sort chronologically
	var errs []error
	for len(names) > keep {
		if err := os.Remove(filepath.Join(dir, names[0])); err != nil {
			errs = append(errs, err)
		}
		names = names[1:]
	}
	return errors.Join(errs...)
}
