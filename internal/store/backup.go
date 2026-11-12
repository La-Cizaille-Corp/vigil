package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

// BackupFile copies the database at src to dest without opening it as a
// Store: no migration runs, so a backup taken with a newer binary before an
// upgrade is a copy of the database as the running version left it.
func BackupFile(ctx context.Context, src, dest string) error {
	if _, err := os.Stat(src); err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	db, err := openReadOnly(src)
	if err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	defer db.Close()
	return backup(ctx, db, dest)
}

// backup writes a consistent copy of the database to dest with VACUUM INTO,
// which SQLite guarantees to be a transactionally consistent snapshot even
// while the server writes. The copy is then checked with integrity_check.
// Copying vigil.db with a file tool while it is open is NOT safe: recent
// transactions live in the -wal file.
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

// openReadOnly opens a database file without changing it: no migration runs.
// As in Open, it waits for a writer rather than failing at once, and keeps
// its temporary data in memory.
func openReadOnly(path string) (*sql.DB, error) {
	name, err := dsn(path, "mode=ro&_pragma=busy_timeout(5000)&_pragma=temp_store(2)")
	if err != nil {
		return nil, err
	}
	return sql.Open("sqlite", name)
}

// CheckIntegrity opens a database file read-only and runs integrity_check.
func CheckIntegrity(ctx context.Context, path string) error {
	db, err := openReadOnly(path)
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
	db, err := openReadOnly(path)
	if err != nil {
		return 0, fmt.Errorf("schema version: %w", err)
	}
	defer db.Close()
	var exists int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'`).Scan(&exists); err != nil || exists == 0 {
		return 0, wrap("schema version", err)
	}
	return schemaVersion(ctx, db)
}

// backupPrefix and backupSuffix name the files written by BackupTo, so that
// rotation never deletes anything else in the directory.
const (
	backupPrefix = "vigil-"
	backupSuffix = ".db"
)

// backupName returns the file name of a scheduled backup taken at t.
func backupName(t time.Time) string {
	return backupPrefix + t.UTC().Format(stampLayout) + backupSuffix
}

// backupStamp tells whether name is exactly a backupName, and when it was taken.
func backupStamp(name string) (time.Time, bool) {
	stamp, ok := strings.CutPrefix(name, backupPrefix)
	if !ok {
		return time.Time{}, false
	}
	if stamp, ok = strings.CutSuffix(stamp, backupSuffix); !ok {
		return time.Time{}, false
	}
	t, err := time.Parse(stampLayout, stamp)
	return t, err == nil
}

// upgradeBackupStamp recognises the copies of the database named base taken
// before a schema upgrade (see backupBeforeUpgrade), and when each was taken.
func upgradeBackupStamp(base string) func(string) (time.Time, bool) {
	return func(name string) (time.Time, bool) {
		rest, ok := strings.CutPrefix(name, base+".schema-")
		if !ok {
			return time.Time{}, false
		}
		if rest, ok = strings.CutSuffix(rest, ".bak"); !ok {
			return time.Time{}, false
		}
		version, stamp, ok := strings.Cut(rest, ".")
		if _, err := strconv.Atoi(version); !ok || err != nil {
			return time.Time{}, false
		}
		t, err := time.Parse(stampLayout, stamp)
		return t, err == nil
	}
}

// BackupTo writes a timestamped backup in dir and keeps only the newest keep
// scheduled backups (keep <= 0 keeps everything).
func (s *Store) BackupTo(ctx context.Context, dir string, keep int) (string, error) {
	dest := filepath.Join(dir, backupName(time.Now()))
	if err := backup(ctx, s.db, dest); err != nil {
		return "", err
	}
	return dest, rotateBackups(dir, keep)
}

// rotateBackups deletes the oldest scheduled backups of dir beyond keep.
func rotateBackups(dir string, keep int) error {
	return pruneBackups(dir, keep, backupStamp)
}

// pruneUpgradeBackups deletes the oldest copies of the database at path taken
// before a schema upgrade beyond keep.
func pruneUpgradeBackups(path string, keep int) error {
	return pruneBackups(filepath.Dir(path), keep, upgradeBackupStamp(filepath.Base(path)))
}

// pruneBackups deletes the oldest backups of dir beyond keep (keep <= 0 keeps
// everything). stampOf recognises a backup by its name and returns the time
// written in it, which orders them even after a copy changed their dates: a
// file it does not recognise, such as a copy made by hand
// ("vigil-avant-maj.db"), is neither counted nor deleted. The temporary file
// of a backup interrupted by a crash, a full copy of the database, is removed
// once clearly abandoned.
func pruneBackups(dir string, keep int, stampOf func(string) (time.Time, bool)) error {
	if keep <= 0 {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("rotate backups: %w", err)
	}
	type backupFile struct {
		name string
		at   time.Time
	}
	var files []backupFile
	var errs []error
	for _, e := range entries {
		n := e.Name()
		if !e.Type().IsRegular() {
			continue
		}
		if at, ok := stampOf(n); ok {
			files = append(files, backupFile{n, at})
		}
		if tmp, ok := strings.CutSuffix(n, ".tmp"); ok {
			if _, ok := stampOf(tmp); ok {
				if info, err := e.Info(); err == nil && time.Since(info.ModTime()) > time.Hour {
					errs = append(errs, os.Remove(filepath.Join(dir, n)))
				}
			}
		}
	}
	slices.SortFunc(files, func(a, b backupFile) int { // newest first
		if c := b.at.Compare(a.at); c != 0 {
			return c
		}
		return strings.Compare(b.name, a.name)
	})
	for _, f := range files[min(keep, len(files)):] {
		if err := os.Remove(filepath.Join(dir, f.name)); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
