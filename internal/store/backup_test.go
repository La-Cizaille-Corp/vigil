package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// A database is opened, copied and checked where it is, whatever the
// characters of its folder: "#" made the read-only opening of a copy read an
// empty database created beside the folder, "%41" was decoded, and "?" cut
// the name given to the driver.
func TestDatabaseInAnyFolder(t *testing.T) {
	ctx := context.Background()
	names := []string{"hash#x", "cent%41", "sp ace"}
	if runtime.GOOS != "windows" { // a reserved character of Windows file names
		names = append(names, "q?x")
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			parent := tempDir(t)
			dir := filepath.Join(parent, name)
			path := filepath.Join(dir, "vigil.db")
			st, err := Open(ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := st.CreateAsset(ctx, Everything, Asset{Name: "nginx", Kind: "technology", Criticality: "low", Source: "manual"}); err != nil {
				t.Fatal(err)
			}
			var fk int
			if err := st.db.QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&fk); err != nil || fk != 1 {
				t.Errorf("foreign keys %d, %v: the options of the connection were lost", fk, err)
			}
			if _, err := st.BackupTo(ctx, dir, 3); err != nil {
				t.Errorf("scheduled backup: %v", err)
			}
			st.Close()

			if v, err := FileSchema(ctx, path); err != nil || v != LatestSchema() {
				t.Errorf("FileSchema = %d, %v; want %d", v, err, LatestSchema())
			}
			if err := CheckIntegrity(ctx, path); err != nil {
				t.Error(err)
			}
			copyPath := filepath.Join(dir, "copy.db")
			if err := BackupFile(ctx, path, copyPath); err != nil {
				t.Fatal(err)
			}
			cp, err := Open(ctx, copyPath)
			if err != nil {
				t.Fatal(err)
			}
			defer cp.Close()
			if list, err := cp.ListAssets(ctx, Everything); err != nil || len(list) != 1 {
				t.Errorf("the copy holds %d assets (%v), want the database's 1", len(list), err)
			}
			entries, _ := os.ReadDir(parent)
			var beside []string
			for _, e := range entries {
				beside = append(beside, e.Name())
			}
			if !slices.Equal(beside, []string{name}) {
				t.Errorf("files written beside the folder: %v", beside)
			}
		})
	}
}

func TestBackupWhileWriting(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	if _, err := st.CreateAsset(ctx, Everything, Asset{Name: "before", Kind: "package", Criticality: "low", Source: "manual"}); err != nil {
		t.Fatal(err)
	}
	// A writer keeps going during the backup.
	done := make(chan error)
	go func() {
		var errs []error
		for range 50 {
			_, err := st.CreateAsset(ctx, Everything, Asset{Name: "during", Kind: "package", Criticality: "low", Source: "manual"})
			errs = append(errs, err)
		}
		done <- errors.Join(errs...)
	}()
	dest := filepath.Join(tempDir(t), "copy.db")
	err := backup(ctx, st.db, dest)
	if werr := <-done; werr != nil {
		t.Errorf("writer during the backup: %v", werr)
	}
	if err != nil {
		t.Fatal(err)
	}

	copyStore, err := Open(ctx, dest)
	if err != nil {
		t.Fatal(err)
	}
	defer copyStore.Close()
	assets, err := copyStore.ListAssets(ctx, Everything)
	if err != nil || len(assets) == 0 || assets[0].Name == "" {
		t.Fatalf("restored assets = %v, %v", assets, err)
	}
	if info, err := os.Stat(dest); err != nil || (info.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/') {
		t.Errorf("backup permissions: %v %v", info.Mode(), err)
	}
}

// A scheduled backup is a whole copy of the database, named after its time,
// and the oldest scheduled backups beyond the number kept are deleted, the
// files of the directory it did not write kept.
func TestScheduledBackup(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	if _, err := st.CreateAsset(ctx, Everything, Asset{Name: "nginx", Kind: "technology", Criticality: "low", Source: "manual"}); err != nil {
		t.Fatal(err)
	}
	dir := tempDir(t)
	old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, name := range []string{backupName(old), backupName(old.Add(time.Hour)), "vigil-avant-maj.db"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	before := time.Now().UTC().Truncate(time.Second)
	dest, err := st.BackupTo(ctx, dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	if at, ok := backupStamp(filepath.Base(dest)); !ok || filepath.Dir(dest) != dir || at.Before(before) || at.After(time.Now()) {
		t.Errorf("backup %s: not a scheduled backup of now in %s", dest, dir)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	want := []string{backupName(old.Add(time.Hour)), filepath.Base(dest), "vigil-avant-maj.db"}
	slices.Sort(want)
	if !slices.Equal(names, want) {
		t.Errorf("after the backup: %v, want %v", names, want)
	}
	copyStore, err := Open(ctx, dest)
	if err != nil {
		t.Fatal(err)
	}
	defer copyStore.Close()
	if assets, err := copyStore.ListAssets(ctx, Everything); err != nil || len(assets) != 1 || assets[0].Name != "nginx" {
		t.Errorf("backed up assets: %+v, %v", assets, err)
	}
}

func TestRotateBackups(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		os.WriteFile(filepath.Join(dir, backupName(base.Add(time.Duration(i)*time.Hour))), nil, 0o600)
	}
	os.WriteFile(filepath.Join(dir, "unrelated.db"), nil, 0o600)
	if err := rotateBackups(dir, 2); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	want := []string{"unrelated.db", backupName(base.Add(3 * time.Hour)), backupName(base.Add(4 * time.Hour))}
	if len(names) != 3 {
		t.Fatalf("after rotation: %v, want %v", names, want)
	}
	for _, w := range want {
		found := false
		for _, n := range names {
			found = found || n == w
		}
		if !found {
			t.Errorf("missing %s in %v", w, names)
		}
	}
}

// A copy made by hand next to the scheduled backups is neither counted nor
// deleted by the rotation.
func TestRotateKeepsManualCopies(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, n := range []string{"vigil-avant-maj.db", "vigil-2026-01-01.db", backupName(base), backupName(base.Add(time.Hour))} {
		os.WriteFile(filepath.Join(dir, n), nil, 0o600)
	}
	if err := rotateBackups(dir, 1); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 3 {
		t.Errorf("after rotation: %d files, want the 2 manual copies and the newest backup", len(entries))
	}
	if _, err := os.Stat(filepath.Join(dir, backupName(base))); !os.IsNotExist(err) {
		t.Error("oldest scheduled backup kept")
	}
}

// Temporary files of interrupted backups are removed once clearly
// abandoned; only the newest copies taken before a schema upgrade are kept.
func TestBackupLeftovers(t *testing.T) {
	dir := t.TempDir()
	stale := filepath.Join(dir, backupName(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))+".tmp")
	fresh := filepath.Join(dir, backupName(time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC))+".tmp")
	os.WriteFile(stale, nil, 0o600)
	os.WriteFile(fresh, nil, 0o600)
	old := time.Now().Add(-2 * time.Hour)
	os.Chtimes(stale, old, old)
	if err := rotateBackups(dir, 5); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Error("abandoned temporary backup kept")
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Error("temporary file of a running backup removed")
	}

	db := filepath.Join(dir, "vigil.db")
	for i := range 5 {
		p := fmt.Sprintf("%s.schema-%d.2026010%d-000000.bak", db, 8+i, i+1)
		os.WriteFile(p, nil, 0o600)
		mod := time.Now().Add(time.Duration(i-10) * time.Hour)
		os.Chtimes(p, mod, mod)
	}
	pruneUpgradeBackups(db, 3)
	matches, _ := filepath.Glob(db + ".schema-*.bak")
	if len(matches) != 3 {
		t.Fatalf("upgrade copies kept: %v", matches)
	}
	for _, m := range matches {
		if strings.Contains(m, "schema-8.") || strings.Contains(m, "schema-9.") {
			t.Errorf("oldest copy kept: %s", m)
		}
	}
}

// The copies taken before an upgrade are ordered by the time in their name,
// as the scheduled backups are: a copy moved or restored by hand gets a new
// date, not a new age. A file the upgrade did not write is left alone.
func TestUpgradeBackupsPrunedByName(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "vigil.db")
	for i := range 4 {
		p := fmt.Sprintf("%s.schema-%d.2026010%d-000000.bak", db, 8+i, i+1)
		os.WriteFile(p, nil, 0o600)
	}
	// The oldest copy was copied back last.
	recent := time.Now()
	os.Chtimes(db+".schema-8.20260101-000000.bak", recent, recent)
	manual := db + ".schema-9.avant-maj.bak"
	os.WriteFile(manual, nil, 0o600)
	old := time.Now().Add(-48 * time.Hour)
	os.Chtimes(manual, old, old)

	if err := pruneUpgradeBackups(db, 3); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(db + ".schema-8.20260101-000000.bak"); !os.IsNotExist(err) {
		t.Error("oldest copy kept because of its file date")
	}
	if _, err := os.Stat(manual); err != nil {
		t.Errorf("copy made by hand removed: %v", err)
	}
	if matches, _ := filepath.Glob(db + ".schema-*.2026*.bak"); len(matches) != 3 {
		t.Errorf("upgrade copies kept: %v", matches)
	}
}
