package store

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBackupWhileWriting(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	if _, err := st.CreateAsset(ctx, Asset{Name: "before", Kind: "package", Criticality: "low", Source: "manual"}); err != nil {
		t.Fatal(err)
	}
	// A writer keeps going during the backup.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 50; i++ {
			st.CreateAsset(ctx, Asset{Name: "during", Kind: "package", Criticality: "low", Source: "manual"})
		}
	}()
	dest := filepath.Join(t.TempDir(), "copy.db")
	if err := st.Backup(ctx, dest); err != nil {
		t.Fatal(err)
	}
	<-done

	copyStore, err := Open(ctx, dest)
	if err != nil {
		t.Fatal(err)
	}
	defer copyStore.Close()
	assets, err := copyStore.ListAssets(ctx)
	if err != nil || len(assets) == 0 || assets[0].Name == "" {
		t.Fatalf("restored assets = %v, %v", assets, err)
	}
	if info, err := os.Stat(dest); err != nil || (info.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/') {
		t.Errorf("backup permissions: %v %v", info.Mode(), err)
	}
}

func TestRotateBackups(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		os.WriteFile(filepath.Join(dir, BackupName(base.Add(time.Duration(i)*time.Hour))), nil, 0o600)
	}
	os.WriteFile(filepath.Join(dir, "unrelated.db"), nil, 0o600)
	if err := RotateBackups(dir, 2); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	want := []string{"unrelated.db", BackupName(base.Add(3 * time.Hour)), BackupName(base.Add(4 * time.Hour))}
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
	for _, n := range []string{"vigil-avant-maj.db", "vigil-2026-01-01.db", BackupName(base), BackupName(base.Add(time.Hour))} {
		os.WriteFile(filepath.Join(dir, n), nil, 0o600)
	}
	if err := RotateBackups(dir, 1); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 3 {
		t.Errorf("after rotation: %d files, want the 2 manual copies and the newest backup", len(entries))
	}
	if _, err := os.Stat(filepath.Join(dir, BackupName(base))); !os.IsNotExist(err) {
		t.Error("oldest scheduled backup kept")
	}
}

// Temporary files of interrupted backups are removed once clearly
// abandoned; only the newest copies taken before a schema upgrade are kept.
func TestBackupLeftovers(t *testing.T) {
	dir := t.TempDir()
	stale := filepath.Join(dir, BackupName(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))+".tmp")
	fresh := filepath.Join(dir, BackupName(time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC))+".tmp")
	os.WriteFile(stale, nil, 0o600)
	os.WriteFile(fresh, nil, 0o600)
	old := time.Now().Add(-2 * time.Hour)
	os.Chtimes(stale, old, old)
	if err := RotateBackups(dir, 5); err != nil {
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
