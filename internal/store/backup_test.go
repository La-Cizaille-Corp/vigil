package store

import (
	"context"
	"os"
	"path/filepath"
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
