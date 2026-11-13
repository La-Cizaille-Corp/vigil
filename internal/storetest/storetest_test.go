package storetest_test

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/store"
	"github.com/La-Cizaille-Corp/vigil/internal/storetest"
)

// The fixtures write what they are given and return what they wrote.
func TestFixtures(t *testing.T) {
	ctx := context.Background()
	st := storetest.Open(t)
	id := storetest.Asset(t, st, store.Asset{Name: "nginx", Kind: "technology", Criticality: "high", Source: "manual"})
	seen := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	first := storetest.Finding(t, st, id, store.Vulnerability{ID: "CVE-1", Severity: "HIGH", EPSS: -1, CVSS: 7.5}, seen)
	second := storetest.Finding(t, st, id, store.Vulnerability{ID: "CVE-2", Severity: "LOW", EPSS: -1, CVSS: 2}, seen)
	for want, fid := range map[string]int64{"CVE-1": first, "CVE-2": second} {
		f, err := st.Finding(ctx, store.Everything, fid)
		if err != nil || f.VulnID != want || f.AssetID != id || !f.FirstSeen.Equal(seen) {
			t.Errorf("finding %d: %+v, %v; want %s on %d", fid, f, err, want, id)
		}
	}
	if again := storetest.Finding(t, st, id, store.Vulnerability{ID: "CVE-1", Severity: "HIGH", EPSS: -1, CVSS: 7.5}, seen); again != first {
		t.Errorf("seen again: finding %d, want %d", again, first)
	}
}

// A snapshot changes with any write, and only then.
func TestSnapshot(t *testing.T) {
	path := filepath.Join(storetest.TempDir(t), "test.db")
	st := storetest.OpenAt(t, path)
	ctx := context.Background()
	db, err := sql.Open("sqlite", path) // another connection, registered by package store
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	before := storetest.Snapshot(t, db)
	if again := storetest.Snapshot(t, db); !reflect.DeepEqual(again, before) {
		t.Error("two snapshots differ without a write")
	}
	if err := st.SetSetting(ctx, "k", "v"); err != nil {
		t.Fatal(err)
	}
	after := storetest.Snapshot(t, db)
	if reflect.DeepEqual(after, before) {
		t.Error("a write left the snapshot as it was")
	}
	if rows := after["settings"]; len(rows) == 0 || rows[len(rows)-1]["value"] != "v" {
		t.Errorf("settings: %v", rows)
	}
}

// The directory of a test database is removed at the end of the test.
func TestTempDirRemoved(t *testing.T) {
	var dir string
	t.Run("database", func(t *testing.T) {
		dir = storetest.TempDir(t)
		storetest.OpenAt(t, filepath.Join(dir, "test.db"))
	})
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("%s left: %v", dir, err)
	}
}
