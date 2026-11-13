// Package storetest gives the tests a database and its fixtures: a migrated
// database removed at the end of the test, an asset, a finding, a snapshot of
// every row, and the store methods reserved to the synchronisation.
//
// Only tests import it. It imports package store, so the internal tests of
// store cannot: those that need it are external tests (package store_test),
// which reach the few internals they use through store's export_test.go.
package storetest

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/store"
)

// Open opens a new migrated database in a directory of the test; it is
// closed, then removed, at the end of the test.
func Open(t testing.TB) *store.Store {
	t.Helper()
	return OpenAt(t, filepath.Join(TempDir(t), "test.db"))
}

// OpenAt opens the database at path, created and migrated if needed, for a
// test that also reaches the file from outside the store; it is closed at the
// end of the test.
func OpenAt(t testing.TB, path string) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Errorf("close the test database: %v", err)
		}
	})
	return st
}

// TempDir is t.TempDir for database files. Its removal is retried for a
// moment: under Windows, an antivirus that scans a file just closed holds it
// a little longer, and the directory is then "not empty", an error that the
// removal by package testing does not retry.
func TempDir(t testing.TB) string {
	t.Helper()
	dir := t.TempDir()
	// Registered after t.TempDir, so run before its removal, which then
	// finds nothing left, or reports what this one could not remove.
	t.Cleanup(func() {
		deadline := time.Now().Add(2 * time.Second)
		for os.RemoveAll(dir) != nil && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
	})
	return dir
}

// Asset creates the asset as given, in no particular scope.
func Asset(t testing.TB, st *store.Store, a store.Asset) int64 {
	t.Helper()
	id, err := st.CreateAsset(context.Background(), store.Everything, a)
	if err != nil {
		t.Fatalf("create asset %q: %v", a.Name, err)
	}
	return id
}

// Finding records the vulnerability as given, and its finding on the asset
// seen at the time given, as a synchronisation would; it returns the
// identifier of the finding.
func Finding(t testing.TB, st *store.Store, assetID int64, v store.Vulnerability, seen time.Time) int64 {
	t.Helper()
	ctx := context.Background()
	if err := st.UpsertVulnerability(ctx, v); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ObserveFinding(ctx, assetID, v.ID, "", seen); err != nil {
		t.Fatal(err)
	}
	list, err := st.ListFindingTriage(ctx, assetID)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range list {
		if f.VulnID == v.ID {
			return f.ID
		}
	}
	t.Fatalf("no finding of %s on asset %d", v.ID, assetID)
	return 0
}

// Snapshot reads every row of every table of db, as text, in rowid order:
// two snapshots are equal when nothing was written in between.
func Snapshot(t testing.TB, db *sql.DB) map[string][]map[string]string {
	t.Helper()
	out, err := snapshot(context.Background(), db)
	if err != nil {
		t.Fatalf("snapshot of the database: %v", err)
	}
	return out
}

func snapshot(ctx context.Context, db *sql.DB) (map[string][]map[string]string, error) {
	tables, err := readRows(ctx, db, `SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		return nil, err
	}
	out := map[string][]map[string]string{}
	for _, table := range tables {
		list, err := readRows(ctx, db, `SELECT * FROM "`+table["name"]+`" ORDER BY rowid`)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", table["name"], err)
		}
		if len(list) > 0 {
			out[table["name"]] = list
		}
	}
	return out, nil
}

// readRows reads every row of a query, each value as text by column name.
func readRows(ctx context.Context, db *sql.DB, query string) ([]map[string]string, error) {
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close() // after a failure; a no-op once closed below
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	var list []map[string]string
	for rows.Next() {
		values := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range values {
			ptrs[i] = &values[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		row := map[string]string{}
		for i, c := range cols {
			row[c] = fmt.Sprintf("%v", values[i])
			if b, ok := values[i].([]byte); ok {
				row[c] = string(b)
			}
		}
		list = append(list, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return list, rows.Close()
}

// SystemMethods are the store methods reserved to the synchronisation, the
// notifications and the generation of digests, with the reason: they take
// no Scope, and internal/web must not call them.
var SystemMethods = map[string]string{}

func init() {
	for reason, names := range map[string][]string{
		"synchronisation, notifications and digest generation only": {
			"ObserveFinding", "InTrackedPeriod", "AutoResolveStale", "SetOlderVulns", "ListFindingTriage", "FoldFindings",
			"UpsertVulnerability", "VulnModified", "SetExploitSignals", "ListVulnCVEs", "MarkAlerted",
			"CreateDigest", "LastDigestTime"},
		"synchronisation only; the store also applies the rules when one is created (CreateDismissalRule)": {
			"ApplyDismissalRules"},
		"OSV reports for a package version, shared by the assets that ask for it, for the synchronisation only": {
			"OSVList", "SaveOSVList", "PurgeOSVLists"},
	} {
		for _, name := range names {
			SystemMethods[name] = reason
		}
	}
}
