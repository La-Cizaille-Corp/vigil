package store

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The tests of this package come in two kinds. External tests (package
// store_test) use internal/storetest, which imports this package and so
// cannot be imported by internal tests; they reach the few internals they
// need through the names below, compiled with the tests only. Internal tests
// (package store) test unexported code and open their database with openTest.

// DB is the connection pool of the store, for the SQL a test writes itself.
func DB(st *Store) *sql.DB { return st.db }

var (
	ErrNewerSchema   = errNewerSchema
	ErrOutsideGroups = errOutsideGroups
	OpenReadOnly     = openReadOnly
	ExtractCVEs      = extractCVEs
	DefaultSLA       = defaultSLA
)

// Migration is a migration file.
type Migration struct {
	Version    int
	Name, Body string
}

// Migrations lists the migration files, in order.
func Migrations() ([]Migration, error) {
	list, err := migrations()
	out := make([]Migration, len(list))
	for i, m := range list {
		out[i] = Migration{Version: m.version, Name: m.name, Body: m.body}
	}
	return out, err
}

// openTest is storetest.Open for the internal tests.
func openTest(t *testing.T) *Store {
	t.Helper()
	st, err := Open(context.Background(), filepath.Join(tempDir(t), "test.db"))
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

// tempDir is storetest.TempDir for the internal tests: its removal is
// retried for a moment, an antivirus holding a database just closed.
func tempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Cleanup(func() {
		deadline := time.Now().Add(2 * time.Second)
		for os.RemoveAll(dir) != nil && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
	})
	return dir
}
