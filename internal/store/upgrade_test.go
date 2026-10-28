package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/auth"
)

// releasedMigrations are the checksums of migrations shipped in a release.
// A released migration must never change: databases that already applied it
// would not get the change. Add a line when a release ships a new migration.
var releasedMigrations = map[string]string{
	"001_init.sql":           "77bab682ec7fb7397fd8c964d2f32a7641e6e7d71b5996bcaa635e2cea1ba038",
	"002_enrichment_cti.sql": "021393522c94953f08d08dcad81ff22e70950a47483f9b93dd9edb2e8db40cab",
	"003_api_tokens.sql":     "9b49610bede551eca6094bbded47ace97c3efb99df7ea1eea4f9e235731eb805",
	"004_totp.sql":           "562b9c6500911d75b6cbdfc38a19f9589f502a6d3430bf0f2876d26d1c8dba47",
	"005_cpe_scope.sql":      "3af2f175d2e3ea441440a238399572ecad169b50378676d3f2cf30526bd5d9d2",
	"006_cvss.sql":           "77cffaa46ed21d8ea8235ee724740bd5fd8145075ffe2a316e710070ca18397f",
	"007_regulations.sql":    "2f0e538b2fbbbe3a0a01bcf1c7e20acafc68bebf7a03816928e564da41c81075",
}

func TestMigrationsFrozen(t *testing.T) {
	list, err := migrations()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range list {
		sum := sha256.Sum256([]byte(strings.ReplaceAll(m.body, "\r\n", "\n")))
		if want, ok := releasedMigrations[m.name]; ok && hex.EncodeToString(sum[:]) != want {
			t.Errorf("%s was released and must not change: add a new migration instead", m.name)
		}
	}
	for i := 1; i < len(list); i++ {
		if list[i].version == list[i-1].version {
			t.Errorf("two migrations share version %d", list[i].version)
		}
	}
}

// transformed lists the columns that a migration rewrites on purpose; every
// other value written by an older version must survive the upgrade as is.
var transformed = map[string]bool{
	"vulnerabilities.modified": true, // 006: forces a refetch to fill the CVSS score
	"assets.cpe_mode":          true, // 008: sliding "recent" mode becomes "all" + start date
}

// TestUpgradeFromReleases opens databases written by every past release
// (testdata/upgrade/vX.Y.Z.sql, produced by the released binaries: users,
// SBOM import, real sync, triage, feeds, webhooks, digest) with this version.
func TestUpgradeFromReleases(t *testing.T) {
	dumps, _ := filepath.Glob("testdata/upgrade/*.sql")
	if len(dumps) < 2 {
		t.Fatal("missing release fixtures")
	}
	for _, dump := range dumps {
		t.Run(filepath.Base(dump), func(t *testing.T) {
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "vigil.db")
			before, oldVersion := loadDump(t, path, dump)

			st, err := Open(ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			if v, _ := st.SchemaVersion(ctx); v != LatestSchema() {
				t.Fatalf("schema %d after upgrade, want %d", v, LatestSchema())
			}

			// The copy written before the upgrade is the old database, intact.
			backup := st.UpgradeBackup()
			if !strings.Contains(backup, fmt.Sprintf(".schema-%d.", oldVersion)) {
				t.Fatalf("upgrade backup: %q", backup)
			}
			if err := CheckIntegrity(ctx, backup); err != nil {
				t.Fatal(err)
			}
			if got := snapshotFile(t, backup); !reflect.DeepEqual(got, before) {
				t.Error("the pre-upgrade copy differs from the original database")
			}

			// Every row and every value written by the old version is still there.
			after := snapshot(t, st.db)
			for table, rows := range before {
				if table == "schema_migrations" {
					continue
				}
				newRows := after[table]
				if len(newRows) < len(rows) {
					t.Errorf("%s: %d rows before, %d after", table, len(rows), len(newRows))
					continue
				}
				for i, row := range rows {
					for col, v := range row {
						if !transformed[table+"."+col] && newRows[i][col] != v {
							t.Errorf("%s row %d, %s: %q became %q", table, i, col, v, newRows[i][col])
						}
					}
				}
			}

			checkUpgradedData(ctx, t, st)

			// Opening again applies nothing and writes no second copy.
			st.Close()
			again, err := Open(ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			if again.UpgradeBackup() != "" {
				t.Error("a second copy was written without a pending migration")
			}
			again.Close()
		})
	}
}

// checkUpgradedData reads the upgraded database through the application code.
func checkUpgradedData(ctx context.Context, t *testing.T, st *Store) {
	t.Helper()
	admin, err := st.UserByName(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := auth.VerifyPassword("un-mot-de-passe-solide", admin.PasswordHash); !ok || admin.Role != "admin" {
		t.Error("the administrator can no longer log in")
	}
	findings, err := st.ListFindings(ctx, FindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	triaged := 0
	for _, f := range findings {
		if f.Status != "in_triage" && strings.Contains(f.Comment, "« manuelle »") {
			triaged++
		}
	}
	if triaged != 3 {
		t.Errorf("%d triaged findings kept, want 3", triaged)
	}
	assets, err := st.ListAssets(ctx)
	if err != nil || len(assets) < 4 {
		t.Fatalf("assets: %d, %v", len(assets), err)
	}
	for _, a := range assets {
		if a.CPEMode == "recent" {
			t.Errorf("%s still uses the sliding NVD mode", a.Name)
		}
	}
	if v, _ := st.Setting(ctx, "watch_countries"); v != "FR,BE" {
		t.Errorf("watch setting: %q", v)
	}
	feeds, _ := st.ListFeeds(ctx)
	custom := false
	for _, f := range feeds {
		custom = custom || (f.Name == "Flux maison" && f.Country == "BE")
		if f.Name == "The Hacker News" && f.Enabled {
			t.Error("a disabled feed was enabled again")
		}
	}
	if !custom {
		t.Error("custom feed lost")
	}
	if hooks, _ := st.ListWebhooks(ctx); len(hooks) != 1 || hooks[0].Name != "Équipe sécu" {
		t.Errorf("webhooks: %+v", hooks)
	}
	if _, err := st.DashboardStats(ctx, time.Now()); err != nil {
		t.Error(err)
	}
}

func TestRefuseNewerSchema(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "vigil.db")
	st, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, `INSERT INTO schema_migrations (version) VALUES (?)`, LatestSchema()+1); err != nil {
		t.Fatal(err)
	}
	st.Close()
	if _, err := Open(ctx, path); !errors.Is(err, ErrNewerSchema) {
		t.Fatalf("a database from a newer version was opened: %v", err)
	}
}

func TestNewDatabaseNeedsNoBackup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vigil.db")
	st, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if st.UpgradeBackup() != "" {
		t.Error("backup of an empty database")
	}
	if files, _ := filepath.Glob(path + ".schema-*"); len(files) != 0 {
		t.Errorf("unexpected files: %v", files)
	}
}

// loadDump creates path from a SQL dump and returns its content and schema version.
func loadDump(t *testing.T, path, dump string) (map[string][]map[string]string, int) {
	t.Helper()
	body, err := os.ReadFile(dump) // #nosec G304 -- test fixture
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(string(body)); err != nil {
		t.Fatal(err)
	}
	var version int
	if err := db.QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	return snapshot(t, db), version
}

func snapshotFile(t *testing.T, path string) map[string][]map[string]string {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	return snapshot(t, db)
}

// snapshot returns every row of every table, as text, in rowid order.
func snapshot(t *testing.T, db *sql.DB) map[string][]map[string]string {
	t.Helper()
	var tables []string
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var n string
		rows.Scan(&n)
		tables = append(tables, n)
	}
	rows.Close()
	out := map[string][]map[string]string{}
	for _, table := range tables {
		rows, err := db.Query(`SELECT * FROM "` + table + `" ORDER BY rowid`)
		if err != nil {
			t.Fatal(err)
		}
		cols, _ := rows.Columns()
		for rows.Next() {
			values := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range values {
				ptrs[i] = &values[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				t.Fatal(err)
			}
			row := map[string]string{}
			for i, c := range cols {
				row[c] = fmt.Sprintf("%v", values[i])
				if b, ok := values[i].([]byte); ok {
					row[c] = string(b)
				}
			}
			out[table] = append(out[table], row)
		}
		rows.Close()
	}
	return out
}

// A backup taken with a newer binary before an upgrade copies the database
// as it is, without upgrading it first.
func TestBackupFileKeepsSchema(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	src := filepath.Join(dir, "vigil.db")
	before, version := loadDump(t, src, "testdata/upgrade/v0.2.0.sql")
	dest := filepath.Join(dir, "copy.db")
	if err := BackupFile(ctx, src, dest); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{src, dest} {
		if v, err := FileSchema(ctx, path); err != nil || v != version {
			t.Errorf("%s: schema %d (%v), want %d", filepath.Base(path), v, err, version)
		}
	}
	if !reflect.DeepEqual(snapshotFile(t, dest), before) {
		t.Error("the backup differs from the database")
	}
	if err := BackupFile(ctx, filepath.Join(dir, "missing.db"), filepath.Join(dir, "x.db")); err == nil {
		t.Error("backup of a missing database")
	}
}
