package store_test

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
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/auth"

	"github.com/La-Cizaille-Corp/vigil/internal/store"
	"github.com/La-Cizaille-Corp/vigil/internal/storetest"
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
	// 0.3.0
	"008_track_since.sql":   "a0c79375395fa37eca683197f284b4fd354a9468eeb34c3b78e1b94f90297ba0",
	"009_notifications.sql": "99a78d86daa59bdde8b87def37f593e73b63790b815bf91a007856cc1b5c6622",
	"010_asset_tags.sql":    "11a059f8323e00223237413263469d7b295acb953476d2ffb858a6ffaea0237d",
	"011_user_status.sql":   "ffc940f22e84eb77b67bde243b35814e3d03e2b67006ea2519ee6350604fb19e",
	"012_asset_retired.sql": "112f2eea05a0537e78a4bf5c5c70505c55fb2954c14bef71f5a38d9cfd289c13",
	// 0.4.0
	"013_vulnerability_news.sql": "2db704d262cde0239048081ae1ab11842ad1fc4ad03207473b4d21ea810aa393",
	"014_dismissal_rules.sql":    "cde67f593e03fc9a8eb357fd0075f2d963a181fab50837e044eb487bf4d32dbb",
	// 0.4.1
	"015_finding_fixed_in.sql": "d17b3ba0ad9efc6d3c878e991fcad3d8ffe66e3fe2a3888bad4de8d549b6ec42",
	// 0.5.0
	"016_history_indexes.sql":          "076c2cb502f9bdd3d6d247fdc5cb19008f97f4aa050e2a045a55958be86d9c63",
	"017_asset_groups.sql":             "2d5166fa82920d11bf1e2072b4baaccaeb559dcc0d258ea1b45c08a165076108",
	"018_group_channels.sql":           "687774aec094144e0ef50995ece82eadbf5dd3ef75c5ac71e7c307b7a4a47b20",
	"019_finding_folded.sql":           "187280da9a05de6ce3c22fa92d6dc7ea8b2b3e9f9ded47304f59dd67b8699a3c",
	"020_osv_lists.sql":                "4f0a7c9ded452840e19f698c204bbf3b7295ad0df888ec5f26ad7e0ef953b1b3",
	"021_vulnerability_list_index.sql": "ed030f51baa1a1e84d55d598860c579e778733f0dff3beeafc7f66e84bba27db",
}

func TestMigrationsFrozen(t *testing.T) {
	list, err := store.Migrations()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range list {
		sum := sha256.Sum256([]byte(strings.ReplaceAll(m.Body, "\r\n", "\n")))
		if want, ok := releasedMigrations[m.Name]; ok && hex.EncodeToString(sum[:]) != want {
			t.Errorf("%s was released and must not change: add a new migration instead", m.Name)
		}
	}
	for i := 1; i < len(list); i++ {
		if list[i].Version == list[i-1].Version {
			t.Errorf("two migrations share version %d", list[i].Version)
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
			path := filepath.Join(storetest.TempDir(t), "vigil.db")
			before, oldVersion := loadDump(t, path, dump)

			st, err := store.Open(ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			if v, _ := st.SchemaVersion(ctx); v != store.LatestSchema() {
				t.Fatalf("schema %d after upgrade, want %d", v, store.LatestSchema())
			}

			// The copy written before the upgrade is the old database, intact.
			// The fixture of the latest release has nothing to upgrade until
			// the next migration: it is then only reopened.
			backup := st.UpgradeBackup()
			if oldVersion == store.LatestSchema() {
				if backup != "" {
					t.Errorf("a copy was written without a pending migration: %q", backup)
				}
			} else {
				if !strings.Contains(backup, fmt.Sprintf(".schema-%d.", oldVersion)) {
					t.Fatalf("upgrade backup: %q", backup)
				}
				if err := store.CheckIntegrity(ctx, backup); err != nil {
					t.Fatal(err)
				}
				if got := snapshotFile(t, backup); !reflect.DeepEqual(got, before) {
					t.Error("the pre-upgrade copy differs from the original database")
				}
			}

			// Every row and every value written by the old version is still there.
			after := storetest.Snapshot(t, store.DB(st))
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

			checkUpgradedData(ctx, t, st, oldVersion)

			// Opening again applies nothing and writes no second copy.
			st.Close()
			again, err := store.Open(ctx, path)
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
// oldVersion is the schema the release wrote the database with.
func checkUpgradedData(ctx context.Context, t *testing.T, st *store.Store, oldVersion int) {
	t.Helper()
	admin, err := st.UserByName(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := auth.VerifyPassword("un-mot-de-passe-solide", admin.PasswordHash); !ok || admin.Role != "admin" {
		t.Error("the administrator can no longer log in")
	}
	findings, err := st.ListFindings(ctx, store.Everything, store.FindingFilter{})
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
	// Migration 019 folds nothing (A80): the next synchronisation does, with
	// what the sources report. Every finding of an older release is still
	// listed; from 0.5.0, the fixture holds the rows its sync folded.
	var folded int
	if err := store.DB(st).QueryRowContext(ctx, `SELECT COUNT(*) FROM findings WHERE folded_into <> 0`).Scan(&folded); err != nil {
		t.Fatal(err)
	}
	if oldVersion < 19 && folded != 0 {
		t.Errorf("%d findings folded by the upgrade, want none", folded)
	}
	assets, err := st.ListAssets(ctx, store.Everything)
	if err != nil || len(assets) < 4 {
		t.Fatalf("assets: %d, %v", len(assets), err)
	}
	for _, a := range assets {
		if a.CPEMode == "recent" {
			t.Errorf("%s still uses the sliding NVD mode", a.Name)
		}
	}
	// The 0.1.0 and 0.2.0 fixtures carry a hand-written "watch_countries" row;
	// from 0.3.0 the fixture holds the key the application really uses.
	watched, _ := st.Setting(ctx, "cti_countries")
	if legacy, _ := st.Setting(ctx, "watch_countries"); legacy != "" {
		watched = legacy
	}
	if watched != "FR,BE" {
		t.Errorf("watch setting: %q", watched)
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
	hooks, _ := st.ListWebhooks(ctx)
	if !slices.ContainsFunc(hooks, func(h store.Webhook) bool { return h.Name == "Équipe sécu" && h.Group == 0 }) {
		t.Errorf("webhooks: %+v", hooks)
	}
	if _, err := st.DashboardStats(ctx, store.Everything, time.Now()); err != nil {
		t.Error(err)
	}
	// T9: every account of a release before 0.5.0 keeps access to everything
	// (migration 017, A68), and sees as many assets and findings as before.
	// From 0.5.0, an account limited to groups stays limited.
	users, err := st.ListUsers(ctx)
	if err != nil || len(users) == 0 {
		t.Fatalf("users: %d, %v", len(users), err)
	}
	for _, u := range users {
		mine, err := st.ListAssets(ctx, u.Scope())
		if err != nil {
			t.Fatal(err)
		}
		seen, err := st.ListFindings(ctx, u.Scope(), store.FindingFilter{})
		if err != nil {
			t.Fatal(err)
		}
		limited := oldVersion >= 17 && u.Restricted()
		full := len(mine) == len(assets) && len(seen) == len(findings)
		if (!limited && (!u.Access.All || !full)) || (limited && (full || len(mine) == 0)) {
			t.Errorf("%s (%s): access %+v, %d assets of %d, %d findings of %d", u.Username, u.Role, u.Access,
				len(mine), len(assets), len(seen), len(findings))
		}
	}
}

func TestRefuseNewerSchema(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(storetest.TempDir(t), "vigil.db")
	st, err := store.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB(st).ExecContext(ctx, `INSERT INTO schema_migrations (version) VALUES (?)`, store.LatestSchema()+1); err != nil {
		t.Fatal(err)
	}
	st.Close()
	if _, err := store.Open(ctx, path); !errors.Is(err, store.ErrNewerSchema) {
		t.Fatalf("a database from a newer version was opened: %v", err)
	}
}

func TestNewDatabaseNeedsNoBackup(t *testing.T) {
	path := filepath.Join(storetest.TempDir(t), "vigil.db")
	st, err := store.Open(context.Background(), path)
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
	return storetest.Snapshot(t, db), version
}

func snapshotFile(t *testing.T, path string) map[string][]map[string]string {
	t.Helper()
	db, err := store.OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	return storetest.Snapshot(t, db)
}

// A backup taken with a newer binary before an upgrade copies the database
// as it is, without upgrading it first.
func TestBackupFileKeepsSchema(t *testing.T) {
	ctx := context.Background()
	dir := storetest.TempDir(t)
	src := filepath.Join(dir, "vigil.db")
	before, version := loadDump(t, src, "testdata/upgrade/v0.2.0.sql")
	dest := filepath.Join(dir, "copy.db")
	if err := store.BackupFile(ctx, src, dest); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{src, dest} {
		if v, err := store.FileSchema(ctx, path); err != nil || v != version {
			t.Errorf("%s: schema %d (%v), want %d", filepath.Base(path), v, err, version)
		}
	}
	if !reflect.DeepEqual(snapshotFile(t, dest), before) {
		t.Error("the backup differs from the database")
	}
	if err := store.BackupFile(ctx, filepath.Join(dir, "missing.db"), filepath.Join(dir, "x.db")); err == nil {
		t.Error("backup of a missing database")
	}
}
