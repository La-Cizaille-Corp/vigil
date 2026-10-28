package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// These tests pin the behaviour of the storage layer independently of the
// SQLite driver: they are the safety net for a driver change (see
// docs/DEPENDENCIES.md, "Plan B").

func TestAssetCRUD(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	a := Asset{Name: "nginx", Kind: "technology", Version: "1.24.0", CPE: "cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*",
		CPEMode: "", Criticality: "high", Owner: "ops", Notes: "frontal", Source: "manual"}
	id, err := st.CreateAsset(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.Asset(ctx, id)
	if err != nil || got.Name != "nginx" || got.CPE != a.CPE || got.Owner != "ops" || got.CreatedAt.IsZero() {
		t.Fatalf("asset = %+v, %v", got, err)
	}
	got.Version, got.CPEMode, got.CPEFrom = "1.25.0", "from", "1.24.0"
	if err := st.UpdateAsset(ctx, got); err != nil {
		t.Fatal(err)
	}
	if again, _ := st.Asset(ctx, id); again.Version != "1.25.0" || again.CPEMode != "from" || again.CPEFrom != "1.24.0" {
		t.Fatalf("update lost: %+v", again)
	}
	if err := st.DeleteAsset(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Asset(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted asset still found: %v", err)
	}
	if err := st.DeleteAsset(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
}

func TestFindingLifecycle(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	assetID, _ := st.CreateAsset(ctx, Asset{Name: "lodash", Kind: "package", Criticality: "low", Source: "manual"})
	userID, _ := st.CreateUser(ctx, "ana", "hash", "analyst")
	st.UpsertVulnerability(ctx, Vulnerability{ID: "GHSA-1", Aliases: []string{"CVE-1"}, Severity: "HIGH", CVSS: 7.5, Modified: "m1"})

	if touch, _ := st.ObserveFinding(ctx, assetID, "GHSA-1", time.Now()); touch != TouchCreated {
		t.Fatalf("first observation: %v", touch)
	}
	if touch, _ := st.ObserveFinding(ctx, assetID, "GHSA-1", time.Now()); touch != TouchExisting {
		t.Fatalf("second observation: %v", touch)
	}
	fs, _ := st.ListFindings(ctx, FindingFilter{})
	if len(fs) != 1 || fs[0].CVSS != 7.5 || fs[0].Aliases[0] != "CVE-1" || fs[0].Status != "in_triage" {
		t.Fatalf("findings = %+v", fs)
	}
	if err := st.SetFindingStatus(ctx, fs[0].ID, userID, "not_affected", "code_not_reachable", "ok"); err != nil {
		t.Fatal(err)
	}
	// The source stops reporting it: resolved automatically; reporting it again reopens it.
	if n, _ := st.AutoResolveStale(ctx, assetID, nil, ""); n != 0 {
		t.Errorf("a triaged not_affected finding must not be auto-resolved (got %d)", n)
	}
	st.SetFindingStatus(ctx, fs[0].ID, userID, "exploitable", "", "")
	if n, _ := st.AutoResolveStale(ctx, assetID, nil, ""); n != 1 {
		t.Fatalf("auto-resolved = %d", n)
	}
	if touch, _ := st.ObserveFinding(ctx, assetID, "GHSA-1", time.Now()); touch != TouchReopened {
		t.Fatalf("reopen: %v", touch)
	}
	events, _ := st.FindingEvents(ctx, fs[0].ID)
	if len(events) < 3 || events[0].Username != "ana" {
		t.Fatalf("events = %+v", events)
	}
	counts, _ := st.CountFindingsByStatus(ctx)
	if counts["in_triage"] != 1 {
		t.Errorf("counts = %v", counts)
	}
	if modified, known, _ := st.VulnModified(ctx, "GHSA-1"); !known || modified != "m1" {
		t.Errorf("VulnModified = %q %v", modified, known)
	}
	if err := st.SetExploitSignals(ctx, "GHSA-1", true, "2026-12-01", 0.9); err != nil {
		t.Fatal(err)
	}
	if v, _ := st.Vulnerability(ctx, "GHSA-1"); !v.KEV || v.EPSS != 0.9 || v.CVSS != 7.5 {
		t.Errorf("signals = %+v", v)
	}
	if cves, _ := st.VulnCVEs(ctx); len(cves["GHSA-1"]) != 1 || cves["GHSA-1"][0] != "CVE-1" {
		t.Errorf("VulnCVEs = %v", cves)
	}
}

func TestUsersSessionsTokens(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	uid, err := st.CreateUser(ctx, "admin", "hash", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateUser(ctx, "admin", "hash", "admin"); err == nil {
		t.Error("duplicate username accepted")
	}
	if _, err := st.CreateUser(ctx, "x", "hash", "root"); err == nil {
		t.Error("unknown role accepted by the schema")
	}
	st.CreateSession(ctx, "h1", uid, "csrf", time.Now().Add(time.Hour))
	st.CreateSession(ctx, "h2", uid, "csrf", time.Now().Add(time.Hour))
	st.CreateSession(ctx, "old", uid, "csrf", time.Now().Add(-time.Hour))
	if _, err := st.SessionByHash(ctx, "old"); !errors.Is(err, ErrNotFound) {
		t.Errorf("expired session accepted: %v", err)
	}
	st.DeleteOtherSessions(ctx, uid, "h1")
	if _, err := st.SessionByHash(ctx, "h2"); !errors.Is(err, ErrNotFound) {
		t.Error("other session survived")
	}
	if s, err := st.SessionByHash(ctx, "h1"); err != nil || s.User.Username != "admin" {
		t.Errorf("current session: %+v %v", s, err)
	}

	tokID, _ := st.CreateAPIToken(ctx, APIToken{Name: "ci", Project: "app"}, "tokhash", uid)
	if tok, err := st.APITokenByHash(ctx, "tokhash"); err != nil || tok.Project != "app" {
		t.Fatalf("token: %+v %v", tok, err)
	}
	if list, _ := st.ListAPITokens(ctx); len(list) != 1 || list[0].LastUsedAt.IsZero() {
		t.Errorf("token use not recorded: %+v", list)
	}
	st.DeleteAPIToken(ctx, tokID)
	if _, err := st.APITokenByHash(ctx, "tokhash"); !errors.Is(err, ErrNotFound) {
		t.Error("revoked token still valid")
	}
}

func TestSettingsDigestsWebhooks(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	if v, _ := st.Setting(ctx, "missing"); v != "" {
		t.Errorf("unset setting = %q", v)
	}
	st.SetSetting(ctx, "k", "a")
	st.SetSetting(ctx, "k", "b")
	if v, _ := st.Setting(ctx, "k"); v != "b" {
		t.Errorf("setting = %q", v)
	}

	if last, _ := st.LastDigestTime(ctx); !last.IsZero() {
		t.Errorf("no digest yet but last = %v", last)
	}
	now := time.Now().UTC().Truncate(time.Second)
	id, _ := st.CreateDigest(ctx, Digest{Since: now.Add(-time.Hour), CreatedAt: now, Markdown: "md", HTML: "<p>h</p>"})
	if d, err := st.Digest(ctx, id); err != nil || d.Markdown != "md" {
		t.Fatalf("digest = %+v %v", d, err)
	}
	if last, _ := st.LastDigestTime(ctx); !last.Equal(now) {
		t.Errorf("last digest = %v, want %v", last, now)
	}

	hid, _ := st.CreateWebhook(ctx, Webhook{Name: "w", Kind: "slack", URL: "https://example.org/x", Enabled: true})
	st.RecordWebhookResult(ctx, hid, errors.New("status 500"))
	if hs, _ := st.ListWebhooks(ctx); len(hs) != 1 || hs[0].LastError != "status 500" {
		t.Errorf("webhooks = %+v", hs)
	}
	st.RecordWebhookResult(ctx, hid, nil)
	if hs, _ := st.ListWebhooks(ctx); hs[0].LastError != "" {
		t.Error("success did not clear the error")
	}
}

// TestMigrationRecentMode replays migration 008 on an asset that used the
// former sliding "recent" mode: it becomes a fixed tracked period.
func TestMigrationRecentMode(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	id, err := st.CreateAsset(ctx, Asset{Name: "fortios", Kind: "os", CPE: "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*",
		Criticality: "high", Source: "manual"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, `UPDATE assets SET cpe_mode = 'recent', created_at = '2026-10-27T08:12:11Z' WHERE id = ?`, id); err != nil {
		t.Fatal(err)
	}
	sql, _ := migrationsFS.ReadFile("migrations/008_track_since.sql")
	update := string(sql[strings.Index(string(sql), "UPDATE"):])
	if _, err := st.db.ExecContext(ctx, update); err != nil {
		t.Fatal(err)
	}
	a, _ := st.Asset(ctx, id)
	if a.CPEMode != "all" || a.TrackSince != "2026-06-29" {
		t.Fatalf("migrated asset: mode %q, since %q", a.CPEMode, a.TrackSince)
	}
}
