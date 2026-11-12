package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// These tests pin the behaviour of the storage layer independently of the
// SQLite driver: they are the safety net for a driver change (see
// docs/DEPENDENCIES.md, "Plan B").

func TestAssetCRUD(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	a := Asset{Name: "nginx", Kind: "technology", Version: "1.24.0", CPE: "cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*",
		CPEMode: "", Criticality: "high", Owner: "ops", Notes: "frontal", Source: "manual"}
	id, err := st.CreateAsset(ctx, Everything, a)
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.Asset(ctx, Everything, id)
	if err != nil || got.Name != "nginx" || got.CPE != a.CPE || got.Owner != "ops" || got.CreatedAt.IsZero() {
		t.Fatalf("asset = %+v, %v", got, err)
	}
	got.Version, got.CPEMode, got.CPEFrom = "1.25.0", "from", "1.24.0"
	if err := st.UpdateAsset(ctx, Everything, got); err != nil {
		t.Fatal(err)
	}
	if again, _ := st.Asset(ctx, Everything, id); again.Version != "1.25.0" || again.CPEMode != "from" || again.CPEFrom != "1.24.0" {
		t.Fatalf("update lost: %+v", again)
	}
	if err := st.DeleteAsset(ctx, Everything, id); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Asset(ctx, Everything, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted asset still found: %v", err)
	}
	if err := st.DeleteAsset(ctx, Everything, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
}

// The error kept for a channel is cut by characters: a French message was cut
// by bytes, possibly in the middle of one.
func TestWebhookErrorStaysValidUTF8(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	id, err := st.CreateWebhook(ctx, Webhook{Name: "w", Kind: "generic", URL: "https://example.org/hook", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.RecordWebhookResult(ctx, id, errors.New(strings.Repeat("a", 299)+"é et la suite")); err != nil {
		t.Fatal(err)
	}
	hooks, _ := st.ListWebhooks(ctx)
	if got := hooks[0].LastError; !utf8.ValidString(got) || got != strings.Repeat("a", 299)+"…" {
		t.Errorf("last_error = %q", got)
	}
}

func TestFindingLifecycle(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	assetID, _ := st.CreateAsset(ctx, Everything, Asset{Name: "lodash", Kind: "package", Criticality: "low", Source: "manual"})
	userID, _ := st.CreateUser(ctx, "ana", "hash", "analyst", Access{All: true})
	st.UpsertVulnerability(ctx, Vulnerability{ID: "GHSA-1", Aliases: []string{"CVE-1"}, Severity: "HIGH", CVSS: 7.5, Modified: "m1"})

	if touch, _ := st.ObserveFinding(ctx, assetID, "GHSA-1", "4.17.19", time.Now()); touch != TouchCreated {
		t.Fatalf("first observation: %v", touch)
	}
	if touch, _ := st.ObserveFinding(ctx, assetID, "GHSA-1", "4.17.21", time.Now()); touch != TouchExisting {
		t.Fatalf("second observation: %v", touch)
	}
	fs, _ := st.ListFindings(ctx, Everything, FindingFilter{})
	if len(fs) != 1 || fs[0].CVSS != 7.5 || fs[0].Aliases[0] != "CVE-1" || fs[0].Status != "in_triage" || fs[0].FixedIn != "4.17.21" {
		t.Fatalf("findings = %+v", fs)
	}
	if err := st.SetFindingStatus(ctx, Everything, fs[0].ID, userID, "not_affected", "code_not_reachable", "ok"); err != nil {
		t.Fatal(err)
	}
	// The source stops reporting it: resolved automatically; reporting it again reopens it.
	if n, _ := st.AutoResolveStale(ctx, assetID, nil, ""); n != 0 {
		t.Errorf("a triaged not_affected finding must not be auto-resolved (got %d)", n)
	}
	st.SetFindingStatus(ctx, Everything, fs[0].ID, userID, "exploitable", "", "")
	if n, _ := st.AutoResolveStale(ctx, assetID, nil, ""); n != 1 {
		t.Fatalf("auto-resolved = %d", n)
	}
	if f, _ := st.Finding(ctx, Everything, fs[0].ID); f.FixedIn != "4.17.21" {
		t.Errorf("fixed version after the resolution: %q", f.FixedIn)
	}
	if touch, _ := st.ObserveFinding(ctx, assetID, "GHSA-1", "", time.Now()); touch != TouchReopened {
		t.Fatalf("reopen: %v", touch)
	}
	if f, _ := st.Finding(ctx, Everything, fs[0].ID); f.FixedIn != "" {
		t.Errorf("fixed version once the source names none: %q", f.FixedIn)
	}
	events, _ := st.ListFindingEvents(ctx, Everything, fs[0].ID)
	if len(events) < 3 || events[0].Username != "ana" {
		t.Fatalf("events = %+v", events)
	}
	counts, _ := st.CountFindingsByStatus(ctx, Everything)
	if counts["in_triage"] != 1 {
		t.Errorf("counts = %v", counts)
	}
	if modified, known, _ := st.VulnModified(ctx, "GHSA-1"); !known || modified != "m1" {
		t.Errorf("VulnModified = %q %v", modified, known)
	}
	if _, err := st.SetExploitSignals(ctx, ExploitSignal{ID: "GHSA-1", KEV: true, KEVDue: "2026-12-01", EPSS: 0.9}); err != nil {
		t.Fatal(err)
	}
	if v, _ := st.Vulnerability(ctx, "GHSA-1"); !v.KEV || v.EPSS != 0.9 || v.CVSS != 7.5 {
		t.Errorf("signals = %+v", v)
	}
	if cves, _ := st.ListVulnCVEs(ctx); len(cves["GHSA-1"]) != 1 || cves["GHSA-1"][0] != "CVE-1" {
		t.Errorf("VulnCVEs = %v", cves)
	}
}

// Triage decisions are applied in order, in one transaction: all of them or,
// on an error, none.
func TestSetFindingStatuses(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	assetID, _ := st.CreateAsset(ctx, Everything, Asset{Name: "lodash", Kind: "package", Criticality: "low", Source: "manual"})
	userID, _ := st.CreateUser(ctx, "ana", "hash", "analyst", Access{All: true})
	for _, id := range []string{"CVE-1", "CVE-2"} {
		st.UpsertVulnerability(ctx, Vulnerability{ID: id, Severity: "HIGH", Modified: "m"})
		st.ObserveFinding(ctx, assetID, id, "", time.Now())
	}
	fs, _ := st.ListFindings(ctx, Everything, FindingFilter{})
	a, b := fs[0].ID, fs[1].ID
	st.SetFindingStatus(ctx, Everything, b, userID, "exploitable", "", "à patcher")

	done, err := st.SetFindingStatuses(ctx, Everything, userID, []StatusChange{
		{ID: a, Status: "exploitable", Comment: "d'abord"},
		{ID: 9999, Status: "resolved"}, // unknown: skipped
		{ID: a, Status: "not_affected", Justification: "code_not_reachable", Comment: "ensuite"},
		{ID: b, Status: "resolved"}, // without a comment: b keeps its own
	})
	if err != nil || done != 3 {
		t.Fatalf("done = %d, err = %v", done, err)
	}
	if f, _ := st.Finding(ctx, Everything, a); f.Status != "not_affected" || f.Justification != "code_not_reachable" || f.Comment != "ensuite" {
		t.Errorf("a = %s %s %q", f.Status, f.Justification, f.Comment)
	}
	if f, _ := st.Finding(ctx, Everything, b); f.Status != "resolved" || f.Comment != "à patcher" {
		t.Errorf("b = %s %q", f.Status, f.Comment)
	}
	events, _ := st.ListFindingEvents(ctx, Everything, a)
	if len(events) != 2 || events[0].NewStatus != "exploitable" || events[1].OldStatus != "exploitable" ||
		events[1].NewStatus != "not_affected" || events[1].Username != "ana" {
		t.Errorf("history of a = %+v", events)
	}

	// A decision the database refuses cancels those before it.
	if _, err := st.SetFindingStatuses(ctx, Everything, userID, []StatusChange{
		{ID: a, Status: "in_triage", Comment: "annulé"}, {ID: b, Status: "bogus"},
	}); err == nil {
		t.Fatal("unknown status accepted")
	}
	if f, _ := st.Finding(ctx, Everything, a); f.Status != "not_affected" || f.Comment != "ensuite" {
		t.Errorf("a changed by a refused batch: %s %q", f.Status, f.Comment)
	}
	if events, _ := st.ListFindingEvents(ctx, Everything, a); len(events) != 2 {
		t.Errorf("history of a after a refused batch: %d events", len(events))
	}
}

// A decision on a whole list (KeepDecided) leaves alone what someone already
// decided, and what has the status already, as the dismissal rules do (A61,
// A85); the system's own changes (auto-resolution, rules) do not count.
func TestSetFindingStatusesKeepsDecisions(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	assetID, _ := st.CreateAsset(ctx, Everything, Asset{Name: "linux", Kind: "os", Criticality: "low", Source: "manual"})
	userID, _ := st.CreateUser(ctx, "ana", "hash", "analyst", Access{All: true})
	ids := map[string]int64{}
	for _, id := range []string{"CVE-HUMAN", "CVE-SYSTEM", "CVE-NEW", "CVE-SAME"} {
		st.UpsertVulnerability(ctx, Vulnerability{ID: id, Severity: "HIGH", Modified: "m"})
		st.ObserveFinding(ctx, assetID, id, "", time.Now())
	}
	fs, _ := st.ListFindings(ctx, Everything, FindingFilter{})
	for _, f := range fs {
		ids[f.VulnID] = f.ID
	}
	st.SetFindingStatus(ctx, Everything, ids["CVE-HUMAN"], userID, "in_triage", "", "à revoir lundi")
	st.SetFindingStatus(ctx, Everything, ids["CVE-SYSTEM"], 0, "resolved", "", "")
	st.SetFindingStatus(ctx, Everything, ids["CVE-SAME"], 0, "false_positive", "", "")
	var changes []StatusChange
	for _, id := range ids {
		changes = append(changes, StatusChange{ID: id, Status: "false_positive", KeepDecided: true})
	}
	done, err := st.SetFindingStatuses(ctx, Everything, userID, changes)
	if err != nil || done != 2 {
		t.Fatalf("done = %d, err = %v, want 2 (system and new)", done, err)
	}
	for name, want := range map[string]string{"CVE-HUMAN": "in_triage", "CVE-SYSTEM": "false_positive", "CVE-NEW": "false_positive", "CVE-SAME": "false_positive"} {
		if f, _ := st.Finding(ctx, Everything, ids[name]); f.Status != want {
			t.Errorf("%s = %s, want %s", name, f.Status, want)
		}
	}
	if events, _ := st.ListFindingEvents(ctx, Everything, ids["CVE-SAME"]); len(events) != 1 {
		t.Errorf("an unchanged finding got %d events", len(events))
	}
}

func TestUsersSessionsTokens(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	uid, err := st.CreateUser(ctx, "admin", "hash", "admin", Access{All: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateUser(ctx, "admin", "hash", "admin", Access{All: true}); err == nil {
		t.Error("duplicate username accepted")
	}
	if _, err := st.CreateUser(ctx, "x", "hash", "root", Access{All: true}); err == nil {
		t.Error("unknown role accepted by the schema")
	}
	st.CreateSession(ctx, "h1", uid, "csrf", time.Now().Add(time.Hour))
	st.CreateSession(ctx, "h2", uid, "csrf", time.Now().Add(time.Hour))
	st.CreateSession(ctx, "old", uid, "csrf", time.Now().Add(-time.Hour))
	if _, err := st.Session(ctx, "old"); !errors.Is(err, ErrNotFound) {
		t.Errorf("expired session accepted: %v", err)
	}
	st.DeleteOtherSessions(ctx, uid, "h1")
	if _, err := st.Session(ctx, "h2"); !errors.Is(err, ErrNotFound) {
		t.Error("other session survived")
	}
	if s, err := st.Session(ctx, "h1"); err != nil || s.User.Username != "admin" {
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
	if d, err := st.Digest(ctx, Everything, id); err != nil || d.Markdown != "md" {
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
	id, err := st.CreateAsset(ctx, Everything, Asset{Name: "fortios", Kind: "os", CPE: "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*",
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
	a, _ := st.Asset(ctx, Everything, id)
	if a.CPEMode != "all" || a.TrackSince != "2026-06-29" {
		t.Fatalf("migrated asset: mode %q, since %q", a.CPEMode, a.TrackSince)
	}
}
