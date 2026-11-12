package store

import (
	"context"
	"testing"
	"time"
)

// A folded finding leaves every list, count and alert, and is no longer
// closed or set aside by the synchronisation; its page remains. The finding
// kept takes the earliest detection and the highest class notified. Folding
// twice changes nothing; observed again, a folded finding is shown again.
func TestFoldedFindingsLeaveEveryList(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	asset, err := st.CreateAsset(ctx, Everything, Asset{Name: "linux", Kind: "os", Criticality: "high", Source: "manual"})
	if err != nil {
		t.Fatal(err)
	}
	early, late := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	for _, v := range []Vulnerability{
		{ID: "GHSA-kept", Aliases: []string{"CVE-2026-1"}, Severity: "CRITICAL", EPSS: -1, CVSS: 9.8},
		{ID: "GO-folded", Aliases: []string{"CVE-2026-1"}, Severity: "CRITICAL", EPSS: -1, CVSS: 9.8},
		{ID: "USN-1-1", Aliases: []string{"CVE-2026-1", "CVE-2026-2"}, KEV: true, EPSS: -1, CVSS: -1},
	} {
		if err := st.UpsertVulnerability(ctx, v); err != nil {
			t.Fatal(err)
		}
	}
	st.SetExploitSignals(ctx, ExploitSignal{ID: "USN-1-1", KEV: true, EPSS: -1})
	st.ObserveFinding(ctx, asset, "GHSA-kept", "", late)
	st.ObserveFinding(ctx, asset, "GO-folded", "", early)
	st.ObserveFinding(ctx, asset, "USN-1-1", "", late)
	ids := map[string]int64{}
	triage, err := st.ListFindingTriage(ctx, asset)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range triage {
		ids[f.VulnID] = f.ID
	}
	// The folded one was notified at a class the kept one was not.
	if _, err := st.db.ExecContext(ctx, `UPDATE findings SET alerted = 2 WHERE id = ?`, ids["GO-folded"]); err != nil {
		t.Fatal(err)
	}
	folds := []Fold{{ID: ids["GO-folded"], Into: ids["GHSA-kept"], Why: "même CVE", Note: "décision divergente"},
		{ID: ids["USN-1-1"], Into: FoldedNotice, Why: "avis groupé"}}
	if err := st.FoldFindings(ctx, folds...); err != nil {
		t.Fatal(err)
	}
	if err := st.FoldFindings(ctx, folds...); err != nil { // already folded: nothing
		t.Fatal(err)
	}
	list, _ := st.ListFindings(ctx, Everything, FindingFilter{})
	if len(list) != 1 || list[0].VulnID != "GHSA-kept" || !list[0].FirstSeen.Equal(early) {
		t.Fatalf("list = %+v", list)
	}
	if counts, _ := st.CountFindingsByStatus(ctx, Everything); counts["in_triage"] != 1 {
		t.Errorf("counts = %v", counts)
	}
	alerts, _ := st.PendingAlerts(ctx, Everything)
	if len(alerts) != 0 {
		t.Errorf("alerts = %+v, want none: the kept finding took the class already notified", alerts)
	}
	stats, _ := st.DashboardStats(ctx, Everything, time.Now())
	if stats.Open != 1 || stats.Priority != 0 || stats.OpenKEV != 0 {
		t.Errorf("stats = %+v", stats)
	}
	feed, _ := st.CreateFeed(ctx, Feed{Name: "Avis", URL: "https://example.org/feed"})
	st.InsertCTIItem(ctx, feed, CTIItem{GUID: "1", Title: "Avis CVE-2026-2", Link: "https://example.org/1", Published: time.Now()})
	if items, _ := st.ListCTIItems(ctx, Everything, CTIFilter{Concerning: true}); len(items) != 0 {
		t.Errorf("news concerning the inventory through a folded advisory: %+v", items)
	}
	if n, err := st.AutoResolveStale(ctx, asset, nil, ""); err != nil || n != 1 {
		t.Errorf("auto-resolved %d (%v), want the kept finding only", n, err)
	}
	usn, err := st.Finding(ctx, Everything, ids["USN-1-1"])
	if err != nil || usn.FoldedInto != FoldedNotice || usn.Status != "in_triage" {
		t.Errorf("page of the folded advisory: %+v, %v", usn, err)
	}
	events, _ := st.ListFindingEvents(ctx, Everything, ids["GHSA-kept"])
	if len(events) != 2 || events[0].Comment != "décision divergente" {
		t.Errorf("history of the kept finding: %+v", events)
	}
	// Reported again on its own, the grouped advisory is shown again.
	if _, err := st.ObserveFinding(ctx, asset, "USN-1-1", "", late); err != nil {
		t.Fatal(err)
	}
	if usn, _ = st.Finding(ctx, Everything, ids["USN-1-1"]); usn.FoldedInto != 0 {
		t.Errorf("observed again, still folded: %+v", usn)
	}
}
