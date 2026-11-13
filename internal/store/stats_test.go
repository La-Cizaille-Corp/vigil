package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/store"
	"github.com/La-Cizaille-Corp/vigil/internal/storetest"
)

func TestDashboardStats(t *testing.T) {
	ctx := context.Background()
	st := storetest.Open(t)
	now := time.Now()

	assetID := storetest.Asset(t, st, store.Asset{Name: "fortios", Kind: "os", Criticality: "high", Source: "manual"})
	ids := map[string]int64{}
	for i, v := range []store.Vulnerability{
		{ID: "CVE-1", Severity: "CRITICAL", EPSS: -1, CVSS: -1},
		{ID: "CVE-2", Severity: "HIGH", EPSS: -1, CVSS: -1},
		{ID: "CVE-3", Severity: "", EPSS: -1, CVSS: -1},
		{ID: "CVE-4", Severity: "MEDIUM", EPSS: -1, CVSS: -1},
	} {
		seen := now.Add(-time.Duration(i) * 24 * time.Hour)
		switch i {
		case 0:
			seen = now.Add(-20 * 24 * time.Hour) // exploited: past the 15-day critical deadline
		case 2:
			seen = now.Add(-40 * 24 * time.Hour) // waiting for triage for too long
		}
		ids[v.ID] = storetest.Finding(t, st, assetID, v, seen)
	}
	if _, err := st.SetExploitSignals(ctx,
		store.ExploitSignal{ID: "CVE-1", KEV: true, KEVDue: "2000-01-01", EPSS: 0.9}, // exploited, CISA deadline passed
		store.ExploitSignal{ID: "CVE-2", EPSS: 0.2},                                  // likely exploited
	); err != nil {
		t.Fatal(err)
	}
	if err := st.SetFindingStatus(ctx, store.Everything, ids["CVE-4"], 0, "resolved", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := st.SetFindingStatus(ctx, store.Everything, ids["CVE-2"], 0, "exploitable", "", ""); err != nil {
		t.Fatal(err)
	}

	s, err := st.DashboardStats(ctx, store.Everything, now)
	if err != nil {
		t.Fatal(err)
	}
	if s.Open != 3 || s.OpenBySeverity["CRITICAL"] != 1 || s.OpenBySeverity["UNKNOWN"] != 1 {
		t.Errorf("open: %d %v", s.Open, s.OpenBySeverity)
	}
	if s.Priority != 2 || s.OpenKEV != 1 || s.Overdue != 1 || s.OverdueKEV != 1 {
		t.Errorf("priority %d, kev %d, overdue %d (%d exploited)", s.Priority, s.OpenKEV, s.Overdue, s.OverdueKEV)
	}
	late, err := st.ListFindings(ctx, store.Everything, store.FindingFilter{Overdue: true})
	if err != nil || len(late) != 1 || late[0].VulnID != "CVE-1" || !late[0].Late {
		t.Errorf("overdue findings: %+v, %v", late, err)
	}
	// A longer critical deadline moves it back within its delay.
	if err := st.SetSLA(ctx, store.SLA{Critical: 30, High: 30, Medium: 90, Low: 0}); err != nil {
		t.Fatal(err)
	}
	if late, _ := st.ListFindings(ctx, store.Everything, store.FindingFilter{Overdue: true}); len(late) != 0 {
		t.Errorf("still overdue: %+v", late)
	}
	if err := st.SetSLA(ctx, store.SLA{Critical: -1}); err == nil {
		t.Error("negative deadline accepted")
	}
	if s.ToTriage != 2 || s.StaleTriage != 1 {
		t.Errorf("triage %d, stale %d", s.ToTriage, s.StaleTriage)
	}
	if s.Closed90 != 1 || s.MeanDaysToFix < 2.9 || s.MeanDaysToFix > 3.1 {
		t.Errorf("closed %d in %.2f days", s.Closed90, s.MeanDaysToFix)
	}
	last := s.Weeks[len(s.Weeks)-1]
	newTotal := 0
	for _, w := range s.Weeks {
		newTotal += w.New
	}
	if len(s.Weeks) != 12 || newTotal != 4 || last.Closed != 1 {
		t.Errorf("weeks: %+v", s.Weeks)
	}
	if len(s.TopAssets) != 1 || s.TopAssets[0].Total() != 3 || s.TopAssets[0].Critical != 1 || s.TopAssets[0].Urgent != s.Priority {
		t.Errorf("top assets: %+v", s.TopAssets)
	}
	// The inventory counts the urgent ones of each asset: those of the dashboard, for its only asset.
	if loads, err := st.AssetLoads(ctx, store.Everything); err != nil || len(loads) != 1 || loads[0].Urgent != s.Priority || loads[0].Total() != s.Open {
		t.Errorf("asset loads: %+v, %v", loads, err)
	}
}

// The mean time to fix leaves out the findings of the first sync of their
// asset: they predate its arrival in Vigil.
func TestMeanDaysToFixAfterFirstSync(t *testing.T) {
	ctx := context.Background()
	st := storetest.Open(t)
	now := time.Now()
	server := storetest.Asset(t, st, store.Asset{Name: "server", Kind: "os", Criticality: "high", Source: "manual"})
	lib := storetest.Asset(t, st, store.Asset{Name: "lib", Kind: "package", Criticality: "low", Source: "manual"})
	first, next := now.Add(-60*24*time.Hour), now.Add(-10*24*time.Hour)
	for _, o := range []struct {
		asset int64
		vuln  string
		seen  time.Time
	}{
		{server, "CVE-OLD-1", first}, // the first sync of the server: two old vulnerabilities
		{server, "CVE-OLD-2", first},
		{server, "CVE-NEW", next}, // a later sync: a new one, fixed in 10 days
		{lib, "CVE-LIB", next},    // the first sync of the library, later than the server's
	} {
		storetest.Finding(t, st, o.asset, store.Vulnerability{ID: o.vuln, Severity: "HIGH", EPSS: -1, CVSS: 7.5}, o.seen)
	}
	fix := func(keep string) {
		t.Helper()
		list, err := st.ListFindings(ctx, store.Everything, store.FindingFilter{})
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range list {
			if f.VulnID != keep && f.Status != "resolved" {
				if err := st.SetFindingStatus(ctx, store.Everything, f.ID, 0, "resolved", "", ""); err != nil {
					t.Fatal(err)
				}
			}
		}
	}

	// Only findings of first syncs are fixed: no mean yet.
	fix("CVE-NEW")
	s, err := st.DashboardStats(ctx, store.Everything, now)
	if err != nil {
		t.Fatal(err)
	}
	if s.Closed90 != 0 || s.MeanDaysToFix != -1 {
		t.Errorf("first syncs only: closed %d in %.2f days, want none", s.Closed90, s.MeanDaysToFix)
	}
	fix("")
	if s, _ = st.DashboardStats(ctx, store.Everything, now); s.Closed90 != 1 || s.MeanDaysToFix < 9.9 || s.MeanDaysToFix > 10.1 {
		t.Errorf("closed %d in %.2f days, want 1 in 10", s.Closed90, s.MeanDaysToFix)
	}
	// The activity chart still counts every closing.
	if closed := s.Weeks[len(s.Weeks)-1].Closed; closed != 4 {
		t.Errorf("%d closings this week, want 4", closed)
	}
}

// A list judges deadlines at the time it is given, as the dashboard figures
// computed with it: "late" and the overdue filter agree with them.
func TestFindingsJudgedAtTheGivenTime(t *testing.T) {
	ctx := context.Background()
	st := storetest.Open(t)
	assetID := storetest.Asset(t, st, store.Asset{Name: "nginx", Kind: "technology", Criticality: "high", Source: "manual"})
	storetest.Finding(t, st, assetID, store.Vulnerability{ID: "CVE-1", Severity: "CRITICAL", EPSS: -1, CVSS: -1}, time.Now())
	for _, c := range []struct {
		at   time.Time
		late bool
	}{{time.Now(), false}, {time.Now().AddDate(0, 0, 20), true}} { // critical: 15 days
		all, err := st.ListFindings(ctx, store.Everything, store.FindingFilter{Now: c.at})
		if err != nil || len(all) != 1 || all[0].Late != c.late {
			t.Fatalf("at %s: %+v, %v; want late %v", c.at, all, err, c.late)
		}
		overdue, err := st.ListFindings(ctx, store.Everything, store.FindingFilter{Overdue: true, Now: c.at})
		if err != nil || (len(overdue) == 1) != c.late {
			t.Errorf("overdue at %s: %d, %v", c.at, len(overdue), err)
		}
		stats, err := st.DashboardStats(ctx, store.Everything, c.at)
		if err != nil || (stats.Overdue == 1) != c.late {
			t.Errorf("dashboard at %s: %d overdue, %v", c.at, stats.Overdue, err)
		}
	}
}

// Deadlines decrease from Basse to Critique, 0 (none) being the longest
// (audit UX 8.3, A89).
func TestSLAOrdered(t *testing.T) {
	for _, c := range []struct {
		sla  store.SLA
		want bool
	}{
		{store.DefaultSLA, true},
		{store.SLA{Critical: 15, High: 15, Medium: 15, Low: 15}, true},
		{store.SLA{Critical: 15, High: 30, Medium: 90, Low: 0}, true},
		{store.SLA{}, true},
		{store.SLA{Critical: 15, High: 5, Medium: 90, Low: 180}, false},
		{store.SLA{Critical: 0, High: 30, Medium: 90, Low: 180}, false},
		{store.SLA{Critical: 15, High: 30, Medium: 200, Low: 180}, false},
	} {
		if got := c.sla.Ordered(); got != c.want {
			t.Errorf("%v: Ordered = %v", c.sla, got)
		}
	}
}
