package store

import (
	"context"
	"testing"
	"time"
)

func TestDashboardStats(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	now := time.Now()

	assetID, err := st.CreateAsset(ctx, Everything, Asset{Name: "fortios", Kind: "os", Criticality: "high", Source: "manual"})
	if err != nil {
		t.Fatal(err)
	}
	vulns := []Vulnerability{
		{ID: "CVE-1", Severity: "CRITICAL", EPSS: -1, CVSS: -1},
		{ID: "CVE-2", Severity: "HIGH", EPSS: -1, CVSS: -1},
		{ID: "CVE-3", Severity: "", EPSS: -1, CVSS: -1},
		{ID: "CVE-4", Severity: "MEDIUM", EPSS: -1, CVSS: -1},
	}
	for _, v := range vulns {
		if err := st.UpsertVulnerability(ctx, v); err != nil {
			t.Fatal(err)
		}
	}
	st.SetExploitSignals(ctx, "CVE-1", true, "2000-01-01", 0.9) // exploited, CISA deadline passed
	st.SetExploitSignals(ctx, "CVE-2", false, "", 0.2)          // likely exploited
	for i, v := range vulns {
		seen := now.Add(-time.Duration(i) * 24 * time.Hour)
		switch i {
		case 0:
			seen = now.Add(-20 * 24 * time.Hour) // exploited: past the 15-day critical deadline
		case 2:
			seen = now.Add(-40 * 24 * time.Hour) // waiting for triage for too long
		}
		if _, err := st.ObserveFinding(ctx, assetID, v.ID, "", seen); err != nil {
			t.Fatal(err)
		}
	}
	list, _ := st.ListFindings(ctx, Everything, FindingFilter{})
	for _, f := range list {
		switch f.VulnID {
		case "CVE-4":
			st.SetFindingStatus(ctx, Everything, f.ID, 0, "resolved", "", "")
		case "CVE-2":
			st.SetFindingStatus(ctx, Everything, f.ID, 0, "exploitable", "", "")
		}
	}

	s, err := st.DashboardStats(ctx, Everything, now)
	if err != nil {
		t.Fatal(err)
	}
	if s.Open != 3 || s.OpenBySeverity["CRITICAL"] != 1 || s.OpenBySeverity["UNKNOWN"] != 1 {
		t.Errorf("open: %d %v", s.Open, s.OpenBySeverity)
	}
	if s.Priority != 2 || s.OpenKEV != 1 || s.Overdue != 1 || s.OverdueKEV != 1 {
		t.Errorf("priority %d, kev %d, overdue %d (%d exploited)", s.Priority, s.OpenKEV, s.Overdue, s.OverdueKEV)
	}
	late, err := st.ListFindings(ctx, Everything, FindingFilter{Overdue: true})
	if err != nil || len(late) != 1 || late[0].VulnID != "CVE-1" || !late[0].Late {
		t.Errorf("overdue findings: %+v, %v", late, err)
	}
	// A longer critical deadline moves it back within its delay.
	if err := st.SetSLA(ctx, SLA{Critical: 30, High: 30, Medium: 90, Low: 0}); err != nil {
		t.Fatal(err)
	}
	if late, _ := st.ListFindings(ctx, Everything, FindingFilter{Overdue: true}); len(late) != 0 {
		t.Errorf("still overdue: %+v", late)
	}
	if err := st.SetSLA(ctx, SLA{Critical: -1}); err == nil {
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
	if len(s.TopAssets) != 1 || s.TopAssets[0].Total() != 3 || s.TopAssets[0].Critical != 1 {
		t.Errorf("top assets: %+v", s.TopAssets)
	}
}

// The mean time to fix leaves out the findings of the first sync of their
// asset: they predate its arrival in Vigil.
func TestMeanDaysToFixAfterFirstSync(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	now := time.Now()
	server, _ := st.CreateAsset(ctx, Everything, Asset{Name: "server", Kind: "os", Criticality: "high", Source: "manual"})
	lib, _ := st.CreateAsset(ctx, Everything, Asset{Name: "lib", Kind: "package", Criticality: "low", Source: "manual"})
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
		if err := st.UpsertVulnerability(ctx, Vulnerability{ID: o.vuln, Severity: "HIGH", EPSS: -1, CVSS: 7.5}); err != nil {
			t.Fatal(err)
		}
		if _, err := st.ObserveFinding(ctx, o.asset, o.vuln, "", o.seen); err != nil {
			t.Fatal(err)
		}
	}
	list, _ := st.ListFindings(ctx, Everything, FindingFilter{})
	fix := func(keep string) {
		t.Helper()
		for _, f := range list {
			if f.VulnID != keep && f.Status != "resolved" {
				if err := st.SetFindingStatus(ctx, Everything, f.ID, 0, "resolved", "", ""); err != nil {
					t.Fatal(err)
				}
			}
		}
		list, _ = st.ListFindings(ctx, Everything, FindingFilter{})
	}

	// Only findings of first syncs are fixed: no mean yet.
	fix("CVE-NEW")
	s, err := st.DashboardStats(ctx, Everything, now)
	if err != nil {
		t.Fatal(err)
	}
	if s.Closed90 != 0 || s.MeanDaysToFix != -1 {
		t.Errorf("first syncs only: closed %d in %.2f days, want none", s.Closed90, s.MeanDaysToFix)
	}
	fix("")
	if s, _ = st.DashboardStats(ctx, Everything, now); s.Closed90 != 1 || s.MeanDaysToFix < 9.9 || s.MeanDaysToFix > 10.1 {
		t.Errorf("closed %d in %.2f days, want 1 in 10", s.Closed90, s.MeanDaysToFix)
	}
	// The activity chart still counts every closing.
	if closed := s.Weeks[len(s.Weeks)-1].Closed; closed != 4 {
		t.Errorf("%d closings this week, want 4", closed)
	}
}
