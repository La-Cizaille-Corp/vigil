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

// A list judges deadlines at the time it is given, as the dashboard figures
// computed with it: "late" and the overdue filter agree with them.
func TestFindingsJudgedAtTheGivenTime(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	assetID, err := st.CreateAsset(ctx, Everything, Asset{Name: "nginx", Kind: "technology", Criticality: "high", Source: "manual"})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertVulnerability(ctx, Vulnerability{ID: "CVE-1", Severity: "CRITICAL", EPSS: -1, CVSS: -1}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ObserveFinding(ctx, assetID, "CVE-1", "", time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		at   time.Time
		late bool
	}{{time.Now(), false}, {time.Now().AddDate(0, 0, 20), true}} { // critical: 15 days
		all, err := st.ListFindings(ctx, Everything, FindingFilter{Now: c.at})
		if err != nil || len(all) != 1 || all[0].Late != c.late {
			t.Fatalf("at %s: %+v, %v; want late %v", c.at, all, err, c.late)
		}
		overdue, err := st.ListFindings(ctx, Everything, FindingFilter{Overdue: true, Now: c.at})
		if err != nil || (len(overdue) == 1) != c.late {
			t.Errorf("overdue at %s: %d, %v", c.at, len(overdue), err)
		}
		stats, err := st.DashboardStats(ctx, Everything, c.at)
		if err != nil || (stats.Overdue == 1) != c.late {
			t.Errorf("dashboard at %s: %d overdue, %v", c.at, stats.Overdue, err)
		}
	}
}
