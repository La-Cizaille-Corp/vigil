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

	assetID, err := st.CreateAsset(ctx, Asset{Name: "fortios", Kind: "os", Criticality: "high", Source: "manual"})
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
		if i == 2 {
			seen = now.Add(-40 * 24 * time.Hour) // waiting for triage for too long
		}
		if _, err := st.ObserveFinding(ctx, assetID, v.ID, seen); err != nil {
			t.Fatal(err)
		}
	}
	list, _ := st.ListFindings(ctx, FindingFilter{})
	for _, f := range list {
		switch f.VulnID {
		case "CVE-4":
			st.SetFindingStatus(ctx, f.ID, 0, "resolved", "", "")
		case "CVE-2":
			st.SetFindingStatus(ctx, f.ID, 0, "exploitable", "", "")
		}
	}

	s, err := st.DashboardStats(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if s.Open != 3 || s.OpenBySeverity["CRITICAL"] != 1 || s.OpenBySeverity["UNKNOWN"] != 1 {
		t.Errorf("open: %d %v", s.Open, s.OpenBySeverity)
	}
	if s.Priority != 2 || s.OpenKEV != 1 || s.KEVOverdue != 1 {
		t.Errorf("priority %d, kev %d, overdue %d", s.Priority, s.OpenKEV, s.KEVOverdue)
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
