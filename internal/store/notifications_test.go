package store

import (
	"context"
	"reflect"
	"testing"
	"time"
)

func TestPendingAlerts(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	assetID, _ := st.CreateAsset(ctx, Asset{Name: "app", Kind: "package", Criticality: "high", Source: "manual"})
	for _, v := range []Vulnerability{
		{ID: "CVE-LOW", Severity: "LOW", EPSS: -1, CVSS: 2},
		{ID: "CVE-HIGH", Severity: "HIGH", EPSS: -1, CVSS: 7.5},
		{ID: "CVE-KEV", Severity: "MEDIUM", EPSS: -1, CVSS: 5},
	} {
		st.UpsertVulnerability(ctx, v)
		st.ObserveFinding(ctx, assetID, v.ID, time.Now())
	}
	st.SetExploitSignals(ctx, "CVE-KEV", true, "", 0.02)

	alerts, err := st.PendingAlerts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 2 || alerts[0].VulnID != "CVE-KEV" || alerts[0].Class != AlertPriority ||
		alerts[1].VulnID != "CVE-HIGH" || alerts[1].Class != AlertSevere {
		t.Fatalf("alerts: %+v", alerts)
	}
	if err := st.MarkAlerted(ctx, alerts); err != nil {
		t.Fatal(err)
	}
	if again, _ := st.PendingAlerts(ctx); len(again) != 0 {
		t.Errorf("alerted twice: %+v", again)
	}
	// The high one becomes likely exploited: alerted again, as raised.
	st.SetExploitSignals(ctx, "CVE-HIGH", false, "", 0.4)
	raised, _ := st.PendingAlerts(ctx)
	if len(raised) != 1 || raised[0].VulnID != "CVE-HIGH" || !raised[0].Raised || raised[0].Class != AlertPriority {
		t.Errorf("raised: %+v", raised)
	}
	// Closed findings are never alerted.
	st.MarkAlerted(ctx, raised)
	st.SetExploitSignals(ctx, "CVE-LOW", true, "", 0.9)
	list, _ := st.ListFindings(ctx, FindingFilter{Search: "CVE-LOW"})
	st.SetFindingStatus(ctx, list[0].ID, 0, "not_affected", "code_not_present", "")
	if closed, _ := st.PendingAlerts(ctx); len(closed) != 0 {
		t.Errorf("closed finding alerted: %+v", closed)
	}
}

func TestCTIMentions(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	if got := ExtractCVEs("Avis cve-2024-3400 et CVE-2024-3400, CVE-2021-44228 ; pas CVE-21-1"); !reflect.DeepEqual(got, []string{"CVE-2024-3400", "CVE-2021-44228"}) {
		t.Errorf("extract: %v", got)
	}
	feeds, _ := st.ListFeeds(ctx)
	assetID, _ := st.CreateAsset(ctx, Asset{Name: "log4j", Kind: "package", Criticality: "high", Source: "manual"})
	st.UpsertVulnerability(ctx, Vulnerability{ID: "GHSA-jfh8-c2jp-5v3q", Aliases: []string{"CVE-2021-44228"}, EPSS: -1, CVSS: -1})
	st.ObserveFinding(ctx, assetID, "GHSA-jfh8-c2jp-5v3q", time.Now())
	for i, title := range []string{"Log4Shell CVE-2021-44228 activement exploitée", "Rien à voir CVE-2020-0001", "Sans CVE"} {
		if _, err := st.InsertCTIItem(ctx, feeds[0].ID, CTIItem{GUID: title, Title: title, Published: time.Now().Add(-time.Duration(i) * time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	items, err := st.ListCTIItems(ctx, CTIFilter{Concerning: true})
	if err != nil || len(items) != 1 || !reflect.DeepEqual(items[0].Concerns, []string{"CVE-2021-44228"}) {
		t.Fatalf("concerning items: %+v, %v", items, err)
	}
	all, _ := st.ListCTIItems(ctx, CTIFilter{})
	if len(all) != 3 || all[1].Concerns != nil {
		t.Errorf("all items: %+v", all)
	}
	mentions, err := st.MentionsOf(ctx, []string{"GHSA-jfh8-c2jp-5v3q", "CVE-2021-44228"}, 5)
	if err != nil || len(mentions) != 1 || mentions[0].FeedName == "" {
		t.Errorf("mentions: %+v, %v", mentions, err)
	}
	// Once the finding is closed, the news no longer concerns the inventory.
	list, _ := st.ListFindings(ctx, FindingFilter{})
	st.SetFindingStatus(ctx, list[0].ID, 0, "resolved", "", "")
	if items, _ := st.ListCTIItems(ctx, CTIFilter{Concerning: true}); len(items) != 0 {
		t.Errorf("closed finding still concerning: %+v", items)
	}
}

func TestWebhookDeliveryAndAudit(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	id, err := st.CreateWebhook(ctx, Webhook{Name: "mail", Kind: "email", URL: "a@example.org", Enabled: true, Digests: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetWebhookDelivery(ctx, id, false, "severe"); err != nil {
		t.Fatal(err)
	}
	hooks, _ := st.ListWebhooks(ctx)
	if len(hooks) != 1 || hooks[0].Digests || hooks[0].Alerts != "severe" || hooks[0].Kind != "email" {
		t.Errorf("webhook: %+v", hooks)
	}
	st.Audit(ctx, 0, "first", "")
	st.Audit(ctx, 0, "second", "detail")
	entries, err := st.ListAudit(ctx, 10)
	if err != nil || len(entries) != 2 || entries[0].Action != "second" || entries[0].Username != "" {
		t.Errorf("audit: %+v, %v", entries, err)
	}
}
