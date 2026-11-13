package store_test

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/store"
	"github.com/La-Cizaille-Corp/vigil/internal/storetest"
)

func TestPendingAlerts(t *testing.T) {
	ctx := context.Background()
	st := storetest.Open(t)
	assetID := storetest.Asset(t, st, store.Asset{Name: "app", Kind: "package", Criticality: "high", Source: "manual"})
	low := storetest.Finding(t, st, assetID, store.Vulnerability{ID: "CVE-LOW", Severity: "LOW", EPSS: -1, CVSS: 2}, time.Now())
	storetest.Finding(t, st, assetID, store.Vulnerability{ID: "CVE-HIGH", Severity: "HIGH", EPSS: -1, CVSS: 7.5}, time.Now())
	storetest.Finding(t, st, assetID, store.Vulnerability{ID: "CVE-KEV", Severity: "MEDIUM", EPSS: -1, CVSS: 5}, time.Now())
	signal := func(s store.ExploitSignal) {
		t.Helper()
		if _, err := st.SetExploitSignals(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	signal(store.ExploitSignal{ID: "CVE-KEV", KEV: true, EPSS: 0.02})

	alerts, err := st.PendingAlerts(ctx, store.Everything)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 2 || alerts[0].VulnID != "CVE-KEV" || alerts[0].Class != store.AlertPriority ||
		alerts[1].VulnID != "CVE-HIGH" || alerts[1].Class != store.AlertSevere {
		t.Fatalf("alerts: %+v", alerts)
	}
	if err := st.MarkAlerted(ctx, alerts); err != nil {
		t.Fatal(err)
	}
	if again, _ := st.PendingAlerts(ctx, store.Everything); len(again) != 0 {
		t.Errorf("alerted twice: %+v", again)
	}
	// The high one becomes likely exploited: alerted again, as raised.
	signal(store.ExploitSignal{ID: "CVE-HIGH", EPSS: 0.4})
	raised, err := st.PendingAlerts(ctx, store.Everything)
	if err != nil || len(raised) != 1 || raised[0].VulnID != "CVE-HIGH" || !raised[0].Raised || raised[0].Class != store.AlertPriority {
		t.Errorf("raised: %+v, %v", raised, err)
	}
	// Closed findings are never alerted.
	if err := st.MarkAlerted(ctx, raised); err != nil {
		t.Fatal(err)
	}
	signal(store.ExploitSignal{ID: "CVE-LOW", KEV: true, EPSS: 0.9})
	if err := st.SetFindingStatus(ctx, store.Everything, low, 0, "not_affected", "code_not_present", ""); err != nil {
		t.Fatal(err)
	}
	if closed, _ := st.PendingAlerts(ctx, store.Everything); len(closed) != 0 {
		t.Errorf("closed finding alerted: %+v", closed)
	}
}

func TestCTIMentions(t *testing.T) {
	ctx := context.Background()
	st := storetest.Open(t)
	for text, want := range map[string][]string{
		"Avis cve-2024-3400 et CVE-2024-3400, CVE-2021-44228 ; pas CVE-21-1": {"CVE-2024-3400", "CVE-2021-44228"},
		"(CVE-2024-1234567)CVE-2023-0001.":                                   {"CVE-2024-1234567", "CVE-2023-0001"},
		"XCVE-2024-1234 CVE-2024-12345678 CVE-2024-123 CVE-2024-1234a CVE-":  nil,
		"fin CVE-2026-42897": {"CVE-2026-42897"},
	} {
		if got := store.ExtractCVEs(text); !reflect.DeepEqual(got, want) {
			t.Errorf("extractCVEs(%q) = %v, want %v", text, got, want)
		}
	}
	feeds, err := st.ListFeeds(ctx)
	if err != nil || len(feeds) == 0 {
		t.Fatalf("feeds: %d, %v", len(feeds), err)
	}
	assetID := storetest.Asset(t, st, store.Asset{Name: "log4j", Kind: "package", Criticality: "high", Source: "manual"})
	finding := storetest.Finding(t, st, assetID, store.Vulnerability{ID: "GHSA-jfh8-c2jp-5v3q", Aliases: []string{"CVE-2021-44228"}, EPSS: -1, CVSS: -1}, time.Now())
	for i, title := range []string{"Log4Shell CVE-2021-44228 activement exploitée", "Rien à voir CVE-2020-0001", "Sans CVE"} {
		if _, err := st.InsertCTIItem(ctx, feeds[0].ID, store.CTIItem{GUID: title, Title: title, Published: time.Now().Add(-time.Duration(i) * time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	items, err := st.ListCTIItems(ctx, store.Everything, store.CTIFilter{Concerning: true})
	if err != nil || len(items) != 1 || !reflect.DeepEqual(items[0].Concerns, []string{"CVE-2021-44228"}) {
		t.Fatalf("concerning items: %+v, %v", items, err)
	}
	all, _ := st.ListCTIItems(ctx, store.Everything, store.CTIFilter{})
	if len(all) != 3 || all[1].Concerns != nil {
		t.Errorf("all items: %+v", all)
	}
	mentions, err := st.ListMentions(ctx, []string{"GHSA-jfh8-c2jp-5v3q", "CVE-2021-44228"}, 5)
	if err != nil || len(mentions) != 1 || mentions[0].FeedName == "" {
		t.Errorf("mentions: %+v, %v", mentions, err)
	}
	// Once the finding is closed, the news no longer concerns the inventory.
	if err := st.SetFindingStatus(ctx, store.Everything, finding, 0, "resolved", "", ""); err != nil {
		t.Fatal(err)
	}
	if items, _ := st.ListCTIItems(ctx, store.Everything, store.CTIFilter{Concerning: true}); len(items) != 0 {
		t.Errorf("closed finding still concerning: %+v", items)
	}
}

func TestWebhookDeliveryAndAudit(t *testing.T) {
	ctx := context.Background()
	st := storetest.Open(t)
	id, err := st.CreateWebhook(ctx, store.Webhook{Name: "mail", Kind: "email", URL: "a@example.org", Enabled: true, Digests: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetWebhookDelivery(ctx, id, false, "severe", 0); err != nil {
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
