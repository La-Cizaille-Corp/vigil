package store

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	st, err := Open(context.Background(), filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestReplaceProjectAssets(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	manual := Asset{Name: "nginx", Kind: "technology", Criticality: "high", Source: "manual", Project: "app"}
	if _, err := st.CreateAsset(ctx, manual); err != nil {
		t.Fatal(err)
	}
	a := Asset{Name: "a", Kind: "package", PURL: "pkg:npm/a@1"}
	b := Asset{Name: "b", Kind: "package", PURL: "pkg:npm/b@1"}
	c := Asset{Name: "c", Kind: "package", PURL: "pkg:npm/c@1"}

	res, err := st.ReplaceProjectAssets(ctx, "app", []Asset{a, b, b})
	if err != nil || res.Added != 2 {
		t.Fatalf("first import: %+v %v", res, err)
	}
	res, err = st.ReplaceProjectAssets(ctx, "app", []Asset{b, c})
	if err != nil || res.Added != 1 || res.Kept != 1 || res.Removed != 1 {
		t.Fatalf("second import: %+v %v", res, err)
	}
	assets, _ := st.ListAssets(ctx)
	if len(assets) != 3 { // nginx (manual, untouched), b, c
		t.Fatalf("assets = %d, want 3", len(assets))
	}
	projects, _ := st.ListProjects(ctx)
	if len(projects) != 1 || projects[0] != "app" {
		t.Fatalf("projects = %v", projects)
	}
}

func TestCTIItemsFilter(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	id, err := st.CreateFeed(ctx, Feed{Name: "test", URL: "https://example.org/feed", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	items := []CTIItem{
		{GUID: "1", Title: "fr health", Published: time.Now(), Countries: []string{"FR"}, Sectors: []string{"health"}},
		{GUID: "2", Title: "us finance", Published: time.Now(), Countries: []string{"US"}, Sectors: []string{"finance"}},
		{GUID: "3", Title: "untagged", Published: time.Now()},
	}
	for _, it := range items {
		if _, err := st.InsertCTIItem(ctx, id, it); err != nil {
			t.Fatal(err)
		}
	}
	if isNew, _ := st.InsertCTIItem(ctx, id, items[0]); isNew {
		t.Fatal("duplicate item inserted")
	}
	got, _ := st.ListCTIItems(ctx, CTIFilter{Countries: []string{"FR", "US"}, Sectors: []string{"finance"}})
	if len(got) != 1 || got[0].GUID != "2" {
		t.Fatalf("filtered items = %+v", got)
	}
	all, _ := st.ListCTIItems(ctx, CTIFilter{})
	if len(all) != 3 {
		t.Fatalf("all items = %d", len(all))
	}
}

// A component dropped from an SBOM is retired, not deleted: open findings
// are resolved with an event, decisions are kept, and the component comes
// back with its history when a later SBOM lists it again.
func TestRetiredComponentsKeepHistory(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	a := Asset{Name: "a", Kind: "package", PURL: "pkg:npm/a@1"}
	b := Asset{Name: "b", Kind: "package", PURL: "pkg:npm/b@1"}
	st.ReplaceProjectAssets(ctx, "app", []Asset{a, b})
	assets, _ := st.ListAssets(ctx)
	ids := map[string]int64{}
	for _, x := range assets {
		ids[x.Name] = x.ID
	}
	st.UpsertVulnerability(ctx, Vulnerability{ID: "V-OPEN", Severity: "HIGH"})
	st.UpsertVulnerability(ctx, Vulnerability{ID: "V-DECIDED", Severity: "LOW"})
	st.ObserveFinding(ctx, ids["b"], "V-OPEN", "", time.Now())
	st.ObserveFinding(ctx, ids["b"], "V-DECIDED", "", time.Now())
	findings, _ := st.ListFindings(ctx, FindingFilter{AssetID: ids["b"]})
	var open, decided int64
	for _, f := range findings {
		if f.VulnID == "V-OPEN" {
			open = f.ID
		} else {
			decided = f.ID
		}
	}
	st.SetFindingStatus(ctx, decided, 0, "not_affected", "code_not_present", "vérifié")

	if res, err := st.ReplaceProjectAssets(ctx, "app", []Asset{a}); err != nil || res.Removed != 1 {
		t.Fatalf("import without b: %+v %v", res, err)
	}
	if active, _ := st.ListAssets(ctx); len(active) != 1 {
		t.Errorf("active assets = %d, want 1", len(active))
	}
	retired, _ := st.ListRetiredAssets(ctx)
	if len(retired) != 1 || retired[0].Retired.IsZero() {
		t.Fatalf("retired = %+v", retired)
	}
	got, _ := st.Finding(ctx, open)
	if got.Status != "resolved" {
		t.Errorf("open finding of a retired component: %s", got.Status)
	}
	if events, _ := st.FindingEvents(ctx, open); len(events) == 0 || events[len(events)-1].NewStatus != "resolved" {
		t.Errorf("no history event: %+v", events)
	}
	if got, _ := st.Finding(ctx, decided); got.Status != "not_affected" || got.Comment != "vérifié" {
		t.Errorf("decision lost: %+v", got)
	}

	if res, err := st.ReplaceProjectAssets(ctx, "app", []Asset{a, b}); err != nil || res.Kept != 2 || res.Added != 0 {
		t.Fatalf("b listed again: %+v %v", res, err)
	}
	if retired, _ := st.ListRetiredAssets(ctx); len(retired) != 0 {
		t.Error("b still retired")
	}
}

// An article published in two feeds is kept once; items without a link are not
// compared.
func TestSameArticleInTwoFeeds(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	first, _ := st.CreateFeed(ctx, Feed{Name: "a", URL: "https://a.example/feed", Enabled: true})
	second, _ := st.CreateFeed(ctx, Feed{Name: "b", URL: "https://b.example/feed", Enabled: true})
	insert := func(feed int64, guid, link string) bool {
		t.Helper()
		created, err := st.InsertCTIItem(ctx, feed, CTIItem{GUID: guid, Title: guid, Link: link, Published: time.Now()})
		if err != nil {
			t.Fatal(err)
		}
		return created
	}
	if !insert(first, "1", "https://site.example/article") {
		t.Error("first copy refused")
	}
	if insert(second, "other-guid", "https://site.example/article") {
		t.Error("the same article was kept twice")
	}
	if !insert(second, "2", "https://site.example/other") {
		t.Error("another article refused")
	}
	if !insert(first, "3", "") || !insert(second, "4", "") {
		t.Error("items without a link must not be compared")
	}
	if insert(first, "1", "https://site.example/article") {
		t.Error("the same item was kept twice")
	}
}

func TestDismissalRules(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	asset, _ := st.CreateAsset(ctx, Asset{Name: "linux", Kind: "os", Criticality: "high", Source: "manual"})
	other, _ := st.CreateAsset(ctx, Asset{Name: "autre", Kind: "os", Criticality: "high", Source: "manual"})
	user, _ := st.CreateUser(ctx, "ana", "x", "analyst")
	add := func(a int64, id, summary string) int64 {
		t.Helper()
		st.UpsertVulnerability(ctx, Vulnerability{ID: id, Summary: summary, EPSS: -1, CVSS: -1})
		if _, err := st.ObserveFinding(ctx, a, id, "", time.Now()); err != nil {
			t.Fatal(err)
		}
		list, _ := st.ListFindings(ctx, FindingFilter{AssetID: a})
		for _, f := range list {
			if f.VulnID == id {
				return f.ID
			}
		}
		t.Fatalf("no finding for %s", id)
		return 0
	}
	state := func(id int64) string {
		t.Helper()
		f, err := st.Finding(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		return f.Status
	}
	wifi := add(asset, "CVE-1", "wifi: fix a leak")
	wifiUpper := add(asset, "CVE-2", "WiFi: another one")
	ipv4 := add(asset, "CVE-3", "ipv4: validate")
	elsewhere := add(other, "CVE-4", "wifi: on another asset")
	exploited := add(asset, "CVE-5", "wifi: exploited")
	st.SetExploitSignals(ctx, "CVE-5", true, "", 0.5)
	decided := add(asset, "CVE-6", "wifi: analysed by someone")
	st.SetFindingStatus(ctx, decided, user, "exploitable", "", "à traiter")
	reset := add(asset, "CVE-7", "wifi: put back by someone")
	st.SetFindingStatus(ctx, reset, user, "in_triage", "", "")

	// What a rule would set aside is what the preview lists.
	preview, _ := st.ListFindings(ctx, FindingFilter{AssetID: asset, Matching: "WIFI:"})
	if len(preview) != 5 {
		t.Errorf("preview: %d findings", len(preview))
	}
	if err := st.CreateDismissalRule(ctx, asset, "wifi:"); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateDismissalRule(ctx, asset, "wifi:"); err != nil {
		t.Errorf("the same rule again: %v", err)
	}
	for id, want := range map[int64]string{wifi: "not_affected", wifiUpper: "not_affected", ipv4: "in_triage", elsewhere: "in_triage",
		exploited: "in_triage", decided: "exploitable", reset: "in_triage"} {
		if got := state(id); got != want {
			t.Errorf("finding %d: %s, want %s", id, got, want)
		}
	}
	f, _ := st.Finding(ctx, wifi)
	if f.Justification != "code_not_present" || !strings.Contains(f.Comment, "wifi:") {
		t.Errorf("set aside: %+v", f)
	}
	if events, _ := st.FindingEvents(ctx, wifi); len(events) == 0 || events[len(events)-1].NewStatus != "not_affected" {
		t.Errorf("history: %+v", events)
	}

	// The next ones too, at the next sync.
	next := add(asset, "CVE-8", "wifi: a new one")
	if n, err := st.ApplyDismissalRules(ctx); err != nil || n != 1 || state(next) != "not_affected" {
		t.Errorf("next one: %d, %v, %s", n, err, state(next))
	}
	rules, _ := st.DismissalRules(ctx, asset)
	if len(rules) != 1 || rules[0].Text != "wifi:" || rules[0].Findings != 3 {
		t.Fatalf("rules: %+v", rules)
	}

	// Known to be exploited later: back to analyse, and not set aside again.
	st.SetExploitSignals(ctx, "CVE-2", true, "", 0.5)
	if _, err := st.ApplyDismissalRules(ctx); err != nil {
		t.Fatal(err)
	}
	if got := state(wifiUpper); got != "in_triage" {
		t.Errorf("exploited later: %s", got)
	}

	// A decision taken by someone is theirs: the rule no longer touches it.
	st.SetFindingStatus(ctx, next, user, "exploitable", "", "finalement si")

	if err := st.DeleteDismissalRule(ctx, other, rules[0].ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("rule of another asset: %v", err)
	}
	if err := st.DeleteDismissalRule(ctx, asset, rules[0].ID); err != nil {
		t.Fatal(err)
	}
	f, _ = st.Finding(ctx, wifi)
	if f.Status != "in_triage" || f.Justification != "" || f.Comment != "" {
		t.Errorf("restored: %+v", f)
	}
	if got := state(next); got != "exploitable" {
		t.Errorf("a decision was undone: %s", got)
	}
	if rules, _ := st.DismissalRules(ctx, asset); len(rules) != 0 {
		t.Errorf("rules left: %+v", rules)
	}
}

// No temporary file: the file system of the container is read-only.
func TestTemporaryDataInMemory(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var mode int
	if err := st.db.QueryRowContext(ctx, `PRAGMA temp_store`).Scan(&mode); err != nil || mode != 2 {
		t.Errorf("temp_store = %d, %v", mode, err)
	}
}
