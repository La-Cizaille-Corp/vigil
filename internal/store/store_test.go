package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/store"
	"github.com/La-Cizaille-Corp/vigil/internal/storetest"
)

func TestReplaceProjectAssets(t *testing.T) {
	ctx := context.Background()
	st := storetest.Open(t)
	manual := store.Asset{Name: "nginx", Kind: "technology", Criticality: "high", Source: "manual", Project: "app"}
	if _, err := st.CreateAsset(ctx, store.Everything, manual); err != nil {
		t.Fatal(err)
	}
	a := store.Asset{Name: "a", Kind: "package", PURL: "pkg:npm/a@1"}
	b := store.Asset{Name: "b", Kind: "package", PURL: "pkg:npm/b@1"}
	c := store.Asset{Name: "c", Kind: "package", PURL: "pkg:npm/c@1"}

	res, err := st.ReplaceProjectAssets(ctx, store.Everything, "app", []store.Asset{a, b, b})
	if err != nil || res.Added != 2 {
		t.Fatalf("first import: %+v %v", res, err)
	}
	res, err = st.ReplaceProjectAssets(ctx, store.Everything, "app", []store.Asset{b, c})
	if err != nil || res.Added != 1 || res.Kept != 1 || res.Removed != 1 {
		t.Fatalf("second import: %+v %v", res, err)
	}
	assets, _ := st.ListAssets(ctx, store.Everything)
	if len(assets) != 3 { // nginx (manual, untouched), b, c
		t.Fatalf("assets = %d, want 3", len(assets))
	}
	projects, _ := st.ListProjects(ctx, store.Everything)
	if len(projects) != 1 || projects[0] != "app" {
		t.Fatalf("projects = %v", projects)
	}
}

// Assets created together are all added, in order, or none: a write that
// fails on the second one leaves the inventory as it was.
func TestCreateAssetsAllOrNothing(t *testing.T) {
	ctx := context.Background()
	st := storetest.Open(t)
	asset := func(name string) store.Asset {
		return store.Asset{Name: name, Kind: "package", Criticality: "low", Source: "manual", Tags: []string{"csv"}}
	}
	ids, err := st.CreateAssets(ctx, store.Everything, []store.Asset{asset("a"), asset("b")})
	if err != nil || len(ids) != 2 || ids[0] >= ids[1] {
		t.Fatalf("ids = %v, %v", ids, err)
	}
	if a, err := st.Asset(ctx, store.Everything, ids[1]); err != nil || a.Name != "b" || len(a.Tags) != 1 {
		t.Errorf("second asset: %+v, %v", a, err)
	}
	if _, err := store.DB(st).ExecContext(ctx, `CREATE TRIGGER failing_write BEFORE INSERT ON assets WHEN NEW.name = 'panne'
		BEGIN SELECT RAISE(ABORT, 'disk I/O error'); END`); err != nil {
		t.Fatal(err)
	}
	if ids, err := st.CreateAssets(ctx, store.Everything, []store.Asset{asset("c"), asset("panne"), asset("d")}); err == nil || ids != nil {
		t.Errorf("failing write: %v, %v", ids, err)
	}
	if list, _ := st.ListAssets(ctx, store.Everything); len(list) != 2 {
		t.Errorf("assets after a failed creation: %+v", list)
	}
}

func TestCTIItemsFilter(t *testing.T) {
	ctx := context.Background()
	st := storetest.Open(t)
	id, err := st.CreateFeed(ctx, store.Feed{Name: "test", URL: "https://example.org/feed", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	items := []store.CTIItem{
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
	got, _ := st.ListCTIItems(ctx, store.Everything, store.CTIFilter{Countries: []string{"FR", "US"}, Sectors: []string{"finance"}})
	if len(got) != 1 || got[0].GUID != "2" {
		t.Fatalf("filtered items = %+v", got)
	}
	all, _ := st.ListCTIItems(ctx, store.Everything, store.CTIFilter{})
	if len(all) != 3 {
		t.Fatalf("all items = %d", len(all))
	}
	// A count reads the same items as the list, whatever it lists.
	for want, f := range map[int]store.CTIFilter{1: {Countries: []string{"FR", "US"}, Sectors: []string{"finance"}}, 3: {Limit: 1}} {
		if n, err := st.CountCTIItems(ctx, store.Everything, f); err != nil || n != want {
			t.Errorf("count of %+v = %d, %v; want %d", f, n, err, want)
		}
	}
}

// A tag is matched literally: "_" is a LIKE wildcard, and "pci_dss" must not
// match "pcixdss", in the news tags as in the tags of assets (see hasTag).
func TestTagFilterIsLiteral(t *testing.T) {
	ctx := context.Background()
	st := storetest.Open(t)
	feed, err := st.CreateFeed(ctx, store.Feed{Name: "test", URL: "https://example.org/feed", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range []store.CTIItem{
		{GUID: "1", Title: "pci", Published: time.Now(), Regulations: []string{"pci_dss"}},
		{GUID: "2", Title: "other", Published: time.Now(), Regulations: []string{"pcixdss"}},
	} {
		if _, err := st.InsertCTIItem(ctx, feed, it); err != nil {
			t.Fatal(err)
		}
	}
	got, err := st.ListCTIItems(ctx, store.Everything, store.CTIFilter{Regulations: []string{"pci_dss"}})
	if err != nil || len(got) != 1 || got[0].GUID != "1" {
		t.Errorf("news tagged pci_dss = %+v, %v", got, err)
	}

	for _, tag := range []string{"web_app", "webxapp"} {
		id := storetest.Asset(t, st, store.Asset{Name: tag, Kind: "technology", Criticality: "high", Tags: []string{tag}})
		storetest.Finding(t, st, id, store.Vulnerability{ID: "GHSA-1"}, time.Now())
	}
	found, err := st.ListFindings(ctx, store.Everything, store.FindingFilter{Tag: "web_app"})
	if err != nil || len(found) != 1 || found[0].AssetName != "web_app" {
		t.Errorf("findings tagged web_app = %+v, %v", found, err)
	}
}

// A component dropped from an SBOM is retired, not deleted: open findings
// are resolved with an event, decisions are kept, and the component comes
// back with its history when a later SBOM lists it again.
func TestRetiredComponentsKeepHistory(t *testing.T) {
	ctx := context.Background()
	st := storetest.Open(t)
	a := store.Asset{Name: "a", Kind: "package", PURL: "pkg:npm/a@1"}
	b := store.Asset{Name: "b", Kind: "package", PURL: "pkg:npm/b@1"}
	if _, err := st.ReplaceProjectAssets(ctx, store.Everything, "app", []store.Asset{a, b}); err != nil {
		t.Fatal(err)
	}
	assets, err := st.ListAssets(ctx, store.Everything)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]int64{}
	for _, x := range assets {
		ids[x.Name] = x.ID
	}
	open := storetest.Finding(t, st, ids["b"], store.Vulnerability{ID: "V-OPEN", Severity: "HIGH"}, time.Now())
	decided := storetest.Finding(t, st, ids["b"], store.Vulnerability{ID: "V-DECIDED", Severity: "LOW"}, time.Now())
	if err := st.SetFindingStatus(ctx, store.Everything, decided, 0, "not_affected", "code_not_present", "vérifié"); err != nil {
		t.Fatal(err)
	}

	if res, err := st.ReplaceProjectAssets(ctx, store.Everything, "app", []store.Asset{a}); err != nil || res.Removed != 1 {
		t.Fatalf("import without b: %+v %v", res, err)
	}
	if active, _ := st.ListAssets(ctx, store.Everything); len(active) != 1 {
		t.Errorf("active assets = %d, want 1", len(active))
	}
	retired, _ := st.ListRetiredAssets(ctx, store.Everything)
	if len(retired) != 1 || retired[0].Retired.IsZero() {
		t.Fatalf("retired = %+v", retired)
	}
	got, _ := st.Finding(ctx, store.Everything, open)
	if got.Status != "resolved" {
		t.Errorf("open finding of a retired component: %s", got.Status)
	}
	if events, _ := st.ListFindingEvents(ctx, store.Everything, open); len(events) == 0 || events[len(events)-1].NewStatus != "resolved" {
		t.Errorf("no history event: %+v", events)
	}
	if got, _ := st.Finding(ctx, store.Everything, decided); got.Status != "not_affected" || got.Comment != "vérifié" {
		t.Errorf("decision lost: %+v", got)
	}

	if res, err := st.ReplaceProjectAssets(ctx, store.Everything, "app", []store.Asset{a, b}); err != nil || res.Kept != 2 || res.Added != 0 {
		t.Fatalf("b listed again: %+v %v", res, err)
	}
	if retired, _ := st.ListRetiredAssets(ctx, store.Everything); len(retired) != 0 {
		t.Error("b still retired")
	}
}

// An article published in two feeds is kept once; items without a link are not
// compared.
func TestSameArticleInTwoFeeds(t *testing.T) {
	ctx := context.Background()
	st := storetest.Open(t)
	first, _ := st.CreateFeed(ctx, store.Feed{Name: "a", URL: "https://a.example/feed", Enabled: true})
	second, _ := st.CreateFeed(ctx, store.Feed{Name: "b", URL: "https://b.example/feed", Enabled: true})
	insert := func(feed int64, guid, link string) bool {
		t.Helper()
		created, err := st.InsertCTIItem(ctx, feed, store.CTIItem{GUID: guid, Title: guid, Link: link, Published: time.Now()})
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
	st := storetest.Open(t)
	asset := storetest.Asset(t, st, store.Asset{Name: "linux", Kind: "os", Criticality: "high", Source: "manual"})
	other := storetest.Asset(t, st, store.Asset{Name: "autre", Kind: "os", Criticality: "high", Source: "manual"})
	user, err := st.CreateUser(ctx, "ana", "x", "analyst", store.Access{All: true})
	if err != nil {
		t.Fatal(err)
	}
	add := func(a int64, id, summary string) int64 {
		t.Helper()
		return storetest.Finding(t, st, a, store.Vulnerability{ID: id, Summary: summary, EPSS: -1, CVSS: -1}, time.Now())
	}
	state := func(id int64) string {
		t.Helper()
		f, err := st.Finding(ctx, store.Everything, id)
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
	st.SetExploitSignals(ctx, store.ExploitSignal{ID: "CVE-5", KEV: true, EPSS: 0.5})
	decided := add(asset, "CVE-6", "wifi: analysed by someone")
	st.SetFindingStatus(ctx, store.Everything, decided, user, "exploitable", "", "à traiter")
	reset := add(asset, "CVE-7", "wifi: put back by someone")
	st.SetFindingStatus(ctx, store.Everything, reset, user, "in_triage", "", "")

	// What a rule would set aside is what the preview lists.
	preview, _ := st.ListFindings(ctx, store.Everything, store.FindingFilter{AssetID: asset, Matching: "WIFI:"})
	if len(preview) != 5 {
		t.Errorf("preview: %d findings", len(preview))
	}
	if err := st.CreateDismissalRule(ctx, store.Everything, asset, "wifi:"); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateDismissalRule(ctx, store.Everything, asset, "wifi:"); err != nil {
		t.Errorf("the same rule again: %v", err)
	}
	for id, want := range map[int64]string{wifi: "not_affected", wifiUpper: "not_affected", ipv4: "in_triage", elsewhere: "in_triage",
		exploited: "in_triage", decided: "exploitable", reset: "in_triage"} {
		if got := state(id); got != want {
			t.Errorf("finding %d: %s, want %s", id, got, want)
		}
	}
	f, _ := st.Finding(ctx, store.Everything, wifi)
	if f.Justification != "code_not_present" || !strings.Contains(f.Comment, "wifi:") {
		t.Errorf("set aside: %+v", f)
	}
	if events, _ := st.ListFindingEvents(ctx, store.Everything, wifi); len(events) == 0 || events[len(events)-1].NewStatus != "not_affected" {
		t.Errorf("history: %+v", events)
	}

	// The next ones too, at the next sync.
	next := add(asset, "CVE-8", "wifi: a new one")
	if n, err := st.ApplyDismissalRules(ctx); err != nil || n != 1 || state(next) != "not_affected" {
		t.Errorf("next one: %d, %v, %s", n, err, state(next))
	}
	rules, _ := st.ListDismissalRules(ctx, store.Everything, asset)
	if len(rules) != 1 || rules[0].Text != "wifi:" || rules[0].Findings != 3 {
		t.Fatalf("rules: %+v", rules)
	}

	// Known to be exploited later: back to analyse, and not set aside again.
	st.SetExploitSignals(ctx, store.ExploitSignal{ID: "CVE-2", KEV: true, EPSS: 0.5})
	if _, err := st.ApplyDismissalRules(ctx); err != nil {
		t.Fatal(err)
	}
	if got := state(wifiUpper); got != "in_triage" {
		t.Errorf("exploited later: %s", got)
	}

	// A decision taken by someone is theirs: the rule no longer touches it.
	st.SetFindingStatus(ctx, store.Everything, next, user, "exploitable", "", "finalement si")

	if err := st.DeleteDismissalRule(ctx, store.Everything, other, rules[0].ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("rule of another asset: %v", err)
	}
	if err := st.DeleteDismissalRule(ctx, store.Everything, asset, rules[0].ID); err != nil {
		t.Fatal(err)
	}
	f, _ = st.Finding(ctx, store.Everything, wifi)
	if f.Status != "in_triage" || f.Justification != "" || f.Comment != "" {
		t.Errorf("restored: %+v", f)
	}
	if got := state(next); got != "exploitable" {
		t.Errorf("a decision was undone: %s", got)
	}
	if rules, _ := st.ListDismissalRules(ctx, store.Everything, asset); len(rules) != 0 {
		t.Errorf("rules left: %+v", rules)
	}
}

// No temporary file: the file system of the container is read-only.
func TestTemporaryDataInMemory(t *testing.T) {
	ctx := context.Background()
	st := storetest.Open(t)
	var mode int
	if err := store.DB(st).QueryRowContext(ctx, `PRAGMA temp_store`).Scan(&mode); err != nil || mode != 2 {
		t.Errorf("temp_store = %d, %v", mode, err)
	}
}
