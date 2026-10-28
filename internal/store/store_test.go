package store

import (
	"context"
	"path/filepath"
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
	st.ObserveFinding(ctx, ids["b"], "V-OPEN", time.Now())
	st.ObserveFinding(ctx, ids["b"], "V-DECIDED", time.Now())
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
