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
