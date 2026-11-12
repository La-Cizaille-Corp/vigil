package web

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/store"
)

// The watch shows its most recent news a page at a time, by day, counts each
// view, the one concerning the inventory first, and says when it shows only
// the most recent ones (A87).
func TestWatchPagesAndCounts(t *testing.T) {
	st, base := newServerWith(t, nil)
	ctx := context.Background()
	asset, _ := st.CreateAsset(ctx, store.Everything, store.Asset{Name: "nginx", Version: "1.24", Kind: "product", Criticality: "high", Source: "manual"})
	st.UpsertVulnerability(ctx, store.Vulnerability{ID: "CVE-2026-1234", Severity: "HIGH", CVSS: 7.5, EPSS: -1})
	st.ObserveFinding(ctx, asset, "CVE-2026-1234", "", time.Now())
	feed, err := st.CreateFeed(ctx, store.Feed{Name: "Avis", URL: "https://example.org/feed", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	const n = store.MaxCTIItems + 20
	start := time.Date(2026, 11, 10, 23, 0, 0, 0, time.UTC)
	for i := range n {
		it := store.CTIItem{GUID: fmt.Sprint(i), Title: fmt.Sprintf("Actualité %03d", i), Link: fmt.Sprintf("https://example.org/%d", i),
			Published: start.Add(-time.Duration(i) * time.Hour), Summary: "Un résumé coupé par sa source, au milieu de"}
		switch {
		case i%10 == 0:
			it.Title += " CVE-2026-1234"
		case i%7 == 0:
			it.Regulations = []string{"nis2"}
		}
		if _, err := st.InsertCTIItem(ctx, feed, it); err != nil {
			t.Fatal(err)
		}
	}
	c := loginAs(t, base, "analyst", "a-strong-password")

	_, body := c.get("/cti?all=1")
	for _, want := range []string{
		`<a href="/cti?all=1&amp;concerning=1" >Qui concernent mon inventaire <small>52</small></a>`,
		`<a href="/cti" >Veille menaces <small>520</small></a>`, // no watch filter: everything
		`<a href="/cti?view=regulatory" >Veille réglementaire <small>`,
		`<a href="/cti?all=1" class="active" aria-current="true">Toutes les actualités <small>520</small></a>`,
		"500 actualité(s) · lignes 1 à 100 sur 500\n  : les 500 plus récentes sur 520",
		`<a href="/cti?all=1&amp;page=2" rel="next">Suivante &rsaquo;</a>`,
		`<h2 class="news-day">10/11/2026</h2>`,
		"Un résumé coupé par sa source, au milieu de…",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("watch misses %q", want)
		}
	}
	if strings.Index(body, "Qui concernent mon inventaire") > strings.Index(body, "Veille menaces <small>") {
		t.Error("the view concerning the inventory is not first")
	}
	if items := strings.Count(body, "<li>\n  <a href=\"https://example.org/"); items != pageSize {
		t.Errorf("%d news on a page, want %d", items, pageSize)
	}
	// A day heading per day of the page, the first one at the top.
	days := regexp.MustCompile(`<h2 class="news-day">`).FindAllStringIndex(body, -1)
	if len(days) != 5 || days[0][0] > strings.Index(body, "Actualité 000") {
		t.Errorf("%d day headings on the first page", len(days))
	}
	_, last := c.get("/cti?all=1&page=5")
	if !strings.Contains(last, "lignes 401 à 500 sur 500") || strings.Contains(last, "Actualité 500") || !strings.Contains(last, "Actualité 499") {
		t.Error("the last page does not end with the 500th most recent")
	}
	_, mine := c.get("/cti?all=1&concerning=1")
	if !strings.Contains(mine, "52 actualité(s)") || strings.Contains(mine, "plus récentes sur") ||
		!strings.Contains(mine, `class="active" aria-current="true">Qui concernent mon inventaire`) {
		t.Error("the view concerning the inventory")
	}
}
