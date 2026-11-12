package web

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/auth"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
)

// On a phone, where the titles of its columns are hidden, a sortable list is
// sorted from a list of them (A33): the form starts from the order shown and
// keeps the filters and the level, not the page nor the message.
func TestPhoneSortForm(t *testing.T) {
	st, base := newServerWith(t, nil)
	seedFindings(t, st)
	c := loginAs(t, base, "analyst", "a-strong-password")

	_, body := c.get("/findings?severity=HIGH&severity=CRITICAL&level=all&sort=cvss&dir=asc&page=1&msg=bulk-updated")
	start := strings.Index(body, `<form method="get" action="/findings" class="sort-form">`)
	end := strings.Index(body[max(start, 0):], "</form>")
	if start < 0 || end < 0 {
		t.Fatalf("no sort form:\n%s", body)
	}
	form := body[start : start+end]
	for _, want := range []string{`<input type="hidden" name="level" value="all">`,
		`<input type="hidden" name="severity" value="HIGH"><input type="hidden" name="severity" value="CRITICAL">`,
		`<option value="cvss" selected>CVSS</option>`, `<option value="asc" selected>croissant</option>`,
		`<option value="priority">Priorité</option>`} {
		if !strings.Contains(form, want) {
			t.Errorf("sort form misses %s:\n%s", want, form)
		}
	}
	for _, unwanted := range []string{`name="page"`, `name="msg"`, `type="hidden" name="sort"`, `type="hidden" name="dir"`, ">Résumé<"} {
		if strings.Contains(form, unwanted) {
			t.Errorf("sort form holds %s:\n%s", unwanted, form)
		}
	}

	// The inventory too, in the natural order of its column.
	_, body = c.get("/assets?sort=criticality")
	for _, want := range []string{`<form method="get" action="/assets" class="sort-form">`,
		`<option value="criticality" selected>Criticité</option>`, `<option value="desc" selected>décroissant</option>`} {
		if !strings.Contains(body, want) {
			t.Errorf("inventory misses %s", want)
		}
	}
}

// Every table of the interface reads as cards on a phone (class cards), and
// says it is a table with explicit roles, which a grid layout takes away in
// some browsers; a link to another site says it opens a new tab (A33).
func TestTablesReadAsCards(t *testing.T) {
	st, base := newServerWith(t, nil)
	ctx := context.Background()
	asset, ids := seedFindings(t, st)
	if err := st.UpsertVulnerability(ctx, store.Vulnerability{ID: "CVE-2024-0001", Severity: "CRITICAL", CVSS: 9.8, EPSS: -1,
		Refs: []string{"https://example.org/advisory"}}); err != nil {
		t.Fatal(err)
	}
	feed, err := st.CreateFeed(ctx, store.Feed{Name: "Avis", URL: "https://example.org/feed", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.InsertCTIItem(ctx, feed, store.CTIItem{GUID: "1", Title: "CVE-2024-0001 exploitée",
		Link: "https://example.org/news", Published: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateWebhook(ctx, store.Webhook{Name: "Équipe", Kind: "generic", URL: "https://example.org/hook", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateAPIToken(ctx, store.APIToken{Name: "ci", Project: "app"}, auth.HashToken("vgl_test"), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateGroup(ctx, "Équipe web"); err != nil {
		t.Fatal(err)
	}
	admin := loginAs(t, base, "admin", "a-strong-password")

	tables := regexp.MustCompile(`<table[^>]*>`)
	cells := regexp.MustCompile(`<t[dh][ >][^>]*>?`)
	for _, path := range []string{"/", "/assets", "/assets/" + strconv.FormatInt(asset, 10), "/findings",
		"/findings/" + strconv.FormatInt(ids[0], 10), "/cti?all=1", "/settings", "/settings/users", "/settings/audit", "/settings/groups"} {
		_, body := admin.get(path)
		found := tables.FindAllString(body, -1)
		if len(found) == 0 && path != "/cti?all=1" && !strings.HasPrefix(path, "/findings/") {
			t.Errorf("%s: no table", path)
		}
		for _, tag := range found {
			if !strings.Contains(tag, `class="cards`) || !strings.Contains(tag, `role="table"`) {
				t.Errorf("%s: %s is not a table of cards with its role", path, tag)
			}
		}
		for _, cell := range cells.FindAllString(body, -1) {
			if !strings.Contains(cell, `role="cell"`) && !strings.Contains(cell, `role="columnheader"`) {
				t.Errorf("%s: %s has no role", path, cell)
			}
		}
		if n, told := strings.Count(body, `target="_blank"`), strings.Count(body, `<span class="sr-only"> (nouvel onglet)</span></a>`); n != told {
			t.Errorf("%s: %d links open a new tab, %d say so", path, n, told)
		}
	}
	_, body := admin.get("/findings/" + strconv.FormatInt(ids[0], 10))
	if !strings.Contains(body, `<a href="https://example.org/advisory" rel="noopener noreferrer" target="_blank">https://example.org/advisory<span class="sr-only"> (nouvel onglet)</span></a>`) {
		t.Error("a reference does not say it opens a new tab")
	}
}
