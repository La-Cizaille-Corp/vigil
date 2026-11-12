package web

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/store"
)

// seedMany gives an asset n findings to analyse, CVE-2026-0000 onwards, and
// returns the asset and the finding of each vulnerability.
func seedMany(t *testing.T, st *store.Store, n int) (int64, map[string]int64) {
	t.Helper()
	ctx := context.Background()
	asset, err := st.CreateAsset(ctx, store.Everything, store.Asset{Name: "linux", Version: "6.12", Kind: "os", Criticality: "high", Source: "manual"})
	if err != nil {
		t.Fatal(err)
	}
	for i := range n {
		id := fmt.Sprintf("CVE-2026-%04d", i)
		if err := st.UpsertVulnerability(ctx, store.Vulnerability{ID: id, Severity: "LOW", CVSS: 3, Summary: "wifi: fix"}); err != nil {
			t.Fatal(err)
		}
		if _, err := st.ObserveFinding(ctx, asset, id, "", time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	ids := map[string]int64{}
	list, err := st.ListFindings(ctx, store.Everything, store.FindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range list {
		ids[f.VulnID] = f.ID
	}
	return asset, ids
}

// A long list is cut into pages of 100 rows after it is filtered and sorted;
// its counts and its export go by the whole list, and a new order or level
// starts at the first page (A85).
func TestListPages(t *testing.T) {
	st, base := newServerWith(t, nil)
	asset, _ := seedMany(t, st, 250)
	c := loginAs(t, base, "analyst", "a-strong-password")

	for query, want := range map[string]struct {
		first, rows int
		page, lines string
	}{
		"":         {0, 100, "Page 1 sur 3", "lignes 1 à 100 sur 250"},
		"&page=2":  {100, 100, "Page 2 sur 3", "lignes 101 à 200 sur 250"},
		"&page=3":  {200, 50, "Page 3 sur 3", "lignes 201 à 250 sur 250"},
		"&page=99": {200, 50, "Page 3 sur 3", "lignes 201 à 250 sur 250"}, // the nearest page
		"&page=0":  {0, 100, "Page 1 sur 3", "lignes 1 à 100 sur 250"},
		"&page=-1": {0, 100, "Page 1 sur 3", "lignes 1 à 100 sur 250"},
		"&page=x":  {0, 100, "Page 1 sur 3", "lignes 1 à 100 sur 250"},
	} {
		_, body := c.get("/findings?sort=vuln" + query)
		got := findingOrder(body)
		if len(got) != want.rows || got[0] != fmt.Sprintf("CVE-2026-%04d", want.first) {
			t.Errorf("%q: %d rows from %v, want %d from %d", query, len(got), got[:1], want.rows, want.first)
		}
		for _, text := range []string{want.page, "250 vulnérabilité(s) · " + want.lines, "Ouvertes <small>250</small>", "toute la liste filtrée (250)"} {
			if !strings.Contains(body, text) {
				t.Errorf("%q misses %q", query, text)
			}
		}
	}
	_, body := c.get("/findings?sort=vuln&page=2")
	for _, want := range []string{
		`<a href="/findings?sort=vuln" rel="prev">&lsaquo; Précédente</a>`, // the first page has no number
		`<a href="/findings?page=3&amp;sort=vuln" rel="next">Suivante &rsaquo;</a>`,
		`<a class="sort" href="/findings?dir=desc&amp;sort=cvss">CVSS</a>`, // a new order starts at the first page
		`<a href="/findings?level=urgent&amp;sort=vuln" >Urgentes`,         // so does a level
		`href="/findings.csv?sort=vuln"`,                                   // the export is the whole list
		`<input type="hidden" name="next" value="/findings?page=2&amp;sort=vuln">`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page 2 misses %s", want)
		}
	}
	if _, last := c.get("/findings?sort=vuln&page=3"); strings.Contains(last, `rel="next"`) || !strings.Contains(last, `<span class="muted">Suivante &rsaquo;</span>`) {
		t.Error("the last page leads further")
	}
	if _, csv := c.get("/findings.csv?sort=vuln&page=2"); strings.Count(csv, "\n") != 251 {
		t.Errorf("the export of page 2 has %d lines, want the whole list", strings.Count(csv, "\n"))
	}
	if _, short := c.get("/findings?q=CVE-2026-000"); strings.Contains(short, `class="pager"`) || strings.Contains(short, "lignes 1 à") {
		t.Error("a list of one page shows a pager")
	}

	// What a rule would set aside on an asset is cut the same way; the page
	// itself shows the ten most urgent and links to its list (A86).
	_, page := c.get("/assets/" + strconv.FormatInt(asset, 10) + "?q=wifi&page=3")
	if got := findingOrder(page[strings.Index(page, `id="apercu"`):]); len(got) != 50 || !strings.Contains(page, "lignes 201 à 250 sur 250") {
		t.Errorf("asset page 3: %d rows", len(got))
	}
	if !strings.Contains(page, "250 vulnérabilité(s) contiennent") {
		t.Error("the search on an asset counts its page only")
	}
	if _, page := c.get("/assets/" + strconv.FormatInt(asset, 10)); len(findingOrder(page)) != assetFirst || strings.Contains(page, `class="pager"`) {
		t.Errorf("the page of an asset lists %d vulnerabilities, want its %d most urgent", len(findingOrder(page)), assetFirst)
	}
}

// A decision on the whole list filtered applies to all its pages, leaves what
// someone already decided, and beyond 50 findings asks to be confirmed with
// their number (A85).
func TestBulkWholeList(t *testing.T) {
	st, base := newServerWith(t, nil)
	ctx := context.Background()
	_, ids := seedMany(t, st, 60)
	analyst, err := st.UserByName(ctx, "analyst")
	if err != nil {
		t.Fatal(err)
	}
	human := ids["CVE-2026-0007"]
	if err := st.SetFindingStatus(ctx, store.Everything, human, analyst.ID, store.StatusInTriage, "", "à revoir avec l'équipe réseau"); err != nil {
		t.Fatal(err)
	}
	c := loginAs(t, base, "analyst", "a-strong-password")
	status := func(id int64) string {
		f, err := st.Finding(ctx, store.Everything, id)
		if err != nil {
			t.Fatal(err)
		}
		return f.Status
	}

	// Up to 50, no confirmation.
	small := url.Values{"csrf": {c.csrf()}, "scope": {"list"}, "next": {"/findings?q=CVE-2026-001"}, "status": {"exploitable"}}
	if code, loc := c.postLocation("/findings/bulk", small); code != http.StatusSeeOther || loc != "/findings?q=CVE-2026-001&msg=bulk-list-updated" {
		t.Fatalf("a small list: %d %s", code, loc)
	}
	if status(ids["CVE-2026-0010"]) != store.StatusExploitable || status(ids["CVE-2026-0009"]) != store.StatusInTriage {
		t.Error("the small list is not the one filtered")
	}

	form := func(confirm string) url.Values {
		f := url.Values{"csrf": {c.csrf()}, "scope": {"list"}, "next": {"/findings?sort=vuln&page=2"}, "status": {"false_positive"}}
		if confirm != "" {
			f.Set("confirm", confirm)
		}
		return f
	}
	for _, confirm := range []string{"", "59", "abc"} {
		code, body := c.postBody("/findings/bulk", form(confirm))
		if code != http.StatusOK || !strings.Contains(body, "Confirmer pour 60 vulnérabilités") ||
			!strings.Contains(body, `<input type="hidden" name="confirm" value="60">`) ||
			!strings.Contains(body, `<input type="radio" name="scope" value="list" checked>`) {
			t.Fatalf("confirm %q: %d, no confirmation of 60", confirm, code)
		}
		if status(ids["CVE-2026-0000"]) != store.StatusInTriage {
			t.Fatal("applied before its confirmation")
		}
	}
	code, loc := c.postLocation("/findings/bulk", form("60"))
	if code != http.StatusSeeOther || loc != "/findings?sort=vuln&page=2&msg=bulk-list-updated" {
		t.Fatalf("confirmed: %d %s", code, loc)
	}
	for vuln, id := range ids {
		want := store.StatusFalsePositive
		switch {
		case id == human:
			want = store.StatusInTriage // decided by someone: unchanged
		case strings.HasPrefix(vuln, "CVE-2026-001"):
			want = store.StatusExploitable // so is a decision on a list before
		}
		if got := status(id); got != want {
			t.Errorf("%s = %s, want %s", vuln, got, want)
		}
	}

	// An empty list is refused beside the choice.
	small.Set("next", "/findings?q=nothing-matches")
	if code, body := c.postBody("/findings/bulk", small); code != http.StatusBadRequest || !strings.Contains(body, `<span class="field-error" id="bulk-error" role="alert">Cette liste est vide.</span>`) {
		t.Errorf("an empty list: %d", code)
	}
}

// A refused bulk decision shows the list again with the boxes ticked, the
// choices made and the panel open, the message beside the field at fault
// (A85).
func TestBulkErrorKeepsChoices(t *testing.T) {
	st, base := newServerWith(t, nil)
	_, ids := seedMany(t, st, 3)
	c := loginAs(t, base, "analyst", "a-strong-password")
	a, b := strconv.FormatInt(ids["CVE-2026-0000"], 10), strconv.FormatInt(ids["CVE-2026-0002"], 10)
	code, body := c.postBody("/findings/bulk", url.Values{"csrf": {c.csrf()}, "scope": {"rows"}, "id": {a, b},
		"status": {"not_affected"}, "comment": {"vu en revue"}, "next": {"/findings?sort=vuln"}})
	if code != http.StatusBadRequest {
		t.Fatalf("not affected without justification: %d", code)
	}
	for _, want := range []string{
		`<details class="card bulk" id="traiter" open>`,
		`value="` + a + `" form="bulk" aria-label="Sélectionner CVE-2026-0000 sur linux" checked>`,
		`value="` + b + `" form="bulk" aria-label="Sélectionner CVE-2026-0002 sur linux" checked>`,
		`<option value="not_affected" selected>`,
		`<select name="justification" aria-invalid="true" aria-describedby="bulk-error">`,
		`<span class="field-error" id="bulk-error" role="alert">Une justification est requise pour « Non affecté ».</span>`,
		`name="comment" maxlength="4000" value="vu en revue"`,
		`<th aria-sort="ascending"><a class="sort" href="/findings?dir=desc&amp;sort=vuln">Vulnérabilité</a></th>`, // the list it came from
	} {
		if !strings.Contains(body, want) {
			t.Errorf("refused decision misses %s", want)
		}
	}
	if strings.Contains(body, `value="`+strconv.FormatInt(ids["CVE-2026-0001"], 10)+`" form="bulk" aria-label="Sélectionner CVE-2026-0001 sur linux" checked>`) {
		t.Error("a box not ticked comes back ticked")
	}
	if !strings.Contains(body, `<a href="/findings" aria-current="page">Vulnérabilités</a>`) || !strings.Contains(body, `<input type="hidden" name="next" value="/findings">`) {
		t.Error("the list shown again is not that of /findings")
	}

	code, body = c.postBody("/findings/bulk", url.Values{"csrf": {c.csrf()}, "scope": {"rows"}, "status": {"resolved"}, "next": {"/findings"}})
	if code != http.StatusBadRequest || !strings.Contains(body, `<fieldset class="plain bulk-scope" aria-describedby="bulk-error">`) ||
		!strings.Contains(body, "Cochez entre 1 et 500 vulnérabilités, ou choisissez toute la liste filtrée.") {
		t.Errorf("nothing ticked: %d", code)
	}
}

// A vulnerability opened from a list leads back to it, with its filters and
// page, and on to the next one of the list, also once a decision took it out
// of the list; a return address that is not a list of Vigil is not followed
// (A85).
func TestBackToTheList(t *testing.T) {
	st, base := newServerWith(t, nil)
	_, ids := seedMany(t, st, 3)
	c := loginAs(t, base, "analyst", "a-strong-password")
	first, second, last := ids["CVE-2026-0000"], ids["CVE-2026-0001"], ids["CVE-2026-0002"]
	list := "/findings?q=CVE-2026&sort=vuln"
	back := url.QueryEscape(list)

	_, body := c.get(list)
	if !strings.Contains(body, `<a href="/findings/`+strconv.FormatInt(first, 10)+`?back=%2ffindings%3fq%3dCVE-2026%26sort%3dvuln">CVE-2026-0000</a>`) {
		t.Fatal("a row does not lead back to its list")
	}
	_, page := c.get(findingPath(first) + "?back=" + back)
	next := `<a href="/findings/` + strconv.FormatInt(second, 10) + `?back=%2ffindings%3fq%3dCVE-2026%26sort%3dvuln">Suivante dans la liste →</a>`
	if !strings.Contains(page, `<a href="/findings?q=CVE-2026&amp;sort=vuln">← Retour à la liste</a>`) || !strings.Contains(page, next) ||
		!strings.Contains(page, `<input type="hidden" name="back" value="/findings?q=CVE-2026&amp;sort=vuln">`) {
		t.Errorf("finding page opened from a list:\n%s", page)
	}
	if _, page := c.get(findingPath(last) + "?back=" + back); strings.Contains(page, "Suivante dans la liste") {
		t.Error("the last one of the list leads further")
	}
	for _, bad := range []string{"https://evil.example/findings?x", "//evil.example/findings", "/findings/bulk", "/settings"} {
		_, page := c.get(findingPath(first) + "?back=" + url.QueryEscape(bad))
		if strings.Contains(page, "evil.example") || !strings.Contains(page, `<a href="/findings">← Retour à la liste</a>`) {
			t.Errorf("back=%s followed", bad)
		}
	}

	// A decision takes it out of the list: the page still leads to the one
	// that followed it.
	code, loc := c.postLocation(findingPath(first), url.Values{"csrf": {c.csrf()}, "status": {"false_positive"}, "back": {list}})
	want := findingPath(first) + "?back=" + back + "&then=" + strconv.FormatInt(second, 10) + "&msg=status-updated"
	if code != http.StatusSeeOther || loc != want {
		t.Fatalf("update: %d %s\nwant %s", code, loc, want)
	}
	if _, page := c.get(loc); !strings.Contains(page, next) || !strings.Contains(page, "Statut mis à jour.") {
		t.Error("after a decision, no way on to the next one")
	}
	if code, loc := c.postLocation(findingPath(first), url.Values{"csrf": {c.csrf()}, "status": {"in_triage"}, "back": {"https://evil.example"}}); code != http.StatusSeeOther ||
		!strings.HasPrefix(loc, findingPath(first)+"?back=%2Ffindings") {
		t.Errorf("an external return address after a decision: %s", loc)
	}
}
