package web

import (
	"context"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/store"
	"github.com/La-Cizaille-Corp/vigil/internal/tracking"
)

// assetOrder returns the asset names of the inventory page, in order.
func assetOrder(body string) []string {
	var out []string
	for _, m := range regexp.MustCompile(`<a href="/assets/\d+">([^<]+)</a>`).FindAllStringSubmatch(body, -1) {
		out = append(out, m[1])
	}
	return out
}

// findingOrder returns the vulnerabilities of a list page, in order.
func findingOrder(body string) []string {
	var out []string
	for _, m := range regexp.MustCompile(`<a href="/findings/\d+">([^<]+)</a>`).FindAllStringSubmatch(body, -1) {
		out = append(out, m[1])
	}
	return out
}

func TestSortAssets(t *testing.T) {
	st, base := newServerWith(t, nil)
	ctx := context.Background()
	for _, a := range []store.Asset{
		{Name: "bravo", Version: "10.0", Kind: "product", Criticality: "low", Project: "web", Owner: "Zoé"},
		{Name: "Alpha", Version: "9.5", Kind: "os", Criticality: "critical", Project: "api"},
		{Name: "charlie", Kind: "package", Criticality: "high", Project: "web", Owner: "Ana", Tags: []string{"prod"}},
	} {
		a.Source = "manual"
		if _, err := st.CreateAsset(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	c := loginAs(t, base, "analyst", "a-strong-password")
	for query, want := range map[string][]string{
		"sort=name":                {"Alpha", "bravo", "charlie"},
		"sort=name&dir=desc":       {"charlie", "bravo", "Alpha"},
		"sort=version":             {"Alpha", "bravo", "charlie"}, // 9.5 before 10.0, none last
		"sort=version&dir=desc":    {"bravo", "Alpha", "charlie"}, // none last here too
		"sort=criticality":         {"Alpha", "charlie", "bravo"}, // most critical first
		"sort=criticality&dir=asc": {"bravo", "charlie", "Alpha"},
		"sort=owner":               {"charlie", "bravo", "Alpha"},
		"sort=nope":                {"Alpha", "bravo", "charlie"}, // api, then web: as stored
		"project=web&sort=name":    {"bravo", "charlie"},
		"project=web&tag=prod":     {"charlie"},
	} {
		_, body := c.get("/assets?" + query)
		if got := assetOrder(body); !slices.Equal(got, want) {
			t.Errorf("%s: %v, want %v", query, got, want)
		}
	}

	// The titles keep the filters, tell the order and reverse it.
	_, body := c.get("/assets?project=web&sort=name&msg=asset-deleted")
	if !strings.Contains(body, `<th aria-sort="ascending"><a class="sort" href="/assets?dir=desc&amp;project=web&amp;sort=name">Nom</a></th>`) {
		t.Errorf("title of the sorted column:\n%s", body)
	}
	if !strings.Contains(body, `href="/assets?dir=desc&amp;project=web&amp;sort=criticality">Criticité</a>`) {
		t.Error("a column of scores or levels must sort from the highest first")
	}

	// Lists instead of a row of links; the choice and the order stay.
	for _, want := range []string{`<option selected>web</option>`, `<option value="prod" >prod (1)</option>`, `name="sort" value="name"`} {
		if !strings.Contains(body, want) {
			t.Errorf("filters miss %s:\n%s", want, body)
		}
	}
	if strings.Contains(body, "Tous les actifs") {
		t.Error("the row of links is still there")
	}
}

func TestSortFindings(t *testing.T) {
	st, base := newServerWith(t, nil)
	seedFindings(t, st) // critical now, high 20 days ago, low 40 days ago
	ctx := context.Background()
	other, _ := st.CreateAsset(ctx, store.Asset{Name: "apache", Version: "2.4", Kind: "product", Criticality: "low", Source: "manual"})
	st.UpsertVulnerability(ctx, store.Vulnerability{ID: "CVE-2024-10000", Severity: "HIGH", EPSS: 0.5, CVSS: -1})
	st.ObserveFinding(ctx, other, "CVE-2024-10000", time.Now().Add(-5*24*time.Hour))
	st.SetExploitSignals(ctx, "CVE-2024-10000", false, "", 0.5)
	c := loginAs(t, base, "analyst", "a-strong-password")
	const crit, high, low, likely = "CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003", "CVE-2024-10000"
	for query, want := range map[string][]string{
		"":                       {likely, crit, high, low}, // the priority: likely to be exploited first
		"sort=priority":          {likely, crit, high, low},
		"dir=asc":                {low, high, crit, likely},
		"sort=cvss":              {crit, high, low, likely}, // unknown score last
		"sort=cvss&dir=asc":      {low, high, crit, likely},
		"sort=epss":              {likely, crit, high, low},
		"sort=vuln":              {crit, high, low, likely}, // 10000 after 0003
		"sort=asset":             {likely, crit, high, low},
		"sort=recent":            {crit, likely, high, low},
		"sort=recent&dir=asc":    {low, high, likely, crit},
		"severity=LOW&sort=cvss": {low},
	} {
		_, body := c.get("/findings?" + query)
		if got := findingOrder(body); !slices.Equal(got, want) {
			t.Errorf("%q: %v, want %v", query, got, want)
		}
	}

	// A status keeps its own order, not the alphabetical one.
	list, _ := st.ListFindings(ctx, store.FindingFilter{})
	for _, f := range list {
		if f.VulnID == high {
			st.SetFindingStatus(ctx, f.ID, 0, "resolved", "", "")
		}
	}
	_, body := c.get("/findings?sort=status&dir=desc")
	if got := findingOrder(body); got[0] != high {
		t.Errorf("by status: %v", got)
	}

	// The titles keep the filters; the export follows the order.
	_, body = c.get("/findings?severity=HIGH&sort=cvss")
	if !strings.Contains(body, `<th aria-sort="descending"><a class="sort" href="/findings?dir=asc&amp;severity=HIGH&amp;sort=cvss">CVSS</a></th>`) {
		t.Errorf("title of the sorted column:\n%s", body)
	}
	if !strings.Contains(body, `name="sort" value="cvss"`) {
		t.Error("filtering again must keep the order")
	}
	if !strings.Contains(body, `<th class="no-sort">Résumé</th>`) {
		t.Error("the summary cannot sort the list")
	}
	code, csv := c.get("/findings.csv?sort=cvss&dir=asc")
	if code != 200 || strings.Index(csv, low) > strings.Index(csv, crit) {
		t.Errorf("CSV order: %d\n%s", code, csv)
	}

	// The list of an asset is not sortable.
	assetID := list[0].AssetID
	_, body = c.get("/assets/" + strconv.FormatInt(assetID, 10))
	if strings.Contains(body, `class="sort"`) {
		t.Error("the list of an asset has sort links")
	}
}

// The state of a run tells how far it went, and what could not be checked.
func TestSyncProgressText(t *testing.T) {
	s := &Server{}
	if err := s.parseTemplates(); err != nil {
		t.Fatal(err)
	}
	render := func(st tracking.Status, details bool) string {
		var b strings.Builder
		if err := s.pages["sync"].ExecuteTemplate(&b, "syncText", syncView{Status: st, Details: details}); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}
	running := render(tracking.Status{Running: true, Started: time.Now(), Total: 40, Done: 12, Current: "Linux Kernel"}, true)
	for _, want := range []string{"12 actif(s) sur 40", "(Linux Kernel)", `<progress value="12" max="40"`} {
		if !strings.Contains(running, want) {
			t.Errorf("running misses %s: %s", want, running)
		}
	}
	if starting := render(tracking.Status{Running: true, Started: time.Now()}, true); !strings.Contains(starting, `<progress aria-label`) {
		t.Errorf("before the count, the bar has no value: %s", starting)
	}
	done := tracking.Status{Finished: time.Now(), Result: tracking.Result{Failed: 2}, Failures: []string{"x : nvd: HTTP 503", "y : nvd: HTTP 503"}}
	if got := render(done, true); !strings.Contains(got, "2 actif(s) non vérifié(s)") || !strings.Contains(got, "x : nvd: HTTP 503") {
		t.Errorf("failures for an analyst: %s", got)
	}
	if got := render(done, false); !strings.Contains(got, "2 actif(s) non vérifié(s)") || strings.Contains(got, "HTTP 503") {
		t.Errorf("failures for a reader: %s", got)
	}
}
