package web

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/auth"
	"github.com/La-Cizaille-Corp/vigil/internal/digest"
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

// findingOrder returns the vulnerabilities of a list page, in order; a row
// may lead back to its list (?back=).
func findingOrder(body string) []string {
	var out []string
	for _, m := range regexp.MustCompile(`<a href="/findings/\d+(?:\?back=[^"]*)?">([^<]+)</a>`).FindAllStringSubmatch(body, -1) {
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
		if _, err := st.CreateAsset(ctx, store.Everything, a); err != nil {
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
	other, _ := st.CreateAsset(ctx, store.Everything, store.Asset{Name: "apache", Version: "2.4", Kind: "product", Criticality: "low", Source: "manual"})
	st.UpsertVulnerability(ctx, store.Vulnerability{ID: "CVE-2024-10000", Severity: "HIGH", EPSS: 0.5, CVSS: -1})
	st.ObserveFinding(ctx, other, "CVE-2024-10000", "", time.Now().Add(-5*24*time.Hour))
	st.SetExploitSignals(ctx, store.ExploitSignal{ID: "CVE-2024-10000", EPSS: 0.5})
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
	list, _ := st.ListFindings(ctx, store.Everything, store.FindingFilter{})
	for _, f := range list {
		if f.VulnID == high {
			st.SetFindingStatus(ctx, store.Everything, f.ID, 0, "resolved", "", "")
		}
	}
	_, body := c.get("/findings?level=all&sort=status&dir=desc")
	if got := findingOrder(body); got[0] != high {
		t.Errorf("by status: %v", got)
	}

	// The titles keep the filters; the export follows the order.
	_, body = c.get("/findings?severity=HIGH&sort=cvss")
	if !strings.Contains(body, `<th aria-sort="descending" class="num"><a class="sort" href="/findings?dir=asc&amp;severity=HIGH&amp;sort=cvss">CVSS</a></th>`) {
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

// The four levels classify the list, which shows the open ones by default and
// the fixed ones apart; the counts follow its filters, not the level chosen,
// and the links keep the filters and the order.
func TestFindingLevels(t *testing.T) {
	st, base := newServerWith(t, nil)
	assetID, ids := seedFindings(t, st) // critical, high, low
	ctx := context.Background()
	st.UpsertVulnerability(ctx, store.Vulnerability{ID: "CVE-2024-0004", Severity: "LOW", EPSS: -1, CVSS: 2})
	st.ObserveFinding(ctx, assetID, "CVE-2024-0004", "", time.Now())
	st.SetExploitSignals(ctx, store.ExploitSignal{ID: "CVE-2024-0004", KEV: true, EPSS: 0.5})
	st.UpsertVulnerability(ctx, store.Vulnerability{ID: "CVE-2024-0005", EPSS: -1, CVSS: -1})
	st.ObserveFinding(ctx, assetID, "CVE-2024-0005", "", time.Now())
	st.UpsertVulnerability(ctx, store.Vulnerability{ID: "CVE-2024-0006", Severity: "HIGH", EPSS: -1, CVSS: 8})
	st.ObserveFinding(ctx, assetID, "CVE-2024-0006", "", time.Now())
	st.UpsertVulnerability(ctx, store.Vulnerability{ID: "CVE-2024-0007", Severity: "HIGH", EPSS: -1, CVSS: 8})
	st.ObserveFinding(ctx, assetID, "CVE-2024-0007", "", time.Now())
	list, _ := st.ListFindings(ctx, store.Everything, store.FindingFilter{})
	for _, f := range list {
		switch f.VulnID {
		case "CVE-2024-0006":
			st.SetFindingStatus(ctx, store.Everything, f.ID, 0, "false_positive", "", "")
		case "CVE-2024-0007":
			st.SetFindingStatus(ctx, store.Everything, f.ID, 0, "resolved", "", "")
		}
	}
	_ = ids
	c := loginAs(t, base, "analyst", "a-strong-password")

	for level, want := range map[string][]string{
		"urgent": {"CVE-2024-0004"},
		"plan":   {"CVE-2024-0001", "CVE-2024-0002"},
		"watch":  {"CVE-2024-0003", "CVE-2024-0005"},
		"aside":  {"CVE-2024-0006"},
	} {
		_, body := c.get("/findings?sort=vuln&level=" + level)
		if got := findingOrder(body); !slices.Equal(got, want) {
			t.Errorf("level %s: %v, want %v", level, got, want)
		}
	}
	open := []string{"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003", "CVE-2024-0004", "CVE-2024-0005"}
	for query, want := range map[string][]string{
		"":                 {"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003", "CVE-2024-0004", "CVE-2024-0005"},
		"&level=nope":      open, // an unknown level: the default
		"&level=open":      open,
		"&level=fixed":     {"CVE-2024-0007"},
		"&level=all":       {"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003", "CVE-2024-0004", "CVE-2024-0005", "CVE-2024-0006", "CVE-2024-0007"},
		"&status=resolved": {"CVE-2024-0007"}, // a status asked for is shown
		"&level=urgent":    {"CVE-2024-0004"}, // the dashboard card and the alerts
	} {
		_, body := c.get("/findings?sort=vuln" + query)
		if got := findingOrder(body); !slices.Equal(got, want) {
			t.Errorf("%q: %v, want %v", query, got, want)
		}
	}
	if _, csv := c.get("/findings.csv"); strings.Count(csv, "\n") != 6 || strings.Contains(csv, "CVE-2024-0007") {
		t.Errorf("the export differs from the default list:\n%s", csv)
	}

	_, body := c.get("/findings?level=plan&sort=vuln&q=CVE-2024")
	for _, want := range []string{
		`<a href="/findings?level=open&amp;q=CVE-2024&amp;sort=vuln" >Ouvertes <small>5</small></a>`,
		`<a href="/findings?level=urgent&amp;q=CVE-2024&amp;sort=vuln" >Urgentes <small>1</small></a>`,
		`<a href="/findings?level=plan&amp;q=CVE-2024&amp;sort=vuln" class="active" aria-current="true">À planifier <small>2</small></a>`,
		`À surveiller <small>2</small>`, `Écartées <small>1</small>`,
		`<a href="/findings?level=fixed&amp;q=CVE-2024&amp;sort=vuln" >Corrigées <small>1</small></a>`,
		`<a class="quiet" href="/findings?level=all&amp;q=CVE-2024&amp;sort=vuln">Toutes (7)</a>`,
		`name="level" value="plan"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page misses %s", want)
		}
	}
	// The open levels, then those closed, then all: the counts add up.
	if open, closed := strings.Index(body, ">À surveiller <"), strings.Index(body, ">Écartées <"); open < 0 || closed < open ||
		!strings.Contains(body[open:closed], `<span class="sep" aria-hidden="true"></span>`) {
		t.Error("the closed levels are not set apart from the open ones")
	}
	counts := map[string]int{}
	for _, m := range regexp.MustCompile(`>([^<>]+) <small>(\d+)</small></a>`).FindAllStringSubmatch(body, -1) {
		counts[m[1]], _ = strconv.Atoi(m[2])
	}
	if open := counts["Urgentes"] + counts["À planifier"] + counts["À surveiller"]; open != counts["Ouvertes"] ||
		open+counts["Écartées"]+counts["Corrigées"] != 7 {
		t.Errorf("the counts do not add up: %v", counts)
	}
	if code, csv := c.get("/findings.csv?level=urgent"); code != 200 || strings.Count(csv, "\n") != 2 || !strings.Contains(csv, "CVE-2024-0004") {
		t.Errorf("CSV of a level: %d\n%s", code, csv)
	}
}

// The links sent before 0.5.0 (alerts, bookmarks) ask for ?priority=1, the box
// that the level Urgentes replaced: they lead to that level, with their other
// filters (A84).
func TestPriorityLinksLeadToUrgent(t *testing.T) {
	st, base := newServerWith(t, nil)
	seedFindings(t, st)
	c := loginAs(t, base, "analyst", "a-strong-password")
	for path, want := range map[string]string{
		"/findings?priority=1":                     "/findings?level=urgent",
		"/findings?priority=1&q=fortios&sort=cvss": "/findings?level=urgent&q=fortios&sort=cvss",
		"/findings?level=plan&priority=1":          "/findings?level=urgent",
		"/findings?priority=0&q=fortios":           "/findings?q=fortios",
		"/findings?priority=":                      "/findings",
		"/findings.csv?priority=1":                 "/findings.csv?level=urgent",
	} {
		if code, loc := c.send(http.MethodGet, path, nil); code != http.StatusMovedPermanently || loc != want {
			t.Errorf("%s: %d %s, want %s", path, code, loc, want)
		}
	}
	if _, body := c.get("/findings"); strings.Contains(body, `name="priority"`) || strings.Contains(body, "Prioritaire") {
		t.Error("the box Prioritaire is still offered beside the levels")
	}
}

// From a search on an asset to a rule, and back.
func TestDismissalFlow(t *testing.T) {
	st, base := newServerWith(t, nil)
	ctx := context.Background()
	asset, _ := st.CreateAsset(ctx, store.Everything, store.Asset{Name: "linux", Kind: "os", Criticality: "high", Source: "manual"})
	for id, summary := range map[string]string{"CVE-1": "wifi: fix", "CVE-2": "wifi: other", "CVE-3": "ipv4: fix"} {
		st.UpsertVulnerability(ctx, store.Vulnerability{ID: id, Summary: summary, EPSS: -1, CVSS: -1})
		st.ObserveFinding(ctx, asset, id, "", time.Now())
	}
	page := "/assets/" + strconv.FormatInt(asset, 10)
	c := loginAs(t, base, "analyst", "a-strong-password")

	_, body := c.get(page + "?q=wifi:")
	// What the rule would set aside is listed apart from the most urgent ones (A86).
	if got := findingOrder(body[strings.Index(body, `id="apercu"`)+1:]); len(got) != 2 {
		t.Errorf("search: %v", got)
	}
	if !strings.Contains(body, "Écarter tout ce qui correspond") || !strings.Contains(body, `name="text" value="wifi:"`) {
		t.Errorf("no way to set them aside:\n%s", body)
	}
	if _, body := c.get(page); strings.Contains(body, "Écarter tout ce qui correspond") {
		t.Error("offered without a search")
	}
	for _, short := range []string{"", "ab", strings.Repeat("x", 101)} {
		if code := c.post(page+"/dismissals", url.Values{"csrf": {c.csrf()}, "text": {short}}); code != 400 {
			t.Errorf("text %q: %d", short, code)
		}
	}
	code, loc := c.postLocation(page+"/dismissals", url.Values{"csrf": {c.csrf()}, "text": {"wifi:"}})
	if code != 303 || !strings.Contains(loc, "msg=rule-created") {
		t.Fatalf("create: %d %s", code, loc)
	}
	_, body = c.get(page)
	if !strings.Contains(body, "<code>wifi:</code>") || !strings.Contains(body, "2 écartée(s)") {
		t.Errorf("rule not shown:\n%s", body)
	}
	_, body = c.get("/findings?level=aside&sort=vuln")
	if got := findingOrder(body); !slices.Equal(got, []string{"CVE-1", "CVE-2"}) {
		t.Errorf("set aside: %v", got)
	}

	hash, _ := auth.HashPassword("a-strong-password")
	st.CreateUser(ctx, "lecteur", hash, auth.RoleViewer, store.Access{All: true})
	viewer := loginAs(t, base, "lecteur", "a-strong-password")
	if code := viewer.post(page+"/dismissals", url.Values{"csrf": {viewer.csrf()}, "text": {"ipv4:"}}); code != 403 {
		t.Errorf("a reader created a rule: %d", code)
	}
	if _, body := viewer.get(page + "?q=wifi:"); strings.Contains(body, "Écarter tout") || strings.Contains(body, "Supprimer la règle") || !strings.Contains(body, "<code>wifi:</code>") {
		t.Errorf("reader's view:\n%s", body)
	}

	rules, _ := st.ListDismissalRules(ctx, store.Everything, asset)
	rule := page + "/dismissals/" + strconv.FormatInt(rules[0].ID, 10) + "/delete"
	if code := c.post(page+"/dismissals/999/delete", url.Values{"csrf": {c.csrf()}}); code != 404 {
		t.Errorf("unknown rule: %d", code)
	}
	if code, loc := c.postLocation(rule, url.Values{"csrf": {c.csrf()}}); code != 303 || !strings.Contains(loc, "msg=rule-deleted") {
		t.Fatalf("delete: %d %s", code, loc)
	}
	_, body = c.get("/findings?level=aside")
	if got := findingOrder(body); len(got) != 0 {
		t.Errorf("still set aside: %v", got)
	}
}

// The list, the dashboard and the digest rank the edge cases of the ranking
// alike (A78): judged exploitable with a KEV entry, a KEV entry without
// severity, EPSS at the threshold, a CVSS score only.
func TestPriorityOrderEverywhere(t *testing.T) {
	st, base := newServerWith(t, nil)
	ctx := context.Background()
	assetID, _ := st.CreateAsset(ctx, store.Everything, store.Asset{Name: "appliance", Kind: "product", Criticality: "high", Source: "manual"})
	want := []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0005", "CVE-2026-0006", "CVE-2026-0007"}
	for _, v := range []struct {
		id, severity string
		cvss         float64
		kev          bool
		epss         float64
	}{
		{"CVE-2026-0007", "HIGH", 8.8, false, -1},
		{"CVE-2026-0006", "", 9.8, false, -1},           // rated critical by its score
		{"CVE-2026-0005", "CRITICAL", 9, false, 0.0999}, // just below the threshold
		{"CVE-2026-0004", "MEDIUM", 5, false, 0.1},      // at the threshold
		{"CVE-2026-0003", "", -1, true, -1},             // KEV without severity
		{"CVE-2026-0002", "LOW", 3, true, -1},           // KEV
		{"CVE-2026-0001", "LOW", 3.1, false, -1},        // judged exploitable, below
	} {
		st.UpsertVulnerability(ctx, store.Vulnerability{ID: v.id, Severity: v.severity, CVSS: v.cvss})
		st.SetExploitSignals(ctx, store.ExploitSignal{ID: v.id, KEV: v.kev, EPSS: v.epss})
		st.ObserveFinding(ctx, assetID, v.id, "", time.Now())
	}
	list, _ := st.ListFindings(ctx, store.Everything, store.FindingFilter{Search: "CVE-2026-0001"})
	if err := st.SetFindingStatus(ctx, store.Everything, list[0].ID, 0, "exploitable", "", ""); err != nil {
		t.Fatal(err)
	}
	c := loginAs(t, base, "analyst", "a-strong-password")
	for _, path := range []string{"/findings", "/"} {
		if _, body := c.get(path); !slices.Equal(findingOrder(body), want) {
			t.Errorf("%s: %v\nwant %v", path, findingOrder(body), want)
		}
	}
	d, err := digest.Generate(ctx, st, store.Group{})
	if err != nil {
		t.Fatal(err)
	}
	var listed []string
	for _, id := range findingOrder(d.HTML) {
		if !slices.Contains(listed, id) {
			listed = append(listed, id)
		}
	}
	if !slices.Equal(listed, want) {
		t.Errorf("digest: %v\nwant %v", listed, want)
	}
}
