package web

import (
	"context"
	"fmt"
	"html"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/auth"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
)

// The list of one asset (?asset=) keeps the asset through its levels, its
// order, its filters and its export (A86); an asset the account does not see
// gives an empty list, never another one.
func TestAssetFilter(t *testing.T) {
	st, base := newServerWith(t, nil)
	ctx := context.Background()
	linux, _ := seedMany(t, st, 3)
	nginx, err := st.CreateAsset(ctx, store.Everything, store.Asset{Name: "nginx", Version: "1.24", Kind: "product", Criticality: "high", Source: "manual"})
	if err != nil {
		t.Fatal(err)
	}
	st.UpsertVulnerability(ctx, store.Vulnerability{ID: "CVE-2026-1000", Severity: "HIGH", CVSS: 7.5, EPSS: -1, Summary: "nginx"})
	st.ObserveFinding(ctx, nginx, "CVE-2026-1000", "", time.Now())
	c := loginAs(t, base, "analyst", "a-strong-password")
	id := itoa(linux)

	_, body := c.get("/findings?asset=" + id)
	if got := findingOrder(body); len(got) != 3 || slices.Contains(got, "CVE-2026-1000") {
		t.Errorf("list of linux: %v", got)
	}
	for _, want := range []string{
		`Vulnérabilités de l'actif <a href="/assets/` + id + `">linux 6.12</a>`,
		`<a href="/findings">tous les actifs</a>`,
		`<input type="hidden" name="asset" value="` + id + `">`, // filtering again keeps it
		`<a href="/findings?asset=` + id + `">Réinitialiser</a>`,
		`<a href="/findings?asset=` + id + `&amp;level=urgent" >Urgentes`,
		`href="/findings.csv?asset=` + id + `"`,
		`<a class="sort" href="/findings?asset=` + id + `&amp;dir=desc&amp;sort=cvss">CVSS</a>`,
		`<input type="hidden" name="next" value="/findings?asset=` + id + `">`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("list of linux misses %s", want)
		}
	}
	if _, csv := c.get("/findings.csv?asset=" + id); strings.Count(csv, "\n") != 4 || strings.Contains(csv, "nginx") {
		t.Errorf("export of linux:\n%s", csv)
	}
	_, body = c.get("/findings?asset=" + itoa(nginx+100))
	if len(findingOrder(body)) != 0 || !strings.Contains(body, "Actif introuvable") {
		t.Error("an unknown asset shows a list")
	}
	if _, body := c.get("/findings?asset=x"); len(findingOrder(body)) != 4 {
		t.Error("a malformed asset is not ignored")
	}
}

// T3 for the asset filter: an account of group A asking for the list of b
// sees an empty list, without b's name, and a decision on that whole list
// changes nothing.
func TestAssetFilterInTheScope(t *testing.T) {
	fx := newGroupFixture(t)
	b := itoa(fx.asset["b"])
	for _, account := range []string{"lec-a", "ana-a", "ana-0"} {
		_, body := fx.client[account].get("/findings?level=all&asset=" + b)
		if len(findingOrder(body)) != 0 || strings.Contains(body, witness) || !strings.Contains(body, "Actif introuvable") {
			t.Errorf("%s: the list of b shows %v", account, findingOrder(body))
		}
	}
	ana, before := fx.client["ana-a"], fx.state(t, "b")
	code, body := ana.postBody("/findings/bulk", url.Values{"csrf": {ana.csrf()}, "scope": {"list"}, "status": {store.StatusFalsePositive},
		"next": {"/findings?level=all&asset=" + b}})
	if code != 400 || !strings.Contains(body, "Cette liste est vide") {
		t.Errorf("decision on the list of b: %d", code)
	}
	if fx.state(t, "b") != before {
		t.Error("a decision on the list of b changed b")
	}
	// The same list, to an account that sees b.
	if _, body := fx.client["analyst"].get("/findings?level=all&asset=" + b); len(findingOrder(body)) != 2 || !strings.Contains(body, "temoinb-nom") {
		t.Errorf("the list of b to an account that sees it: %v", findingOrder(body))
	}
}

// levelCounters reads the counters of the page of an asset: level, link and number.
var levelCounters = regexp.MustCompile(`<a class="kpi level-card-(\w+)" href="([^"]+)">\s*<span class="kpi-label">[^<]*</span>\s*<span class="kpi-value">(\d+)</span>`)

// The page of an asset counts its vulnerabilities by level, each count the
// length of the list it links to, and shows the ten most urgent open ones,
// the urgent first (A86).
func TestAssetPageLevels(t *testing.T) {
	st, base := newServerWith(t, nil)
	ctx := context.Background()
	asset, err := st.CreateAsset(ctx, store.Everything, store.Asset{Name: "srv", Version: "1.0", Kind: "os", Criticality: "high", Source: "manual"})
	if err != nil {
		t.Fatal(err)
	}
	statuses := map[string]string{"CVE-2026-0004": store.StatusFalsePositive, "CVE-2026-0005": store.StatusResolved}
	for i := 1; i <= 17; i++ {
		v := store.Vulnerability{ID: fmt.Sprintf("CVE-2026-%04d", i), Severity: "LOW", CVSS: 3, EPSS: -1, Summary: "faille"}
		switch i {
		case 1:
			v.Severity, v.CVSS = "MEDIUM", 5 // urgent by KEV below
		case 2:
			v.Severity, v.CVSS = "CRITICAL", 9.8
		}
		st.UpsertVulnerability(ctx, v)
		st.ObserveFinding(ctx, asset, v.ID, "", time.Now().Add(time.Duration(i)*time.Minute))
	}
	st.SetExploitSignals(ctx, store.ExploitSignal{ID: "CVE-2026-0001", KEV: true, EPSS: 0.2})
	list, _ := st.ListFindings(ctx, store.Everything, store.FindingFilter{AssetID: asset})
	for _, f := range list {
		if s, ok := statuses[f.VulnID]; ok {
			st.SetFindingStatus(ctx, store.Everything, f.ID, 0, s, "", "")
		}
	}
	c := loginAs(t, base, "analyst", "a-strong-password")
	id := itoa(asset)
	_, page := c.get("/assets/" + id)

	got := map[string]int{}
	for _, m := range levelCounters.FindAllStringSubmatch(page, -1) {
		n, _ := strconv.Atoi(m[3])
		got[m[1]] = n
		href := html.UnescapeString(m[2])
		if want := "/findings?asset=" + id + "&level=" + m[1]; href != want {
			t.Errorf("counter %s leads to %s, want %s", m[1], href, want)
		}
		if _, list := c.get(href); len(findingOrder(list)) != n {
			t.Errorf("counter %s says %d, its list holds %d", m[1], n, len(findingOrder(list)))
		}
	}
	if want := map[string]int{"urgent": 1, "plan": 1, "watch": 13, "aside": 1, "fixed": 1}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("counters %v, want %v", got, want)
	}
	first := findingOrder(page)
	if len(first) != assetFirst || first[0] != "CVE-2026-0001" || first[1] != "CVE-2026-0002" {
		t.Errorf("most urgent: %v", first)
	}
	for _, want := range []string{"Vulnérabilités de cet actif <span class=\"muted small\">· 17</span>",
		`<a href="/findings?asset=` + id + `&amp;level=urgent"><strong>Voir les 1 urgente(s) ›</strong></a>`,
		`<a href="/findings?asset=` + id + `&amp;level=open">Toute la liste de cet actif (15 ouverte(s))`,
		`<section class="card" id="bruit"`, `name="q" value="" minlength="3"`} {
		if !strings.Contains(page, want) {
			t.Errorf("page of the asset misses %s", want)
		}
	}
	if strings.Contains(page, "Écarter tout ce qui correspond") || strings.Contains(page, `id="apercu"`) {
		t.Error("a rule is offered before any search")
	}
	// A search without result still offers the rule, for the next ones.
	if _, page := c.get("/assets/" + id + "?q=x509"); !strings.Contains(page, "Aucune vulnérabilité ne contient « x509 » maintenant") ||
		!strings.Contains(page, "Écarter tout ce qui correspond") {
		t.Error("a search without result")
	}
	// A reader sees the levels, not the noise block nor what a rule would set aside.
	hash, _ := auth.HashPassword("a-strong-password")
	st.CreateUser(ctx, "lecteur", hash, auth.RoleViewer, store.Access{All: true})
	_, page = loginAs(t, base, "lecteur", "a-strong-password").get("/assets/" + id + "?q=faille")
	if len(levelCounters.FindAllString(page, -1)) != 5 || strings.Contains(page, `id="bruit"`) || strings.Contains(page, `id="apercu"`) {
		t.Error("reader's view of the asset")
	}
}

// Following the whole history of an asset adds its older vulnerabilities and
// their alerts: it is confirmed first, with their number (A86).
func TestFullHistoryConfirmed(t *testing.T) {
	st, base := newServerWith(t, nil)
	ctx := context.Background()
	asset, _ := st.CreateAsset(ctx, store.Everything, store.Asset{Name: "linux", Version: "6.12", Kind: "os", Criticality: "high",
		Source: "manual", TrackSince: "2026-07-08"})
	st.SetOlderVulns(ctx, asset, 2487)
	_, page := loginAs(t, base, "analyst", "a-strong-password").get("/assets/" + itoa(asset))
	confirm := strings.Index(page, `<details class="confirm">
    <summary>Suivre tout l'historique…</summary>`)
	form := strings.Index(page, `action="/assets/`+itoa(asset)+`/full-history"`)
	if confirm < 0 || form < confirm || !strings.Contains(page, "Ajouter les 2487 vulnérabilité(s) publiées avant le 08/07/2026") {
		t.Errorf("full history without confirmation: details at %d, form at %d", confirm, form)
	}
}

// The inventory says what each asset exposes, sorts by it and links to its
// list; it is searched by name, purl or CPE (A86).
func TestInventoryCounts(t *testing.T) {
	st, base := newServerWith(t, nil)
	ctx := context.Background()
	ids := map[string]int64{}
	for _, a := range []store.Asset{
		{Name: "srv", Version: "1.0", Kind: "os", CPE: "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:*"},
		{Name: "libssl3", Version: "3.0.19-1~deb12u2", Kind: "package", PURL: "pkg:deb/debian/libssl3@3.0.11-1~deb12u2"},
		{Name: "calme", Version: "2.0", Kind: "package"},
	} {
		a.Criticality, a.Source = "high", "manual"
		id, err := st.CreateAsset(ctx, store.Everything, a)
		if err != nil {
			t.Fatal(err)
		}
		ids[a.Name] = id
	}
	for _, o := range []struct {
		asset, vuln string
		kev         bool
	}{{"srv", "CVE-2026-0001", true}, {"srv", "CVE-2026-0002", false}, {"srv", "CVE-2026-0003", false}, {"libssl3", "CVE-2026-0004", false}} {
		st.UpsertVulnerability(ctx, store.Vulnerability{ID: o.vuln, Severity: "HIGH", CVSS: 7.5, EPSS: -1})
		st.SetExploitSignals(ctx, store.ExploitSignal{ID: o.vuln, KEV: o.kev, EPSS: -1})
		st.ObserveFinding(ctx, ids[o.asset], o.vuln, "", time.Now())
	}
	c := loginAs(t, base, "analyst", "a-strong-password")
	_, body := c.get("/assets?sort=urgent")
	srv, lib := itoa(ids["srv"]), itoa(ids["libssl3"])
	for _, want := range []string{
		`<td data-label="Urgentes" class="num"><a class="level level-urgent" href="/findings?asset=` + srv + `&amp;level=urgent">1</a></td>`,
		`<td data-label="Ouvertes" class="num"><a href="/findings?asset=` + srv + `">3</a></td>`,
		`<td data-label="Ouvertes" class="num"><a href="/findings?asset=` + lib + `">1</a></td>`,
		`<td data-label="Urgentes" class="num"><span class="muted">0</span></td>`,
		`<th aria-sort="descending" class="num"><a class="sort" href="/assets?dir=asc&amp;sort=urgent">Urgentes</a></th>`,
		`<br><small class="muted">version vérifiée : 3.0.19-1~deb12u2</small>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("inventory misses %s", want)
		}
	}
	if got := assetOrder(body); len(got) != 3 || got[0] != "srv" {
		t.Errorf("sorted by urgent: %v", got)
	}
	if _, body := c.get("/assets?sort=open&dir=asc"); !slices.Equal(assetOrder(body), []string{"calme", "libssl3", "srv"}) {
		t.Errorf("sorted by open, ascending: %v", assetOrder(body))
	}
	for q, want := range map[string][]string{"SSL": {"libssl3"}, "debian_linux": {"srv"}, "deb12u2": {"libssl3"}, "zzz": nil} {
		_, body := c.get("/assets?q=" + url.QueryEscape(q))
		if got := assetOrder(body); !slices.Equal(got, want) {
			t.Errorf("search %q: %v, want %v", q, got, want)
		}
		if want == nil && !strings.Contains(body, "Aucun actif ne contient « zzz »") {
			t.Error("an empty search says the inventory is empty")
		}
	}
}

// A search of the vulnerability list leads an analyst to the dismissal rule
// of its text on each asset, seen first on its page (A61, A86).
func TestNoiseOffer(t *testing.T) {
	st, base := newServerWith(t, nil)
	ctx := context.Background()
	linux, _ := seedMany(t, st, 3) // "wifi: fix"
	tool, _ := st.CreateAsset(ctx, store.Everything, store.Asset{Name: "wifi-manager", Version: "2", Kind: "package", Criticality: "low", Source: "manual"})
	st.UpsertVulnerability(ctx, store.Vulnerability{ID: "CVE-2026-2000", Severity: "LOW", CVSS: 3, EPSS: -1, Summary: "wifi password"})
	st.ObserveFinding(ctx, tool, "CVE-2026-2000", "", time.Now())
	analyst := loginAs(t, base, "analyst", "a-strong-password")

	_, body := analyst.get("/findings?q=wifi")
	link := `<a href="/assets/` + itoa(linux) + `?q=wifi#bruit">linux 6.12 (3)</a>`
	if !strings.Contains(body, "Écartez « wifi » sur un actif") || !strings.Contains(body, link) {
		t.Errorf("no way to set the noise aside:\n%s", body)
	}
	if strings.Contains(body, `href="/assets/`+itoa(tool)+`?q=wifi`) {
		t.Error("offered on an asset found by its name")
	}
	if _, body := analyst.get("/findings?q=wi"); strings.Contains(body, "Écartez") {
		t.Error("offered for a text too short to be a rule")
	}
	hash, _ := auth.HashPassword("a-strong-password")
	st.CreateUser(ctx, "lecteur", hash, auth.RoleViewer, store.Access{All: true})
	if _, body := loginAs(t, base, "lecteur", "a-strong-password").get("/findings?q=wifi"); strings.Contains(body, "Écartez") {
		t.Error("offered to a reader")
	}
	// The link lands on what the rule would set aside.
	if _, page := analyst.get("/assets/" + itoa(linux) + "?q=wifi"); !strings.Contains(page, "3 vulnérabilité(s) contiennent « wifi »") {
		t.Error("the link does not show what the rule would set aside")
	}
}

// The page of a vulnerability (A86): an advisory of several CVEs keeps its
// name, a fixed one has no deadline left, a CISA deadline passed says so, and
// a CVE leads to its other assets.
func TestFindingPageDetails(t *testing.T) {
	st, base := newServerWith(t, nil)
	ctx := context.Background()
	asset, _ := st.CreateAsset(ctx, store.Everything, store.Asset{Name: "linux", Version: "5.15", Kind: "os", Criticality: "high", Source: "manual"})
	aliases := []string{"CVE-2022-3114"}
	for i := range 25 {
		aliases = append(aliases, fmt.Sprintf("CVE-2022-4%04d", i))
	}
	for _, v := range []store.Vulnerability{
		{ID: "USN-8875-1", Aliases: aliases, Severity: "HIGH", CVSS: 7.5, EPSS: -1, Summary: "Linux kernel vulnerabilities"},
		{ID: "RHSA-2026:0001", Aliases: []string{"CVE-2026-0001"}, Severity: "CRITICAL", CVSS: 9.8, EPSS: -1, Summary: "Red Hat Security Advisory: openssl security update"},
	} {
		st.UpsertVulnerability(ctx, v)
		st.ObserveFinding(ctx, asset, v.ID, "", time.Now().Add(-40*24*time.Hour))
	}
	st.SetExploitSignals(ctx, store.ExploitSignal{ID: "RHSA-2026:0001", KEV: true, KEVDue: "2026-01-15", EPSS: -1})
	ids := map[string]int64{}
	list, _ := st.ListFindings(ctx, store.Everything, store.FindingFilter{AssetID: asset})
	for _, f := range list {
		ids[f.VulnID] = f.ID
	}
	c := loginAs(t, base, "analyst", "a-strong-password")

	_, grouped := c.get("/findings/" + itoa(ids["USN-8875-1"]))
	if !strings.Contains(grouped, "<h1>USN-8875-1</h1>") || strings.Contains(grouped, "sur tous les actifs") ||
		!strings.Contains(grouped, "<details><summary>Les 26 alias</summary>") || !strings.Contains(grouped, "CVE-2022-3114, CVE-2022-40000, CVE-2022-40001 et 23 autres") {
		t.Errorf("advisory of several CVEs:\n%s", grouped)
	}
	_, rhsa := c.get("/findings/" + itoa(ids["RHSA-2026:0001"]))
	for _, want := range []string{"<h1>CVE-2026-0001 (RHSA-2026:0001)</h1>", `échéance CISA 15/01/2026 <span class="late">dépassée</span>`,
		`<a href="/findings?q=CVE-2026-0001&amp;level=all">CVE-2026-0001 sur tous les actifs</a>`,
		`<a href="https://nvd.nist.gov/vuln/detail/CVE-2026-0001" rel="noopener noreferrer" target="_blank">Description de CVE-2026-0001 dans la NVD</a>`,
		"Échéance de traitement"} {
		if !strings.Contains(rhsa, want) {
			t.Errorf("RHSA page misses %s", want)
		}
	}
	st.SetFindingStatus(ctx, store.Everything, ids["RHSA-2026:0001"], 0, store.StatusResolved, "", "")
	if _, fixed := c.get("/findings/" + itoa(ids["RHSA-2026:0001"])); strings.Contains(fixed, "Échéance de traitement") || strings.Contains(fixed, "dépassée") {
		t.Error("a fixed vulnerability shows its deadlines")
	}
}
