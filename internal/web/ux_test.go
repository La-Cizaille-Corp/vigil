package web

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/auth"
	"github.com/La-Cizaille-Corp/vigil/internal/cti"
	"github.com/La-Cizaille-Corp/vigil/internal/inventory"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
)

// postLocation posts a form and returns the status and redirect target.
func (c *client) postLocation(path string, form url.Values) (int, string) {
	return c.send(http.MethodPost, path, form)
}

func loginAs(t *testing.T, base, username, password string) *client {
	t.Helper()
	c := newClient(t, base)
	if code := c.post("/login", url.Values{"username": {username}, "password": {password}}); code != http.StatusSeeOther {
		t.Fatalf("login %s: %d", username, code)
	}
	return c
}

func TestAssetAndSyncFlow(t *testing.T) {
	st, base := newTestServer(t)
	hash, _ := auth.HashPassword("a-strong-password")
	st.CreateUser(context.Background(), "admin", hash, auth.RoleAdmin, store.Access{All: true})
	c := loginAs(t, base, "admin", "a-strong-password")

	// A new asset is tracked over the last 120 days by default.
	_, body := c.get("/assets/new")
	if want := `name="track_since" value="` + inventory.DefaultSince(time.Now()) + `"`; !strings.Contains(body, want) {
		t.Errorf("default tracked period missing: %s", want)
	}
	code, loc := c.postLocation("/assets", url.Values{"csrf": {c.csrf()}, "name": {"lodash"}, "kind": {"package"},
		"criticality": {"high"}, "purl": {"pkg:npm/lodash@4.17.15"}, "track_since": {"2026-01-01"}})
	if code != http.StatusSeeOther || !strings.HasPrefix(loc, "/assets/") || !strings.Contains(loc, "msg=asset-created") {
		t.Fatalf("create: %d %s", code, loc)
	}
	assets, _ := st.ListAssets(context.Background(), store.Everything)
	if len(assets) != 1 || assets[0].TrackSince != "2026-01-01" {
		t.Fatalf("assets: %+v", assets)
	}
	if code, _ := c.postLocation("/assets", url.Values{"csrf": {c.csrf()}, "name": {"x"}, "kind": {"package"},
		"criticality": {"high"}, "track_since": {"hier"}}); code != http.StatusBadRequest {
		t.Errorf("invalid date accepted: %d", code)
	}

	// A sync returns to the page it was started from, never elsewhere.
	for next, want := range map[string]string{"/findings": "/findings?", "https://evil.example": "/?", "/assets": "/assets?"} {
		_, loc := c.postLocation("/sync", url.Values{"csrf": {c.csrf()}, "next": {next}})
		if !strings.HasPrefix(loc, want) {
			t.Errorf("sync from %s redirected to %s", next, loc)
		}
	}
}

// The Version field overrides the purl: editing it keeps the purl as written,
// and editing the purl alone brings the field along.
func TestAssetUpdateVersionAndPURL(t *testing.T) {
	st, base := newTestServer(t)
	ctx := context.Background()
	hash, _ := auth.HashPassword("a-strong-password")
	st.CreateUser(ctx, "admin", hash, auth.RoleAdmin, store.Access{All: true})
	c := loginAs(t, base, "admin", "a-strong-password")

	id, err := st.CreateAsset(ctx, store.Everything, store.Asset{Name: "lodash", Kind: "package", Criticality: "high",
		Source: "manual", PURL: "pkg:npm/lodash@4.17.15", Version: "4.17.15"})
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range []struct{ purl, version, want string }{
		{"pkg:npm/lodash@4.17.15", "4.17.21", "4.17.21"},
		{"pkg:npm/lodash@4.17.30", "4.17.21", "4.17.30"},
	} {
		code, loc := c.postLocation("/assets/"+strconv.FormatInt(id, 10), url.Values{"csrf": {c.csrf()}, "name": {"lodash"},
			"kind": {"package"}, "criticality": {"high"}, "purl": {step.purl}, "version": {step.version}})
		if code != http.StatusSeeOther || !strings.Contains(loc, "msg=asset-updated") {
			t.Fatalf("update: %d %s", code, loc)
		}
		a, err := st.Asset(ctx, store.Everything, id)
		if err != nil {
			t.Fatal(err)
		}
		if a.PURL != step.purl || a.Version != step.want {
			t.Errorf("after %+v: purl = %q, version = %q", step, a.PURL, a.Version)
		}
	}
}

// An asset page tells what the asset is before its vulnerabilities; the edit
// form stays folded until values are refused. Each vulnerability shows the
// versions fixing it for the asset, in the page and in the export.
func TestAssetPageLayout(t *testing.T) {
	st, base := newTestServer(t)
	ctx := context.Background()
	hash, _ := auth.HashPassword("a-strong-password")
	st.CreateUser(ctx, "admin", hash, auth.RoleAdmin, store.Access{All: true})
	st.CreateUser(ctx, "reader", hash, auth.RoleViewer, store.Access{All: true})
	id, err := st.CreateAsset(ctx, store.Everything, store.Asset{Name: "lodash", Kind: "package", Criticality: "high",
		Source: "manual", PURL: "pkg:npm/lodash", Version: "4.17.15"})
	if err != nil {
		t.Fatal(err)
	}
	st.UpsertVulnerability(ctx, store.Vulnerability{ID: "GHSA-fix", Severity: "HIGH", Modified: "m"})
	st.UpsertVulnerability(ctx, store.Vulnerability{ID: "GHSA-open", Severity: "LOW", Modified: "m"})
	st.ObserveFinding(ctx, id, "GHSA-fix", "4.17.21", time.Now())
	st.ObserveFinding(ctx, id, "GHSA-open", "", time.Now())
	path := "/assets/" + strconv.FormatInt(id, 10)

	admin := loginAs(t, base, "admin", "a-strong-password")
	_, page := admin.get(path)
	details, vulns := strings.Index(page, "<h2>Détails</h2>"), strings.Index(page, `<h2 id="vulnerabilites">Vulnérabilités de cet actif`)
	if details < 0 || vulns < 0 || details > vulns || !strings.Contains(page, `<details class="card edit">`) {
		t.Fatalf("details at %d, vulnerabilities at %d, folded form: %v", details, vulns, strings.Contains(page, `<details class="card edit">`))
	}
	if !strings.Contains(page, `<td data-label="Corrigée en">4.17.21</td>`) || !strings.Contains(page, `<td data-label="Corrigée en"></td>`) {
		t.Error("fixed versions missing, or a placeholder where none is known")
	}

	// Refused values: the form opens on them, the details keep what is saved.
	code, page := admin.postBody(path, url.Values{"csrf": {admin.csrf()}, "name": {"lodash"}, "kind": {"package"},
		"criticality": {"high"}, "purl": {"npm/lodash"}, "version": {"4.17.15"}})
	if code != http.StatusBadRequest || !strings.Contains(page, `<details class="card edit" open>`) ||
		!strings.Contains(page, `value="npm/lodash"`) || !strings.Contains(page, "<code>pkg:npm/lodash</code>") {
		t.Errorf("refused form: %d, open %v", code, strings.Contains(page, `<details class="card edit" open>`))
	}

	reader := loginAs(t, base, "reader", "a-strong-password")
	if _, page := reader.get(path); !strings.Contains(page, "<h2>Détails</h2>") || strings.Contains(page, "Modifier l'actif") {
		t.Error("a viewer sees the details only")
	}
	_, csv := admin.get("/findings.csv")
	if lines := strings.Split(csv, "\n"); !strings.Contains(lines[0], ";version;corrigee_en;projet;") || !strings.Contains(csv, ";4.17.15;4.17.21;") {
		t.Errorf("export: %q", lines[0])
	}
}

// The dashboard cards open the list they count: their query was escaped as a
// whole by html/template (status%3din_triage…), so the list ignored it.
func TestDashboardCardsLinkToTheirList(t *testing.T) {
	st, base := newServerWith(t, nil)
	seedFindings(t, st)
	c := loginAs(t, base, "analyst", "a-strong-password")
	_, page := c.get("/")
	if !strings.Contains(page, `<a class="kpi kpi-hero" href="/findings?level=urgent">`) ||
		!strings.Contains(page, `<a class="kpi" href="/findings">`) || strings.Contains(page, "%3d") {
		t.Error("dashboard cards do not link to the open findings")
	}
	// The mean time to fix says what it counts.
	if !strings.Contains(page, "traitée(s) en 90 jours, hors celles trouvées à la première analyse de leur actif") {
		t.Error("the mean time to fix does not say what it counts")
	}
}

// The new vulnerabilities of the dashboard are the open ones of the week, and
// its link opens the list of exactly those (A84): before, a fixed one could
// come first, and the link opened the whole list.
func TestDashboardWeekIsTheList(t *testing.T) {
	st, base := newServerWith(t, nil)
	ctx := context.Background()
	asset, _ := seedFindings(t, st) // one of the week, two older
	for i := range 12 {
		id := fmt.Sprintf("CVE-2026-%04d", i)
		st.UpsertVulnerability(ctx, store.Vulnerability{ID: id, Severity: "MEDIUM", EPSS: -1, CVSS: 5})
		st.ObserveFinding(ctx, asset, id, "", time.Now().Add(-time.Hour))
	}
	fixed := "CVE-2026-0000"
	st.UpsertVulnerability(ctx, store.Vulnerability{ID: fixed, Severity: "CRITICAL", EPSS: -1, CVSS: 10})
	list, _ := st.ListFindings(ctx, store.Everything, store.FindingFilter{})
	for _, f := range list {
		if f.VulnID == fixed {
			st.SetFindingStatus(ctx, store.Everything, f.ID, 0, "resolved", "", "")
		}
	}
	c := loginAs(t, base, "analyst", "a-strong-password")
	_, page := c.get("/")
	if strings.Contains(page, ">"+fixed+"<") {
		t.Error("a fixed vulnerability among the new ones")
	}
	link := `<a href="/findings?since=7&amp;sort=recent">Voir les 12 vulnérabilités ouvertes de la semaine</a>`
	if !strings.Contains(page, link) {
		t.Fatalf("link to the week misses %s", link)
	}
	_, list2 := c.get("/findings?since=7&sort=recent")
	if got := findingOrder(list2); len(got) != 12 || slices.Contains(got, fixed) || slices.Contains(got, "CVE-2024-0002") {
		t.Errorf("the week's list: %v", got)
	}
	if !regexp.MustCompile(`name="since"[^>]*value="7"`).MatchString(list2) || !strings.Contains(list2, "Plus de filtres (1 appliqué)") {
		t.Error("the period is not kept in the filter form")
	}
	for _, bad := range []string{"0", "-3", "x", "99999"} {
		if _, body := c.get("/findings?since=" + bad); len(findingOrder(body)) != 14 {
			t.Errorf("since=%s narrows the list", bad)
		}
	}
}

// Every page opens on a skip link to its content and names its menu; the bulk
// panel follows the list, so that it can stick to the bottom of the screen
// beside the boxes ticked; a summary may break anywhere, never widening the
// list; the views of the watch say which one is shown.
func TestLandmarksAndBulkPanel(t *testing.T) {
	st, base := newServerWith(t, nil)
	seedFindings(t, st)
	c := loginAs(t, base, "analyst", "a-strong-password")
	_, page := c.get("/findings")
	for _, want := range []string{`<a class="skip" href="#contenu">`, `<main id="contenu">`,
		`<nav aria-label="Navigation principale">`, `<td data-label="Résumé" class="text">`} {
		if !strings.Contains(page, want) {
			t.Errorf("findings page misses %s", want)
		}
	}
	if list, panel := strings.Index(page, "</table>"), strings.Index(page, `id="traiter"`); list < 0 || panel < list {
		t.Errorf("bulk panel at %d, before the list ending at %d", panel, list)
	}
	if _, page := c.get("/cti"); !strings.Contains(page, `<nav class="filters" aria-label="Vues de la veille">`) ||
		!strings.Contains(page, `class="active" aria-current="true">Veille menaces <small>`) {
		t.Error("the views of the watch do not say which one is shown")
	}
}

func TestFeedTags(t *testing.T) {
	st, base := newTestServer(t)
	ctx := context.Background()
	hash, _ := auth.HashPassword("a-strong-password")
	st.CreateUser(ctx, "admin", hash, auth.RoleAdmin, store.Access{All: true})
	c := loginAs(t, base, "admin", "a-strong-password")

	form := url.Values{"csrf": {c.csrf()}, "name": {"Test"}, "url": {"https://example.org/feed.xml"},
		"country": {"FR", "EU", "XX"}, "regulation": {"nis2", "cra"}}
	if code := c.post("/settings/feeds", form); code != http.StatusSeeOther {
		t.Fatalf("create feed: %d", code)
	}
	feeds, _ := st.ListFeeds(ctx)
	var id int64
	for _, f := range feeds {
		if f.Name == "Test" {
			id = f.ID
			if f.Country != "FR,EU" || f.Regulations != "nis2,cra" {
				t.Errorf("tags: %+v", f)
			}
		}
	}
	update := url.Values{"csrf": {c.csrf()}, "sector": {"energy"}}
	if code := c.post("/settings/feeds/"+strconv.FormatInt(id, 10), update); code != http.StatusSeeOther {
		t.Fatalf("update feed: %d", code)
	}
	feeds, _ = st.ListFeeds(ctx)
	for _, f := range feeds {
		if f.ID == id && (f.Country != "" || f.Sectors != "energy" || f.Regulations != "") {
			t.Errorf("updated tags: %+v", f)
		}
	}
}

func TestPasswordChange(t *testing.T) {
	st, base := newTestServer(t)
	hash, _ := auth.HashPassword("a-strong-password")
	st.CreateUser(context.Background(), "bob", hash, auth.RoleViewer, store.Access{All: true})
	c := loginAs(t, base, "bob", "a-strong-password")
	other := loginAs(t, base, "bob", "a-strong-password")

	change := func(current, next, confirm string) int {
		return c.post("/account/password", url.Values{"csrf": {c.csrf()}, "current": {current}, "new": {next}, "confirm": {confirm}})
	}
	if code := change("wrong-password", "another-strong-one", "another-strong-one"); code != http.StatusBadRequest {
		t.Errorf("wrong current password: %d", code)
	}
	if code := change("a-strong-password", "another-strong-one", "different-one-here"); code != http.StatusBadRequest {
		t.Errorf("mismatch: %d", code)
	}
	if code := change("a-strong-password", "short", "short"); code != http.StatusBadRequest {
		t.Errorf("weak password: %d", code)
	}
	if code := change("a-strong-password", "another-strong-one", "another-strong-one"); code != http.StatusSeeOther {
		t.Fatalf("change: %d", code)
	}
	if code, _ := other.get("/account"); code != http.StatusSeeOther {
		t.Errorf("other session still valid: %d", code)
	}
	loginAs(t, base, "bob", "another-strong-one")
}

func TestNewsFrequency(t *testing.T) {
	st, base := newTestServer(t)
	ctx := context.Background()
	hash, _ := auth.HashPassword("a-strong-password")
	st.CreateUser(ctx, "admin", hash, auth.RoleAdmin, store.Access{All: true})
	st.CreateUser(ctx, "bob", hash, auth.RoleViewer, store.Access{All: true})
	c := loginAs(t, base, "admin", "a-strong-password")
	_, body := c.get("/settings")
	if !strings.Contains(body, `<option value="4" selected>4 fois par jour</option>`) || !strings.Contains(body, "À la demande seulement") {
		t.Errorf("default frequency not offered:\n%s", body)
	}
	if code := c.post("/settings/news", url.Values{"csrf": {c.csrf()}, "per_day": {"12"}}); code != http.StatusSeeOther {
		t.Fatalf("save: %d", code)
	}
	if v, _ := st.Setting(ctx, cti.SettingNewsPerDay); v != "12" {
		t.Errorf("setting = %q", v)
	}
	for _, bad := range []string{"3", "x", "-1", ""} {
		if code := c.post("/settings/news", url.Values{"csrf": {c.csrf()}, "per_day": {bad}}); code != http.StatusBadRequest {
			t.Errorf("frequency %q: %d", bad, code)
		}
	}
	viewer := loginAs(t, base, "bob", "a-strong-password")
	if code := viewer.post("/settings/news", url.Values{"csrf": {viewer.csrf()}, "per_day": {"1"}}); code != http.StatusForbidden {
		t.Errorf("a reader changed the frequency: %d", code)
	}
	if _, body := viewer.get("/settings"); !strings.Contains(body, "12 fois par jour") || strings.Contains(body, `name="per_day"`) {
		t.Errorf("reader's view:\n%s", body)
	}
}

// The settings speak of levels, and « actif » is an asset, not the state of an
// account (A84).
func TestLevelWordsInSettings(t *testing.T) {
	st, base := newServerWith(t, nil)
	admin := loginAs(t, base, "admin", "a-strong-password")
	_, body := admin.get("/settings")
	for _, want := range []string{">Aucune alerte immédiate</option>", ">Urgentes seulement</option>", ">Urgentes et À planifier</option>"} {
		if !strings.Contains(body, want) {
			t.Errorf("settings miss %s", want)
		}
	}
	if strings.Contains(body, "Exploitées ou probables") || strings.Contains(body, "élevées") {
		t.Error("an alert setting is not named by its levels")
	}
	u, err := st.UserByName(context.Background(), "analyst")
	if err != nil {
		t.Fatal(err)
	}
	if code := admin.post("/settings/users/"+strconv.FormatInt(u.ID, 10)+"/disable", url.Values{"csrf": {admin.csrf()}}); code != http.StatusSeeOther {
		t.Fatalf("disable: %d", code)
	}
	_, body = admin.get("/settings/users")
	if !strings.Contains(body, "<td>Activé</td>") || !strings.Contains(body, `<span class="late">Désactivé</span>`) || strings.Contains(body, "<td>Actif</td>") {
		t.Error("the state of an account is not Activé / Désactivé")
	}
}
