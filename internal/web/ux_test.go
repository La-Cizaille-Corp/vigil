package web

import (
	"context"
	"net/http"
	"net/url"
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
	details, vulns := strings.Index(page, "<h2>Détails</h2>"), strings.Index(page, "<h2>Vulnérabilités de cet actif</h2>")
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
	if !strings.Contains(page, `<a class="kpi kpi-hero" href="/findings?priority=1">`) ||
		!strings.Contains(page, `<a class="kpi" href="/findings">`) || strings.Contains(page, "%3d") {
		t.Error("dashboard cards do not link to the open findings")
	}
	// The mean time to fix says what it counts.
	if !strings.Contains(page, "traitée(s) en 90 jours, hors celles trouvées à la première analyse de leur actif") {
		t.Error("the mean time to fix does not say what it counts")
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
		!strings.Contains(page, `class="active" aria-current="true">Veille menaces</a>`) {
		t.Error("the views of the watch do not say which one is shown")
	}
}

// A list row names three aliases at most; the finding page keeps them all.
func TestAliasList(t *testing.T) {
	for n, want := range map[int]string{
		0: "", 1: "A0", 3: "A0, A1, A2", 4: "A0, A1, A2 et 1 autre", 1902: "A0, A1, A2 et 1899 autres",
	} {
		list := make([]string, n)
		for i := range list {
			list[i] = "A" + strconv.Itoa(i)
		}
		if got := aliasList(list); got != want {
			t.Errorf("%d aliases: %q, want %q", n, got, want)
		}
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
