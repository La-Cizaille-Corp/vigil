package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/La-Cizaille-Corp/vigil/internal/store"
)

// section is the part of page between <section id="id" and its end, "" when
// the page has none.
func section(page, id string) string {
	start := strings.Index(page, `<section id="`+id+`"`)
	if start < 0 {
		return ""
	}
	end := strings.Index(page[start:], "</section>")
	if end < 0 {
		return page[start:]
	}
	return page[start : start+end]
}

// The page of new assets opens on four ways in, each a link to its form
// further down; the form of an asset holds three groups, the optional ones
// folded (audit UX 7.1, A88).
func TestAddAssetsPage(t *testing.T) {
	_, base := newServerWith(t, nil)
	c := loginAs(t, base, "analyst", "a-strong-password")
	_, page := c.get("/assets/new")
	for _, want := range []string{`<nav class="add-ways" aria-label="Façons d'ajouter des actifs">`,
		`<a href="#paquet">`, `<a href="#produit">`, `<a href="#sbom">`, `<a href="#csv">`,
		`<form method="post" action="/assets#paquet" class="card">`, `action="/assets/import#sbom"`, `action="/assets/import-csv#csv"`,
		`<legend>1. Ce qu'il faut vérifier</legend>`, `<details class="group">
  <summary>2. Organisation`, `<details class="group">
  <summary>3. Période de suivi`, `<summary>Aide : comment Vigil trouve les vulnérabilités</summary>`,
		`<summary>Colonnes reconnues et valeurs admises</summary>`} {
		if !strings.Contains(page, want) {
			t.Errorf("page misses %s", want)
		}
	}
	for _, id := range []string{"paquet", "produit", "sbom", "csv"} {
		if section(page, id) == "" {
			t.Errorf("no section %s", id)
		}
	}
	// A product chosen in the CPE search comes back to the form, named as such.
	_, page = c.get(prefill("FortiOS", "7.2.4", "os", "cpe:2.3:o:fortinet:fortios:7.2.4:*:*:*:*:*:*:*", ""))
	if !strings.Contains(section(page, "paquet"), "<h2 id=\"t-paquet\">Le produit choisi</h2>") {
		t.Error("a product chosen is not named as such")
	}
	if !strings.HasSuffix(prefill("x", "", "os", "cpe:2.3:o:a:b:*:*:*:*:*:*:*:*", ""), "#paquet") {
		t.Error("the CPE search does not lead to the form")
	}
}

// A refusal shows in the form refused, which the browser comes back to, not at
// the top of a long page; the groups of a refused asset are unfolded, and its
// values kept (audit UX 7.1 and 7.3, A88).
func TestAddAssetsRefusalInItsForm(t *testing.T) {
	st, base := newServerWith(t, nil)
	c := loginAs(t, base, "analyst", "a-strong-password")

	code, page := c.upload("/assets/import-csv", "csv", "x.csv", "nom;type;criticité\nx;librairie;énorme\n", url.Values{"csrf": {c.csrf()}})
	csv := section(page, "csv")
	if code != http.StatusBadRequest || !strings.Contains(csv, `<p class="error" role="alert">Import CSV refusé, aucun actif ajouté :
Ligne 2 (x) : type « librairie » inconnu : Paquet / dépendance, Technologie, Produit ou Système d&#39;exploitation attendu.
Ligne 2 (x) : criticité « énorme » inconnue : Faible, Moyenne, Haute ou Critique attendue.</p>`) {
		t.Errorf("CSV refused: %d\n%s", code, csv)
	}
	if top := page[:strings.Index(page, `<nav class="add-ways"`)]; strings.Contains(top, `class="error"`) {
		t.Error("the refusal is shown at the top of the page too")
	}

	code, page = c.upload("/assets/import", "sbom", "bom.json", `{"bomFormat":"CycloneDX","components":"lodash"}`, url.Values{"csrf": {c.csrf()}})
	if code != http.StatusBadRequest || !strings.Contains(section(page, "sbom"),
		"Import refusé, aucun actif modifié : ce n&#39;est pas un SBOM CycloneDX valide : components doit être une liste, pas un texte.") {
		t.Errorf("SBOM refused: %d\n%s", code, section(page, "sbom"))
	}

	code, page = c.postBody("/assets", url.Values{"csrf": {c.csrf()}, "name": {"lodash"}, "kind": {"package"}, "criticality": {"high"},
		"purl": {"pkg:npm"}, "owner": {"équipe web"}})
	form := section(page, "paquet")
	if code != http.StatusBadRequest || !strings.Contains(form, "Purl incomplet : pkg:type/nom@version attendu") ||
		strings.Count(form, `<details class="group" open>`) != 2 || !strings.Contains(form, `name="owner" value="équipe web"`) {
		t.Errorf("asset refused: %d\n%s", code, form)
	}
	if assets, _ := st.ListAssets(context.Background(), store.Everything); len(assets) != 0 {
		t.Errorf("assets created: %+v", assets)
	}
}

// The message of an asset added says how its vulnerabilities are looked for,
// and what is missing when it is only by its name or not at all (audit UX 7.2,
// A88).
func TestAssetCreatedSaysItsDetection(t *testing.T) {
	_, base := newServerWith(t, nil)
	c := loginAs(t, base, "analyst", "a-strong-password")
	for _, tc := range []struct {
		form url.Values
		msg  string
		says string
	}{
		{url.Values{"name": {"lodash"}, "purl": {"pkg:npm/lodash@4.17.15"}}, "asset-created", "dans OSV, par son paquet et sa version"},
		{url.Values{"name": {"FortiOS"}, "cpe": {"cpe:2.3:o:fortinet:fortios:7.2.4:*:*:*:*:*:*:*"}}, "asset-created-cpe", "dans la NVD, par son CPE"},
		{url.Values{"name": {"nginx"}, "ecosystem": {"npm"}}, "asset-created-name", "cherche son nom dans les descriptions des CVE"},
		{url.Values{"name": {"left-pad"}, "purl": {"pkg:npm/left-pad"}}, "asset-created-none", "son purl ne donne pas de version"},
	} {
		tc.form.Set("csrf", c.csrf())
		tc.form.Set("kind", "package")
		code, loc := c.postLocation("/assets", tc.form)
		if code != http.StatusSeeOther || !strings.HasSuffix(loc, "?msg="+tc.msg) {
			t.Errorf("%s: %d %s, want msg=%s", tc.form.Get("name"), code, loc, tc.msg)
			continue
		}
		if _, page := c.get(loc); !strings.Contains(page, tc.says) {
			t.Errorf("%s: the page does not say %q", tc.form.Get("name"), tc.says)
		}
	}
}

// The first administrator types the password twice, as only the machine can
// reset it; a refusal keeps the name typed (audit UX 7.4, A88).
func TestSetupConfirmsThePassword(t *testing.T) {
	st, fresh := newTestServer(t)
	c := newClient(t, fresh)
	code, page := c.postBody("/setup", url.Values{"username": {"root"}, "password": {"a-strong-password"}, "confirm": {"a-strong-passwrd"}})
	if code != http.StatusBadRequest || !strings.Contains(page, "Les deux mots de passe ne correspondent pas.") ||
		!strings.Contains(page, `name="username" value="root"`) {
		t.Errorf("mismatch: %d\n%s", code, page)
	}
	if n, _ := st.CountUsers(context.Background()); n != 0 {
		t.Errorf("%d account created", n)
	}
}

// An empty inventory shows « Pour commencer » alone, adding assets as its main
// button, and no indicator at zero (audit UX 7.4, A88); a filtered list that
// comes out empty says so, and offers to reset its filters (7.5).
func TestEmptyStates(t *testing.T) {
	st, base := newServerWith(t, nil)
	c := loginAs(t, base, "analyst", "a-strong-password")
	_, page := c.get("/")
	if !strings.Contains(page, "<h2>Pour commencer</h2>") || !strings.Contains(page, `<a class="button" href="/assets/new">Ajouter des actifs</a>`) ||
		strings.Contains(page, "Indicateurs clés") || strings.Contains(page, "Synchroniser l'inventaire") {
		t.Errorf("empty dashboard:\n%s", page)
	}
	seedFindings(t, st)
	_, page = c.get("/")
	if strings.Contains(page, "Pour commencer") || !strings.Contains(page, "Indicateurs clés") {
		t.Error("the dashboard of an inventory still says how to begin")
	}
	_, page = c.get("/assets?tag=inexistante")
	if !strings.Contains(page, `Aucun actif ne
  correspond à ces filtres. <a href="/assets">Réinitialiser les filtres</a>`) {
		t.Error("an inventory filtered to nothing reads as empty")
	}
	_, page = c.get("/findings?q=introuvable")
	if !strings.Contains(page, `Aucune vulnérabilité ne correspond à ces filtres. <a href="/findings">Réinitialiser les filtres</a>`) {
		t.Error("a search without result offers no reset")
	}
	if _, page = c.get("/findings?level=aside"); strings.Contains(page, "Réinitialiser les filtres") {
		t.Error("an empty level is not a filter to reset")
	}
}
