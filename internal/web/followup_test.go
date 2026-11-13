package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/store"
	"github.com/La-Cizaille-Corp/vigil/internal/storetest"
)

// Where a second factor is required, an account without one only reaches
// its own page until it sets it up.
func TestTOTPPolicy(t *testing.T) {
	st, base := newServerWith(t, nil)
	admin := loginAs(t, base, "admin", testPassword)
	analyst := loginAs(t, base, "analyst", testPassword)
	if code := admin.post("/settings/users/totp-policy", url.Values{"csrf": {admin.csrf()}, "policy": {"admin"}}); code != http.StatusSeeOther {
		t.Fatalf("policy: %d", code)
	}
	if code, loc := admin.send(http.MethodGet, "/findings", nil); code != http.StatusSeeOther || !strings.HasPrefix(loc, "/account") {
		t.Errorf("admin without second factor reached /findings: %d %s", code, loc)
	}
	if code, _ := admin.get("/account"); code != http.StatusOK {
		t.Errorf("account page: %d", code)
	}
	if code, _ := analyst.get("/findings"); code != http.StatusOK {
		t.Errorf("analyst blocked by the admin policy: %d", code)
	}
	if err := st.SetTOTPPolicy(context.Background(), store.TOTPEveryone); err != nil {
		t.Fatal(err)
	}
	if code, _ := analyst.get("/findings"); code != http.StatusSeeOther {
		t.Errorf("analyst without second factor not redirected: %d", code)
	}
}

// Components dropped from an SBOM are listed apart, and are not checked
// any more; the add forms have their own page.
func TestRetiredComponentsAndAddPage(t *testing.T) {
	st, base := newServerWith(t, nil)
	ctx := context.Background()
	a := store.Asset{Name: "kept", Kind: "package", PURL: "pkg:npm/kept@1"}
	b := store.Asset{Name: "dropped", Kind: "package", PURL: "pkg:npm/dropped@1"}
	for _, sbom := range [][]store.Asset{{a, b}, {a}} {
		if _, err := st.ReplaceProjectAssets(ctx, store.Everything, "app", sbom); err != nil {
			t.Fatal(err)
		}
	}
	c := loginAs(t, base, "analyst", testPassword)

	_, list := c.get("/assets")
	pageHas(t, "inventory", list, []string{"1 composant(s) retiré(s)"}, ">dropped<")
	_, retired := c.get("/assets?retired=1")
	pageHas(t, "retired view", retired, []string{">dropped<"}, ">kept<")
	gone, err := st.ListRetiredAssets(ctx, store.Everything)
	if err != nil || len(gone) != 1 {
		t.Fatalf("retired assets: %+v, %v", gone, err)
	}
	_, page := c.get("/assets/" + itoa(gone[0].ID))
	pageHas(t, "retired asset page", page, []string{"absent du dernier SBOM"}, "Analyser cet actif")

	if code, body := c.get("/assets/new"); code != http.StatusOK || !strings.Contains(body, `name="purl"`) {
		t.Errorf("add page: %d", code)
	}
	if code, body := c.get("/assets"); code != http.StatusOK || strings.Contains(body, `name="purl"`) {
		t.Error("the inventory still carries the add form")
	}
}

// The finding page reads the fix from the advisory stored by the sync.
func TestFindingPageShowsFix(t *testing.T) {
	st, base := newServerWith(t, nil)
	id := storetest.Asset(t, st, store.Asset{Name: "log4j-core", Version: "2.14.1", Kind: "package", Criticality: "high",
		Source: "manual", PURL: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"})
	finding := storetest.Finding(t, st, id, store.Vulnerability{ID: "GHSA-jfh8", Severity: "CRITICAL", Raw: `{"affected":[{"package":
		{"purl":"pkg:maven/org.apache.logging.log4j/log4j-core"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"2.13.0"},{"fixed":"2.15.0"}]}]}]}`},
		time.Now())
	_, body := loginAs(t, base, "analyst", testPassword).get("/findings/" + itoa(finding))
	if !strings.Contains(body, "corrigée en 2.15.0") {
		t.Error("fixed version missing from the finding page")
	}
}

// A severity without a CVSS score is the rating of the source (a priority of
// Ubuntu, a GitHub rating): the finding page says so.
func TestFindingPageSeverityWithoutScore(t *testing.T) {
	st, base := newServerWith(t, nil)
	id := storetest.Asset(t, st, store.Asset{Name: "linux", Version: "5.15.0-100.110", Kind: "os",
		Criticality: "high", Source: "manual", Ecosystem: "Ubuntu:22.04:LTS"})
	c := loginAs(t, base, "analyst", testPassword)
	for _, v := range []struct {
		vuln  store.Vulnerability
		rated bool
	}{
		{store.Vulnerability{ID: "UBUNTU-CVE-2026-1", Severity: "MEDIUM", CVSS: -1}, true},
		{store.Vulnerability{ID: "UBUNTU-CVE-2026-2", Severity: "HIGH", CVSS: 7.8}, false},
	} {
		_, body := c.get("/findings/" + itoa(storetest.Finding(t, st, id, v.vuln, time.Now())))
		if strings.Contains(body, "évaluation de la source, sans score CVSS") != v.rated {
			t.Errorf("%s: source rating shown = %v, want %v", v.vuln.ID, !v.rated, v.rated)
		}
	}
}

func TestSyncPage(t *testing.T) {
	_, base := newServerWith(t, nil)
	c := loginAs(t, base, "analyst", testPassword)
	code, body := c.get("/sync")
	if code != http.StatusOK || !strings.Contains(body, "Aucune synchronisation") || strings.Contains(body, `http-equiv="refresh"`) {
		t.Errorf("sync page: %d", code)
	}
}
