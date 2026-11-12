package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/store"
)

// Where a second factor is required, an account without one only reaches
// its own page until it sets it up.
func TestTOTPPolicy(t *testing.T) {
	st, base := newServerWith(t, nil)
	admin := loginAs(t, base, "admin", "a-strong-password")
	analyst := loginAs(t, base, "analyst", "a-strong-password")
	if code := admin.post("/settings/users/totp-policy", url.Values{"csrf": {admin.csrf()}, "policy": {"admin"}}); code != http.StatusSeeOther {
		t.Fatalf("policy: %d", code)
	}
	req, _ := http.NewRequest(http.MethodGet, base+"/findings", nil)
	resp, err := admin.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if loc := resp.Header.Get("Location"); resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(loc, "/account") {
		t.Errorf("admin without second factor reached /findings: %d %s", resp.StatusCode, loc)
	}
	if code, _ := admin.get("/account"); code != http.StatusOK {
		t.Errorf("account page: %d", code)
	}
	if code, _ := analyst.get("/findings"); code != http.StatusOK {
		t.Errorf("analyst blocked by the admin policy: %d", code)
	}
	st.SetTOTPPolicy(context.Background(), store.TOTPEveryone)
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
	st.ReplaceProjectAssets(ctx, store.Everything, "app", []store.Asset{a, b})
	st.ReplaceProjectAssets(ctx, store.Everything, "app", []store.Asset{a})
	c := loginAs(t, base, "analyst", "a-strong-password")

	_, list := c.get("/assets")
	if strings.Contains(list, ">dropped<") || !strings.Contains(list, "1 composant(s) retiré(s)") {
		t.Error("retired component in the inventory, or no link to it")
	}
	_, retired := c.get("/assets?retired=1")
	if !strings.Contains(retired, ">dropped<") || strings.Contains(retired, ">kept<") {
		t.Error("retired view")
	}
	ids, _ := st.ListRetiredAssets(ctx, store.Everything)
	_, page := c.get("/assets/" + itoa(ids[0].ID))
	if !strings.Contains(page, "absent du dernier SBOM") || strings.Contains(page, "Analyser cet actif") {
		t.Error("retired asset page")
	}

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
	ctx := context.Background()
	id, _ := st.CreateAsset(ctx, store.Everything, store.Asset{Name: "log4j-core", Version: "2.14.1", Kind: "package", Criticality: "high",
		Source: "manual", PURL: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"})
	st.UpsertVulnerability(ctx, store.Vulnerability{ID: "GHSA-jfh8", Severity: "CRITICAL", Raw: `{"affected":[{"package":
		{"purl":"pkg:maven/org.apache.logging.log4j/log4j-core"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"2.13.0"},{"fixed":"2.15.0"}]}]}]}`})
	st.ObserveFinding(ctx, id, "GHSA-jfh8", "", time.Now())
	findings, _ := st.ListFindings(ctx, store.Everything, store.FindingFilter{AssetID: id})
	_, body := loginAs(t, base, "analyst", "a-strong-password").get("/findings/" + itoa(findings[0].ID))
	if !strings.Contains(body, "corrigée en 2.15.0") {
		t.Error("fixed version missing from the finding page")
	}
}

// A severity without a CVSS score is the rating of the source (a priority of
// Ubuntu, a GitHub rating): the finding page says so.
func TestFindingPageSeverityWithoutScore(t *testing.T) {
	st, base := newServerWith(t, nil)
	ctx := context.Background()
	id, _ := st.CreateAsset(ctx, store.Everything, store.Asset{Name: "linux", Version: "5.15.0-100.110", Kind: "os",
		Criticality: "high", Source: "manual", Ecosystem: "Ubuntu:22.04:LTS"})
	st.UpsertVulnerability(ctx, store.Vulnerability{ID: "UBUNTU-CVE-2026-1", Severity: "MEDIUM", CVSS: -1})
	st.UpsertVulnerability(ctx, store.Vulnerability{ID: "UBUNTU-CVE-2026-2", Severity: "HIGH", CVSS: 7.8})
	c := loginAs(t, base, "analyst", "a-strong-password")
	for vuln, rated := range map[string]bool{"UBUNTU-CVE-2026-1": true, "UBUNTU-CVE-2026-2": false} {
		st.ObserveFinding(ctx, id, vuln, "", time.Now())
		findings, _ := st.ListFindings(ctx, store.Everything, store.FindingFilter{AssetID: id, Search: vuln})
		_, body := c.get("/findings/" + itoa(findings[0].ID))
		if strings.Contains(body, "évaluation de la source, sans score CVSS") != rated {
			t.Errorf("%s: source rating shown = %v, want %v", vuln, !rated, rated)
		}
	}
}

func TestSyncPage(t *testing.T) {
	_, base := newServerWith(t, nil)
	c := loginAs(t, base, "analyst", "a-strong-password")
	code, body := c.get("/sync")
	if code != http.StatusOK || !strings.Contains(body, "Aucune synchronisation") || strings.Contains(body, `http-equiv="refresh"`) {
		t.Errorf("sync page: %d", code)
	}
}
