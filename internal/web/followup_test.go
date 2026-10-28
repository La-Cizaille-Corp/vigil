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
	st.ReplaceProjectAssets(ctx, "app", []store.Asset{a, b})
	st.ReplaceProjectAssets(ctx, "app", []store.Asset{a})
	c := loginAs(t, base, "analyst", "a-strong-password")

	_, list := c.get("/assets")
	if strings.Contains(list, ">dropped<") || !strings.Contains(list, "1 composant(s) retiré(s)") {
		t.Error("retired component in the inventory, or no link to it")
	}
	_, retired := c.get("/assets?retired=1")
	if !strings.Contains(retired, ">dropped<") || strings.Contains(retired, ">kept<") {
		t.Error("retired view")
	}
	ids, _ := st.ListRetiredAssets(ctx)
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
	id, _ := st.CreateAsset(ctx, store.Asset{Name: "log4j-core", Version: "2.14.1", Kind: "package", Criticality: "high",
		Source: "manual", PURL: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"})
	st.UpsertVulnerability(ctx, store.Vulnerability{ID: "GHSA-jfh8", Severity: "CRITICAL", Raw: `{"affected":[{"package":
		{"purl":"pkg:maven/org.apache.logging.log4j/log4j-core"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"2.13.0"},{"fixed":"2.15.0"}]}]}]}`})
	st.ObserveFinding(ctx, id, "GHSA-jfh8", time.Now())
	findings, _ := st.ListFindings(ctx, store.FindingFilter{AssetID: id})
	_, body := loginAs(t, base, "analyst", "a-strong-password").get("/findings/" + itoa(findings[0].ID))
	if !strings.Contains(body, "corrigée en 2.15.0") {
		t.Error("fixed version missing from the finding page")
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

// The fixed version comes from the stored advisory; the range holding the
// asset's version comes first.
func TestFixLines(t *testing.T) {
	osvRaw := `{"affected":[{"package":{"purl":"pkg:maven/org.apache.logging.log4j/log4j-core"},"ranges":[
		{"type":"ECOSYSTEM","events":[{"introduced":"2.4"},{"fixed":"2.12.2"}]},
		{"type":"ECOSYSTEM","events":[{"introduced":"2.13.0"},{"fixed":"2.15.0"}]},
		{"type":"GIT","events":[{"introduced":"0"},{"fixed":"abc123"}]}]},
		{"package":{"purl":"pkg:maven/other/lib"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"9.9"}]}]}]}`
	lines := fixLines(osvRaw, store.Finding{AssetPURL: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"})
	if len(lines) != 2 || !lines[0].Yours || !strings.Contains(lines[0].Text, "2.15.0") || lines[1].Yours {
		t.Errorf("OSV: %+v", lines)
	}

	nvdRaw := `{"configurations":[{"nodes":[{"cpeMatch":[
		{"vulnerable":true,"criteria":"cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*","versionStartIncluding":"7.2.0","versionEndExcluding":"7.2.5"},
		{"vulnerable":true,"criteria":"cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*","versionStartIncluding":"7.0.0","versionEndIncluding":"7.0.12"},
		{"vulnerable":true,"criteria":"cpe:2.3:a:fortinet:fortiproxy:*:*:*:*:*:*:*:*","versionEndExcluding":"7.0.10"}]}]}]}`
	lines = fixLines(nvdRaw, store.Finding{AssetCPE: "cpe:2.3:o:fortinet:fortios:7.2.4:*:*:*:*:*:*:*", AssetVersion: "7.2.4"})
	if len(lines) != 2 || !lines[0].Yours || !strings.Contains(lines[0].Text, "corrigée en 7.2.5") {
		t.Errorf("NVD: %+v", lines)
	}
	lines = fixLines(nvdRaw, store.Finding{AssetCPE: "cpe:2.3:*:fortinet:*:*:*:*:*:*:*:*:*"})
	if len(lines) != 3 || !strings.HasPrefix(lines[2].Text, "fortiproxy : ") {
		t.Errorf("whole vendor: %+v", lines)
	}
}
