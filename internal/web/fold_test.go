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

// One finding per CVE (A80), as the pages show it: the finding of a CVE names
// the grouped advisories citing it and the other advisories folded into it;
// a folded finding leads to the one kept, and a grouped advisory decided on
// offers to apply its decision to its CVEs, by the batch triage.
func TestFoldedFindingPages(t *testing.T) {
	st, base := newServerWith(t, nil)
	ctx := context.Background()
	asset := storetest.Asset(t, st, store.Asset{Name: "linux", Kind: "os", Ecosystem: "Ubuntu:22.04:LTS",
		Version: "5.15.0-100.110", Criticality: "high", Source: "manual"})
	ranges := `{"affected":[{"package":{"name":"linux","ecosystem":"Ubuntu:22.04:LTS"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"5.15.0-200.1"}]}]}]}`
	for _, v := range []store.Vulnerability{
		{ID: "UBUNTU-CVE-2026-1", Aliases: []string{"CVE-2026-1"}, Severity: "MEDIUM", Raw: ranges},
		{ID: "UBUNTU-CVE-2026-2", Aliases: []string{"CVE-2026-2"}, Severity: "MEDIUM", Raw: ranges},
		{ID: "GHSA-same", Aliases: []string{"CVE-2026-1"}, Raw: ranges},
		{ID: "USN-9000-1", Aliases: []string{"CVE-2026-1", "CVE-2026-2", "UBUNTU-CVE-2026-1", "UBUNTU-CVE-2026-2"}, Raw: ranges},
	} {
		v.EPSS, v.CVSS = -1, -1
		storetest.Finding(t, st, asset, v, time.Now())
	}
	ids := map[string]int64{}
	triage, _ := st.ListFindingTriage(ctx, asset)
	for _, f := range triage {
		ids[f.VulnID] = f.ID
	}
	analyst, err := st.AnyUserByName(ctx, "analyst")
	if err != nil {
		t.Fatal(err)
	}
	st.SetFindingStatus(ctx, store.Everything, ids["USN-9000-1"], analyst.ID, "not_affected", "code_not_present", "pas de wifi")
	if err := st.FoldFindings(ctx, store.Fold{ID: ids["USN-9000-1"], Into: store.FoldedNotice, Why: "avis groupé"},
		store.Fold{ID: ids["GHSA-same"], Into: ids["UBUNTU-CVE-2026-1"], Why: "même CVE"}); err != nil {
		t.Fatal(err)
	}
	c := loginAs(t, base, "analyst", testPassword)

	_, body := c.get("/findings/" + itoa(ids["UBUNTU-CVE-2026-1"]))
	for _, want := range []string{"Avis groupés", "https://osv.dev/vulnerability/USN-9000-1", "corrigée en 5.15.0-200.1",
		"« Non affecté » par analyst", "Autres avis de cette CVE", "GHSA-same"} {
		if !strings.Contains(body, want) {
			t.Errorf("finding of the CVE: %q missing", want)
		}
	}
	_, body = c.get("/findings/" + itoa(ids["GHSA-same"]))
	if !strings.Contains(body, "Regroupée") || !strings.Contains(body, "/findings/"+itoa(ids["UBUNTU-CVE-2026-1"])) {
		t.Error("folded finding: no link to the finding kept")
	}
	_, body = c.get("/findings/" + itoa(ids["USN-9000-1"]))
	if !strings.Contains(body, "Avis groupé : chacune de ses CVE") || !strings.Contains(body, "Appliquer « Non affecté » à 2 vulnérabilité(s)") {
		t.Fatal("grouped advisory: no form to apply its decision")
	}
	if _, list := c.get("/findings"); strings.Contains(list, "USN-9000-1") || strings.Contains(list, "GHSA-same") {
		t.Error("a folded finding is listed")
	}
	// The form of the page, sent as is, applies the decision to the CVEs.
	form := url.Values{"csrf": {c.csrf()}, "next": {"/findings"}, "status": {"not_affected"}, "justification": {"code_not_present"},
		"comment": {"Décision de l'avis groupé USN-9000-1 : pas de wifi"},
		"id":      {itoa(ids["UBUNTU-CVE-2026-1"]), itoa(ids["UBUNTU-CVE-2026-2"])}}
	if code := c.post("/findings/bulk", form); code != http.StatusSeeOther {
		t.Fatalf("batch triage: %d", code)
	}
	for _, vuln := range []string{"UBUNTU-CVE-2026-1", "UBUNTU-CVE-2026-2"} {
		if f, _ := st.Finding(ctx, store.Everything, ids[vuln]); f.Status != "not_affected" {
			t.Errorf("%s: %s", vuln, f.Status)
		}
	}
}
