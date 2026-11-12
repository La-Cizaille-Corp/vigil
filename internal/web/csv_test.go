package web

import (
	"context"
	"net/http"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/store"
)

// seedCSV fills an inventory whose exports go through every rule of the CSV
// writing: quotes, separators and line breaks inside values, formulas at
// every cell start, accents, empty cells, labels, dates and decimals.
func seedCSV(t *testing.T, st *store.Store) {
	t.Helper()
	ctx := context.Background()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	lodash, err := st.CreateAsset(ctx, store.Everything, store.Asset{Name: "lodash", Version: "4.17.15", Kind: "package",
		Criticality: "high", Owner: "équipe; -web", Project: "+portail", PURL: "pkg:npm/lodash@4.17.15", Ecosystem: "npm",
		TrackSince: "2026-01-01", Notes: "voir \"ticket\"\n=HYPERLINK(\"https://evil.example\")\r+1, @2\t=3", Source: "manual",
		Tags: []string{"prod", "=1+1", "équipe web"}})
	must(err)
	fortios, err := st.CreateAsset(ctx, store.Everything, store.Asset{Name: "FortiOS", Version: "7.2.4", Kind: "os",
		Criticality: "critical", CPE: "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", CPEMode: "from", CPEFrom: "7.0",
		Notes: "2.0 - 2.5, a = b", Source: "manual"})
	must(err)
	seen := time.Date(2026, 1, 5, 12, 0, 0, 0, time.UTC)
	for _, v := range []store.Vulnerability{
		{ID: "CVE-2026-0001", Aliases: []string{"GHSA-aaaa-bbbb-cccc"}, Severity: "CRITICAL", CVSS: 9.8, EPSS: -1,
			Summary: "@SUM(A1); \"quoted\"\nsecond line"},
		{ID: "GHSA-dddd-eeee-ffff", Severity: "HIGH", CVSS: -1, EPSS: -1, Summary: "-2 versions"},
		{ID: "CVE-2026-0003", Severity: "MEDIUM", CVSS: 5.3, EPSS: -1, Summary: "plain"},
	} {
		must(st.UpsertVulnerability(ctx, v))
	}
	if _, err := st.SetExploitSignals(ctx, store.ExploitSignal{ID: "CVE-2026-0001", KEV: true, KEVDue: "2026-02-01", EPSS: 0.9731},
		store.ExploitSignal{ID: "CVE-2026-0003", EPSS: 0.0004}); err != nil {
		t.Fatal(err)
	}
	for _, f := range []struct {
		asset          int64
		vuln, fixed    string
		status, justif string
		comment        string
	}{
		{lodash, "CVE-2026-0001", "4.17.21", "", "", ""},
		{lodash, "GHSA-dddd-eeee-ffff", "", "not_affected", "code_not_reachable", "=désactivé; voir \"wiki\""},
		{fortios, "CVE-2026-0003", "7.2.5", "exploitable", "", "à corriger"},
	} {
		_, err := st.ObserveFinding(ctx, f.asset, f.vuln, f.fixed, seen)
		must(err)
		if f.status == "" {
			continue
		}
		list, err := st.ListFindings(ctx, store.Everything, store.FindingFilter{AssetID: f.asset})
		must(err)
		for _, fd := range list {
			if fd.VulnID == f.vuln {
				must(st.SetFindingStatus(ctx, store.Everything, fd.ID, 0, f.status, f.justif, f.comment))
			}
		}
	}
}

// R6: the exports keep their bytes when their writing is shared: separator,
// byte order mark, quoting, cells neutralised against formulas, columns,
// decimal commas, labels, dates and links.
func TestCSVExportsByteForByte(t *testing.T) {
	st, base := newServerWith(t, func(s *Server) { s.BaseURL = "https://vigil.example/" })
	seedCSV(t, st)
	c := loginAs(t, base, "analyst", "a-strong-password")
	for _, e := range []struct{ path, want string }{
		{"/assets.csv", bom + wantAssetsCSV},
		{"/findings.csv?status=in_triage&status=exploitable&status=not_affected&sort=vuln&dir=asc", bom + wantFindingsCSV},
	} {
		code, body := c.get(e.path)
		if code != http.StatusOK || body != e.want {
			t.Errorf("%s: %d\n got %q\nwant %q", e.path, code, body, e.want)
		}
	}
}

// R12: a CSV import is all or nothing, a failure while the assets are written
// included. It used to create them one by one: a failure in the middle of the
// file left the first ones in the inventory.
func TestCSVImportAllOrNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "web.db")
	st, base := newServerIn(t, path, nil)
	// A write that fails in the middle of the file, as a full disk would.
	breakDB(t, path, `CREATE TRIGGER failing_write BEFORE INSERT ON assets WHEN NEW.name = 'panne'
		BEGIN SELECT RAISE(ABORT, 'disk I/O error'); END`)
	c := loginAs(t, base, "analyst", "a-strong-password")
	code, _ := c.upload("/assets/import-csv", "csv", "inventaire.csv", "name\navant\npanne\naprès\n", url.Values{"csrf": {c.csrf()}})
	assets, err := st.ListAssets(context.Background(), store.Everything)
	if code != http.StatusInternalServerError || err != nil || len(assets) != 0 {
		t.Errorf("import failing at its second asset: %d, assets left %+v, %v", code, assets, err)
	}
}

// bom is the UTF-8 byte order mark that starts every export.
const bom = "\xef\xbb\xbf"

// The exports of seedCSV, as written before the CSV writing was shared.
const (
	wantAssetsCSV = "name;version;kind;criticality;owner;project;purl;ecosystem;cpe;cpe_mode;cpe_from;track_since;notes;tags\n" +
		"FortiOS;7.2.4;os;critical;;;;;cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*;from;7.0;;2.0 - 2.5, a = b;\n" +
		"lodash;4.17.15;package;high;\"équipe; '-web\";'+portail;pkg:npm/lodash@4.17.15;npm;;;;2026-01-01;" +
		"\"voir \"\"ticket\"\"\n'=HYPERLINK(\"\"https://evil.example\"\")\r'+1, '@2\t'=3\";prod, '=1+1, équipe web\n"

	wantFindingsCSV = "id;vulnerabilite;alias;severite;cvss;epss;exploitee_kev;actif;version;corrigee_en;projet;statut;" +
		"justification;commentaire;detectee_le;echeance;hors_delai;resume;lien\n" +
		"1;CVE-2026-0001;GHSA-aaaa-bbbb-cccc;Critique;9,8;97,3;oui;lodash;4.17.15;4.17.21;'+portail;À analyser;;;" +
		"2026-01-05;2026-01-20;oui;\"'@SUM(A1); \"\"quoted\"\"\nsecond line\";https://vigil.example/findings/1\n" +
		"3;CVE-2026-0003;;Moyenne;5,3;0,0;non;FortiOS;7.2.4;7.2.5;;Exploitable – à traiter;;à corriger;" +
		"2026-01-05;2026-04-05;oui;plain;https://vigil.example/findings/3\n" +
		"2;GHSA-dddd-eeee-ffff;;Haute;;;non;lodash;4.17.15;;'+portail;Non affecté;Code vulnérable non atteignable;" +
		"\"'=désactivé; voir \"\"wiki\"\"\";2026-01-05;2026-02-04;non;'-2 versions;https://vigil.example/findings/2\n"
)
