package web

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/auth"
	"github.com/La-Cizaille-Corp/vigil/internal/digest"
	"github.com/La-Cizaille-Corp/vigil/internal/notify"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
	"github.com/La-Cizaille-Corp/vigil/internal/tracking"
)

// T3: nothing of B leaves through a page of an account of A: no list,
// counter, export, hint (tags, projects, groups), digest or state of the
// synchronisation names b, its tags, its project, its findings, their
// comments or its rules. The news citing b's vulnerability is public: its
// title shows, but it does not « concern » the inventory of A.
func TestNothingOfAnotherGroupLeaks(t *testing.T) {
	fx := newGroupFixture(t)
	id := func(v int64) string { return strconv.FormatInt(v, 10) }
	var paths []string
	for _, rt := range (&Server{}).routes() {
		method, path, _ := strings.Cut(rt.pattern, " ")
		if method != http.MethodGet || rt.role == public {
			continue
		}
		obj := fx.asset["p"]
		switch objectOf(t, rt.pattern) {
		case "finding":
			obj = fx.finding["p"]
		case "digest":
			obj = fx.digest
		}
		paths = append(paths, strings.NewReplacer("{$}", "", "{id}", id(obj)).Replace(path))
	}
	// Filters naming b's project or tag: the page repeats what was asked
	// (echo), and must show nothing else of b.
	echoes := map[string]string{}
	for _, f := range []string{"project=temoinb-projet", "tag=temoinb-tag"} {
		for _, list := range []string{"/assets?", "/findings?level=all&", "/findings/vex?", "/assets.csv?"} {
			echoes[list+f] = strings.Split(f, "=")[1]
		}
	}
	echoes["/assets?q=temoinb-nom"] = "temoinb-nom" // the search of the inventory (A86)
	paths = append(paths, "/findings?level=all&asset="+id(fx.asset["b"]), "/findings.csv?level=all&asset="+id(fx.asset["b"]))
	paths = append(paths, "/assets?retired=1", "/assets?group="+id(fx.groupB), "/assets/"+id(fx.asset["a"]),
		"/assets/"+id(fx.asset["p"])+"?q=9002", "/findings?level=all", "/findings?level=all&q=9002",
		"/findings?level=all&group="+id(fx.groupB), "/findings.csv?level=all", "/findings.csv?level=all&group="+id(fx.groupB),
		"/findings/vex", "/findings/"+id(fx.finding["a"]), "/cti?all=1", "/cti?all=1&concerning=1",
		"/digests/"+id(fx.digest)+"/markdown", "/settings/groups/"+id(fx.groupB),
		"/digests/"+id(fx.digests["dB"]), "/digests/"+id(fx.digests["dB"])+"/markdown", "/digests/"+id(fx.digests["dA"])+"/markdown")
	for path := range echoes {
		paths = append(paths, path)
	}
	for _, account := range []string{"ana-a", "lec-a", "ana-0"} {
		for _, path := range paths {
			code, body := fx.client[account].get(path)
			if code >= 500 {
				t.Errorf("%s as %s: %d", path, account, code)
			}
			if echo := echoes[path]; echo != "" {
				body = strings.ReplaceAll(body, echo, "")
			}
			if strings.Contains(strings.ToLower(body), witness) {
				t.Errorf("%s as %s shows %s", path, account, witness)
			}
			// A public news item may cite any vulnerability.
			if strings.Contains(body, witnessCVE) && (!strings.HasPrefix(path, "/cti") || strings.Contains(path, "concerning")) {
				t.Errorf("%s as %s shows %s", path, account, witnessCVE)
			}
		}
		if _, body := fx.client[account].get("/cti?all=1&concerning=1"); strings.Contains(body, witnessNews) {
			t.Errorf("the news citing b concerns the inventory of %s", account)
		}
	}
	// The same pages show b to an account that sees everything: the witness
	// is really in them.
	for _, path := range []string{"/assets", "/findings?level=all", "/findings.csv?level=all", "/assets/new",
		"/digests/" + id(fx.digest) + "/markdown", "/assets/" + id(fx.asset["p"]), "/sync"} {
		if path == "/sync" {
			continue // no synchronisation in this test: see TestSyncStateOfARestrictedAccount
		}
		if _, body := fx.client["analyst"].get(path); !strings.Contains(body, witness) && !strings.Contains(body, witnessCVE) {
			t.Errorf("%s does not show b to an account that sees everything", path)
		}
	}
	if _, body := fx.client["analyst"].get("/cti?all=1&concerning=1"); !strings.Contains(body, witnessNews) {
		t.Error("the news citing b does not concern the whole inventory")
	}
	// What A does see: its assets, the shared one, its group only.
	_, body := fx.client["lec-a"].get("/assets")
	for _, want := range []string{"alpha", "partage", "Équipe A"} {
		if !strings.Contains(body, want) {
			t.Errorf("A does not see %s", want)
		}
	}
	if strings.Contains(body, "orphelin") {
		t.Error("A sees the asset in no group")
	}
	if _, body := fx.client["ana-0"].get("/findings?level=all"); !strings.Contains(body, "Aucune vulnérabilité") {
		t.Error("an account without a group sees findings")
	}
}

// findingLinks are the findings a page links to.
var findingLinks = regexp.MustCompile(`href="/findings/([0-9]+)["?]`)

// T4: the figures of a restricted account are those of its assets: the
// dashboard, the counts by status, the rows of the list.
func TestFiguresOfARestrictedAccount(t *testing.T) {
	fx := newGroupFixture(t)
	ctx := context.Background()
	all, err := fx.st.ListFindings(ctx, store.Everything, store.FindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	var mine []store.Finding
	for _, f := range all {
		if f.AssetID == fx.asset["a"] || f.AssetID == fx.asset["p"] {
			mine = append(mine, f)
		}
	}
	sc := store.InGroups(fx.groupA)
	stats, err := fx.st.DashboardStats(ctx, sc, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	counts, err := fx.st.CountFindingsByStatus(ctx, sc)
	if err != nil {
		t.Fatal(err)
	}
	open, byStatus, bySeverity := 0, map[string]int{}, map[string]int{}
	for _, f := range mine {
		byStatus[f.Status]++
		if f.Open() {
			open++
			bySeverity[f.Severity]++
		}
	}
	if stats.Open != open || !reflect.DeepEqual(stats.OpenBySeverity, bySeverity) || !reflect.DeepEqual(counts, byStatus) {
		t.Errorf("figures of A: open %d %v, statuses %v; want %d %v, %v", stats.Open, stats.OpenBySeverity, counts,
			open, bySeverity, byStatus)
	}
	if len(stats.TopAssets) != 2 {
		t.Errorf("most exposed assets of A: %+v", stats.TopAssets)
	}
	for _, a := range stats.TopAssets {
		if a.ID != fx.asset["a"] && a.ID != fx.asset["p"] {
			t.Errorf("most exposed assets of A: %s", a.Name)
		}
	}
	if stats.Concerning30 != 0 {
		t.Errorf("news concerning A: %d", stats.Concerning30)
	}
	_, body := fx.client["lec-a"].get("/findings?level=all")
	seen := map[string]bool{}
	for _, m := range findingLinks.FindAllStringSubmatch(body, -1) {
		seen[m[1]] = true
	}
	if len(seen) != len(mine) {
		t.Errorf("list of A: %d findings, want %d", len(seen), len(mine))
	}
}

// The triage of a selection and a VEX import only reach the findings of the
// account: an identifier or a statement of another group is skipped, as an
// unknown one, and the audit log counts what was applied.
func TestTriageStaysInTheScope(t *testing.T) {
	fx := newGroupFixture(t)
	ctx := context.Background()
	before := fx.state(t, "b")
	c := fx.client["ana-a"]
	code := c.post("/findings/bulk", url.Values{"csrf": {c.csrf()}, "status": {store.StatusFalsePositive}, "comment": {"lot"},
		"next": {"/findings"}, "id": {strconv.FormatInt(fx.finding["b"], 10), strconv.FormatInt(fx.finding["a"], 10)}})
	if code != http.StatusSeeOther {
		t.Fatalf("bulk: %d", code)
	}
	if fx.state(t, "b") != before {
		t.Error("the bulk triage of A changed a finding of B")
	}
	if f, _ := fx.st.Finding(ctx, store.Everything, fx.finding["a"]); f.Status != store.StatusFalsePositive {
		t.Errorf("finding of A: %s", f.Status)
	}
	entries, _ := fx.st.ListAudit(ctx, 1)
	if len(entries) != 1 || entries[0].Detail != "count=1 status=false_positive" {
		t.Errorf("audit of the bulk triage: %+v", entries)
	}

	doc := `{"bomFormat":"CycloneDX","specVersion":"1.5","vulnerabilities":[
		{"id":"` + witnessCVE + `","analysis":{"state":"resolved","detail":"vex"},"affects":[{"ref":"pkg:npm/temoinb@1.0.0"}]},
		{"id":"` + sharedCVE + `","analysis":{"state":"resolved","detail":"vex"},"affects":[{"ref":"pkg:npm/temoinb@1.0.0"}]},
		{"id":"` + sharedCVE + `","analysis":{"state":"resolved","detail":"vex"},"affects":[{"ref":"pkg:npm/partage@1.0.0"}]}]}`
	if code, _ := c.upload("/findings/vex", "vex", "vex.json", doc, url.Values{"csrf": {c.csrf()}}); code != http.StatusSeeOther {
		t.Fatalf("VEX import: %d", code)
	}
	if fx.state(t, "b") != before {
		t.Error("the VEX import of A changed a finding of B")
	}
	entries, _ = fx.st.ListAudit(ctx, 1)
	if len(entries) != 1 || entries[0].Detail != "applied=1 ignored=2" {
		t.Errorf("audit of the VEX import: %+v", entries)
	}
}

// The state of a synchronisation names assets and counts findings over the
// whole inventory: an account restricted to groups sees whether it runs and
// how far, without them (A68).
func TestSyncStateOfARestrictedAccount(t *testing.T) {
	s := &Server{}
	if err := s.parseTemplates(); err != nil {
		t.Fatal(err)
	}
	render := func(st tracking.Status, u store.User) string {
		var b strings.Builder
		if err := s.pages["sync"].ExecuteTemplate(&b, "syncText", newSyncView(st, u)); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}
	restricted := store.User{Role: auth.RoleAnalyst, Access: store.Access{Groups: []int64{1}}}
	full := store.User{Role: auth.RoleAnalyst, Access: store.Access{All: true}}
	running := tracking.Status{Running: true, Asset: "temoinb-nom", Started: time.Now(), Total: 40, Done: 10, Current: "temoinb-encours"}
	failed := tracking.Status{Asset: "temoinb-nom", Finished: time.Now(), Err: "temoinb-erreur",
		Result: tracking.Result{Created: 7, Failed: 2}, Failures: []string{"temoinb-echec : HTTP 503"}}
	done := tracking.Status{Finished: time.Now(), Result: tracking.Result{Created: 7, Resolved: 3, Failed: 1},
		Failures: []string{"temoinb-echec : HTTP 503"}}
	if got := render(running, restricted); strings.Contains(got, witness) || strings.Contains(got, "sur 40") ||
		!strings.Contains(got, ": 25 %") || !strings.Contains(got, `<progress value="25" max="100"`) {
		t.Errorf("running, restricted: %s", got)
	}
	if got := render(failed, restricted); strings.Contains(got, witness) || strings.Contains(got, "503") || !strings.Contains(got, "échec") {
		t.Errorf("failed, restricted: %s", got)
	}
	if got := render(done, restricted); strings.Contains(got, witness) || strings.Contains(got, "nouvelle") ||
		strings.Contains(got, "non vérifié") || !strings.Contains(got, "terminée") {
		t.Errorf("done, restricted: %s", got)
	}
	for _, st := range []tracking.Status{running, failed, done} {
		if got := render(st, full); !strings.Contains(got, witness) {
			t.Errorf("an account that sees everything: %s", got)
		}
	}
	if got := render(done, full); !strings.Contains(got, "7 nouvelle(s)") {
		t.Errorf("counts for an account that sees everything: %s", got)
	}
}

// Settings → Groups: an administrator creates a group, chooses its rules,
// renames and deletes it, gives an account access to it; each step is in
// the audit log, and the account sees what the group covers at once.
func TestGroupAdministration(t *testing.T) {
	st, base := newServerWith(t, nil)
	ctx := context.Background()
	web, _ := st.CreateAsset(ctx, store.Everything, store.Asset{Name: "nginx", Kind: "product", Criticality: "low", Source: "manual",
		Tags: []string{"web"}})
	st.CreateAsset(ctx, store.Everything, store.Asset{Name: "compta", Kind: "product", Criticality: "low", Source: "manual",
		Tags: []string{"webapp"}, Project: "erp"})
	admin := loginAs(t, base, "admin", "a-strong-password")
	audited := func(action, detail string) {
		t.Helper()
		entries, _ := st.ListAudit(ctx, 1)
		if len(entries) != 1 || entries[0].Action != action || entries[0].Detail != detail {
			t.Errorf("audit: %+v, want %s %q", entries, action, detail)
		}
	}
	code, loc := admin.postLocation("/settings/groups", url.Values{"csrf": {admin.csrf()}, "name": {"  Équipe   web "}})
	if code != http.StatusSeeOther || !strings.HasPrefix(loc, "/settings/groups/") {
		t.Fatalf("create: %d %s", code, loc)
	}
	path, _, _ := strings.Cut(loc, "?")
	id := path[strings.LastIndex(path, "/")+1:]
	audited("group_create", "id="+id+` name="Équipe web"`)
	for _, name := range []string{"équipe WEB", "a,b", strings.Repeat("x", 101)} {
		if code := admin.post("/settings/groups", url.Values{"csrf": {admin.csrf()}, "name": {name}}); code != http.StatusBadRequest {
			t.Errorf("group named %q: %d", name, code)
		}
	}
	_, body := admin.get(path)
	for _, want := range []string{`value="web"`, `value="webapp"`, `value="erp"`, "0 actif(s)"} {
		if !strings.Contains(body, want) {
			t.Errorf("group page misses %s", want)
		}
	}
	if code, _ := admin.postLocation(path+"/rules", url.Values{"csrf": {admin.csrf()}, "tag": {"web"}, "new_tag": {" Futur "},
		"new_project": {"boutique"}}); code != http.StatusSeeOther {
		t.Fatalf("rules: %d", code)
	}
	audited("group_rules", "id="+id+" tags=web,futur projects=boutique")
	if _, body = admin.get(path); !strings.Contains(body, "1 actif(s)") || !strings.Contains(body, `value="futur" checked`) {
		t.Error("the group does not cover the asset tagged web, or forgets the tag not in use")
	}
	if code, _ := admin.postLocation(path, url.Values{"csrf": {admin.csrf()}, "name": {"Web"}}); code != http.StatusSeeOther {
		t.Fatalf("rename: %d", code)
	}
	audited("group_rename", "id="+id+" name=Web")

	// An account limited to the group, then given everything, then nothing.
	if code := admin.post("/settings/users", url.Values{"csrf": {admin.csrf()}, "username": {"camille"}, "role": {"viewer"}}); code != http.StatusBadRequest {
		t.Errorf("account created without a chosen access: %d", code)
	}
	if code := admin.post("/settings/users", url.Values{"csrf": {admin.csrf()}, "username": {"camille"}, "role": {"viewer"},
		"access": {"groups"}, "group": {id, "999"}}); code != http.StatusSeeOther {
		t.Fatalf("create a restricted account: %d", code)
	}
	camille, _ := st.AnyUserByName(ctx, "camille")
	audited("user_create", fmt.Sprintf("id=%d user=camille role=viewer access=groups groups=Web", camille.ID))
	if _, body = admin.get("/settings/users"); !strings.Contains(body, "Web") {
		t.Error("the list of users does not show the access")
	}
	reader := loginAs(t, base, "camille", admin.newPassword(t, camille.ID))
	if _, body := reader.get("/assets"); !strings.Contains(body, "nginx") || strings.Contains(body, "compta") {
		t.Error("the restricted account does not see exactly its group")
	}
	if _, body := reader.get("/account"); !strings.Contains(body, "<strong>Web</strong>") {
		t.Error("Mon compte does not tell the access")
	}
	if _, body := reader.get("/assets/" + strconv.FormatInt(web, 10)); !strings.Contains(body, `Groupes : <a href="/assets?group=`+id+`">Web</a>`) {
		t.Error("the page of the asset does not name its group")
	}
	access := "/settings/users/" + strconv.FormatInt(camille.ID, 10) + "/access"
	if code := admin.post(access, url.Values{"csrf": {admin.csrf()}, "access": {"all"}}); code != http.StatusSeeOther {
		t.Fatalf("access: %d", code)
	}
	audited("user_access", fmt.Sprintf("id=%d access=all", camille.ID))
	if _, body := reader.get("/assets"); !strings.Contains(body, "compta") {
		t.Error("the change of access does not apply at once")
	}
	if code := admin.post(access, url.Values{"csrf": {admin.csrf()}}); code != http.StatusBadRequest {
		t.Errorf("access without a choice: %d", code)
	}
	if code := admin.post(access, url.Values{"csrf": {admin.csrf()}, "access": {"groups"}}); code != http.StatusSeeOther {
		t.Fatalf("access: %d", code)
	}
	audited("user_access", fmt.Sprintf(`id=%d access=groups groups=""`, camille.ID))
	if _, body := reader.get("/assets"); strings.Contains(body, "nginx") {
		t.Error("an account without a group sees assets")
	}

	if code, loc := admin.postLocation(path+"/delete", url.Values{"csrf": {admin.csrf()}}); code != http.StatusSeeOther || loc != "/settings/groups?msg=group-deleted" {
		t.Fatalf("delete: %d %s", code, loc)
	}
	audited("group_delete", "id="+id+" name=Web")
	if code, _ := admin.get(path); code != http.StatusNotFound {
		t.Errorf("deleted group: %d", code)
	}
	if _, body := admin.get("/settings/groups"); !strings.Contains(body, "2 actif(s) hors de tout groupe") {
		t.Error("the assets in no group are not counted")
	}
}

// newPassword gives the account id a temporary password, as an administrator.
func (c *client) newPassword(t *testing.T, id int64) string {
	t.Helper()
	if code := c.post("/settings/users/"+strconv.FormatInt(id, 10)+"/password", url.Values{"csrf": {c.csrf()}}); code != http.StatusSeeOther {
		t.Fatalf("temporary password: %d", code)
	}
	_, body := c.get("/settings/users")
	m := passwordRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatal("no temporary password shown")
	}
	return m[1]
}

// T6: an analyst of A makes an asset enter only its groups and leave only
// its groups, by the form, a deletion, a CSV or an SBOM import: what would
// break it is refused with the reason, and changes nothing. The watch
// filters, common to every account, are not its to change (D4).
func TestRestrictedWritesThroughThePages(t *testing.T) {
	fx := newGroupFixture(t)
	ctx := context.Background()
	c := fx.client["ana-a"]
	assets := func() int {
		list, err := fx.st.ListAssets(ctx, store.Everything)
		if err != nil {
			t.Fatal(err)
		}
		return len(list)
	}
	count, stateB, stateP := assets(), fx.state(t, "b"), fx.state(t, "p")
	form := func(tags string) url.Values {
		return url.Values{"csrf": {c.csrf()}, "name": {"nouveau"}, "kind": {"package"}, "criticality": {"low"}, "tags": {tags}}
	}
	p := "/assets/" + strconv.FormatInt(fx.asset["p"], 10)
	if _, body := c.get("/assets/new"); !strings.Contains(body, "porter une de ces étiquettes : equipe-a") {
		t.Error("the form does not tell which tags keep an asset in the groups of the account")
	}
	for _, refusal := range []struct {
		label, path string
		form        url.Values
		want        string
	}{
		{"created in no group", "/assets", form(""), "donnez-lui l&#39;étiquette « equipe-a »"},
		{"created in B too", "/assets", form("equipe-a, equipe-b"), "l&#39;étiquette « equipe-b » le rattache à un groupe"},
		{"B removed from p", p, url.Values{"csrf": {c.csrf()}, "name": {"partage"}, "version": {"1.0.0"}, "kind": {"package"},
			"criticality": {"high"}, "purl": {"pkg:npm/partage@1.0.0"}, "tags": {"equipe-a"}}, "l&#39;étiquette « equipe-b »"},
		{"p deleted", p + "/delete", url.Values{"csrf": {c.csrf()}}, "seul un compte qui voit tout l&#39;inventaire peut le supprimer"},
	} {
		code, body := c.postBody(refusal.path, refusal.form)
		if code != http.StatusBadRequest || !strings.Contains(body, refusal.want) {
			t.Errorf("%s: %d, want 400 with %q", refusal.label, code, refusal.want)
		}
	}
	for _, csv := range []string{"nom;étiquettes\nautre;equipe-a\nencore;equipe-b\n",
		"nom;version;projet;purl\ntemoinb-nom;1.0.0;temoinb-projet;pkg:npm/temoinb@1.0.0\n"} {
		code, body := c.upload("/assets/import-csv", "csv", "inventaire.csv", csv, url.Values{"csrf": {c.csrf()}})
		if code != http.StatusBadRequest || !strings.Contains(body, "Import CSV refusé, aucun actif ajouté") {
			t.Errorf("CSV with a line of B: %d", code)
		}
	}
	bom := `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
		{"type":"library","name":"lodash","version":"4.17.15","purl":"pkg:npm/lodash@4.17.15"}]}`
	for project, want := range map[string]string{"temoinb-projet": "relève d&#39;un groupe dont vous ne faites pas partie",
		"inconnu": "ne fait partie d&#39;aucun de vos groupes"} {
		code, body := c.upload("/assets/import", "sbom", "bom.json", bom, url.Values{"csrf": {c.csrf()}, "project": {project}})
		if code != http.StatusBadRequest || !strings.Contains(body, want) {
			t.Errorf("SBOM of the project %s: %d, want %q", project, code, want)
		}
	}
	if code, _ := c.postBody("/settings/watch", url.Values{"csrf": {c.csrf()}, "country": {"FR"}}); code != http.StatusForbidden {
		t.Errorf("watch filters changed by a restricted account: %d", code)
	}
	if _, body := c.get("/settings/watch"); !strings.Contains(body, "seul un compte qui voit") || strings.Contains(body, `action="/settings/watch`) {
		t.Error("the watch filters form is offered to a restricted account")
	}
	if assets() != count || fx.state(t, "b") != stateB || fx.state(t, "p") != stateP {
		t.Fatal("a refused write changed the inventory")
	}
	if watched, _ := fx.st.Setting(ctx, "cti_countries"); watched != "" {
		t.Errorf("watch filters: %q", watched)
	}

	// Within its groups, the analyst of A writes as anyone.
	if code := c.post("/assets", form("equipe-a")); code != http.StatusSeeOther {
		t.Errorf("created in A: %d", code)
	}
	if code, _ := c.upload("/assets/import-csv", "csv", "inventaire.csv", "nom;étiquettes\nautre;equipe-a\n",
		url.Values{"csrf": {c.csrf()}}); code != http.StatusSeeOther {
		t.Errorf("CSV of A: %d", code)
	}
	if code := c.post("/assets/"+strconv.FormatInt(fx.asset["a"], 10)+"/delete", url.Values{"csrf": {c.csrf()}}); code != http.StatusSeeOther {
		t.Errorf("an asset of A alone deleted: %d", code)
	}
	if code := fx.client["analyst"].post("/settings/watch", url.Values{"csrf": {fx.client["analyst"].csrf()}, "country": {"FR"}}); code != http.StatusSeeOther {
		t.Errorf("watch filters changed by an account that sees everything: %d", code)
	}
}

// An administrator creating a token may add its project to a group: the
// components the pipeline pushes are then seen by the accounts of the group.
func TestTokenProjectJoinsAGroup(t *testing.T) {
	fx := newGroupFixture(t)
	ctx := context.Background()
	admin := fx.client["admin"]
	if code := admin.post("/settings/tokens", url.Values{"csrf": {admin.csrf()}, "name": {"ci"}, "project": {"ci-app"},
		"group": {"999"}}); code != http.StatusNotFound {
		t.Errorf("token with an unknown group: %d", code)
	}
	if tokens, _ := fx.st.ListAPITokens(ctx); len(tokens) != 0 {
		t.Error("token created for an unknown group")
	}
	if code := admin.post("/settings/tokens", url.Values{"csrf": {admin.csrf()}, "name": {"ci"}, "project": {"ci-app"},
		"group": {strconv.FormatInt(fx.groupA, 10)}}); code != http.StatusSeeOther {
		t.Fatalf("token: %d", code)
	}
	g, err := fx.st.Group(ctx, store.Everything, fx.groupA)
	if err != nil || !slices.Equal(g.Projects, []string{"ci-app"}) {
		t.Fatalf("projects of A: %v, %v", g.Projects, err)
	}
	entries, _ := fx.st.ListAudit(ctx, 1)
	if want := fmt.Sprintf("id=%d tags=equipe-a projects=ci-app", fx.groupA); len(entries) != 1 || entries[0].Detail != want {
		t.Errorf("audit: %+v, want %q", entries, want)
	}
	tokens, _ := fx.st.ListAPITokens(ctx)
	secret := "vgl_group-test-secret"
	if _, err := fx.st.CreateAPIToken(ctx, store.APIToken{Name: "ci2", Project: "ci-app"}, auth.HashToken(secret), 0); err != nil || len(tokens) != 1 {
		t.Fatal(err)
	}
	bom := `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
		{"type":"library","name":"pousse-par-ci","version":"1.0.0","purl":"pkg:npm/pousse-par-ci@1.0.0"}]}`
	if code := putSBOM(t, fx.base, "ci-app", secret, bom); code != http.StatusOK {
		t.Fatalf("SBOM by the API: %d", code)
	}
	if _, body := fx.client["lec-a"].get("/assets"); !strings.Contains(body, "pousse-par-ci") {
		t.Error("the components pushed for the project are not seen by its group")
	}
}

// A restricted account reads and generates the digests of its groups only;
// an account that sees everything reads them all and generates the digest of
// the whole inventory by default.
func TestDigestsOfAGroupThroughThePages(t *testing.T) {
	fx := newGroupFixture(t)
	c := fx.client["ana-a"]
	group := func(id int64) string { return strconv.FormatInt(id, 10) }
	_, body := fx.client["lec-a"].get("/digests")
	if !strings.Contains(body, "/digests/"+group(fx.digests["dA"])) || strings.Contains(body, "/digests/"+group(fx.digests["dB"])) ||
		strings.Contains(body, "/digests/"+group(fx.digest)+"\"") {
		t.Errorf("digests listed for A: %s", body)
	}
	if _, body := fx.client["analyst"].get("/digests"); !strings.Contains(body, "groupe Groupe temoinb") ||
		!strings.Contains(body, `<option value="">tout l'inventaire</option>`) {
		t.Errorf("an account that sees everything does not list every digest, or cannot choose the whole inventory: %s", body)
	}
	if code, _ := c.postBody("/digests", url.Values{"csrf": {c.csrf()}}); code != http.StatusBadRequest {
		t.Errorf("digest of the whole inventory by A: %d", code)
	}
	if code := c.post("/digests", url.Values{"csrf": {c.csrf()}, "group": {group(fx.groupB)}}); code != http.StatusNotFound {
		t.Errorf("digest of B by A: %d", code)
	}
	code, loc := c.postLocation("/digests", url.Values{"csrf": {c.csrf()}, "group": {group(fx.groupA)}})
	if code != http.StatusSeeOther {
		t.Fatalf("digest of A by A: %d", code)
	}
	path, _, _ := strings.Cut(loc, "?")
	if code, body := fx.client["lec-a"].get(path + "/markdown"); code != http.StatusOK || !strings.Contains(body, "Digest de veille sécurité — Équipe A") ||
		strings.Contains(body, witness) {
		t.Errorf("new digest of A: %d", code)
	}
	// Its counts lead to the lists of its group (A87).
	if _, body := fx.client["lec-a"].get(path); !strings.Contains(body, `<a href="/findings?group=`+group(fx.groupA)+`&amp;level=urgent">Urgentes</a>`) {
		t.Errorf("the levels of the digest of A do not lead to the lists of A:\n%s", body)
	}
	entries, _ := fx.st.ListAudit(context.Background(), 1)
	if want := "id=" + path[strings.LastIndex(path, "/")+1:] + ` group="Équipe A"`; len(entries) != 1 || entries[0].Detail != want {
		t.Errorf("audit: %+v, want %q", entries, want)
	}
	if code, loc := fx.client["analyst"].postLocation("/digests", url.Values{"csrf": {fx.client["analyst"].csrf()}}); code != http.StatusSeeOther {
		t.Errorf("digest of the whole inventory: %d %s", code, loc)
	}
}

// T3, messages: a channel limited to a group receives the alerts and the
// digest of that group only, nothing of the other groups; a channel of the
// whole inventory receives everything, as before. A group with a channel is
// not deleted (D7).
func TestChannelsOfAGroup(t *testing.T) {
	fx := newGroupFixture(t)
	ctx := context.Background()
	var mu sync.Mutex
	received := map[string]string{}
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		received[r.URL.Path] += string(b)
		mu.Unlock()
	}))
	defer hook.Close()
	admin := fx.client["admin"]
	// The form limits a channel to a group (an address of its own, never
	// called: the channel is disabled at once).
	if code := admin.post("/settings/webhooks", url.Values{"csrf": {admin.csrf()}, "name": {"équipe A"}, "kind": {"generic"},
		"url": {"https://hooks.example.org/a"}, "group": {strconv.FormatInt(fx.groupA, 10)}}); code != http.StatusSeeOther {
		t.Fatalf("channel of A by the form: %d", code)
	}
	hooks, _ := fx.st.ListWebhooks(ctx)
	if len(hooks) != 1 || hooks[0].Group != fx.groupA {
		t.Fatalf("channels: %+v", hooks)
	}
	if err := fx.st.SetWebhookEnabled(ctx, hooks[0].ID, false); err != nil {
		t.Fatal(err)
	}
	entries, _ := fx.st.ListAudit(ctx, 1)
	if want := fmt.Sprintf(`id=%d target=https://hooks.example.org/… group="Équipe A"`, hooks[0].ID); len(entries) != 1 || entries[0].Detail != want {
		t.Errorf("audit: %+v, want %q", entries, want)
	}
	if code := admin.post("/settings/webhooks", url.Values{"csrf": {admin.csrf()}, "name": {"x"}, "kind": {"generic"},
		"url": {"https://hooks.example.org/x"}, "group": {"999"}}); code != http.StatusNotFound {
		t.Errorf("channel of an unknown group: %d", code)
	}
	for path, group := range map[string]int64{"/tout": 0, "/a": fx.groupA, "/b": fx.groupB} {
		if _, err := fx.st.CreateWebhook(ctx, store.Webhook{Name: "canal " + path, Kind: "generic", URL: hook.URL + path,
			Enabled: true, Digests: true, Alerts: "severe", Group: group}); err != nil {
			t.Fatal(err)
		}
	}
	n := &notify.Notifier{Store: fx.st, HTTP: hook.Client(), Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := n.SendAlerts(ctx); err != nil {
		t.Fatal(err)
	}
	made, err := digest.Run(ctx, fx.st, func(d store.Digest) error { _, err := n.SendDigest(ctx, d); return err })
	if err != nil || len(made) != 3 {
		t.Fatalf("digests made: %d, %v (whole inventory, A, B)", len(made), err)
	}
	mu.Lock()
	defer mu.Unlock()
	for path, want := range map[string]bool{"/tout": true, "/a": false, "/b": true} {
		got := received[path]
		alert, digestPart, ok := strings.Cut(got, `"event":"digest"`)
		if !ok || !strings.Contains(alert, `"event":"alert"`) {
			t.Errorf("%s did not receive an alert, then a digest: %.200s", path, got)
		}
		// The digest lists the public news of the watch, the one citing b's
		// vulnerability among them: that one is checked in the alerts only.
		if strings.Contains(got, witness) != want || strings.Contains(alert, witnessCVE) != want {
			t.Errorf("%s receives the witness of B: %v, want %v", path, !want, want)
		}
		if strings.Contains(digestPart, "Actualités citant vos vulnérabilités") != want {
			t.Errorf("%s: the news citing b concerns it: %v, want %v", path, !want, want)
		}
	}
	if !strings.Contains(received["/a"], "partage") || strings.Contains(received["/a"], "orphelin") {
		t.Error("the channel of A does not receive exactly its assets")
	}

	_, body := admin.get("/settings/webhooks")
	if !strings.Contains(body, `aria-label="Périmètre de canal /a"`) ||
		!strings.Contains(body, fmt.Sprintf(`<option value="%d" selected>groupe Équipe A</option>`, fx.groupA)) {
		t.Error("the settings do not show the group of each channel")
	}
	if _, body = admin.get("/settings/tokens"); !strings.Contains(body, "Créer le jeton") || !strings.Contains(body, "Ajouter ce projet au groupe") {
		t.Error("the tokens page does not offer to add their project to a group")
	}
	_, body = admin.get("/settings/groups/" + strconv.FormatInt(fx.groupA, 10))
	if !strings.Contains(body, "2 canal(aux)") {
		t.Error("the page of a group does not count its channels")
	}
	if code, body := admin.postBody("/settings/groups/"+strconv.FormatInt(fx.groupA, 10)+"/delete", url.Values{"csrf": {admin.csrf()}}); code != http.StatusConflict ||
		!strings.Contains(body, "Des canaux de notification sont limités à ce groupe") {
		t.Errorf("group with a channel deleted: %d", code)
	}
}

// The group filter narrows a list to a group of the account, and to nothing
// for a group it does not see; an account that sees everything may filter by
// any group.
func TestGroupFilter(t *testing.T) {
	fx := newGroupFixture(t)
	names := func(body string) []string {
		var out []string
		for _, n := range []string{"alpha", "temoinb-nom", "partage", "orphelin"} {
			if strings.Contains(body, ">"+n+"<") || strings.Contains(body, ">"+n+" 1.0.0<") {
				out = append(out, n)
			}
		}
		return out
	}
	for _, c := range []struct {
		account string
		group   int64
		want    []string
	}{
		{"analyst", fx.groupB, []string{"temoinb-nom", "partage"}},
		{"analyst", fx.groupA, []string{"alpha", "partage"}},
		{"lec-a", fx.groupA, []string{"alpha", "partage"}},
		{"lec-a", fx.groupB, nil},
		{"lec-a", 0, []string{"alpha", "partage"}},
	} {
		q := "?group=" + strconv.FormatInt(c.group, 10)
		for _, path := range []string{"/assets" + q, "/findings" + q + "&level=all"} {
			if _, body := fx.client[c.account].get(path); !slices.Equal(names(body), c.want) {
				t.Errorf("%s as %s: %v, want %v", path, c.account, names(body), c.want)
			}
		}
	}
}
