package web

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/auth"
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
	paths = append(paths, "/assets?retired=1", "/assets?group="+id(fx.groupB), "/assets/"+id(fx.asset["a"]),
		"/assets/"+id(fx.asset["p"])+"?q=9002", "/findings?level=all", "/findings?level=all&q=9002",
		"/findings?level=all&group="+id(fx.groupB), "/findings.csv?level=all", "/findings.csv?level=all&group="+id(fx.groupB),
		"/findings/vex", "/findings/"+id(fx.finding["a"]), "/cti?all=1", "/cti?all=1&concerning=1",
		"/digests/"+id(fx.digest)+"/markdown", "/settings/groups/"+id(fx.groupB))
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
var findingLinks = regexp.MustCompile(`href="/findings/([0-9]+)"`)

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
