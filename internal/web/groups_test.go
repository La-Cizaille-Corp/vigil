package web

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/auth"
	"github.com/La-Cizaille-Corp/vigil/internal/digest"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
)

// The common set of the tests of the groups (A68): groups A and B; assets a
// (in A), b (in B), p (in both) and o (in none), each with findings, a
// history, a dismissal rule; a digest; and five accounts. b carries values
// found nowhere else, all holding "temoinb": the witness that nothing of B
// leaves through a page of A.
type groupFixture struct {
	st             *store.Store
	base           string
	groupA, groupB int64
	asset          map[string]int64   // a, b, p, o
	finding        map[string]int64   // the finding of its own vulnerability, per asset
	rule           map[string]int64   // the dismissal rule, per asset
	digest         int64              // of the whole inventory
	digests        map[string]int64   // d (whole inventory), dA and dB (of groups A and B)
	client         map[string]*client // per account
}

const (
	witness     = "temoinb"
	witnessCVE  = "CVE-2026-9002"
	sharedCVE   = "CVE-2026-9100"
	witnessNews = "Bulletin public 42"
)

// fixtureAccount is an account of the fixture: its role, and the groups of a
// restricted one ("all" for everything).
type fixtureAccount struct{ role, groups string }

var fixtureAccounts = map[string]fixtureAccount{
	"admin":   {auth.RoleAdmin, "all"},
	"analyst": {auth.RoleAnalyst, "all"},
	"ana-a":   {auth.RoleAnalyst, "A"},
	"lec-a":   {auth.RoleViewer, "A"},
	"ana-0":   {auth.RoleAnalyst, ""},
}

// sees is the policy of the fixture: whether an account sees an object, an
// asset (a, b, p, o), its findings and rules, or a digest (d of the whole
// inventory, dA and dB of the groups).
func sees(account, object string) bool {
	switch fixtureAccounts[account].groups {
	case "all":
		return true
	case "A":
		return object == "a" || object == "p" || object == "dA"
	}
	return false
}

func newGroupFixture(t *testing.T) *groupFixture {
	t.Helper()
	ctx := context.Background()
	st, base := newTestServer(t)
	fx := &groupFixture{st: st, base: base, asset: map[string]int64{}, finding: map[string]int64{},
		rule: map[string]int64{}, client: map[string]*client{}, digests: map[string]int64{}}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	var err error
	fx.groupA, err = st.CreateGroup(ctx, "Équipe A")
	must(err)
	must(st.SetGroupRules(ctx, fx.groupA, []string{"equipe-a"}, nil))
	fx.groupB, err = st.CreateGroup(ctx, "Groupe temoinb")
	must(err)
	must(st.SetGroupRules(ctx, fx.groupB, []string{"equipe-b"}, []string{"temoinb-projet"}))

	for name, a := range map[string]store.Asset{
		"a": {Name: "alpha", PURL: "pkg:npm/alpha@1.0.0", Tags: []string{"equipe-a"}},
		"b": {Name: "temoinb-nom", PURL: "pkg:npm/temoinb@1.0.0", Tags: []string{"equipe-b", "temoinb-tag"},
			Project: "temoinb-projet", Owner: "temoinb-responsable"},
		"p": {Name: "partage", PURL: "pkg:npm/partage@1.0.0", Tags: []string{"equipe-a", "equipe-b"}},
		"o": {Name: "orphelin", PURL: "pkg:npm/orphelin@1.0.0"},
	} {
		a.Kind, a.Criticality, a.Source, a.Version = "package", "high", "manual", "1.0.0"
		fx.asset[name], err = st.CreateAsset(ctx, store.Everything, a)
		must(err)
	}
	seen := time.Now().Add(-time.Hour)
	for i, name := range []string{"a", "b", "p", "o"} {
		own := store.Vulnerability{ID: fmt.Sprintf("CVE-2026-900%d", i+1), Severity: "HIGH", CVSS: 7.5, EPSS: -1,
			Summary: "faille de " + name}
		if name == "b" {
			own.Summary, own.Severity, own.CVSS = "temoinb-resume", "CRITICAL", 9.8
		}
		for _, v := range []store.Vulnerability{own, {ID: sharedCVE, Severity: "MEDIUM", CVSS: 5, EPSS: -1, Summary: "commune"}} {
			must(st.UpsertVulnerability(ctx, v))
			_, err := st.ObserveFinding(ctx, fx.asset[name], v.ID, "", seen)
			must(err)
		}
		list, err := st.ListFindings(ctx, store.Everything, store.FindingFilter{AssetID: fx.asset[name], Search: own.ID})
		must(err)
		fx.finding[name] = list[0].ID
		comment := "analyse de " + name
		if name == "b" {
			comment = "temoinb-commentaire"
		}
		must(st.SetFindingStatus(ctx, store.Everything, fx.finding[name], 0, store.StatusExploitable, "", comment))
		text := "regle " + name
		if name == "b" {
			text = "temoinb-regle"
		}
		must(st.CreateDismissalRule(ctx, store.Everything, fx.asset[name], text))
		rules, err := st.ListDismissalRules(ctx, store.Everything, fx.asset[name])
		must(err)
		fx.rule[name] = rules[0].ID
	}
	for name, g := range map[string]store.Group{"d": {}, "dA": {ID: fx.groupA, Name: "Équipe A"}, "dB": {ID: fx.groupB, Name: "Groupe temoinb"}} {
		d, err := digest.Generate(ctx, st, g)
		must(err)
		fx.digests[name] = d.ID
	}
	fx.digest = fx.digests["d"]
	feed, err := st.CreateFeed(ctx, store.Feed{Name: "Avis", URL: "https://example.org/feed", Enabled: true})
	must(err)
	_, err = st.InsertCTIItem(ctx, feed, store.CTIItem{GUID: "42", Title: witnessNews + " " + witnessCVE,
		Link: "https://example.org/42", Published: time.Now()})
	must(err)

	hash, err := auth.HashPassword("a-strong-password")
	must(err)
	for name, a := range fixtureAccounts {
		access := store.Access{All: a.groups == "all"}
		if a.groups == "A" {
			access.Groups = []int64{fx.groupA}
		}
		_, err := st.CreateUser(ctx, name, hash, a.role, access)
		must(err)
		fx.client[name] = loginAs(t, base, name, "a-strong-password")
	}
	return fx
}

// state is what the store holds of an asset, its findings, their history and
// its rules: unchanged after a refused request.
func (fx *groupFixture) state(t *testing.T, name string) string {
	t.Helper()
	ctx := context.Background()
	a, err := fx.st.Asset(ctx, store.Everything, fx.asset[name])
	if err != nil {
		t.Fatal(err)
	}
	findings, err := fx.st.ListFindings(ctx, store.Everything, store.FindingFilter{AssetID: a.ID})
	if err != nil {
		t.Fatal(err)
	}
	var events []store.FindingEvent
	for _, f := range findings {
		list, err := fx.st.ListFindingEvents(ctx, store.Everything, f.ID)
		if err != nil {
			t.Fatal(err)
		}
		events = append(events, list...)
	}
	rules, err := fx.st.ListDismissalRules(ctx, store.Everything, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%+v %+v %+v %+v", a, findings, events, rules)
}

// objectOf classifies a route whose path names an object of the inventory:
// asset, finding or digest. A new route of that kind must be classified here.
func objectOf(t *testing.T, pattern string) string {
	_, path, _ := strings.Cut(pattern, " ")
	switch {
	case strings.HasPrefix(path, "/assets/{id}"):
		return "asset"
	case strings.HasPrefix(path, "/findings/{id}"):
		return "finding"
	case strings.HasPrefix(path, "/digests/{id}"):
		return "digest"
	case strings.HasPrefix(path, "/settings/") || strings.HasPrefix(path, "/api/") || !strings.Contains(strings.ReplaceAll(path, "{$}", ""), "{"):
		return ""
	}
	t.Errorf("%s: an object of which kind? Classify it in objectOf", pattern)
	return ""
}

// T2: every route of an object, for every account and every object, answers
// as the policy says: the role first (403), then the scope (404, as for an
// object that does not exist); a refused request changes nothing.
func TestObjectRoutesFollowTheScope(t *testing.T) {
	fx := newGroupFixture(t)
	before := map[string]string{}
	for name := range fx.asset {
		before[name] = fx.state(t, name)
	}
	checked := 0
	for _, rt := range (&Server{}).routes() {
		kind := objectOf(t, rt.pattern)
		if kind == "" || rt.role == public {
			continue
		}
		method, path, _ := strings.Cut(rt.pattern, " ")
		objects := []string{"a", "b", "p", "o"}
		if kind == "digest" {
			objects = []string{"d", "dA", "dB"}
		}
		for account, c := range fx.client {
			token := c.csrf()
			for _, obj := range objects {
				id := fx.asset[obj]
				switch kind {
				case "finding":
					id = fx.finding[obj]
				case "digest":
					id = fx.digests[obj]
				}
				target := strings.NewReplacer("{id}", strconv.FormatInt(id, 10), "{rule}", strconv.FormatInt(fx.rule[obj], 10)).Replace(path)
				visible := sees(account, obj)
				want := http.StatusOK
				switch {
				case !auth.RoleAtLeast(fixtureAccounts[account].role, rt.role):
					want = http.StatusForbidden
				case !visible:
					want = http.StatusNotFound
				case method != http.MethodGet:
					continue // allowed: not run, so that the fixture stays as it is
				}
				form := url.Values{"csrf": {token}, "name": {"renamed"}, "kind": {"package"}, "criticality": {"low"},
					"status": {store.StatusFalsePositive}, "comment": {"refusé"}, "text": {"nouvelle règle"}}
				code, _ := c.send(method, target, form)
				if code != want {
					t.Errorf("%s %s as %s on %s: %d, want %d", method, target, account, obj, code, want)
				}
				checked++
			}
		}
	}
	if checked < 100 {
		t.Fatalf("only %d requests checked", checked)
	}
	for name := range fx.asset {
		if got := fx.state(t, name); got != before[name] {
			t.Errorf("asset %s changed by refused requests", name)
		}
	}
}
