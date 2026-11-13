package store

import (
	"context"
	"errors"
	"math/rand/v2"
	"reflect"
	"slices"
	"testing"
	"time"
)

// inGroup is the rule of A68 written in Go, as a reference for the SQL of
// Scope.cond: an asset belongs to a group when it carries one of its tags or
// belongs to one of its projects, values compared exactly.
func inGroup(a Asset, g Group) bool {
	return slices.ContainsFunc(a.Tags, func(t string) bool { return slices.Contains(g.Tags, t) }) ||
		a.Project != "" && slices.Contains(g.Projects, a.Project)
}

// T5: the condition of the store says what the rule says, on random tags,
// projects and rules, with the edge cases among the values: « web » and
// « webapp », LIKE wildcards, the case of a project, retired components, a
// group without rules.
func TestScopeMatchesTheRule(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	rnd := rand.New(rand.NewPCG(68, 1))
	tags := []string{"web", "webapp", "app", "w_b", "w%b", "prod", "équipe-web", "Web"}
	projects := []string{"", "boutique", "Boutique", "intranet", "web"}
	pick := func(from []string, max int) []string {
		var out []string
		for _, v := range from {
			if len(out) < max && rnd.IntN(4) == 0 {
				out = append(out, v)
			}
		}
		return out
	}
	for i := range 120 {
		a := Asset{Name: "a", Version: string(rune('a' + i%26)), Kind: "package", Criticality: "low", Source: "manual",
			Project: projects[rnd.IntN(len(projects))], Tags: pick(tags, 3)}
		id, err := st.CreateAsset(ctx, Everything, a)
		if err != nil {
			t.Fatal(err)
		}
		if rnd.IntN(5) == 0 { // a component dropped from its SBOM keeps its groups
			if _, err := st.db.ExecContext(ctx, `UPDATE assets SET retired_at = ? WHERE id = ?`, now(), id); err != nil {
				t.Fatal(err)
			}
		}
	}
	active, err := st.ListAssets(ctx, Everything)
	if err != nil {
		t.Fatal(err)
	}
	retired, err := st.ListRetiredAssets(ctx, Everything)
	if err != nil {
		t.Fatal(err)
	}
	var ids []int64
	for i := range 8 {
		id, err := st.CreateGroup(ctx, "groupe "+string(rune('A'+i)))
		if err != nil {
			t.Fatal(err)
		}
		if i > 0 { // the first one has no rule: it takes in nothing
			if err := st.SetGroupRules(ctx, id, pick(tags, 2), pick(projects[1:], 2)); err != nil {
				t.Fatal(err)
			}
		}
		ids = append(ids, id)
	}
	groups, err := st.ListGroups(ctx, Everything)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[int64]Group{}
	covered := 0
	for _, g := range groups {
		byID[g.ID] = g
		covered += g.Assets
		want := 0
		for _, a := range active {
			if inGroup(a, g) {
				want++
			}
		}
		if g.Assets != want {
			t.Errorf("group %s %v %v: %d assets, want %d", g.Name, g.Tags, g.Projects, g.Assets, want)
		}
	}
	if byID[ids[0]].Assets != 0 {
		t.Error("a group without rules takes in assets")
	}
	if covered == 0 || covered == len(groups)*len(active) {
		t.Fatalf("the random groups cover %d assets: no comparison", covered)
	}

	names := func(list []Asset) []int64 {
		var out []int64
		for _, a := range list {
			out = append(out, a.ID)
		}
		slices.Sort(out)
		return out
	}
	for trial := range 40 {
		var chosen []int64
		for _, id := range ids {
			if rnd.IntN(3) == 0 {
				chosen = append(chosen, id)
			}
		}
		sc := InGroups(chosen...)
		for _, set := range []struct {
			all  []Asset
			list func(context.Context, Scope) ([]Asset, error)
		}{{active, st.ListAssets}, {retired, st.ListRetiredAssets}} {
			var want []Asset
			for _, a := range set.all {
				if slices.ContainsFunc(chosen, func(id int64) bool { return inGroup(a, byID[id]) }) {
					want = append(want, a)
				}
			}
			got, err := set.list(ctx, sc)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(names(got), names(want)) {
				t.Errorf("trial %d, groups %v: %d assets, want %d", trial, chosen, len(got), len(want))
			}
		}
	}

	// The groups shown on the page of an asset are those of the rule, among
	// the groups of the scope.
	for _, a := range append(active[:20:20], retired...) {
		list, err := st.ListAssetGroups(ctx, Everything, a.ID)
		if err != nil {
			t.Fatal(err)
		}
		var got, want []int64
		for _, g := range list {
			got = append(got, g.ID)
		}
		for _, g := range groups {
			if inGroup(a, g) {
				want = append(want, g.ID)
			}
		}
		slices.Sort(got)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("asset %v %q: groups %v, want %v", a.Tags, a.Project, got, want)
		}
		mine, err := st.ListAssetGroups(ctx, InGroups(ids[1]), a.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(mine) > 1 || len(mine) == 1 && mine[0].ID != ids[1] || len(mine) == 0 && inGroup(a, byID[ids[1]]) {
			t.Errorf("asset %v %q: groups %v seen from %d", a.Tags, a.Project, mine, ids[1])
		}
	}
}

// T6: a restricted account makes an asset enter only its groups, leave only
// its groups, and stay in one of them unless it deletes it: whatever the way
// (creation, change, deletion, several at once, SBOM), a write that would
// break it is refused, says why, and changes nothing.
func TestRestrictedWrites(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	group := func(name string, tags, projects []string) int64 {
		t.Helper()
		id, err := st.CreateGroup(ctx, name)
		if err != nil {
			t.Fatal(err)
		}
		if err := st.SetGroupRules(ctx, id, tags, projects); err != nil {
			t.Fatal(err)
		}
		return id
	}
	a := group("A", []string{"equipe-a"}, []string{"boutique"})
	group("B", []string{"equipe-b"}, []string{"erp", "partage"})
	group("A et B", nil, []string{"partage"})
	asset := func(name string, project string, tags ...string) Asset {
		return Asset{Name: name, Kind: "package", Criticality: "low", Source: "manual", Project: project, Tags: tags}
	}
	mine, err := st.CreateAsset(ctx, Everything, asset("mine", "", "equipe-a"))
	if err != nil {
		t.Fatal(err)
	}
	shared, err := st.CreateAsset(ctx, Everything, asset("shared", "", "equipe-a", "equipe-b"))
	if err != nil {
		t.Fatal(err)
	}
	sc := InGroups(a)
	refused := func(label string, err error, want OutsideGroupsError) {
		t.Helper()
		var e *OutsideGroupsError
		if !errors.As(err, &e) || !errors.Is(err, errOutsideGroups) {
			t.Errorf("%s: %v, want refused", label, err)
			return
		}
		if !reflect.DeepEqual(*e, want) {
			t.Errorf("%s: %+v, want %+v", label, *e, want)
		}
	}
	update := func(id int64, project string, tags ...string) error {
		a, err := st.Asset(ctx, Everything, id)
		if err != nil {
			t.Fatal(err)
		}
		a.Project, a.Tags = project, tags
		return st.UpdateAsset(ctx, sc, a)
	}
	before := fingerprint(t, st)
	suggest := OutsideGroupsError{Tags: []string{"equipe-a"}, Projects: []string{"boutique"}}
	_, err = st.CreateAsset(ctx, sc, asset("nowhere", ""))
	refused("created in no group", err, OutsideGroupsError{Asset: "nowhere", Tags: suggest.Tags, Projects: suggest.Projects})
	_, err = st.CreateAsset(ctx, sc, asset("also B", "", "equipe-a", "equipe-b"))
	refused("created in B too", err, OutsideGroupsError{Asset: "also B", ForeignTags: []string{"equipe-b"}})
	_, err = st.CreateAssets(ctx, sc, []Asset{asset("fine", "boutique"), asset("erp", "erp")})
	refused("one of several in B", err, OutsideGroupsError{Asset: "erp", ForeignProjects: []string{"erp"},
		Tags: suggest.Tags, Projects: suggest.Projects})
	refused("B added", update(mine, "", "equipe-a", "equipe-b"), OutsideGroupsError{Asset: "mine", ForeignTags: []string{"equipe-b"}})
	refused("B removed", update(shared, "", "equipe-a"), OutsideGroupsError{Asset: "shared", ForeignTags: []string{"equipe-b"}})
	refused("A removed", update(mine, ""), OutsideGroupsError{Asset: "mine", Tags: suggest.Tags, Projects: suggest.Projects})
	refused("shared deleted", st.DeleteAsset(ctx, sc, shared), OutsideGroupsError{Asset: "shared", Deleting: true,
		ForeignTags: []string{"equipe-b"}})
	for _, project := range []string{"erp", "partage", "inconnu"} {
		_, err := st.ReplaceProjectAssets(ctx, sc, project, []Asset{{Name: "c", Kind: "package", PURL: "pkg:npm/c@1"}})
		if !errors.Is(err, errOutsideGroups) {
			t.Errorf("SBOM of the project %s: %v", project, err)
		}
	}
	if fingerprint(t, st) != before {
		t.Fatal("a refused write changed the database")
	}

	// Within its groups, it writes as anyone.
	if err := update(mine, "boutique"); err != nil {
		t.Errorf("tag of A replaced by a project of A: %v", err)
	}
	if err := update(shared, "", "equipe-a", "equipe-b", "prod"); err != nil {
		t.Errorf("a tag of no group added to a shared asset: %v", err)
	}
	if _, err := st.CreateAssets(ctx, sc, []Asset{asset("fine", "boutique"), asset("fine too", "", "equipe-a")}); err != nil {
		t.Errorf("created in A: %v", err)
	}
	if _, err := st.ReplaceProjectAssets(ctx, sc, "boutique", []Asset{{Name: "c", Kind: "package", PURL: "pkg:npm/c@1"}}); err != nil {
		t.Errorf("SBOM of a project of A: %v", err)
	}
	if err := st.DeleteAsset(ctx, sc, mine); err != nil {
		t.Errorf("an asset of A alone deleted: %v", err)
	}
	if err := st.DeleteAsset(ctx, Everything, shared); err != nil {
		t.Errorf("deleted by an account that sees everything: %v", err)
	}
}

// An account sees the assets of its groups only, an administrator everything
// whatever its access; an account deprived of its last group sees nothing,
// never everything (T8).
func TestAccessOfAnAccount(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	web, err := st.CreateAsset(ctx, Everything, Asset{Name: "nginx", Kind: "product", Criticality: "low", Source: "manual", Tags: []string{"web"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateAsset(ctx, Everything, Asset{Name: "compta", Kind: "product", Criticality: "low", Source: "manual"}); err != nil {
		t.Fatal(err)
	}
	group, err := st.CreateGroup(ctx, "Équipe web")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetGroupRules(ctx, group, []string{"web"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateGroup(ctx, "équipe WEB"); !errors.Is(err, ErrExists) {
		t.Errorf("a name differing by case: %v", err)
	}
	other, _ := st.CreateGroup(ctx, "Compta")
	if err := st.RenameGroup(ctx, other, "ÉQUIPE web"); !errors.Is(err, ErrExists) {
		t.Errorf("renamed as another group: %v", err)
	}
	if err := st.RenameGroup(ctx, group, "équipe Web"); err != nil {
		t.Errorf("a group renamed at its own case: %v", err)
	}

	sees := func(name string) []int64 {
		t.Helper()
		u, err := st.AnyUserByName(ctx, name)
		if err != nil {
			t.Fatal(err)
		}
		list, err := st.ListAssets(ctx, u.Scope())
		if err != nil {
			t.Fatal(err)
		}
		var ids []int64
		for _, a := range list {
			ids = append(ids, a.ID)
		}
		return ids
	}
	ana, err := st.CreateUser(ctx, "ana", "hash", "analyst", Access{Groups: []int64{group, 999}})
	if err != nil {
		t.Fatal(err)
	}
	if u, _ := st.User(ctx, ana); u.Access.All || !slices.Equal(u.Access.Groups, []int64{group}) || !u.Restricted() {
		t.Errorf("access of a restricted account: %+v (an unknown group is left out)", u.Access)
	}
	if got := sees("ana"); !slices.Equal(got, []int64{web}) {
		t.Errorf("restricted account sees %v", got)
	}
	if _, err := st.CreateUser(ctx, "boss", "hash", "admin", Access{}); err != nil {
		t.Fatal(err)
	}
	if got := sees("boss"); len(got) != 2 {
		t.Errorf("an administrator restricted to no group sees %v", got)
	}
	if err := st.SetUserAccess(ctx, ana, Access{}); err != nil {
		t.Fatal(err)
	}
	if got := sees("ana"); len(got) != 0 {
		t.Errorf("without a group: sees %v", got)
	}
	if err := st.SetUserAccess(ctx, ana, Access{Groups: []int64{group}}); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteGroup(ctx, group); err != nil {
		t.Fatal(err)
	}
	if got := sees("ana"); len(got) != 0 {
		t.Errorf("its group deleted: sees %v", got)
	}
	if err := st.SetUserAccess(ctx, 999, Access{All: true}); !errors.Is(err, ErrNotFound) {
		t.Errorf("access of an unknown account: %v", err)
	}
	// An account inserted without an access, as an older binary would not:
	// the default of the column denies.
	if _, err := st.db.ExecContext(ctx, `INSERT INTO users (username, password_hash, role, created_at) VALUES ('raw', 'x', 'viewer', ?)`, now()); err != nil {
		t.Fatal(err)
	}
	if got := sees("raw"); len(got) != 0 {
		t.Errorf("account without a chosen access sees %v", got)
	}
	// The session carries the access: a change applies at the next request.
	if err := st.CreateSession(ctx, "token", ana, "csrf", parseTime(now()).Add(3600e9)); err != nil {
		t.Fatal(err)
	}
	if err := st.SetUserAccess(ctx, ana, Access{All: true}); err != nil {
		t.Fatal(err)
	}
	if sess, err := st.Session(ctx, "token"); err != nil || !sess.User.Access.All {
		t.Errorf("session after a change of access: %+v, %v", sess.User.Access, err)
	}
}

// A68, step 5: a digest covers the whole inventory or a group; a restricted
// account reads those of its groups only, and each one starts where the
// previous one of the same group ended. A channel may be limited to a group,
// which cannot be deleted while it has one (D7); its digests go with it.
func TestDigestsAndChannelsOfAGroup(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	a, _ := st.CreateGroup(ctx, "A")
	b, _ := st.CreateGroup(ctx, "B")
	at := func(h int) time.Time { return time.Date(2026, 11, 1, h, 0, 0, 0, time.UTC) }
	digests := map[string]int64{}
	for name, d := range map[string]Digest{"all": {CreatedAt: at(9)}, "a": {CreatedAt: at(10), Group: a}, "b": {CreatedAt: at(11), Group: b}} {
		id, err := st.CreateDigest(ctx, d)
		if err != nil {
			t.Fatal(err)
		}
		digests[name] = id
	}
	list, err := st.ListDigests(ctx, InGroups(a))
	if err != nil || len(list) != 1 || list[0].ID != digests["a"] || list[0].GroupName != "A" {
		t.Errorf("digests of A: %+v, %v", list, err)
	}
	if all, _ := st.ListDigests(ctx, Everything); len(all) != 3 {
		t.Errorf("every digest: %d", len(all))
	}
	for _, name := range []string{"all", "b"} {
		if _, err := st.Digest(ctx, InGroups(a), digests[name]); !errors.Is(err, ErrNotFound) {
			t.Errorf("digest %s read from A: %v", name, err)
		}
	}
	for group, want := range map[int64]time.Time{0: at(9), a: at(10), b: at(11), 999: {}} {
		if last, err := st.LastDigestTime(ctx, group); err != nil || !last.Equal(want) {
			t.Errorf("last digest of %d: %v, %v; want %v", group, last, err, want)
		}
	}

	if _, err := st.CreateWebhook(ctx, Webhook{Name: "x", Kind: "generic", URL: "https://example.org", Group: 999}); !errors.Is(err, ErrNotFound) {
		t.Errorf("channel of an unknown group: %v", err)
	}
	hook, err := st.CreateWebhook(ctx, Webhook{Name: "équipe A", Kind: "generic", URL: "https://example.org", Group: a})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetWebhookDelivery(ctx, hook, true, "", 999); !errors.Is(err, ErrNotFound) {
		t.Errorf("channel moved to an unknown group: %v", err)
	}
	if h, _ := st.Webhook(ctx, hook); h.Group != a || h.GroupName != "A" {
		t.Errorf("channel: %+v", h)
	}
	if g, _ := st.Group(ctx, Everything, a); g.Channels != 1 {
		t.Errorf("channels of A: %d", g.Channels)
	}
	if err := st.DeleteGroup(ctx, a); !errors.Is(err, ErrGroupInUse) {
		t.Errorf("group with a channel deleted: %v", err)
	}
	if err := st.SetWebhookDelivery(ctx, hook, true, "", 0); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteGroup(ctx, a); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Digest(ctx, Everything, digests["a"]); !errors.Is(err, ErrNotFound) {
		t.Errorf("digest of a deleted group: %v", err)
	}
	if _, err := st.Digest(ctx, Everything, digests["b"]); err != nil {
		t.Errorf("digest of another group: %v", err)
	}
}
