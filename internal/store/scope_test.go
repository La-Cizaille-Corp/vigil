package store_test

import (
	"context"
	"errors"
	"maps"
	"reflect"
	"testing"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/store"
	"github.com/La-Cizaille-Corp/vigil/internal/storetest"
)

// scopeFixture is a small inventory reached by every scoped method: a manual
// asset with an open finding cited by a news item and a closed one, a dismissal
// rule, a component kept by an SBOM and another one retired from it, a digest,
// a group taking in the manual asset, and another group taking in nothing.
type scopeFixture struct {
	asset, open, closed, rule, digest, group, other int64
	folded                                          int64 // a second advisory of the open finding's CVE, folded into it
}

func newScopeFixture(t *testing.T) (*store.Store, scopeFixture) {
	t.Helper()
	ctx := context.Background()
	st := storetest.Open(t)
	var fx scopeFixture
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	fx.asset = storetest.Asset(t, st, store.Asset{Name: "canari", Kind: "package", Criticality: "high",
		Source: "manual", Project: "app", Tags: []string{"equipe"}})
	_, err := st.ReplaceProjectAssets(ctx, store.Everything, "sbom", []store.Asset{
		{Name: "kept", Kind: "package", PURL: "pkg:npm/kept@1"}, {Name: "gone", Kind: "package", PURL: "pkg:npm/gone@1"}})
	must(err)
	_, err = st.ReplaceProjectAssets(ctx, store.Everything, "sbom", []store.Asset{{Name: "kept", Kind: "package", PURL: "pkg:npm/kept@1"}})
	must(err)

	seen := time.Now()
	fx.open = storetest.Finding(t, st, fx.asset, store.Vulnerability{ID: "CVE-2026-0001", Severity: "CRITICAL", Summary: "open one", EPSS: -1, CVSS: 9.8}, seen)
	fx.closed = storetest.Finding(t, st, fx.asset, store.Vulnerability{ID: "CVE-2026-0002", Severity: "HIGH", Summary: "closed one", EPSS: -1, CVSS: 7.5}, seen)
	must(st.SetFindingStatus(ctx, store.Everything, fx.closed, 0, "resolved", "", "corrigée"))
	fx.folded = storetest.Finding(t, st, fx.asset, store.Vulnerability{ID: "GHSA-0001", Aliases: []string{"CVE-2026-0001"}, EPSS: -1, CVSS: -1}, seen)
	must(st.FoldFindings(ctx, store.Fold{ID: fx.folded, Into: fx.open, Why: "même CVE"}))
	must(st.CreateDismissalRule(ctx, store.Everything, fx.asset, "matches nothing"))
	rules, err := st.ListDismissalRules(ctx, store.Everything, fx.asset)
	must(err)
	fx.rule = rules[0].ID

	fx.digest, err = st.CreateDigest(ctx, store.Digest{Since: seen.Add(-time.Hour), CreatedAt: seen, Markdown: "canari", HTML: "canari"})
	must(err)
	feed, err := st.CreateFeed(ctx, store.Feed{Name: "Avis", URL: "https://example.org/feed"})
	must(err)
	_, err = st.InsertCTIItem(ctx, feed, store.CTIItem{GUID: "1", Title: "Avis CVE-2026-0001", Link: "https://example.org/1", Published: seen})
	must(err)

	fx.group, err = st.CreateGroup(ctx, "Équipe")
	must(err)
	must(st.SetGroupRules(ctx, fx.group, []string{"equipe"}, nil))
	fx.other, err = st.CreateGroup(ctx, "Ailleurs")
	must(err)
	must(st.SetGroupRules(ctx, fx.other, []string{"ailleurs"}, []string{"ailleurs"}))
	return st, fx
}

// found turns the error of a lookup into "reached".
func found(err error) (bool, error) {
	if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrOutsideGroups) {
		return false, nil
	}
	return err == nil, err
}

// isolationCases call each scoped method on the fixture and report whether it
// reached it: returned it, counted it or changed it. A method that takes a
// Scope must have a case here (TestEveryStoreMethodIsScopedOrExempt).
var isolationCases = map[string]func(context.Context, *store.Store, store.Scope, scopeFixture) (bool, error){
	"Asset": func(ctx context.Context, st *store.Store, sc store.Scope, fx scopeFixture) (bool, error) {
		_, err := st.Asset(ctx, sc, fx.asset)
		return found(err)
	},
	"ListAssets": func(ctx context.Context, st *store.Store, sc store.Scope, _ scopeFixture) (bool, error) {
		list, err := st.ListAssets(ctx, sc)
		return len(list) > 0, err
	},
	"ListRetiredAssets": func(ctx context.Context, st *store.Store, sc store.Scope, _ scopeFixture) (bool, error) {
		list, err := st.ListRetiredAssets(ctx, sc)
		return len(list) > 0, err
	},
	"ListAssetTags": func(ctx context.Context, st *store.Store, sc store.Scope, _ scopeFixture) (bool, error) {
		tags, err := st.ListAssetTags(ctx, sc)
		return len(tags) > 0, err
	},
	"ListProjects": func(ctx context.Context, st *store.Store, sc store.Scope, _ scopeFixture) (bool, error) {
		list, err := st.ListProjects(ctx, sc)
		return len(list) > 0, err
	},
	"CreateAsset": func(ctx context.Context, st *store.Store, sc store.Scope, _ scopeFixture) (bool, error) {
		_, err := st.CreateAsset(ctx, sc, store.Asset{Name: "new", Kind: "package", Criticality: "low", Source: "manual"})
		return found(err)
	},
	"CreateAssets": func(ctx context.Context, st *store.Store, sc store.Scope, _ scopeFixture) (bool, error) {
		_, err := st.CreateAssets(ctx, sc, []store.Asset{{Name: "new", Kind: "package", Criticality: "low", Source: "manual"}})
		return found(err)
	},
	"UpdateAsset": func(ctx context.Context, st *store.Store, sc store.Scope, fx scopeFixture) (bool, error) {
		return found(st.UpdateAsset(ctx, sc, store.Asset{ID: fx.asset, Name: "renamed", Kind: "package", Criticality: "low"}))
	},
	"DeleteAsset": func(ctx context.Context, st *store.Store, sc store.Scope, fx scopeFixture) (bool, error) {
		return found(st.DeleteAsset(ctx, sc, fx.asset))
	},
	"ReplaceProjectAssets": func(ctx context.Context, st *store.Store, sc store.Scope, _ scopeFixture) (bool, error) {
		_, err := st.ReplaceProjectAssets(ctx, sc, "sbom", []store.Asset{{Name: "other", Kind: "package", PURL: "pkg:npm/other@1"}})
		return found(err)
	},
	"ListFindings": func(ctx context.Context, st *store.Store, sc store.Scope, _ scopeFixture) (bool, error) {
		list, err := st.ListFindings(ctx, sc, store.FindingFilter{})
		return len(list) > 0, err
	},
	"Finding": func(ctx context.Context, st *store.Store, sc store.Scope, fx scopeFixture) (bool, error) {
		_, err := st.Finding(ctx, sc, fx.open)
		return found(err)
	},
	"ListFindingEvents": func(ctx context.Context, st *store.Store, sc store.Scope, fx scopeFixture) (bool, error) {
		events, err := st.ListFindingEvents(ctx, sc, fx.closed)
		return len(events) > 0, err
	},
	"SetFindingStatus": func(ctx context.Context, st *store.Store, sc store.Scope, fx scopeFixture) (bool, error) {
		return found(st.SetFindingStatus(ctx, sc, fx.open, 0, "exploitable", "", ""))
	},
	"SetFindingStatuses": func(ctx context.Context, st *store.Store, sc store.Scope, fx scopeFixture) (bool, error) {
		n, err := st.SetFindingStatuses(ctx, sc, 0, []store.StatusChange{{ID: fx.open, Status: "exploitable"}, {ID: fx.closed, Status: "exploitable"}})
		return n > 0, err
	},
	"CountFindingsByStatus": func(ctx context.Context, st *store.Store, sc store.Scope, _ scopeFixture) (bool, error) {
		counts, err := st.CountFindingsByStatus(ctx, sc)
		return len(counts) > 0, err
	},
	"DashboardStats": func(ctx context.Context, st *store.Store, sc store.Scope, _ scopeFixture) (bool, error) {
		s, err := st.DashboardStats(ctx, sc, time.Now())
		weeks := 0
		for _, w := range s.Weeks {
			weeks += w.New + w.Closed
		}
		// Each figure that depends on the inventory, so that zero means none of them leaked.
		return s.Open+s.Closed90+s.Concerning30+len(s.TopAssets)+weeks > 0, err
	},
	"AssetLoads": func(ctx context.Context, st *store.Store, sc store.Scope, _ scopeFixture) (bool, error) {
		loads, err := st.AssetLoads(ctx, sc)
		return len(loads) > 0, err
	},
	"PendingAlerts": func(ctx context.Context, st *store.Store, sc store.Scope, _ scopeFixture) (bool, error) {
		alerts, err := st.PendingAlerts(ctx, sc)
		return len(alerts) > 0, err
	},
	"ListDigests": func(ctx context.Context, st *store.Store, sc store.Scope, _ scopeFixture) (bool, error) {
		list, err := st.ListDigests(ctx, sc)
		return len(list) > 0, err
	},
	"Digest": func(ctx context.Context, st *store.Store, sc store.Scope, fx scopeFixture) (bool, error) {
		_, err := st.Digest(ctx, sc, fx.digest)
		return found(err)
	},
	"ListFoldedInto": func(ctx context.Context, st *store.Store, sc store.Scope, fx scopeFixture) (bool, error) {
		list, err := st.ListFoldedInto(ctx, sc, fx.open)
		return len(list) > 0, err
	},
	"ListNotices": func(ctx context.Context, st *store.Store, sc store.Scope, fx scopeFixture) (bool, error) {
		list, err := st.ListNotices(ctx, sc, fx.asset, []string{"CVE-2026-0001"})
		if errors.Is(err, store.ErrNotFound) {
			return false, nil
		}
		return len(list) > 0, err
	},
	"ListDismissalRules": func(ctx context.Context, st *store.Store, sc store.Scope, fx scopeFixture) (bool, error) {
		rules, err := st.ListDismissalRules(ctx, sc, fx.asset)
		return len(rules) > 0, err
	},
	"CreateDismissalRule": func(ctx context.Context, st *store.Store, sc store.Scope, fx scopeFixture) (bool, error) {
		return found(st.CreateDismissalRule(ctx, sc, fx.asset, "another text"))
	},
	"DeleteDismissalRule": func(ctx context.Context, st *store.Store, sc store.Scope, fx scopeFixture) (bool, error) {
		return found(st.DeleteDismissalRule(ctx, sc, fx.asset, fx.rule))
	},
	"CountCTIItems": func(ctx context.Context, st *store.Store, sc store.Scope, _ scopeFixture) (bool, error) {
		// News are shared; only those concerning the inventory depend on the scope.
		n, err := st.CountCTIItems(ctx, sc, store.CTIFilter{Concerning: true})
		return n > 0, err
	},
	"ListCTIItems": func(ctx context.Context, st *store.Store, sc store.Scope, _ scopeFixture) (bool, error) {
		// News are shared; only the mark "concerns the inventory" depends on the scope.
		items, err := st.ListCTIItems(ctx, sc, store.CTIFilter{})
		concerning, err2 := st.ListCTIItems(ctx, sc, store.CTIFilter{Concerning: true})
		reached := len(concerning) > 0
		for _, it := range items {
			reached = reached || len(it.Concerns) > 0
		}
		return reached, errors.Join(err, err2)
	},
	"ListGroups": func(ctx context.Context, st *store.Store, sc store.Scope, fx scopeFixture) (bool, error) {
		// The names of the groups of a scope are its own: a group reaches the
		// fixture when it is the fixture's, or covers some of its assets.
		list, err := st.ListGroups(ctx, sc)
		reached := false
		for _, g := range list {
			reached = reached || g.ID == fx.group || g.Assets > 0
		}
		return reached, err
	},
	"Group": func(ctx context.Context, st *store.Store, sc store.Scope, fx scopeFixture) (bool, error) {
		_, err := st.Group(ctx, sc, fx.group)
		return found(err)
	},
	"ListAssetGroups": func(ctx context.Context, st *store.Store, sc store.Scope, fx scopeFixture) (bool, error) {
		list, err := st.ListAssetGroups(ctx, sc, fx.asset)
		return len(list) > 0, err
	},
	"UngroupedAssets": func(ctx context.Context, st *store.Store, sc store.Scope, _ scopeFixture) (bool, error) {
		n, err := st.UngroupedAssets(ctx, sc) // the components of the SBOM, in no group
		return n > 0, err
	},
}

// unscoped lists the methods that take no scope, with the reason. Those of the
// synchronisation (storetest.SystemMethods) must not be called by
// internal/web (see its scope tests).
var unscoped = maps.Clone(storetest.SystemMethods)

func init() {
	for reason, names := range map[string][]string{
		"accounts, sessions and the audit log: the caller's own data or the administration's": {
			"CountUsers", "CreateUser", "UserByName", "CreateSession", "Session", "DeleteSession",
			"DeleteOtherSessions", "DeleteExpiredSessions", "Audit", "SetPassword", "ListAudit", "PurgeAudit",
			"ListUsers", "User", "AnyUserByName", "CreateFirstAdmin", "SetRole", "SetDisabled",
			"ResetPassword", "ResetTOTP", "ResetAllTOTP", "TOTPPolicy", "SetTOTPPolicy", "UserTOTP",
			"SetTOTPPending", "EnableTOTP", "DisableTOTP", "ResetTOTPByName", "UseTOTPStep", "SetUserAccess"},
		"groups: definitions managed by administrators, which read no asset": {
			"CreateGroup", "RenameGroup", "SetGroupRules", "DeleteGroup"},
		"threat-intelligence watch: public news and shared settings": {
			"ListFeeds", "Feed", "CreateFeed", "SetFeedEnabled", "DeleteFeed", "RecordFeedFetch", "InsertCTIItem",
			"ListMentions", "PurgeCTIItems", "Setting", "SetSetting", "UpdateFeedTags", "ListFeedItems", "SetCTIItemTags"},
		"shared settings, channels and API tokens, managed by administrators": {
			"SLA", "SetSLA", "ListWebhooks", "Webhook", "CreateWebhook", "DeleteWebhook", "RecordWebhookResult",
			"SetWebhookDelivery", "SetWebhookEnabled", "ListAPITokens", "CreateAPIToken", "APITokenByHash", "DeleteAPIToken"},
		"advisories: read for a finding of the scope or by the synchronisation, never with an identifier taken from the request": {
			"Vulnerability"},
		"the database itself": {"Close", "SchemaVersion", "UpgradeBackup", "BackupTo", "InTx"},
	} {
		for _, name := range names {
			unscoped[name] = reason
		}
	}
}

// A method added to the store is either scoped and covered by an isolation
// case, or exempt for a stated reason: none can escape the check unnoticed.
func TestEveryStoreMethodIsScopedOrExempt(t *testing.T) {
	scope, typ := reflect.TypeOf(store.Scope{}), reflect.TypeOf(&store.Store{})
	methods := map[string]bool{}
	for i := range typ.NumMethod() {
		m := typ.Method(i)
		methods[m.Name] = true
		scoped := false
		for j := 1; j < m.Type.NumIn(); j++ {
			scoped = scoped || m.Type.In(j) == scope
		}
		_, covered := isolationCases[m.Name]
		_, exempt := unscoped[m.Name]
		switch {
		case scoped && !covered:
			t.Errorf("%s takes a Scope but has no isolation case", m.Name)
		case scoped && exempt:
			t.Errorf("%s takes a Scope but is listed as unscoped", m.Name)
		case !scoped && !exempt:
			t.Errorf("%s takes no Scope: give it one, or list it in unscoped with the reason", m.Name)
		}
	}
	for name := range isolationCases {
		if !methods[name] {
			t.Errorf("isolation case %s: no such method", name)
		}
	}
	for name := range unscoped {
		if !methods[name] {
			t.Errorf("unscoped %s: no such method", name)
		}
	}
}

// The zero scope reaches nothing and changes nothing (T8), nor does the scope
// of a group that takes in none of the fixture (A68), whatever the method;
// Everything reaches the fixture.
func TestScopeIsolation(t *testing.T) {
	ctx := context.Background()
	for name, run := range isolationCases {
		t.Run(name, func(t *testing.T) {
			st, fx := newScopeFixture(t)
			before := storetest.Snapshot(t, store.DB(st))
			for label, sc := range map[string]store.Scope{"zero scope": {}, "other group": store.InGroups(fx.other)} {
				reached, err := run(ctx, st, sc, fx)
				if err != nil {
					t.Fatalf("%s: %v", label, err)
				}
				if reached {
					t.Errorf("%s reached the fixture", label)
				}
				if !reflect.DeepEqual(storetest.Snapshot(t, store.DB(st)), before) {
					t.Errorf("%s changed the database", label)
				}
			}
			if reached, err := run(ctx, st, store.Everything, fx); err != nil || !reached {
				t.Errorf("Everything: reached %v, %v", reached, err)
			}
		})
	}
}

// T6: a restricted account makes an asset enter only its groups, leave only
// its groups, and stay in one of them unless it deletes it: whatever the way
// (creation, change, deletion, several at once, SBOM), a write that would
// break it is refused, says why, and changes nothing.
func TestRestrictedWrites(t *testing.T) {
	ctx := context.Background()
	st := storetest.Open(t)
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
	asset := func(name string, project string, tags ...string) store.Asset {
		return store.Asset{Name: name, Kind: "package", Criticality: "low", Source: "manual", Project: project, Tags: tags}
	}
	mine, err := st.CreateAsset(ctx, store.Everything, asset("mine", "", "equipe-a"))
	if err != nil {
		t.Fatal(err)
	}
	shared, err := st.CreateAsset(ctx, store.Everything, asset("shared", "", "equipe-a", "equipe-b"))
	if err != nil {
		t.Fatal(err)
	}
	sc := store.InGroups(a)
	refused := func(label string, err error, want store.OutsideGroupsError) {
		t.Helper()
		var e *store.OutsideGroupsError
		if !errors.As(err, &e) || !errors.Is(err, store.ErrOutsideGroups) {
			t.Errorf("%s: %v, want refused", label, err)
			return
		}
		if !reflect.DeepEqual(*e, want) {
			t.Errorf("%s: %+v, want %+v", label, *e, want)
		}
	}
	update := func(id int64, project string, tags ...string) error {
		a, err := st.Asset(ctx, store.Everything, id)
		if err != nil {
			t.Fatal(err)
		}
		a.Project, a.Tags = project, tags
		return st.UpdateAsset(ctx, sc, a)
	}
	before := storetest.Snapshot(t, store.DB(st))
	suggest := store.OutsideGroupsError{Tags: []string{"equipe-a"}, Projects: []string{"boutique"}}
	_, err = st.CreateAsset(ctx, sc, asset("nowhere", ""))
	refused("created in no group", err, store.OutsideGroupsError{Asset: "nowhere", Tags: suggest.Tags, Projects: suggest.Projects})
	_, err = st.CreateAsset(ctx, sc, asset("also B", "", "equipe-a", "equipe-b"))
	refused("created in B too", err, store.OutsideGroupsError{Asset: "also B", ForeignTags: []string{"equipe-b"}})
	_, err = st.CreateAssets(ctx, sc, []store.Asset{asset("fine", "boutique"), asset("erp", "erp")})
	refused("one of several in B", err, store.OutsideGroupsError{Asset: "erp", ForeignProjects: []string{"erp"},
		Tags: suggest.Tags, Projects: suggest.Projects})
	refused("B added", update(mine, "", "equipe-a", "equipe-b"), store.OutsideGroupsError{Asset: "mine", ForeignTags: []string{"equipe-b"}})
	refused("B removed", update(shared, "", "equipe-a"), store.OutsideGroupsError{Asset: "shared", ForeignTags: []string{"equipe-b"}})
	refused("A removed", update(mine, ""), store.OutsideGroupsError{Asset: "mine", Tags: suggest.Tags, Projects: suggest.Projects})
	refused("shared deleted", st.DeleteAsset(ctx, sc, shared), store.OutsideGroupsError{Asset: "shared", Deleting: true,
		ForeignTags: []string{"equipe-b"}})
	for _, project := range []string{"erp", "partage", "inconnu"} {
		_, err := st.ReplaceProjectAssets(ctx, sc, project, []store.Asset{{Name: "c", Kind: "package", PURL: "pkg:npm/c@1"}})
		if !errors.Is(err, store.ErrOutsideGroups) {
			t.Errorf("SBOM of the project %s: %v", project, err)
		}
	}
	if !reflect.DeepEqual(storetest.Snapshot(t, store.DB(st)), before) {
		t.Fatal("a refused write changed the database")
	}

	// Within its groups, it writes as anyone.
	if err := update(mine, "boutique"); err != nil {
		t.Errorf("tag of A replaced by a project of A: %v", err)
	}
	if err := update(shared, "", "equipe-a", "equipe-b", "prod"); err != nil {
		t.Errorf("a tag of no group added to a shared asset: %v", err)
	}
	if _, err := st.CreateAssets(ctx, sc, []store.Asset{asset("fine", "boutique"), asset("fine too", "", "equipe-a")}); err != nil {
		t.Errorf("created in A: %v", err)
	}
	if _, err := st.ReplaceProjectAssets(ctx, sc, "boutique", []store.Asset{{Name: "c", Kind: "package", PURL: "pkg:npm/c@1"}}); err != nil {
		t.Errorf("SBOM of a project of A: %v", err)
	}
	if err := st.DeleteAsset(ctx, sc, mine); err != nil {
		t.Errorf("an asset of A alone deleted: %v", err)
	}
	if err := st.DeleteAsset(ctx, store.Everything, shared); err != nil {
		t.Errorf("deleted by an account that sees everything: %v", err)
	}
}
