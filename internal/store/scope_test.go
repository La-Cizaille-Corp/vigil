package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"
)

// scopeFixture is a small inventory reached by every scoped method: a manual
// asset with an open finding cited by a news item and a closed one, a dismissal
// rule, a component kept by an SBOM and another one retired from it, a digest,
// a group taking in the manual asset, and another group taking in nothing.
type scopeFixture struct {
	asset, open, closed, rule, digest, group, other int64
	folded                                          int64 // a second advisory of the open finding's CVE, folded into it
}

func newScopeFixture(t *testing.T) (*Store, scopeFixture) {
	t.Helper()
	ctx := context.Background()
	st := openTest(t)
	var fx scopeFixture
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	var err error
	fx.asset, err = st.CreateAsset(ctx, Everything, Asset{Name: "canari", Kind: "package", Criticality: "high",
		Source: "manual", Project: "app", Tags: []string{"equipe"}})
	must(err)
	_, err = st.ReplaceProjectAssets(ctx, Everything, "sbom", []Asset{
		{Name: "kept", Kind: "package", PURL: "pkg:npm/kept@1"}, {Name: "gone", Kind: "package", PURL: "pkg:npm/gone@1"}})
	must(err)
	_, err = st.ReplaceProjectAssets(ctx, Everything, "sbom", []Asset{{Name: "kept", Kind: "package", PURL: "pkg:npm/kept@1"}})
	must(err)

	seen := time.Now()
	for _, v := range []Vulnerability{
		{ID: "CVE-2026-0001", Severity: "CRITICAL", Summary: "open one", EPSS: -1, CVSS: 9.8},
		{ID: "CVE-2026-0002", Severity: "HIGH", Summary: "closed one", EPSS: -1, CVSS: 7.5},
	} {
		must(st.UpsertVulnerability(ctx, v))
		_, err = st.ObserveFinding(ctx, fx.asset, v.ID, "", seen)
		must(err)
	}
	list, err := st.ListFindings(ctx, Everything, FindingFilter{AssetID: fx.asset})
	must(err)
	for _, f := range list {
		if f.VulnID == "CVE-2026-0001" {
			fx.open = f.ID
		} else {
			fx.closed = f.ID
		}
	}
	must(st.SetFindingStatus(ctx, Everything, fx.closed, 0, "resolved", "", "corrigée"))
	must(st.UpsertVulnerability(ctx, Vulnerability{ID: "GHSA-0001", Aliases: []string{"CVE-2026-0001"}, EPSS: -1, CVSS: -1}))
	_, err = st.ObserveFinding(ctx, fx.asset, "GHSA-0001", "", seen)
	must(err)
	triage, err := st.ListFindingTriage(ctx, fx.asset)
	must(err)
	for _, f := range triage {
		if f.VulnID == "GHSA-0001" {
			fx.folded = f.ID
		}
	}
	must(st.FoldFindings(ctx, Fold{ID: fx.folded, Into: fx.open, Why: "même CVE"}))
	must(st.CreateDismissalRule(ctx, Everything, fx.asset, "matches nothing"))
	rules, err := st.ListDismissalRules(ctx, Everything, fx.asset)
	must(err)
	fx.rule = rules[0].ID

	fx.digest, err = st.CreateDigest(ctx, Digest{Since: seen.Add(-time.Hour), CreatedAt: seen, Markdown: "canari", HTML: "canari"})
	must(err)
	feed, err := st.CreateFeed(ctx, Feed{Name: "Avis", URL: "https://example.org/feed"})
	must(err)
	_, err = st.InsertCTIItem(ctx, feed, CTIItem{GUID: "1", Title: "Avis CVE-2026-0001", Link: "https://example.org/1", Published: seen})
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
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrOutsideGroups) {
		return false, nil
	}
	return err == nil, err
}

// isolationCases call each scoped method on the fixture and report whether it
// reached it: returned it, counted it or changed it. A method that takes a
// Scope must have a case here (TestEveryStoreMethodIsScopedOrExempt).
var isolationCases = map[string]func(context.Context, *Store, Scope, scopeFixture) (bool, error){
	"Asset": func(ctx context.Context, st *Store, sc Scope, fx scopeFixture) (bool, error) {
		_, err := st.Asset(ctx, sc, fx.asset)
		return found(err)
	},
	"ListAssets": func(ctx context.Context, st *Store, sc Scope, _ scopeFixture) (bool, error) {
		list, err := st.ListAssets(ctx, sc)
		return len(list) > 0, err
	},
	"ListRetiredAssets": func(ctx context.Context, st *Store, sc Scope, _ scopeFixture) (bool, error) {
		list, err := st.ListRetiredAssets(ctx, sc)
		return len(list) > 0, err
	},
	"ListAssetTags": func(ctx context.Context, st *Store, sc Scope, _ scopeFixture) (bool, error) {
		tags, err := st.ListAssetTags(ctx, sc)
		return len(tags) > 0, err
	},
	"ListProjects": func(ctx context.Context, st *Store, sc Scope, _ scopeFixture) (bool, error) {
		list, err := st.ListProjects(ctx, sc)
		return len(list) > 0, err
	},
	"CreateAsset": func(ctx context.Context, st *Store, sc Scope, _ scopeFixture) (bool, error) {
		_, err := st.CreateAsset(ctx, sc, Asset{Name: "new", Kind: "package", Criticality: "low", Source: "manual"})
		return found(err)
	},
	"CreateAssets": func(ctx context.Context, st *Store, sc Scope, _ scopeFixture) (bool, error) {
		_, err := st.CreateAssets(ctx, sc, []Asset{{Name: "new", Kind: "package", Criticality: "low", Source: "manual"}})
		return found(err)
	},
	"UpdateAsset": func(ctx context.Context, st *Store, sc Scope, fx scopeFixture) (bool, error) {
		return found(st.UpdateAsset(ctx, sc, Asset{ID: fx.asset, Name: "renamed", Kind: "package", Criticality: "low"}))
	},
	"DeleteAsset": func(ctx context.Context, st *Store, sc Scope, fx scopeFixture) (bool, error) {
		return found(st.DeleteAsset(ctx, sc, fx.asset))
	},
	"ReplaceProjectAssets": func(ctx context.Context, st *Store, sc Scope, _ scopeFixture) (bool, error) {
		_, err := st.ReplaceProjectAssets(ctx, sc, "sbom", []Asset{{Name: "other", Kind: "package", PURL: "pkg:npm/other@1"}})
		return found(err)
	},
	"ListFindings": func(ctx context.Context, st *Store, sc Scope, _ scopeFixture) (bool, error) {
		list, err := st.ListFindings(ctx, sc, FindingFilter{})
		return len(list) > 0, err
	},
	"Finding": func(ctx context.Context, st *Store, sc Scope, fx scopeFixture) (bool, error) {
		_, err := st.Finding(ctx, sc, fx.open)
		return found(err)
	},
	"ListFindingEvents": func(ctx context.Context, st *Store, sc Scope, fx scopeFixture) (bool, error) {
		events, err := st.ListFindingEvents(ctx, sc, fx.closed)
		return len(events) > 0, err
	},
	"SetFindingStatus": func(ctx context.Context, st *Store, sc Scope, fx scopeFixture) (bool, error) {
		return found(st.SetFindingStatus(ctx, sc, fx.open, 0, "exploitable", "", ""))
	},
	"SetFindingStatuses": func(ctx context.Context, st *Store, sc Scope, fx scopeFixture) (bool, error) {
		n, err := st.SetFindingStatuses(ctx, sc, 0, []StatusChange{{ID: fx.open, Status: "exploitable"}, {ID: fx.closed, Status: "exploitable"}})
		return n > 0, err
	},
	"CountFindingsByStatus": func(ctx context.Context, st *Store, sc Scope, _ scopeFixture) (bool, error) {
		counts, err := st.CountFindingsByStatus(ctx, sc)
		return len(counts) > 0, err
	},
	"DashboardStats": func(ctx context.Context, st *Store, sc Scope, _ scopeFixture) (bool, error) {
		s, err := st.DashboardStats(ctx, sc, time.Now())
		weeks := 0
		for _, w := range s.Weeks {
			weeks += w.New + w.Closed
		}
		// Each figure that depends on the inventory, so that zero means none of them leaked.
		return s.Open+s.Closed90+s.Concerning30+len(s.TopAssets)+weeks > 0, err
	},
	"AssetLoads": func(ctx context.Context, st *Store, sc Scope, _ scopeFixture) (bool, error) {
		loads, err := st.AssetLoads(ctx, sc)
		return len(loads) > 0, err
	},
	"PendingAlerts": func(ctx context.Context, st *Store, sc Scope, _ scopeFixture) (bool, error) {
		alerts, err := st.PendingAlerts(ctx, sc)
		return len(alerts) > 0, err
	},
	"ListDigests": func(ctx context.Context, st *Store, sc Scope, _ scopeFixture) (bool, error) {
		list, err := st.ListDigests(ctx, sc)
		return len(list) > 0, err
	},
	"Digest": func(ctx context.Context, st *Store, sc Scope, fx scopeFixture) (bool, error) {
		_, err := st.Digest(ctx, sc, fx.digest)
		return found(err)
	},
	"ListFoldedInto": func(ctx context.Context, st *Store, sc Scope, fx scopeFixture) (bool, error) {
		list, err := st.ListFoldedInto(ctx, sc, fx.open)
		return len(list) > 0, err
	},
	"ListNotices": func(ctx context.Context, st *Store, sc Scope, fx scopeFixture) (bool, error) {
		list, err := st.ListNotices(ctx, sc, fx.asset, []string{"CVE-2026-0001"})
		if errors.Is(err, ErrNotFound) {
			return false, nil
		}
		return len(list) > 0, err
	},
	"ListDismissalRules": func(ctx context.Context, st *Store, sc Scope, fx scopeFixture) (bool, error) {
		rules, err := st.ListDismissalRules(ctx, sc, fx.asset)
		return len(rules) > 0, err
	},
	"CreateDismissalRule": func(ctx context.Context, st *Store, sc Scope, fx scopeFixture) (bool, error) {
		return found(st.CreateDismissalRule(ctx, sc, fx.asset, "another text"))
	},
	"DeleteDismissalRule": func(ctx context.Context, st *Store, sc Scope, fx scopeFixture) (bool, error) {
		return found(st.DeleteDismissalRule(ctx, sc, fx.asset, fx.rule))
	},
	"CountCTIItems": func(ctx context.Context, st *Store, sc Scope, _ scopeFixture) (bool, error) {
		// News are shared; only those concerning the inventory depend on the scope.
		n, err := st.CountCTIItems(ctx, sc, CTIFilter{Concerning: true})
		return n > 0, err
	},
	"ListCTIItems": func(ctx context.Context, st *Store, sc Scope, _ scopeFixture) (bool, error) {
		// News are shared; only the mark "concerns the inventory" depends on the scope.
		items, err := st.ListCTIItems(ctx, sc, CTIFilter{})
		concerning, err2 := st.ListCTIItems(ctx, sc, CTIFilter{Concerning: true})
		reached := len(concerning) > 0
		for _, it := range items {
			reached = reached || len(it.Concerns) > 0
		}
		return reached, errors.Join(err, err2)
	},
	"ListGroups": func(ctx context.Context, st *Store, sc Scope, fx scopeFixture) (bool, error) {
		// The names of the groups of a scope are its own: a group reaches the
		// fixture when it is the fixture's, or covers some of its assets.
		list, err := st.ListGroups(ctx, sc)
		reached := false
		for _, g := range list {
			reached = reached || g.ID == fx.group || g.Assets > 0
		}
		return reached, err
	},
	"Group": func(ctx context.Context, st *Store, sc Scope, fx scopeFixture) (bool, error) {
		_, err := st.Group(ctx, sc, fx.group)
		return found(err)
	},
	"ListAssetGroups": func(ctx context.Context, st *Store, sc Scope, fx scopeFixture) (bool, error) {
		list, err := st.ListAssetGroups(ctx, sc, fx.asset)
		return len(list) > 0, err
	},
	"UngroupedAssets": func(ctx context.Context, st *Store, sc Scope, _ scopeFixture) (bool, error) {
		n, err := st.UngroupedAssets(ctx, sc) // the components of the SBOM, in no group
		return n > 0, err
	},
}

// unscoped lists the methods that take no scope, with the reason. Those of the
// synchronisation must not be called by internal/web (see its scope tests).
var unscoped = map[string]string{}

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
		"advisories: public data, the same for everyone": {"Vulnerability"},
		"synchronisation, notifications and digest generation only": {
			"ObserveFinding", "InTrackedPeriod", "AutoResolveStale", "SetOlderVulns", "ApplyDismissalRules",
			"ListFindingTriage", "FoldFindings",
			"UpsertVulnerability", "VulnModified", "SetExploitSignals", "ListVulnCVEs", "MarkAlerted",
			"CreateDigest", "LastDigestTime"},
		"advisories OSV reports for a package version, shared by the assets that ask it, for the synchronisation only": {
			"OSVList", "SaveOSVList", "PurgeOSVLists"},
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
	scope, typ := reflect.TypeOf(Scope{}), reflect.TypeOf(&Store{})
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
			before := fingerprint(t, st)
			for label, sc := range map[string]Scope{"zero scope": {}, "other group": InGroups(fx.other)} {
				reached, err := run(ctx, st, sc, fx)
				if err != nil {
					t.Fatalf("%s: %v", label, err)
				}
				if reached {
					t.Errorf("%s reached the fixture", label)
				}
				if fingerprint(t, st) != before {
					t.Errorf("%s changed the database", label)
				}
			}
			if reached, err := run(ctx, st, Everything, fx); err != nil || !reached {
				t.Errorf("Everything: reached %v, %v", reached, err)
			}
		})
	}
}

// fingerprint hashes every row of every table, to tell whether a call changed
// anything.
func fingerprint(t *testing.T, st *Store) string {
	t.Helper()
	ctx := context.Background()
	rows, err := st.db.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, name)
	}
	rows.Close()
	h := sha256.New()
	for _, table := range tables {
		rows, err := st.db.QueryContext(ctx, `SELECT * FROM "`+table+`" ORDER BY rowid`)
		if err != nil {
			t.Fatal(err)
		}
		cols, _ := rows.Columns()
		for rows.Next() {
			values := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range values {
				ptrs[i] = &values[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				t.Fatal(err)
			}
			fmt.Fprintf(h, "%s%v\n", table, values)
		}
		rows.Close()
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}
