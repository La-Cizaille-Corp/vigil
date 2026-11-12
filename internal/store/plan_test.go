package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// queryPlan returns the steps of SQLite's plan for a query.
func queryPlan(t *testing.T, st *Store, query string, args []any) []string {
	t.Helper()
	plan, err := collect(context.Background(), st.db, "query plan", func(row scanner) (string, error) {
		var id, parent, unused int
		var detail string
		err := row.Scan(&id, &parent, &unused, &detail)
		return detail, err
	}, "EXPLAIN QUERY PLAN "+query, args...)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

// The history of a finding, read on its page, and the findings a rule sets
// aside, counted for each rule, go through an index (migration 016): none of
// the tables is read whole.
func TestHistoryQueriesUseIndexes(t *testing.T) {
	st := openTest(t)
	for name, query := range map[string]func() (string, []any){
		"ListFindingEvents":  func() (string, []any) { return findingEventsQuery(Everything, 1) },
		"ListDismissalRules": func() (string, []any) { return dismissalRulesQuery(Everything, 1) },
	} {
		q, args := query()
		plan := queryPlan(t, st, q, args)
		for _, step := range plan {
			if strings.HasPrefix(step, "SCAN ") {
				t.Errorf("%s reads a whole table: %s (plan %q)", name, step, plan)
			}
		}
	}
}

// sqliteConn is what the connections of the driver do, and what recorded
// passes on.
type sqliteConn interface {
	driver.Conn
	driver.ConnBeginTx
	driver.ConnPrepareContext
	driver.ExecerContext
	driver.QueryerContext
}

// statement is a statement run by the store, with its arguments.
type statement struct {
	query string
	args  []any
}

// recorded is a connection of the driver that notes the statements run on it.
type recorded struct {
	sqliteConn
	seen *[]statement
}

func (c recorded) note(query string, args []driver.NamedValue) {
	values := make([]any, len(args))
	for i, a := range args {
		values[i] = a.Value
	}
	*c.seen = append(*c.seen, statement{query, values})
}

func (c recorded) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	c.note(query, args)
	return c.sqliteConn.ExecContext(ctx, query, args)
}

func (c recorded) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	c.note(query, args)
	return c.sqliteConn.QueryContext(ctx, query, args)
}

// recorder opens the recorded connections of a database file.
type recorder struct {
	driver driver.Driver
	name   string
	seen   *[]statement
}

func (r recorder) Connect(context.Context) (driver.Conn, error) {
	conn, err := r.driver.Open(r.name)
	if err != nil {
		return nil, err
	}
	return recorded{conn.(sqliteConn), r.seen}, nil
}

func (r recorder) Driver() driver.Driver { return r.driver }

// recordingStore opens the database at path as Open does, but notes every
// statement made with the context of the calls.
func recordingStore(t *testing.T, path string, seen *[]statement) *Store {
	t.Helper()
	plain, err := sql.Open("sqlite", "")
	if err != nil {
		t.Fatal(err)
	}
	name, err := dsn(path, "_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=temp_store(2)")
	if err != nil {
		t.Fatal(err)
	}
	db := sql.OpenDB(recorder{plain.Driver(), name, seen})
	plain.Close()
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	return &Store{db: db}
}

// readsAdvisory matches a step of a plan reading the vulnerabilities aliased v.
var readsAdvisory = regexp.MustCompile(`^(SEARCH|SCAN) v\b`)

// What lists, counts, alerts, the dashboard and the synchronisation read of an
// advisory comes from the index vulnerabilities_listed alone (A91): its record,
// whose stored advisory takes several overflow pages, is never read.
func TestAdvisoriesReadThroughTheirIndex(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "vigil.db")
	setup, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	asset, err := setup.CreateAsset(ctx, Everything, Asset{Name: "linux", Kind: "os", Criticality: "high", Source: "manual", Tags: []string{"web"}})
	if err != nil {
		t.Fatal(err)
	}
	group, err := setup.CreateGroup(ctx, "Web")
	if err != nil {
		t.Fatal(err)
	}
	if err := setup.SetGroupRules(ctx, group, []string{"web"}, nil); err != nil {
		t.Fatal(err)
	}
	for _, v := range []Vulnerability{
		{ID: "CVE-2026-0001", Severity: "CRITICAL", Summary: "wifi: overflow", EPSS: 0.5, CVSS: 9.8, Published: "2026-01-01", Raw: strings.Repeat("x", 20000)},
		{ID: "GHSA-0001", Aliases: []string{"CVE-2026-0001"}, Severity: "HIGH", EPSS: -1, CVSS: 7.5, Raw: strings.Repeat("y", 20000)},
	} {
		if err := setup.UpsertVulnerability(ctx, v); err != nil {
			t.Fatal(err)
		}
		if _, err := setup.ObserveFinding(ctx, asset, v.ID, "", time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	feed, err := setup.CreateFeed(ctx, Feed{Name: "Avis", URL: "https://example.org/feed"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := setup.InsertCTIItem(ctx, feed, CTIItem{GUID: "1", Title: "CVE-2026-0001", Published: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := setup.CreateDismissalRule(ctx, Everything, asset, "bluetooth"); err != nil {
		t.Fatal(err)
	}
	setup.Close()

	var seen []statement
	st := recordingStore(t, path, &seen)
	for name, call := range map[string]func() error{
		"ListFindings": func() error {
			for _, f := range []FindingFilter{{}, {Overdue: true}, {Search: "wifi", MinCVSS: 7, MinEPSS: 0.1, Severities: []string{"CRITICAL"}, KEV: true},
				{AssetID: asset, Matching: "wifi"}, {AssetID: asset, CVEs: []string{"CVE-2026-0001"}}} {
				if _, err := st.ListFindings(ctx, Everything, f); err != nil {
					return err
				}
			}
			_, err := st.ListFindings(ctx, InGroups(group), FindingFilter{})
			return err
		},
		"Finding":         func() error { _, err := st.Finding(ctx, Everything, 1); return err },
		"ListFoldedInto":  func() error { _, err := st.ListFoldedInto(ctx, Everything, 1); return err },
		"PendingAlerts":   func() error { _, err := st.PendingAlerts(ctx, Everything); return err },
		"DashboardStats":  func() error { _, err := st.DashboardStats(ctx, Everything, time.Now()); return err },
		"AssetLoads":      func() error { _, err := st.AssetLoads(ctx, Everything); return err },
		"ListCTIItems":    func() error { _, err := st.ListCTIItems(ctx, Everything, CTIFilter{Concerning: true}); return err },
		"InTrackedPeriod": func() error { _, err := st.InTrackedPeriod(ctx, asset, "GHSA-0001", "2026-06-01"); return err },
		"AutoResolveStale": func() error {
			_, err := st.AutoResolveStale(ctx, asset, []string{"CVE-2026-0001", "GHSA-0001"}, "2026-06-01")
			return err
		},
		"ApplyDismissalRules": func() error { _, err := st.ApplyDismissalRules(ctx); return err },
	} {
		before := len(seen)
		if err := call(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		checked := 0
		for _, s := range seen[before:] {
			if !strings.Contains(s.query, "vulnerabilities v") {
				continue
			}
			plan := queryPlan(t, st, s.query, s.args)
			for _, step := range plan {
				if readsAdvisory.MatchString(step) {
					checked++
					if !strings.Contains(step, "USING COVERING INDEX vulnerabilities_listed") {
						t.Errorf("%s reads the record of an advisory: %s (plan %q)", name, step, plan)
					}
				}
			}
		}
		if checked == 0 {
			t.Errorf("%s: no read of an advisory recorded", name)
		}
	}
}
