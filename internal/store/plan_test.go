package store

import (
	"context"
	"strings"
	"testing"
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
