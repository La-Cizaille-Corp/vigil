package store

import (
	"context"
	"database/sql"
	"errors"
	"slices"
)

// Scope is the part of the inventory a caller may see and change (A67). Every
// method reading or writing an asset, or what depends on one (finding, its
// history, dismissal rule, digest, dashboard figure, alert), takes one. The
// zero value covers nothing: a forgotten scope shows an empty page, never the
// assets of somebody else.
//
// SECURITY: access to objects is checked here, inside every query, rather
// than by each page: lists, counters and identifiers posted in a form or a
// file all go through the same condition.
type Scope struct {
	all    bool
	groups []int64
}

// Everything is the scope of the system (synchronisation, notifications,
// command line) and of the accounts that see every asset.
var Everything = Scope{all: true}

// InGroups is the scope of a restricted account (A68): the assets of the
// groups given, none without a group.
func InGroups(ids ...int64) Scope { return Scope{groups: slices.Clone(ids)} }

// Only narrows the scope to one of its groups, for a list filtered by group.
// It never widens it: a group the scope does not hold gives nothing.
func (sc Scope) Only(group int64) Scope {
	if sc.all || slices.Contains(sc.groups, group) {
		return InGroups(group)
	}
	return Scope{}
}

// ErrOutsideGroups is returned when a write would place an asset outside the
// caller's scope; an OutsideGroupsError says why.
var ErrOutsideGroups = errors.New("asset outside the caller's groups")

// OutsideGroupsError is a write of a restricted account refused because it
// would move an asset across groups the account does not hold (A68), with
// what the user needs to correct it.
type OutsideGroupsError struct {
	Asset    string // the asset refused, named as given
	Deleting bool
	// ForeignTags and ForeignProjects are the tags and the project of the
	// asset, before or after the write, that place it in groups of other
	// accounts: not to add, nor to remove.
	ForeignTags, ForeignProjects []string
	// Tags and Projects, when it would be in none of the caller's groups,
	// are the values that would put it in one.
	Tags, Projects []string
}

func (e *OutsideGroupsError) Error() string {
	return "asset " + e.Asset + " outside the caller's groups"
}

// Is makes errors.Is(err, ErrOutsideGroups) true.
func (e *OutsideGroupsError) Is(target error) bool { return target == ErrOutsideGroups }

// ruleMatch is the condition "the rule aliased gr takes in the asset aliased
// alias" (a constant of the query): exact values, the tag "web" not taking in
// "webapp", as tags are stored between commas (see joinTags).
func ruleMatch(alias string) string {
	return `(gr.kind = 'project' AND gr.value = ` + alias + `.project
		OR gr.kind = 'tag' AND instr(` + alias + `.tags, ',' || gr.value || ',') > 0)`
}

// cond returns the SQL condition, and its arguments, that keeps the asset
// aliased alias (a constant of the query) inside the scope. The assets of
// the groups are computed once per query, not row by row (A68, measured).
func (sc Scope) cond(alias string) (string, []any) {
	switch {
	case sc.all:
		return "1", nil
	case len(sc.groups) == 0:
		return "0", nil
	}
	where, args := inClause(nil, nil, "gr.group_id", sc.groups)
	return alias + `.id IN (SELECT ga.id FROM assets ga WHERE EXISTS (
		SELECT 1 FROM group_rules gr WHERE ` + where[0] + ` AND ` + ruleMatch("ga") + `))`, args
}

// groupCond returns the condition that keeps a row whose column (a constant
// of the query) names a group inside the scope: every row for Everything,
// those of its groups for a restricted account. On a group's id, it keeps the
// groups of the scope; on the group of a digest (A68), the digests of the
// scope, a digest of the whole inventory (NULL) being for Everything only.
func (sc Scope) groupCond(column string) (string, []any) {
	switch {
	case sc.all:
		return "1", nil
	case len(sc.groups) == 0:
		return "0", nil
	}
	where, args := inClause(nil, nil, column, sc.groups)
	return where[0], args
}

// moves reports what a write moving an asset from the groups before to the
// groups after (nil for a new or a deleted asset) does to the scope (A68): the
// groups it would enter or leave that the scope does not hold, and whether
// the asset stays in one of the scope's groups. A restricted account makes an
// asset enter only its groups, leave only its groups, and stay in one of them
// unless it deletes it; Everything may do anything.
func (sc Scope) moves(before, after []int64, deleting bool) (foreign []int64, stays bool) {
	if sc.all {
		return nil, true
	}
	for _, g := range append(slices.Clone(before), after...) {
		if slices.Contains(before, g) != slices.Contains(after, g) && !slices.Contains(sc.groups, g) && !slices.Contains(foreign, g) {
			foreign = append(foreign, g)
		}
	}
	stays = deleting || slices.ContainsFunc(after, func(g int64) bool { return slices.Contains(sc.groups, g) })
	return foreign, stays
}

// assetInScope returns ErrNotFound when the asset does not exist or is outside
// the scope: the caller cannot tell one from the other.
func assetInScope(ctx context.Context, q querier, sc Scope, id int64) error {
	cond, args := sc.cond("a")
	var one int
	err := q.QueryRowContext(ctx, `SELECT 1 FROM assets a WHERE a.id = ? AND `+cond, append([]any{id}, args...)...).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// openCVEs returns a WITH clause naming open_cves the CVE identifiers (id or
// alias) of the open findings of the scope, with its arguments. Queries put it
// first, so that its arguments come first too.
func openCVEs(sc Scope) (string, []any) {
	cond, args := sc.cond("a")
	return `WITH open_cves(cve) AS (
		SELECT v.id FROM findings f JOIN vulnerabilities v ON v.id = f.vuln_id JOIN assets a ON a.id = f.asset_id
		WHERE f.status IN ` + openStatuses + ` AND ` + shownExpr + ` AND v.id LIKE 'CVE-%' AND ` + cond + `
		UNION
		SELECT j.value FROM findings f JOIN vulnerabilities v ON v.id = f.vuln_id JOIN assets a ON a.id = f.asset_id,
		       json_each(v.aliases) j
		WHERE f.status IN ` + openStatuses + ` AND ` + shownExpr + ` AND j.value LIKE 'CVE-%' AND ` + cond + `)
	`, append(slices.Clone(args), args...)
}
