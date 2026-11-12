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
	all bool
}

// Everything is the scope of the system (synchronisation, notifications,
// command line) and of the accounts that see every asset.
var Everything = Scope{all: true}

// ErrOutsideGroups is returned when a write would place an asset outside the
// caller's scope.
var ErrOutsideGroups = errors.New("asset outside the caller's groups")

// cond returns the SQL condition, and its arguments, that keeps the asset
// aliased alias (a constant of the query) inside the scope. The conditions on
// groups will apply to the columns of that alias.
func (sc Scope) cond(alias string) (string, []any) {
	if sc.all {
		return "1", nil
	}
	return "0", nil
}

// digestCond keeps the digests of the scope. Every digest covers the whole
// inventory so far: only Everything sees them.
func (sc Scope) digestCond() string {
	if sc.all {
		return "1"
	}
	return "0"
}

// writable reports whether the scope may add assets: a new asset must land
// inside it.
func (sc Scope) writable() error {
	if sc.all {
		return nil
	}
	return ErrOutsideGroups
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
		WHERE f.status IN ` + openStatuses + ` AND v.id LIKE 'CVE-%' AND ` + cond + `
		UNION
		SELECT j.value FROM findings f JOIN vulnerabilities v ON v.id = f.vuln_id JOIN assets a ON a.id = f.asset_id,
		       json_each(v.aliases) j
		WHERE f.status IN ` + openStatuses + ` AND j.value LIKE 'CVE-%' AND ` + cond + `)
	`, append(slices.Clone(args), args...)
}
