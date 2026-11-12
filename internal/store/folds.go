package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// One finding per CVE (A80). A source can report one vulnerability of an
// asset under several advisories: the advisory of the CVE and a grouped one
// that lists it with hundreds of others (an Ubuntu USN, a Debian DSA), or two
// databases for the same flaw (GHSA and GO). The synchronisation keeps one
// finding per CVE and folds the others into it (findings.folded_into): they
// leave every list and count (shownExpr) and keep their triage and history.

// FoldedNotice is the folded_into of a grouped advisory, shown through the
// findings of its CVEs.
const FoldedNotice = -1

// FindingTriage is a finding as the synchronisation weighs it before folding:
// its state, and the last decision a user made on it.
type FindingTriage struct {
	ID         int64
	VulnID     string
	Status     string
	FoldedInto int64
	// The last decision of a user, if any: the event (0 for none, a later
	// decision has a greater one), the status chosen, by whom, when.
	Decision      int64
	DecidedStatus string
	DecidedBy     string
	DecidedAt     time.Time
}

// Decided reports whether a user decided on the finding.
func (f FindingTriage) Decided() bool { return f.Decision != 0 }

// lastDecision joins, to the finding aliased f, the last event of its history
// made by a user (e, through the index finding_events_finding) and its author
// (u).
const lastDecision = `
	LEFT JOIN finding_events e ON e.id = (SELECT MAX(h.id) FROM finding_events h WHERE h.finding_id = f.id AND h.user_id IS NOT NULL)
	LEFT JOIN users u ON u.id = e.user_id`

// ListFindingTriage returns every finding of an asset, folded or not, with its
// last decision by a user.
func (s *Store) ListFindingTriage(ctx context.Context, assetID int64) ([]FindingTriage, error) {
	return collect(ctx, s.q(ctx), "list finding triage", func(row scanner) (FindingTriage, error) {
		var f FindingTriage
		var at string
		err := row.Scan(&f.ID, &f.VulnID, &f.Status, &f.FoldedInto, &f.Decision, &f.DecidedStatus, &f.DecidedBy, &at)
		f.DecidedAt = parseTime(at)
		return f, err
	}, `
		SELECT f.id, f.vuln_id, f.status, f.folded_into, COALESCE(e.id, 0), COALESCE(e.new_status, ''), COALESCE(u.username, ''), COALESCE(e.created_at, '')
		FROM findings f`+lastDecision+`
		WHERE f.asset_id = ? ORDER BY f.id`, assetID)
}

// Fold folds a finding into others.
type Fold struct {
	ID   int64  // the finding folded
	Into int64  // the finding kept for its CVE, or FoldedNotice
	Why  string // the event added to the history of the finding folded
	// Note, if not empty, is an event added to the history of the finding
	// kept: a decision that differs from its own.
	Note string
}

// FoldFindings folds findings, with an event in their history. A finding
// kept for a CVE takes the earliest detection of those folded into it and the
// highest alert class already notified: the CVE is neither new again nor
// notified twice. A finding already folded is left as it is.
func (s *Store) FoldFindings(ctx context.Context, folds ...Fold) error {
	ts := now()
	return wrap("fold findings", s.inTx(ctx, func(tx *sql.Tx) error {
		for _, fd := range folds {
			var status, first string
			var alerted int
			err := tx.QueryRowContext(ctx, `SELECT f.status, f.first_seen, f.alerted FROM findings f WHERE f.id = ? AND `+shownExpr,
				fd.ID).Scan(&status, &first, &alerted)
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			if err != nil {
				return fmt.Errorf("finding %d: %w", fd.ID, err)
			}
			if _, err := tx.ExecContext(ctx, `UPDATE findings SET folded_into = ?, updated_at = ? WHERE id = ?`, fd.Into, ts, fd.ID); err != nil {
				return fmt.Errorf("finding %d: %w", fd.ID, err)
			}
			if err := insertEvent(ctx, tx, fd.ID, 0, status, status, fd.Why, ts); err != nil {
				return fmt.Errorf("finding %d: %w", fd.ID, err)
			}
			if fd.Into <= 0 {
				continue
			}
			var kept string
			err = tx.QueryRowContext(ctx, `
				UPDATE findings SET alerted = MAX(alerted, ?), first_seen = MIN(first_seen, ?) WHERE id = ? RETURNING status`,
				alerted, first, fd.Into).Scan(&kept)
			if err != nil {
				return fmt.Errorf("finding %d: %w", fd.Into, err)
			}
			if fd.Note != "" {
				if err := insertEvent(ctx, tx, fd.Into, 0, kept, kept, fd.Note, ts); err != nil {
					return fmt.Errorf("finding %d: %w", fd.Into, err)
				}
			}
		}
		return nil
	}))
}

// ListFoldedInto returns the findings of the scope folded into a finding: the
// other advisories of its CVE.
func (s *Store) ListFoldedInto(ctx context.Context, sc Scope, findingID int64) ([]Finding, error) {
	sla, err := s.SLA(ctx)
	if err != nil {
		return nil, err
	}
	cond, args := sc.cond("a")
	today := day(time.Now())
	// #nosec G202 -- cond is a fixed expression of Scope.cond; the values are parameters.
	return collect(ctx, s.q(ctx), "list folded findings", func(row scanner) (Finding, error) {
		return scanFinding(row, today)
	}, findingSelect+` WHERE f.folded_into = ? AND `+cond+` ORDER BY f.id`, append(append(sla.args(), findingID), args...)...)
}

// Notice is a stored advisory that names a CVE, with the finding of an asset
// for it if any: a grouped advisory is shown on the findings of its CVEs.
type Notice struct {
	ID      string
	Aliases []string
	Refs    []string
	Raw     string
	// The asset's finding of the advisory, folded or not; 0 for none.
	FindingID     int64
	Status        string
	DecidedStatus string // the last decision of a user on it, if any
	DecidedBy     string
	DecidedAt     time.Time
}

// ListNotices returns the stored advisories that name one of cves among their
// aliases, with the finding of an asset of the scope for each one; ErrNotFound
// when the asset is outside the scope. The caller tells the grouped ones.
func (s *Store) ListNotices(ctx context.Context, sc Scope, assetID int64, cves []string) ([]Notice, error) {
	if err := assetInScope(ctx, s.q(ctx), sc, assetID); err != nil {
		return nil, err
	}
	if len(cves) == 0 {
		return nil, nil
	}
	where, args := inClause(nil, []any{assetID}, "j.value", cves)
	// #nosec G202 -- where is the fixed expression of inClause; the values are parameters.
	return collect(ctx, s.q(ctx), "list notices", func(row scanner) (Notice, error) {
		var n Notice
		var aliases, refs, at string
		err := row.Scan(&n.ID, &aliases, &refs, &n.Raw, &n.FindingID, &n.Status, &n.DecidedStatus, &n.DecidedBy, &at)
		if err != nil {
			return n, err
		}
		n.DecidedAt = parseTime(at)
		if err := json.Unmarshal([]byte(aliases), &n.Aliases); err != nil {
			return n, fmt.Errorf("decode aliases of %s: %w", n.ID, err)
		}
		if err := json.Unmarshal([]byte(refs), &n.Refs); err != nil {
			return n, fmt.Errorf("decode references of %s: %w", n.ID, err)
		}
		return n, nil
	}, `
		SELECT v.id, v.aliases, v.refs, v.raw, COALESCE(f.id, 0), COALESCE(f.status, ''),
		       COALESCE(e.new_status, ''), COALESCE(u.username, ''), COALESCE(e.created_at, '')
		FROM vulnerabilities v
		LEFT JOIN findings f ON f.vuln_id = v.id AND f.asset_id = ?`+lastDecision+`
		WHERE EXISTS (SELECT 1 FROM json_each(v.aliases) j WHERE `+where[0]+`)
		ORDER BY v.published DESC, v.id`, args...)
}
