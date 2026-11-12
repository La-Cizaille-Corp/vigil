package store

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
)

// LikelyEPSS is the EPSS probability from which exploitation is considered
// likely (A15). It is written only here: the queries below are built from it,
// and Go code compares with it.
const LikelyEPSS = 0.1

// Alert classes, from the least to the most urgent. A finding is notified
// once when it reaches a class, and again only if it rises to a higher one.
// They are the levels of tracking.Level too (A60).
const (
	AlertNone     = 0
	AlertSevere   = 1 // critical or high severity, or a CVSS score of 7 or more
	AlertPriority = 2 // exploited (CISA KEV), likely to be (EPSS >= LikelyEPSS) or judged exploitable (A78)
)

// The urgency rules on the finding aliased f of the vulnerability aliased v
// (A78), built once from LikelyEPSS.
var (
	// exploitedExpr tells whether v is exploited (CISA KEV) or likely to be.
	exploitedExpr = `(v.kev = 1 OR v.epss >= ` + strconv.FormatFloat(LikelyEPSS, 'f', -1, 64) + `)`
	// urgentExpr tells whether f comes first: its vulnerability is exploited
	// or likely to be, or a user judged it exploitable, which ranks with an
	// exploited one.
	urgentExpr = `(f.status = 'exploitable' OR ` + exploitedExpr + `)`
	// alertClassExpr is the alert class of f (Finding.Class). Migration 009
	// filled in the classes already notified with this rule, the status aside.
	alertClassExpr = `CASE
		WHEN ` + urgentExpr + ` THEN 2
		WHEN v.severity IN ('CRITICAL', 'HIGH') OR v.cvss >= 7 THEN 1
		ELSE 0 END`
)

// Alert is an open finding more urgent than what was already notified, at
// its class (Finding.Class).
type Alert struct {
	Finding
	Raised bool // notified before at a lower class: it became more urgent
}

// PendingAlerts returns the open findings of the scope not notified at their
// current class, most urgent first.
func (s *Store) PendingAlerts(ctx context.Context, sc Scope) ([]Alert, error) {
	sla, err := s.SLA(ctx)
	if err != nil {
		return nil, err
	}
	cond, args := sc.cond("a")
	// #nosec G202 -- cond is a fixed expression of Scope.cond; the values are parameters.
	rows, err := s.db.QueryContext(ctx, `SELECT `+findingColumns+`, f.alerted`+findingFrom+`
		WHERE f.status IN `+openStatuses+` AND `+alertClassExpr+` > f.alerted AND `+cond+`
		ORDER BY alert_class DESC, v.cvss DESC, f.id`, append(sla.args(), args...)...)
	if err != nil {
		return nil, fmt.Errorf("pending alerts: %w", err)
	}
	defer rows.Close()
	var out []Alert
	for rows.Next() {
		var a Alert
		var alerted int
		if a.Finding, err = scanFinding(rows, &alerted); err != nil {
			return nil, fmt.Errorf("pending alerts: %w", err)
		}
		a.Raised = alerted > AlertNone
		out = append(out, a)
	}
	return out, rows.Err()
}

// MarkAlerted records that the given alerts were notified.
func (s *Store) MarkAlerted(ctx context.Context, alerts []Alert) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		for _, a := range alerts {
			if _, err := tx.ExecContext(ctx,
				`UPDATE findings SET alerted = MAX(alerted, ?) WHERE id = ?`, a.Class, a.ID); err != nil {
				return fmt.Errorf("mark alerted: %w", err)
			}
		}
		return nil
	})
}
