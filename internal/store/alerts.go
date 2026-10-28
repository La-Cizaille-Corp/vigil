package store

import (
	"context"
	"database/sql"
	"fmt"
)

// Alert classes, from the least to the most urgent. A finding is notified
// once when it reaches a class, and again only if it rises to a higher one.
const (
	AlertNone     = 0
	AlertSevere   = 1 // critical or high severity
	AlertPriority = 2 // exploited (CISA KEV) or likely to be (EPSS >= 10 %)
)

// alertClassExpr is the alert class of the vulnerability aliased v; it must
// match the backfill of migration 009.
const alertClassExpr = `CASE
		WHEN v.kev = 1 OR v.epss >= 0.1 THEN 2
		WHEN v.severity IN ('CRITICAL', 'HIGH') OR v.cvss >= 7 THEN 1
		ELSE 0 END`

// Alert is an open finding more urgent than what was already notified.
type Alert struct {
	Finding
	Class  int
	Raised bool // notified before at a lower class: it became more urgent
}

// PendingAlerts returns the open findings not notified at their current
// class, most urgent first.
func (s *Store) PendingAlerts(ctx context.Context) ([]Alert, error) {
	sla, err := s.SLA(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+findingColumns+`, `+alertClassExpr+`, f.alerted`+findingFrom+`
		WHERE f.status IN `+openStatuses+` AND `+alertClassExpr+` > f.alerted
		ORDER BY 21 DESC, v.cvss DESC, f.id`, sla.args()...)
	if err != nil {
		return nil, fmt.Errorf("pending alerts: %w", err)
	}
	defer rows.Close()
	var out []Alert
	for rows.Next() {
		var a Alert
		var alerted int
		if a.Finding, err = scanFinding(rows, &a.Class, &alerted); err != nil {
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
