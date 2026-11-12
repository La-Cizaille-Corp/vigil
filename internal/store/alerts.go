package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// Alert classes, from the least to the most urgent. A finding is notified
// once when it reaches a class, and again only if it rises to a higher one.
const (
	alertNone     = 0
	AlertSevere   = 1 // critical or high severity
	AlertPriority = 2 // exploited (CISA KEV) or likely to be (EPSS >= 10 %)
)

// alertClassExpr is the alert class of the vulnerability aliased v; it must
// match the backfill of migration 009, whose comment calls it store.AlertClass.
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

// PendingAlerts returns the open findings of the scope not notified at their
// current class, most urgent first.
func (s *Store) PendingAlerts(ctx context.Context, sc Scope) ([]Alert, error) {
	sla, err := s.SLA(ctx)
	if err != nil {
		return nil, err
	}
	cond, args := sc.cond("a")
	today := day(time.Now())
	// #nosec G202 -- cond is a fixed expression of Scope.cond; the values are parameters.
	return collect(ctx, s.db, "pending alerts", func(row scanner) (Alert, error) {
		var a Alert
		var alerted int
		var err error
		a.Finding, err = scanFinding(row, today, &a.Class, &alerted)
		a.Raised = alerted > alertNone
		return a, err
	}, `SELECT `+findingColumns+`, `+alertClassExpr+` AS alert_class, f.alerted`+findingFrom+`
		WHERE f.status IN `+openStatuses+` AND `+alertClassExpr+` > f.alerted AND `+cond+`
		ORDER BY alert_class DESC, v.cvss DESC, f.id`, append(sla.args(), args...)...)
}

// MarkAlerted records that the given alerts were notified.
func (s *Store) MarkAlerted(ctx context.Context, alerts []Alert) error {
	return wrap("mark alerted", s.inTx(ctx, func(tx *sql.Tx) error {
		for _, a := range alerts {
			if _, err := tx.ExecContext(ctx,
				`UPDATE findings SET alerted = MAX(alerted, ?) WHERE id = ?`, a.Class, a.ID); err != nil {
				return fmt.Errorf("finding %d: %w", a.ID, err)
			}
		}
		return nil
	}))
}
