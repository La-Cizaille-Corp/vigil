package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// Stats are the indicators of the dashboard. "Open" findings are those still
// to triage or to fix (in_triage, exploitable).
type Stats struct {
	Open           int
	OpenBySeverity map[string]int // CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
	Priority       int            // open and exploited (KEV) or likely to be (EPSS >= 10 %)
	OpenKEV        int
	Overdue        int // open and past the remediation deadline (see SLA)
	OverdueKEV     int // of which exploited
	ToTriage       int
	StaleTriage    int     // to triage for more than StaleAfter
	Closed90       int     // findings closed (fixed or dismissed) in the last 90 days
	MeanDaysToFix  float64 // mean days from detection to closing, over Closed90; -1 without data
	Weeks          []WeekCount
	TopAssets      []AssetLoad
	CTIWeek        int // news collected in the last 7 days
	Regulatory30   int // regulatory news of the last 30 days
	Concerning30   int // news of the last 30 days citing a vulnerability of an open finding
}

// WeekCount is the activity of one week.
type WeekCount struct {
	Start  time.Time
	New    int // findings detected
	Closed int // findings closed
}

// AssetLoad is an asset with its open findings by severity.
type AssetLoad struct {
	ID                            int64
	Name, Version                 string
	Critical, High, Medium, Other int
}

// Total is the number of open findings of the asset.
func (a AssetLoad) Total() int { return a.Critical + a.High + a.Medium + a.Other }

const (
	// StaleAfter is when a finding waiting for triage is reported as late.
	StaleAfter = 30 * 24 * time.Hour
	statsWeeks = 12
	topAssets  = 6
)

// severityExpr normalises the severity of vulnerabilities aliased v.
const severityExpr = `CASE WHEN v.severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW') THEN v.severity ELSE 'UNKNOWN' END`

// closedStatuses are the statuses that end the follow-up of a finding.
const closedStatuses = `('resolved', 'not_affected', 'false_positive')`

// DashboardStats computes the dashboard indicators at time now.
func (s *Store) DashboardStats(ctx context.Context, now time.Time) (Stats, error) {
	st := Stats{OpenBySeverity: map[string]int{}, MeanDaysToFix: -1}
	steps := []func(context.Context, time.Time, *Stats) error{
		s.openStats, s.closedStats, s.weeklyStats, s.topAssets, s.ctiStats,
	}
	for _, step := range steps {
		if err := step(ctx, now, &st); err != nil {
			return st, fmt.Errorf("dashboard stats: %w", err)
		}
	}
	return st, nil
}

func (s *Store) openStats(ctx context.Context, now time.Time, st *Stats) error {
	sla, err := s.SLA(ctx)
	if err != nil {
		return err
	}
	today := now.UTC().Format(time.DateOnly)
	args := append(append(sla.args(), today), sla.args()...)
	args = append(args, today, formatTime(now.Add(-StaleAfter)))
	rows, err := s.db.QueryContext(ctx, `
		SELECT `+severityExpr+`, COUNT(*),
		       SUM(v.kev OR v.epss >= 0.1),
		       SUM(v.kev),
		       SUM(COALESCE(`+dueExpr+` < ?, 0)),
		       SUM(v.kev AND COALESCE(`+dueExpr+` < ?, 0)),
		       SUM(f.status = 'in_triage'),
		       SUM(f.status = 'in_triage' AND f.first_seen < ?)
		FROM findings f JOIN vulnerabilities v ON v.id = f.vuln_id
		WHERE f.status IN `+openStatuses+`
		GROUP BY 1`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var sev string
		var n, prio, kev, overdue, overdueKEV, triage, stale int
		if err := rows.Scan(&sev, &n, &prio, &kev, &overdue, &overdueKEV, &triage, &stale); err != nil {
			return err
		}
		st.OpenBySeverity[sev] = n
		st.Open += n
		st.Priority += prio
		st.OpenKEV += kev
		st.Overdue += overdue
		st.OverdueKEV += overdueKEV
		st.ToTriage += triage
		st.StaleTriage += stale
	}
	return rows.Err()
}

// closedStats measures the time to close findings, from their detection to
// their last closing event, over the last 90 days.
func (s *Store) closedStats(ctx context.Context, now time.Time, st *Stats) error {
	var mean sql.NullFloat64
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*), AVG(julianday(c.closed_at) - julianday(f.first_seen))
		FROM findings f
		JOIN (SELECT finding_id, MAX(created_at) AS closed_at FROM finding_events
		      WHERE new_status IN `+closedStatuses+` GROUP BY finding_id) c ON c.finding_id = f.id
		WHERE f.status IN `+closedStatuses+` AND c.closed_at >= ?`,
		formatTime(now.Add(-90*24*time.Hour))).Scan(&st.Closed90, &mean)
	if err != nil {
		return err
	}
	if mean.Valid {
		st.MeanDaysToFix = max(mean.Float64, 0)
	}
	return nil
}

// weeklyStats counts detections and closings over the last weeks, weeks
// starting on Monday.
func (s *Store) weeklyStats(ctx context.Context, now time.Time, st *Stats) error {
	day := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	monday := day.AddDate(0, 0, -(int(day.Weekday())+6)%7)
	start := monday.AddDate(0, 0, -7*(statsWeeks-1))
	st.Weeks = make([]WeekCount, statsWeeks)
	for i := range st.Weeks {
		st.Weeks[i].Start = start.AddDate(0, 0, 7*i)
	}
	index := func(ts string) int {
		t := parseTime(ts)
		if t.Before(start) {
			return -1
		}
		return min(int(t.Sub(start)/(7*24*time.Hour)), statsWeeks-1)
	}
	count := func(query string, add func(*WeekCount)) error {
		rows, err := s.db.QueryContext(ctx, query, formatTime(start))
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var ts string
			if err := rows.Scan(&ts); err != nil {
				return err
			}
			if i := index(ts); i >= 0 {
				add(&st.Weeks[i])
			}
		}
		return rows.Err()
	}
	if err := count(`SELECT first_seen FROM findings WHERE first_seen >= ?`,
		func(w *WeekCount) { w.New++ }); err != nil {
		return err
	}
	return count(`SELECT MAX(created_at) FROM finding_events WHERE new_status IN `+closedStatuses+`
		GROUP BY finding_id HAVING MAX(created_at) >= ?`,
		func(w *WeekCount) { w.Closed++ })
}

func (s *Store) topAssets(ctx context.Context, _ time.Time, st *Stats) error {
	rows, err := s.db.QueryContext(ctx, `
		SELECT a.id, a.name, a.version,
		       SUM(v.severity = 'CRITICAL'), SUM(v.severity = 'HIGH'), SUM(v.severity = 'MEDIUM'),
		       SUM(v.severity NOT IN ('CRITICAL', 'HIGH', 'MEDIUM'))
		FROM findings f JOIN assets a ON a.id = f.asset_id JOIN vulnerabilities v ON v.id = f.vuln_id
		WHERE f.status IN ('in_triage', 'exploitable')
		GROUP BY a.id
		ORDER BY 4 DESC, 5 DESC, COUNT(*) DESC, a.name
		LIMIT ?`, topAssets)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var a AssetLoad
		if err := rows.Scan(&a.ID, &a.Name, &a.Version, &a.Critical, &a.High, &a.Medium, &a.Other); err != nil {
			return err
		}
		st.TopAssets = append(st.TopAssets, a)
	}
	return rows.Err()
}

func (s *Store) ctiStats(ctx context.Context, now time.Time, st *Stats) error {
	month := formatTime(now.Add(-30 * 24 * time.Hour))
	return s.db.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(published >= ?), 0), COALESCE(SUM(regulations <> '' AND published >= ?), 0),
		       COALESCE(SUM(published >= ? AND EXISTS (SELECT 1 FROM cti_mentions m
		                    WHERE m.item_id = i.id AND m.cve IN (`+openCVEs+`))), 0)
		FROM cti_items i`,
		formatTime(now.Add(-7*24*time.Hour)), month, month).Scan(&st.CTIWeek, &st.Regulatory30, &st.Concerning30)
}
