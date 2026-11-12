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
	Closed90       int     // closed (fixed or dismissed) in the last 90 days, found after the first sync of their asset
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

// DashboardStats computes the dashboard indicators of the scope at time now.
func (s *Store) DashboardStats(ctx context.Context, sc Scope, now time.Time) (Stats, error) {
	st := Stats{OpenBySeverity: map[string]int{}, MeanDaysToFix: -1}
	steps := []func(context.Context, Scope, time.Time, *Stats) error{
		s.openStats, s.closedStats, s.weeklyStats, s.topAssets, s.ctiStats,
	}
	for _, step := range steps {
		if err := step(ctx, sc, now, &st); err != nil {
			return st, fmt.Errorf("dashboard stats: %w", err)
		}
	}
	return st, nil
}

func (s *Store) openStats(ctx context.Context, sc Scope, now time.Time, st *Stats) error {
	sla, err := s.SLA(ctx)
	if err != nil {
		return err
	}
	today := now.UTC().Format(time.DateOnly)
	cond, condArgs := sc.cond("a")
	args := append(append(sla.args(), today), sla.args()...)
	args = append(append(args, today, formatTime(now.Add(-StaleAfter))), condArgs...)
	// #nosec G202 -- cond is a fixed expression of Scope.cond; the values are parameters.
	rows, err := s.db.QueryContext(ctx, `
		SELECT `+severityExpr+`, COUNT(*),
		       SUM(v.kev OR v.epss >= 0.1),
		       SUM(v.kev),
		       SUM(COALESCE(`+dueExpr+` < ?, 0)),
		       SUM(v.kev AND COALESCE(`+dueExpr+` < ?, 0)),
		       SUM(f.status = 'in_triage'),
		       SUM(f.status = 'in_triage' AND f.first_seen < ?)
		FROM findings f JOIN vulnerabilities v ON v.id = f.vuln_id JOIN assets a ON a.id = f.asset_id
		WHERE f.status IN `+openStatuses+` AND `+cond+`
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
// their last closing event, over the last 90 days, apart from the findings of
// the first sync of their asset: these predate its arrival in Vigil, and
// their delay says nothing of the reaction to a new vulnerability.
//
// They are the findings detected at the earliest time of the asset: a run
// stamps every finding it creates with its start time (tracking.Syncer), and
// nothing else creates findings, so no column has to record the first sync.
// An asset that had no vulnerability at its first sync also has the findings
// of its next detecting run left out: the mean loses them, but never counts
// one of a first sync.
func (s *Store) closedStats(ctx context.Context, sc Scope, now time.Time, st *Stats) error {
	var mean sql.NullFloat64
	cond, args := sc.cond("a")
	err := s.db.QueryRowContext(ctx, `
		WITH first_sync AS (SELECT asset_id, MIN(first_seen) AS at FROM findings GROUP BY asset_id)
		SELECT COUNT(*), AVG(julianday(c.closed_at) - julianday(f.first_seen))
		FROM findings f JOIN assets a ON a.id = f.asset_id
		JOIN first_sync fs ON fs.asset_id = f.asset_id
		JOIN (SELECT finding_id, MAX(created_at) AS closed_at FROM finding_events
		      WHERE new_status IN `+closedStatuses+` GROUP BY finding_id) c ON c.finding_id = f.id
		WHERE f.status IN `+closedStatuses+` AND c.closed_at >= ? AND f.first_seen > fs.at AND `+cond,
		append([]any{formatTime(now.Add(-90 * 24 * time.Hour))}, args...)...).Scan(&st.Closed90, &mean)
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
func (s *Store) weeklyStats(ctx context.Context, sc Scope, now time.Time, st *Stats) error {
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
	cond, condArgs := sc.cond("a")
	args := append([]any{formatTime(start)}, condArgs...)
	count := func(query string, add func(*WeekCount)) error {
		rows, err := s.db.QueryContext(ctx, query, args...)
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
	if err := count(`SELECT f.first_seen FROM findings f JOIN assets a ON a.id = f.asset_id
		WHERE f.first_seen >= ? AND `+cond,
		func(w *WeekCount) { w.New++ }); err != nil {
		return err
	}
	// The latest closing of each finding, then the scope: the start of the
	// period comes first here too, as in the query above.
	return count(`SELECT c.closed_at FROM (
		    SELECT MAX(e.created_at) AS closed_at, e.finding_id FROM finding_events e
		    WHERE e.new_status IN `+closedStatuses+` GROUP BY e.finding_id) c
		JOIN findings f ON f.id = c.finding_id JOIN assets a ON a.id = f.asset_id
		WHERE c.closed_at >= ? AND `+cond,
		func(w *WeekCount) { w.Closed++ })
}

func (s *Store) topAssets(ctx context.Context, sc Scope, _ time.Time, st *Stats) error {
	cond, args := sc.cond("a")
	// #nosec G202 -- cond is a fixed expression of Scope.cond; the values are parameters.
	rows, err := s.db.QueryContext(ctx, `
		SELECT a.id, a.name, a.version,
		       SUM(v.severity = 'CRITICAL'), SUM(v.severity = 'HIGH'), SUM(v.severity = 'MEDIUM'),
		       SUM(v.severity NOT IN ('CRITICAL', 'HIGH', 'MEDIUM'))
		FROM findings f JOIN assets a ON a.id = f.asset_id JOIN vulnerabilities v ON v.id = f.vuln_id
		WHERE f.status IN ('in_triage', 'exploitable') AND `+cond+`
		GROUP BY a.id
		ORDER BY 4 DESC, 5 DESC, COUNT(*) DESC, a.name
		LIMIT ?`, append(args, topAssets)...)
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

func (s *Store) ctiStats(ctx context.Context, sc Scope, now time.Time, st *Stats) error {
	month := formatTime(now.Add(-30 * 24 * time.Hour))
	with, args := openCVEs(sc)
	return s.db.QueryRowContext(ctx, with+`
		SELECT COALESCE(SUM(published >= ?), 0), COALESCE(SUM(regulations <> '' AND published >= ?), 0),
		       COALESCE(SUM(published >= ? AND EXISTS (SELECT 1 FROM cti_mentions m
		                    WHERE m.item_id = i.id AND m.cve IN (SELECT cve FROM open_cves))), 0)
		FROM cti_items i`,
		append(args, formatTime(now.Add(-7*24*time.Hour)), month, month)...).Scan(&st.CTIWeek, &st.Regulatory30, &st.Concerning30)
}
