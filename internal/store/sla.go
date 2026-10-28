package store

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// SLA holds the remediation deadlines, in days from detection, by severity;
// 0 means no deadline. Exploited vulnerabilities (CISA KEV) get the critical
// deadline whatever their score; unrated ones get the medium one.
type SLA struct {
	Critical, High, Medium, Low int
}

// DefaultSLA follows common practice: CISA BOD 19-02 for critical and high.
var DefaultSLA = SLA{Critical: 15, High: 30, Medium: 90, Low: 180}

// MaxSLADays bounds a deadline (about three years).
const MaxSLADays = 1000

const slaKey = "sla"

// dueExpr is the deadline date ('YYYY-MM-DD', NULL without one) of findings
// aliased f and v; it takes SLA.args() as arguments.
const dueExpr = `date(f.first_seen, '+' || NULLIF(CASE
		WHEN v.kev = 1 OR v.severity = 'CRITICAL' THEN ?
		WHEN v.severity = 'HIGH' THEN ?
		WHEN v.severity = 'LOW' THEN ?
		ELSE ? END, 0) || ' days')`

func (l SLA) args() []any { return []any{l.Critical, l.High, l.Low, l.Medium} }

// String encodes the SLA as stored: "critical,high,medium,low".
func (l SLA) String() string {
	return fmt.Sprintf("%d,%d,%d,%d", l.Critical, l.High, l.Medium, l.Low)
}

// Valid reports whether every deadline is within bounds.
func (l SLA) Valid() bool {
	for _, d := range []int{l.Critical, l.High, l.Medium, l.Low} {
		if d < 0 || d > MaxSLADays {
			return false
		}
	}
	return true
}

// SLA returns the remediation deadlines, DefaultSLA until they are set.
func (s *Store) SLA(ctx context.Context) (SLA, error) {
	v, err := s.Setting(ctx, slaKey)
	if err != nil || v == "" {
		return DefaultSLA, err
	}
	parts := strings.Split(v, ",")
	if len(parts) != 4 {
		return DefaultSLA, nil
	}
	var days [4]int
	for i, p := range parts {
		if days[i], err = strconv.Atoi(p); err != nil {
			return DefaultSLA, nil
		}
	}
	l := SLA{Critical: days[0], High: days[1], Medium: days[2], Low: days[3]}
	if !l.Valid() {
		return DefaultSLA, nil
	}
	return l, nil
}

// SetSLA stores the remediation deadlines; deadlines of existing findings
// follow, since they are computed from the detection date.
func (s *Store) SetSLA(ctx context.Context, l SLA) error {
	if !l.Valid() {
		return fmt.Errorf("délai hors limites (0 à %d jours)", MaxSLADays)
	}
	return s.SetSetting(ctx, slaKey, l.String())
}
