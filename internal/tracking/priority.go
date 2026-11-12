package tracking

import (
	"cmp"
	"slices"
	"strings"

	"github.com/La-Cizaille-Corp/vigil/internal/choice"
	"github.com/La-Cizaille-Corp/vigil/internal/cvss"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
)

// Band returns the severity range of a finding, one of the values of
// Severities: its advisory severity, or the rating of its CVSS score when the
// advisory gives none (CRITICAL from 9, HIGH from 7, MEDIUM from 4, LOW
// below), UNKNOWN without either.
func Band(f store.Finding) string {
	s := strings.ToUpper(f.Severity)
	if s == "" {
		s = cvss.Severity(f.CVSS)
	}
	if severityRank(s) == 0 {
		return "UNKNOWN"
	}
	return s
}

// severityRank orders the values of Severities, most severe highest: 0 for
// UNKNOWN and for anything else.
func severityRank(s string) int {
	i := choice.Rank(Severities, s)
	if i < 0 {
		return 0
	}
	return len(Severities) - 1 - i
}

// The levels findings are classified in, for every product alike: the alert
// classes of the store (A60).
const (
	LevelUrgent = "urgent" // exploited (KEV), likely to be (EPSS >= store.LikelyEPSS) or judged exploitable
	LevelPlan   = "plan"   // critical or high severity, or a CVSS score of 7 or more
	LevelWatch  = "watch"  // the rest, without a score included
	LevelAside  = "aside"  // decided not to concern the asset
)

// Levels are the levels of a finding, labelled in French, most urgent first.
var Levels = []choice.Option{
	{Value: LevelUrgent, Label: "Urgentes"},
	{Value: LevelPlan, Label: "À planifier"},
	{Value: LevelWatch, Label: "À surveiller"},
	{Value: LevelAside, Label: "Écartées"},
}

// Level classifies a finding read from the store by its alert class
// (store.Finding.Class), so that a level and an alert say the same thing; it
// is "" for a fixed one, which has no level left.
func Level(f store.Finding) string {
	switch f.Status {
	case store.StatusResolved:
		return ""
	case store.StatusNotAffected, store.StatusFalsePositive:
		return LevelAside
	}
	switch f.Class {
	case store.AlertPriority:
		return LevelUrgent
	case store.AlertSevere:
		return LevelPlan
	}
	return LevelWatch
}

// urgency is the first key of ComparePriority (A15, A78): exploited (CISA
// KEV) or judged exploitable by a user, then likely to be exploited.
func urgency(f store.Finding) int {
	switch {
	case f.KEV || f.Status == store.StatusExploitable:
		return 2
	case f.EPSS >= store.LikelyEPSS:
		return 1
	}
	return 0
}

// ComparePriority compares the urgency of two findings, like cmp.Compare:
// positive when a is more urgent than b. Exploited (KEV) or judged
// exploitable come first, then likely to be exploited (EPSS >=
// store.LikelyEPSS), then the severity band (see Band), the EPSS score, the
// CVSS score, and the most recent detection. It is the only ranking of
// findings (A78): lists, dashboard and digest.
func ComparePriority(a, b store.Finding) int {
	return cmp.Or(
		cmp.Compare(urgency(a), urgency(b)),
		cmp.Compare(severityRank(Band(a)), severityRank(Band(b))),
		cmp.Compare(a.EPSS, b.EPSS),
		cmp.Compare(a.CVSS, b.CVSS),
		a.FirstSeen.Compare(b.FirstSeen),
	)
}

// SortByPriority orders findings by ComparePriority, most urgent first;
// findings that compare equal keep their order.
func SortByPriority(fs []store.Finding) {
	slices.SortStableFunc(fs, func(a, b store.Finding) int { return ComparePriority(b, a) })
}
