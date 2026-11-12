package tracking

import (
	"cmp"
	"slices"
	"strconv"
	"strings"

	"github.com/La-Cizaille-Corp/vigil/internal/choice"
	"github.com/La-Cizaille-Corp/vigil/internal/cvss"
	"github.com/La-Cizaille-Corp/vigil/internal/fr"
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

// levelNames name one finding of each level, on its badge.
var levelNames = map[string]string{
	LevelUrgent: "Urgente", LevelPlan: "À planifier", LevelWatch: "À surveiller", LevelAside: "Écartée",
}

// levelName names one finding of a level ("Urgente"), "" for no level.
func levelName(level string) string { return levelNames[level] }

// ground is what makes a finding urgent, or to plan by its CVSS score alone:
// the reason of its level that its severity band does not tell (A84).
type ground int

const (
	groundNone      ground = iota
	groundExploited        // listed in CISA KEV
	groundJudged           // judged exploitable by a user
	groundLikely           // EPSS >= store.LikelyEPSS
	groundScore            // to plan by a CVSS score of store.SevereCVSS or more, its severity being lower
)

// urgency is the first key of ComparePriority (A15, A78), with its ground:
// exploited (CISA KEV) or judged exploitable by a user, then likely to be
// exploited. The level of a finding (its alert class) follows the same rule.
func urgency(f store.Finding) (int, ground) {
	switch {
	case f.KEV:
		return 2, groundExploited
	case f.Status == store.StatusExploitable:
		return 2, groundJudged
	case f.EPSS >= store.LikelyEPSS:
		return 1, groundLikely
	}
	return 0, groundNone
}

// groundOf is the ground of a finding: its urgency, else, for one to plan
// whose band is below HIGH, its CVSS score (the alert class counts a score
// of store.SevereCVSS whatever the advisory says).
func groundOf(f store.Finding) ground {
	if _, g := urgency(f); g != groundNone {
		return g
	}
	if Level(f) == LevelPlan && severityRank(Band(f)) < severityRank("HIGH") {
		return groundScore
	}
	return groundNone
}

// Reason says in a few words what makes a finding urgent (set aside or
// fixed, what would), or to plan when its severity band does not say it,
// beside that band in a list or an alert: "exploitée (CISA KEV)", "jugée
// exploitable", "EPSS 12,3 %", "CVSS 7,5"; "" when the band says it all. It
// is the rule of the ranking (urgency) and of the levels, not a copy of it.
func Reason(f store.Finding) string {
	switch groundOf(f) {
	case groundExploited:
		return "exploitée (CISA KEV)"
	case groundJudged:
		return "jugée exploitable"
	case groundLikely:
		return "EPSS " + fr.Percent(f.EPSS)
	case groundScore:
		return "CVSS " + fr.Score(f.CVSS)
	}
	return ""
}

// explain says in a sentence why a finding has its level, on its page:
// "la probabilité d'exploitation EPSS est de 74,8 % (seuil 10,0 %)". It is ""
// for a fixed finding, which has no level.
func explain(f store.Finding) string {
	switch Level(f) {
	case "":
		return ""
	case LevelAside:
		return "elle est marquée « " + choice.Label(Statuses, f.Status) + " »"
	}
	switch groundOf(f) {
	case groundExploited:
		return "elle est exploitée activement (CISA KEV)"
	case groundJudged:
		return "l'équipe l'a jugée exploitable"
	case groundLikely:
		return "la probabilité d'exploitation EPSS est de " + fr.Percent(f.EPSS) +
			" (seuil " + fr.Percent(store.LikelyEPSS) + ")"
	case groundScore:
		return "son score CVSS est de " + fr.Score(f.CVSS) + " (seuil " + strconv.Itoa(store.SevereCVSS) + ")"
	}
	if Level(f) == LevelPlan {
		return "sa sévérité est " + strings.ToLower(SeverityLabel(Band(f)))
	}
	return "elle n'est ni exploitée, ni probable, ni critique ou haute"
}

// ComparePriority compares the urgency of two findings, like cmp.Compare:
// positive when a is more urgent than b. Exploited (KEV) or judged
// exploitable come first, then likely to be exploited (EPSS >=
// store.LikelyEPSS), then the severity band (see Band), the EPSS score, the
// CVSS score, and the most recent detection. It is the only ranking of
// findings (A78): lists, dashboard and digest.
func ComparePriority(a, b store.Finding) int {
	ua, _ := urgency(a)
	ub, _ := urgency(b)
	return cmp.Or(
		cmp.Compare(ua, ub),
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
