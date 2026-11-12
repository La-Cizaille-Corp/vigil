// Package fr writes dates and numbers the French way, for what Vigil shows:
// the pages, the digest, the alerts and the CSV exports. The convention is
// written here once (A79):
//
//   - a day: 09/02/2026 (Date), without its year on a chart axis: 09/02
//     (DayMonth); a moment: 09/02/2026 14:05, in local time (DateTime);
//   - a decimal comma, no thousands separator: 9,8 (Decimal);
//   - a score, CVSS or EPSS, with one decimal, 0 included: 0,0 (Score); a
//     negative score is unknown and written "", the caller shows its dash;
//   - a percentage with a no-break space before its sign, which never
//     goes alone to the next line: 12,3 % (Percent);
//   - a number of days, its unit kept the same way: < 1 j, 3,5 j, 12 j (days);
//   - the values a field accepts, in an error: Faible, Moyenne ou Haute (Or).
//
// The values of form fields stay as HTML reads them, with a point
// (input type="number"), and so do machine formats: ISO dates of the CSV
// exports and of the API, JSON numbers.
//
// Funcs gives these to the templates of the web pages and of the digest,
// with tracking.TemplateFuncs for the words of the findings. The package
// imports nothing of Vigil, so that any package may write the same way.
package fr

import (
	"strconv"
	"strings"
	"time"
)

// nbsp is the no-break space between a number and its unit (A84).
const nbsp = "\u00a0"

// Date writes the day of t as it is, without changing its time zone: a
// deadline or a publication date is a day, not a moment.
func Date(t time.Time) string { return t.Format("02/01/2006") }

// DayMonth writes the day of t without its year, for a chart axis.
func DayMonth(t time.Time) string { return t.Format("02/01") }

// DateTime writes the moment t in local time, to the minute.
func DateTime(t time.Time) string { return t.Local().Format("02/01/2006 15:04") }

// Decimal writes v with n decimals and a decimal comma.
func Decimal(v float64, n int) string {
	return strings.Replace(strconv.FormatFloat(v, 'f', n, 64), ".", ",", 1)
}

// Score writes a score with one decimal, or "" when it is unknown (negative).
func Score(v float64) string {
	if v < 0 {
		return ""
	}
	return Decimal(v, 1)
}

// Percent writes a probability (0 to 1) as a percentage with one decimal, or
// "" when it is unknown (negative).
func Percent(p float64) string {
	if p < 0 {
		return ""
	}
	return Decimal(p*100, 1) + nbsp + "%"
}

// days writes a number of days: "< 1 j", one decimal below 10, none above.
func days(d float64) string {
	switch {
	case d < 1:
		return "<" + nbsp + "1" + nbsp + "j"
	case d < 10:
		return Decimal(d, 1) + nbsp + "j"
	}
	return Decimal(d, 0) + nbsp + "j"
}

// Or writes alternatives: "a", "a ou b", "a, b ou c".
func Or(words []string) string { return Join(words, "ou") }

// Join writes a list in a sentence, its last two words joined by conj ("et",
// "ou"): "a", "a et b", "a, b et c".
func Join(words []string, conj string) string {
	if len(words) < 2 {
		return strings.Join(words, "")
	}
	return strings.Join(words[:len(words)-1], ", ") + " " + conj + " " + words[len(words)-1]
}

// Funcs returns the template functions that write dates and numbers, shared
// by the web pages and the digest.
func Funcs() map[string]any {
	return map[string]any{
		"date": DateTime,
		"day":  Date,
		"cvss": Score,
		"epss": Percent,
		"days": days,
		"join": strings.Join,
	}
}
