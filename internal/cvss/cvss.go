// Package cvss computes CVSS 3.x base scores from vector strings
// (https://www.first.org/cvss/v3.1/specification-document), so that
// advisories which only publish a vector can be filtered by score.
package cvss

import (
	"math"
	"strings"
)

// Unknown is returned when no score can be computed.
const Unknown = -1.0

var weights = map[string]map[string]float64{
	"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
	"AC": {"L": 0.77, "H": 0.44},
	"UI": {"N": 0.85, "R": 0.62},
	"C":  {"H": 0.56, "L": 0.22, "N": 0},
	"I":  {"H": 0.56, "L": 0.22, "N": 0},
	"A":  {"H": 0.56, "L": 0.22, "N": 0},
}

// BaseScore returns the base score of a CVSS:3.0 or CVSS:3.1 vector, or
// Unknown for any other or malformed vector.
func BaseScore(vector string) float64 {
	parts := strings.Split(vector, "/")
	if len(parts) < 9 || (parts[0] != "CVSS:3.1" && parts[0] != "CVSS:3.0") {
		return Unknown
	}
	m := map[string]string{}
	for _, p := range parts[1:] {
		k, v, ok := strings.Cut(p, ":")
		if !ok {
			return Unknown
		}
		m[k] = v
	}
	changed := m["S"] == "C"
	if m["S"] != "C" && m["S"] != "U" {
		return Unknown
	}
	pr := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	if changed {
		pr["L"], pr["H"] = 0.68, 0.5
	}
	val := func(metric string, table map[string]float64) (float64, bool) {
		w, ok := table[m[metric]]
		return w, ok
	}
	var w [7]float64
	var ok [7]bool
	w[0], ok[0] = val("AV", weights["AV"])
	w[1], ok[1] = val("AC", weights["AC"])
	w[2], ok[2] = val("PR", pr)
	w[3], ok[3] = val("UI", weights["UI"])
	w[4], ok[4] = val("C", weights["C"])
	w[5], ok[5] = val("I", weights["I"])
	w[6], ok[6] = val("A", weights["A"])
	for _, b := range ok {
		if !b {
			return Unknown
		}
	}

	iss := 1 - (1-w[4])*(1-w[5])*(1-w[6])
	impact := 6.42 * iss
	if changed {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	if impact <= 0 {
		return 0
	}
	exploitability := 8.22 * w[0] * w[1] * w[2] * w[3]
	if changed {
		return roundUp(math.Min(1.08*(impact+exploitability), 10))
	}
	return roundUp(math.Min(impact+exploitability, 10))
}

// roundUp is the specification's Roundup, robust to floating point errors.
func roundUp(x float64) float64 {
	i := math.Round(x * 100000)
	if math.Mod(i, 10000) == 0 {
		return i / 100000
	}
	return (math.Floor(i/10000) + 1) / 10
}

// Severity maps a score to its qualitative rating.
func Severity(score float64) string {
	switch {
	case score >= 9:
		return "CRITICAL"
	case score >= 7:
		return "HIGH"
	case score >= 4:
		return "MEDIUM"
	case score > 0:
		return "LOW"
	case score == 0:
		return "NONE"
	}
	return ""
}
