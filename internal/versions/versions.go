// Package versions compares version strings without knowing their scheme,
// and tells whether a version falls in an affected range.
package versions

import (
	"cmp"
	"strconv"
	"strings"
	"unicode"
)

// Compare orders version strings by their numbers, then their letters,
// ignoring case: 9.5.5 > 9.5.3 > 8.19.23, 10.0 > 9.9, 1.4.0 > 1.4.0-beta1,
// 22.7R2 > 22.7 (see extraRank).
func Compare(a, b string) int {
	pa, pb := parts(strings.ToLower(a)), parts(strings.ToLower(b))
	for i := 0; i < min(len(pa), len(pb)); i++ {
		x, y := pa[i], pb[i]
		xn, xerr := strconv.Atoi(x)
		yn, yerr := strconv.Atoi(y)
		switch {
		case xerr == nil && yerr == nil && xn != yn:
			return cmp.Compare(xn, yn)
		case (xerr == nil) != (yerr == nil):
			if xerr == nil { // a number ranks above a pre-release label
				return 1
			}
			return -1
		case x != y:
			return strings.Compare(x, y)
		}
	}
	switch {
	case len(pa) > len(pb):
		return extraRank(pa[len(pb):])
	case len(pb) > len(pa):
		return -extraRank(pb[len(pa):])
	}
	return 0
}

// extraRank ranks a version that goes on past another, rest being its
// extra parts: above with a number (1.4.1 > 1.4) or an update label
// (22.7R2 > 22.7, 9.5p1 > 9.5, 1.1.1w > 1.1.1); below with a pre-release
// label (1.4.0 > 1.4.0-beta1, 2.0 > 2.0a1, 3.0 > 3.0-M1).
func extraRank(rest []string) int {
	switch rest[0] {
	case "alpha", "beta", "rc", "pre", "preview", "dev", "snapshot", "ea", "cr", "canary", "nightly", "milestone":
		return -1
	case "a", "b", "c", "m":
		if len(rest) > 1 { // 2.0a1, not OpenSSL's 1.0.2a
			return -1
		}
	}
	return 1
}

// parts splits a version into runs of digits and runs of letters.
func parts(v string) []string {
	var out []string
	start := -1
	digit := false
	for i, r := range v {
		isDigit, isLetter := r >= '0' && r <= '9', unicode.IsLetter(r)
		if !isDigit && !isLetter {
			if start >= 0 {
				out = append(out, v[start:i])
			}
			start = -1
			continue
		}
		if start >= 0 && isDigit != digit {
			out = append(out, v[start:i])
			start = -1
		}
		if start < 0 {
			start, digit = i, isDigit
		}
	}
	if start >= 0 {
		out = append(out, v[start:])
	}
	return out
}

// Range is an affected range: from Start (included unless StartOpen; ""
// or "0" for the first version) to Fixed (excluded) or LastAffected
// (included). Without either end, every later version is affected.
type Range struct {
	Start, Fixed, LastAffected string
	StartOpen                  bool
}

// Holds reports whether version v is in the range.
func (r Range) Holds(v string) bool {
	if v == "" {
		return false
	}
	if r.Start != "" && r.Start != "0" {
		c := Compare(v, r.Start)
		if c < 0 || c == 0 && r.StartOpen {
			return false
		}
	}
	switch {
	case r.Fixed != "":
		return Compare(v, r.Fixed) < 0
	case r.LastAffected != "":
		return Compare(v, r.LastAffected) <= 0
	}
	return true
}
