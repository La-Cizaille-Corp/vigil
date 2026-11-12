package nvd

import (
	"encoding/json"
	"slices"
	"strings"
	"unicode"

	"github.com/La-Cizaille-Corp/vigil/internal/versions"
)

// Match is a vulnerable product named by the configurations of a CVE: one
// release, or a range of versions when Version is "*" or "-".
type Match struct {
	Vendor, Product string
	Version         string
	Update          string         // of the release: r2.1 for Ivanti 22.7R2.1, "-" for none, "*" for any
	Range           versions.Range // Fixed: versionEndExcluding; LastAffected: versionEndIncluding
}

// Matches returns the vulnerable products of a CVE record (raw JSON).
func Matches(raw []byte) []Match {
	var doc struct {
		Configurations []struct {
			Nodes []struct {
				CPEMatch []struct {
					Vulnerable            bool   `json:"vulnerable"`
					Criteria              string `json:"criteria"`
					VersionStartIncluding string `json:"versionStartIncluding"`
					VersionStartExcluding string `json:"versionStartExcluding"`
					VersionEndExcluding   string `json:"versionEndExcluding"`
					VersionEndIncluding   string `json:"versionEndIncluding"`
				} `json:"cpeMatch"`
			} `json:"nodes"`
		} `json:"configurations"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		return nil
	}
	var out []Match
	for _, c := range doc.Configurations {
		for _, n := range c.Nodes {
			for _, m := range n.CPEMatch {
				f, ok := SplitCPE(m.Criteria)
				if !m.Vulnerable || !ok {
					continue
				}
				r := versions.Range{Start: m.VersionStartIncluding, Fixed: m.VersionEndExcluding, LastAffected: m.VersionEndIncluding}
				if m.VersionStartExcluding != "" {
					r.Start, r.StartOpen = m.VersionStartExcluding, true
				}
				out = append(out, Match{Vendor: f[3], Product: f[4], Version: f[5], Update: f[6], Range: r})
			}
		}
	}
	return out
}

// Ranged reports whether m covers versions of the product rather than one
// release.
func (m Match) Ranged() bool { return m.Version == "*" || m.Version == "-" }

// Open reports whether m still affects the latest release: every version of
// the product from its start, with no end. A range ending with an included
// version ("up to 7.2.13") is fixed in a later release: vendors' advisories
// list the affected versions that way, the fix with them.
func (m Match) Open() bool {
	return m.Ranged() && m.Range.Fixed == "" && m.Range.LastAffected == ""
}

// Affects reports whether version v is affected: in the range, or the very
// release named. With an update (22.7:r2.1), v must name it too (22.7R2.1),
// unless v gives none (22.7); with none ("-"), v must be the release alone;
// with any ("*"), any suffix of v is an update (22.8R2 for 22.8, not 22.8.1).
func (m Match) Affects(v string) bool {
	if m.Ranged() {
		return m.Range.Holds(v)
	}
	unescape := func(s string) string { return strings.ToLower(strings.ReplaceAll(s, `\`, "")) }
	v, release := strings.ToLower(v), unescape(m.Version)
	switch {
	case versions.Compare(v, release) == 0:
		return true
	case m.Update == "-":
		return false
	case m.Update != "*" && m.Update != "":
		return versions.Compare(v, release+unescape(m.Update)) == 0
	}
	rest, ok := strings.CutPrefix(v, release)
	return ok && rest != "" && rest[0] != '.' && (rest[0] < '0' || rest[0] > '9')
}

// Named reports whether the name of an asset designates the product of m:
// every word of the name is in the vendor and product (Exchange Server →
// microsoft:exchange_server), or every word of the product is in the name
// (nginx frontal → f5:nginx).
func (m Match) Named(name string) bool {
	nameWords := words(name)
	product := words(m.Product)
	return len(nameWords) > 0 && len(product) > 0 &&
		(subset(nameWords, append(words(m.Vendor), product...)) || subset(product, nameWords))
}

// SplitCPE splits a CPE 2.3 name into its 13 fields, keeping escaped colons:
// cpe:2.3:a:lemonldap-ng:lemonldap\:\:ng:… has the product lemonldap\:\:ng.
// It reports false for anything else. Every CPE is split here: a plain
// split on ":" cuts the names that the NVD dictionary escapes.
func SplitCPE(cpe string) ([]string, bool) {
	var fields []string
	start := 0
	for i := 0; i < len(cpe); i++ {
		switch cpe[i] {
		case '\\':
			i++ // the escaped character
		case ':':
			fields = append(fields, cpe[start:i])
			start = i + 1
		}
	}
	fields = append(fields, cpe[start:])
	if len(fields) != 13 || fields[0] != "cpe" || fields[1] != "2.3" {
		return nil, false
	}
	return fields, true
}

// UnfixedFor reports whether a CVE still affects the latest release of the
// product of a CPE, or of any product of its vendor for a vendor CPE.
func UnfixedFor(c CVE, cpe string) bool {
	f, ok := SplitCPE(cpe)
	if !ok {
		return false
	}
	return slices.ContainsFunc(Matches(c.Raw), func(m Match) bool {
		return m.Vendor == f[3] && (f[4] == "*" || m.Product == f[4]) && m.Open()
	})
}

// NameAffects reports whether a CVE found by searching the name of an asset
// may affect it, at version, or at its latest release. A CVE awaiting
// analysis (no configuration yet) is kept; once analysed, it must list a
// product that the name designates, at the version (any without one), or
// without fixed version for the latest release. A CVE whose description
// only mentions the name (Shellshock through Apache HTTP Server) is dropped.
func NameAffects(c CVE, name, version string, latest bool) bool {
	all := Matches(c.Raw)
	if len(all) == 0 {
		return true
	}
	return slices.ContainsFunc(all, func(m Match) bool {
		switch {
		case !m.Named(name):
			return false
		case latest:
			return m.Open()
		}
		return version == "" || m.Affects(version)
	})
}

// words splits a name or a CPE field into lower-case words of letters and
// digits: "node\.js" → node, js.
func words(s string) []string {
	return strings.FieldsFunc(strings.ToLower(s), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) })
}

func subset(small, large []string) bool {
	for _, w := range small {
		if !slices.Contains(large, w) {
			return false
		}
	}
	return true
}
