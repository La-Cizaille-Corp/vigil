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
	// Declared: by the CNA of a CVE that the NVD has not analysed yet, its
	// vendor and product named in words ("GitLab", "Apache HTTP Server")
	// rather than CPE fields (A101).
	Declared bool
}

// Matches returns the vulnerable products of a CVE record (raw JSON): those
// of its configurations, or, while the NVD has not analysed it (no
// configuration), those its CNA declares (see declared).
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
	if len(doc.Configurations) == 0 {
		return declared(raw)
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

// declared returns the products that the CNA of a CVE declares affected (its
// CVE JSON 5 "affected" list, relayed by the NVD): a range for an affected
// entry from "version" to "lessThan" or "lessThanOrEqual" ("*": no end), a
// release for a single version, every version for "*". What cannot be
// compared is left out: an entry without vendor or product ("n/a"), a range
// of commits (versionType git), a version that is not one ("unspecified"),
// and an entry affected by default, whose affected versions are all but those
// it lists: the kernel's CNA lists 6.1 "affected" and the fixed branches
// "unaffected", and read alone, 6.1 would leave out 6.12.
func declared(raw []byte) []Match {
	var doc struct {
		Affected []struct {
			AffectedData []struct {
				Vendor        string `json:"vendor"`
				Product       string `json:"product"`
				DefaultStatus string `json:"defaultStatus"`
				Versions      []struct {
					Version         string `json:"version"`
					LessThan        string `json:"lessThan"`
					LessThanOrEqual string `json:"lessThanOrEqual"`
					VersionType     string `json:"versionType"`
					Status          string `json:"status"`
				} `json:"versions"`
			} `json:"affectedData"`
		} `json:"affected"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		return nil
	}
	var out []Match
	for _, source := range doc.Affected {
		for _, a := range source.AffectedData {
			if unstated(a.Vendor) || unstated(a.Product) || strings.EqualFold(a.DefaultStatus, "affected") {
				continue
			}
			for _, v := range a.Versions {
				if v.Status != "affected" || strings.EqualFold(v.VersionType, "git") {
					continue
				}
				m := Match{Vendor: a.Vendor, Product: a.Product, Version: "*", Declared: true}
				switch {
				case v.LessThan != "" || v.LessThanOrEqual != "":
					if !unstated(v.Version) && v.Version != "*" {
						m.Range.Start = v.Version
					}
					switch {
					case v.LessThan == "*" || v.LessThanOrEqual == "*": // no end
					case v.LessThan != "":
						m.Range.Fixed = v.LessThan
					default:
						m.Range.LastAffected = v.LessThanOrEqual
					}
				case v.Version == "*": // every version
				case unstated(v.Version):
					continue
				default:
					m.Version = v.Version // one release
				}
				out = append(out, m)
			}
		}
	}
	return out
}

// unstated reports whether a name or a version declared by a CNA says
// nothing: "", "n/a", "unknown", "unspecified", "-".
func unstated(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "n/a", "na", "unknown", "unspecified", "-":
		return true
	}
	return false
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
	unescape := func(s string) string { return strings.ToLower(Unescape(s)) }
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

// OfCPE reports whether m is the product of a CPE (its fields, see SplitCPE),
// or a product of its vendor when the CPE names them all ("*"). A product of
// the NVD's analysis has the CPE's very names. One declared by a CNA, in
// words, has the words of the vendor in its own, and exactly the words of
// the product, alone or after the vendor's: "GitLab" and "Apache HTTP
// Server" are gitlab:gitlab and apache:http_server, "GitLab Runner" is not
// gitlab:gitlab.
func (m Match) OfCPE(f []string) bool {
	if !m.Declared {
		return m.Vendor == f[3] && (f[4] == "*" || m.Product == f[4])
	}
	vendor := words(Unescape(f[3]))
	if len(vendor) == 0 || !subset(vendor, words(m.Vendor)) {
		return false
	}
	if f[4] == "*" {
		return true
	}
	product, named := words(Unescape(f[4])), words(m.Product)
	return len(product) > 0 && (slices.Equal(named, product) || slices.Equal(named, append(slices.Clone(vendor), product...)))
}

// Reaches reports whether m affects a version from `from` on: a range that
// does not end before it, or a release that is not older.
func (m Match) Reaches(from string) bool {
	switch {
	case !m.Ranged():
		return versions.Compare(Unescape(m.Version), from) >= 0
	case m.Range.Fixed != "":
		return versions.Compare(m.Range.Fixed, from) > 0
	case m.Range.LastAffected != "":
		return versions.Compare(m.Range.LastAffected, from) >= 0
	}
	return true
}

// SplitCPE splits a CPE 2.3 name into its 13 fields, keeping escaped colons:
// cpe:2.3:a:lemonldap-ng:lemonldap\:\:ng:… has the product lemonldap\:\:ng.
// It reports false for anything else: another count of fields, an empty
// one, a part other than a (application), o (system), h (hardware) or *, a
// space or a control character, a backslash that escapes nothing. Every CPE
// is split, and checked, here: a plain split on ":" cuts the names that the
// NVD dictionary escapes.
func SplitCPE(cpe string) ([]string, bool) {
	invalid := func(c byte) bool { return c <= ' ' || c == 0x7f }
	var fields []string
	start := 0
	for i := 0; i < len(cpe); i++ {
		switch {
		case invalid(cpe[i]):
			return nil, false
		case cpe[i] == '\\':
			if i+1 == len(cpe) || invalid(cpe[i+1]) {
				return nil, false
			}
			i++ // the escaped character
		case cpe[i] == ':':
			fields = append(fields, cpe[start:i])
			start = i + 1
		}
	}
	fields = append(fields, cpe[start:])
	if len(fields) != 13 || fields[0] != "cpe" || fields[1] != "2.3" ||
		!slices.Contains([]string{"a", "o", "h", "*"}, fields[2]) || slices.Contains(fields, "") {
		return nil, false
	}
	return fields, true
}

// Unescape is the readable form of a field of a CPE, without the backslashes
// that escape its characters: lemonldap\:\:ng reads lemonldap::ng. It is for
// display and for comparisons with names and versions; the CPE itself, as
// stored and sent to the NVD, keeps its escapes.
func Unescape(field string) string {
	if !strings.Contains(field, `\`) {
		return field
	}
	var b strings.Builder
	for i := 0; i < len(field); i++ {
		if field[i] == '\\' && i+1 < len(field) {
			i++ // the escaped character, kept
		}
		b.WriteByte(field[i])
	}
	return b.String()
}

// UnfixedFor reports whether a CVE still affects the latest release of the
// product of a CPE, or of any product of its vendor for a vendor CPE.
func UnfixedFor(c CVE, cpe string) bool {
	f, ok := SplitCPE(cpe)
	if !ok {
		return false
	}
	return slices.ContainsFunc(Matches(c.Raw), func(m Match) bool {
		return m.OfCPE(f) && m.Open()
	})
}

// NameAffects reports whether a CVE found by searching the name of an asset
// may affect it, at version, or at its latest release. It must list a
// product that the name designates, in the NVD's analysis or, before it, in
// what its CNA declares (A101), at the version (any without one), or without
// fixed version for the latest release. A CVE whose description only
// mentions the name (Shellshock through Apache HTTP Server, a CNA's "end of
// service date" for an asset named date) is dropped. One that lists no
// product that can be compared (awaiting analysis, CNA silent or "n/a") is
// kept.
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
