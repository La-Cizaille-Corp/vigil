package tracking

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/La-Cizaille-Corp/vigil/internal/inventory"
	"github.com/La-Cizaille-Corp/vigil/internal/sources/nvd"
	"github.com/La-Cizaille-Corp/vigil/internal/sources/osv"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
	"github.com/La-Cizaille-Corp/vigil/internal/versions"
)

// Fix is one affected range of a vulnerability and how it ends.
type Fix struct {
	Text  string
	Fixed string // the version ending the range, "" without one
	Yours bool   // the range holds the asset's version
}

// maxFixes bounds the ranges shown on a finding page, maxFixedIn the versions
// kept as fixing a finding.
const (
	maxFixes   = 8
	maxFixedIn = 3
)

// Fixes reads, in the advisory stored for a finding of asset a, which
// versions fix it: OSV ranges for a package, NVD configurations for a
// product, named by its CPE or by the asset's name. The range holding the
// asset's version comes first; for an asset kept at its latest release, the
// ranges without a fixed version.
func Fixes(raw string, a store.Asset) []Fix {
	var lines []Fix
	version := a.Version
	if version == "" {
		version = osv.PURLVersion(a.PURL)
	}
	switch {
	case a.PURL != "" || inventory.Queryable(a):
		lines = osvFixes(raw, inventory.Package(a), version)
	case a.CPE != "":
		if f, ok := nvd.SplitCPE(a.CPE); ok {
			whole := f[4] == "*"
			if whole && version != inventory.Latest {
				version = "" // the version of no product in particular
			}
			lines = nvdFixes(raw, version, whole, func(m nvd.Match) bool { return m.Vendor == f[3] && (whole || m.Product == f[4]) })
		}
	case inventory.ByName(a):
		lines = nvdFixes(raw, version, true, func(m nvd.Match) bool { return m.Named(a.Name) })
	}
	var out, others []Fix
	seen := map[string]bool{}
	for _, l := range lines {
		if seen[l.Text] {
			continue
		}
		seen[l.Text] = true
		if l.Yours {
			out = append(out, l)
		} else {
			others = append(others, l)
		}
	}
	out = append(out, others...)
	return out[:min(len(out), maxFixes)]
}

// FixedIn returns the versions fixing a finding of asset a: those ending the
// ranges that hold its version. It is "" when the source names none, as for an
// asset kept at its latest release, where those ranges are the open ones.
func FixedIn(raw string, a store.Asset) string {
	var out []string
	for _, f := range Fixes(raw, a) {
		if f.Yours && f.Fixed != "" && !slices.Contains(out, f.Fixed) {
			out = append(out, f.Fixed)
		}
	}
	return strings.Join(out[:min(len(out), maxFixedIn)], ", ")
}

// rangeText describes how a range ends.
func rangeText(r versions.Range, prefix string) string {
	from := ""
	if r.Start != "" && r.Start != "0" {
		from = " (affectée à partir de " + r.Start + ")"
		if r.StartOpen {
			from = " (affectée après " + r.Start + ")"
		}
	}
	switch {
	case r.Fixed != "":
		return prefix + "corrigée en " + r.Fixed + from
	case r.LastAffected != "":
		return prefix + "affectée jusqu'à " + r.LastAffected + " incluse, sans version corrigée indiquée" + from
	}
	return prefix + "aucune version corrigée indiquée" + from
}

// osvFixes reads the ranges of an OSV advisory for a package. At the latest
// release, the ranges without a fixed version are the asset's (see
// osv.Vuln.Unfixed).
func osvFixes(raw string, pkg osv.Package, version string) []Fix {
	var v osv.Vuln
	if json.Unmarshal([]byte(raw), &v) != nil {
		return nil
	}
	latest := version == inventory.Latest
	var out []Fix
	for _, a := range v.For(pkg) {
		for _, r := range a.Ranges {
			for _, iv := range r.Intervals() {
				yours := iv.Holds(version)
				if latest {
					yours = iv.Fixed == ""
				}
				out = append(out, Fix{rangeText(iv, ""), iv.Fixed, yours})
			}
		}
	}
	return out
}

// nvdFixes reads the version ranges of an NVD record for the products kept;
// with several products possible (a whole vendor, an asset named), each line
// names its product. At the latest release, the open ranges are the asset's
// (see nvd.Match.Open).
func nvdFixes(raw, version string, several bool, keep func(nvd.Match) bool) []Fix {
	var out []Fix
	for _, m := range nvd.Matches([]byte(raw)) {
		if !keep(m) {
			continue
		}
		prefix := ""
		if several {
			prefix = m.Product + " : "
		}
		if !m.Ranged() { // one release: shown when it is the asset's
			if version != "" && version != inventory.Latest && m.Affects(version) {
				out = append(out, Fix{prefix + "version " + release(m) + " citée comme affectée, sans version corrigée indiquée", "", true})
			}
			continue
		}
		yours := m.Range.Holds(version)
		if version == inventory.Latest {
			yours = m.Open()
		}
		out = append(out, Fix{rangeText(m.Range, prefix), m.Range.Fixed, yours})
	}
	return out
}

// release names the release of a match: "22.7 r2.3", "2.4.62".
func release(m nvd.Match) string {
	name := nvd.Unescape(m.Version)
	if m.Update != "*" && m.Update != "-" && m.Update != "" {
		name += " " + nvd.Unescape(m.Update)
	}
	return name
}
