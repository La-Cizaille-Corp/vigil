package web

import (
	"encoding/json"
	"strings"

	"github.com/La-Cizaille-Corp/vigil/internal/store"
)

// fixLine is one affected range of a vulnerability and how it ends.
type fixLine struct {
	Text  string
	Yours bool // the range holds the asset's version
}

// maxFixLines bounds the ranges shown on a finding page.
const maxFixLines = 8

// fixLines reads, in the advisory stored for f, which versions fix it for
// the finding's asset: OSV ranges for a package, NVD configurations for a
// product. The range holding the asset's version comes first.
func fixLines(raw string, f store.Finding) []fixLine {
	var lines []fixLine
	version := f.AssetVersion
	if version == "" {
		version = purlVersion(f.AssetPURL)
	}
	switch {
	case f.AssetPURL != "":
		lines = osvFixes(raw, f.AssetPURL, version)
	case f.AssetCPE != "":
		lines = nvdFixes(raw, f.AssetCPE, version)
	}
	var out, others []fixLine
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
	return out[:min(len(out), maxFixLines)]
}

// purlVersion is the version of a purl: pkg:npm/lodash@4.17.15 → 4.17.15.
func purlVersion(purl string) string {
	_, v, ok := strings.Cut(purl, "@")
	if !ok {
		return ""
	}
	v, _, _ = strings.Cut(v, "?")
	v, _, _ = strings.Cut(v, "#")
	return v
}

// purlBase drops the version and qualifiers: pkg:npm/lodash@4.17.15 → pkg:npm/lodash.
func purlBase(purl string) string {
	base, _, _ := strings.Cut(purl, "@")
	base, _, _ = strings.Cut(base, "?")
	return strings.ToLower(base)
}

// interval is an affected range: from start (included unless startOpen) to
// fixed (excluded) or lastAffected (included).
type interval struct {
	start, fixed, lastAffected string
	startOpen                  bool
}

func (iv interval) holds(v string) bool {
	if v == "" {
		return false
	}
	if iv.start != "" && iv.start != "0" {
		c := compareVersions(v, iv.start)
		if c < 0 || c == 0 && iv.startOpen {
			return false
		}
	}
	switch {
	case iv.fixed != "":
		return compareVersions(v, iv.fixed) < 0
	case iv.lastAffected != "":
		return compareVersions(v, iv.lastAffected) <= 0
	}
	return true
}

func (iv interval) text(prefix string) string {
	from := ""
	if iv.start != "" && iv.start != "0" {
		from = " (affectée à partir de " + iv.start + ")"
		if iv.startOpen {
			from = " (affectée après " + iv.start + ")"
		}
	}
	switch {
	case iv.fixed != "":
		return prefix + "corrigée en " + iv.fixed + from
	case iv.lastAffected != "":
		return prefix + "affectée jusqu'à " + iv.lastAffected + " incluse, sans version corrigée indiquée" + from
	}
	return prefix + "aucune version corrigée indiquée" + from
}

// osvFixes reads the ranges of an OSV advisory for the package of purl.
func osvFixes(raw, purl, version string) []fixLine {
	var doc struct {
		Affected []struct {
			Package struct {
				Ecosystem string `json:"ecosystem"`
				Name      string `json:"name"`
				PURL      string `json:"purl"`
			} `json:"package"`
			Ranges []struct {
				Type   string              `json:"type"`
				Events []map[string]string `json:"events"`
			} `json:"ranges"`
		} `json:"affected"`
	}
	if json.Unmarshal([]byte(raw), &doc) != nil {
		return nil
	}
	want := purlBase(purl)
	var out []fixLine
	for _, a := range doc.Affected {
		if purlBase(a.Package.PURL) != want {
			continue
		}
		for _, r := range a.Ranges {
			if r.Type == "GIT" { // commit hashes, not versions
				continue
			}
			var iv interval
			for _, e := range r.Events {
				switch {
				case e["introduced"] != "":
					iv = interval{start: e["introduced"]}
				case e["fixed"] != "":
					iv.fixed = e["fixed"]
					out = append(out, fixLine{iv.text(""), iv.holds(version)})
					iv = interval{}
				case e["last_affected"] != "":
					iv.lastAffected = e["last_affected"]
					out = append(out, fixLine{iv.text(""), iv.holds(version)})
					iv = interval{}
				}
			}
		}
	}
	return out
}

// nvdFixes reads the CPE ranges of an NVD record for the product of cpe, or
// for every product of the vendor when cpe tracks a whole vendor.
func nvdFixes(raw, cpe, version string) []fixLine {
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
	asset := strings.Split(cpe, ":")
	if json.Unmarshal([]byte(raw), &doc) != nil || len(asset) != 13 {
		return nil
	}
	wholeVendor := asset[4] == "*"
	var out []fixLine
	for _, c := range doc.Configurations {
		for _, n := range c.Nodes {
			for _, m := range n.CPEMatch {
				f := strings.Split(m.Criteria, ":")
				if !m.Vulnerable || len(f) != 13 || f[3] != asset[3] || !wholeVendor && f[4] != asset[4] {
					continue
				}
				iv := interval{start: m.VersionStartIncluding, fixed: m.VersionEndExcluding, lastAffected: m.VersionEndIncluding}
				if m.VersionStartExcluding != "" {
					iv.start, iv.startOpen = m.VersionStartExcluding, true
				}
				if iv.fixed == "" && iv.lastAffected == "" { // one release named in the criteria
					continue
				}
				prefix := ""
				if wholeVendor {
					prefix = f[4] + " : "
				}
				out = append(out, fixLine{iv.text(prefix), !wholeVendor && iv.holds(version)})
			}
		}
	}
	return out
}
