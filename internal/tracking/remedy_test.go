package tracking_test

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/La-Cizaille-Corp/vigil/internal/sources/osv"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
	"github.com/La-Cizaille-Corp/vigil/internal/tracking"
)

// The fixed version comes from the stored advisory; the range holding the
// asset's version comes first, the asset's own (yours), and the others follow.
func TestFixLines(t *testing.T) {
	const (
		kernel = `{"affected":[{"package":{"name":"Kernel","ecosystem":"Linux"},"ranges":[
		{"type":"ECOSYSTEM","events":[{"introduced":"5.11.0"},{"fixed":"5.15.223"}]},
		{"type":"ECOSYSTEM","events":[{"introduced":"6.7.0"},{"fixed":"6.12.113"}]}]}]}`
		latest = `{"affected":[{"package":{"purl":"pkg:npm/x"},"ranges":[
		{"type":"SEMVER","events":[{"introduced":"0"},{"last_affected":"1.0"},{"introduced":"2.0"},{"fixed":"2.5"}]},
		{"type":"SEMVER","events":[{"introduced":"3.0"},{"fixed":"3.1"},{"introduced":"4.0"},{"last_affected":"4.2"}]}]}]}`
		osvRaw = `{"affected":[{"package":{"purl":"pkg:maven/org.apache.logging.log4j/log4j-core"},"ranges":[
		{"type":"ECOSYSTEM","events":[{"introduced":"2.4"},{"fixed":"2.12.2"}]},
		{"type":"ECOSYSTEM","events":[{"introduced":"2.13.0"},{"fixed":"2.15.0"}]},
		{"type":"GIT","events":[{"introduced":"0"},{"fixed":"abc123"}]}]},
		{"package":{"purl":"pkg:maven/other/lib"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"9.9"}]}]}]}`
		nvdRaw = `{"configurations":[{"nodes":[{"cpeMatch":[
		{"vulnerable":true,"criteria":"cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*","versionStartIncluding":"7.2.0","versionEndExcluding":"7.2.5"},
		{"vulnerable":true,"criteria":"cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*","versionStartIncluding":"7.0.0","versionEndIncluding":"7.0.12"},
		{"vulnerable":true,"criteria":"cpe:2.3:a:fortinet:fortiproxy:*:*:*:*:*:*:*:*","versionEndExcluding":"7.0.10"}]}]}]}`
		openRaw = `{"affected":[{"package":{"purl":"pkg:npm/left"},"ranges":[
		{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.0"}]},
		{"type":"SEMVER","events":[{"introduced":"2.0.0"}]}]}]}`
		nvdOpen = `{"configurations":[{"nodes":[{"cpeMatch":[
		{"vulnerable":true,"criteria":"cpe:2.3:a:ivanti:connect_secure:*:*:*:*:*:*:*:*","versionEndExcluding":"22.7"},
		{"vulnerable":true,"criteria":"cpe:2.3:a:ivanti:connect_secure:*:*:*:*:*:*:*:*","versionStartIncluding":"22.7"},
		{"vulnerable":true,"criteria":"cpe:2.3:a:ivanti:policy_secure:*:*:*:*:*:*:*:*","versionEndExcluding":"22.8"}]}]}]}`
		nvdRelease = `{"configurations":[{"nodes":[{"cpeMatch":[
		{"vulnerable":true,"criteria":"cpe:2.3:a:ivanti:connect_secure:*:*:*:*:*:*:*:*","versionEndExcluding":"22.7"},
		{"vulnerable":true,"criteria":"cpe:2.3:a:ivanti:connect_secure:22.7:r2.2:*:*:*:*:*:*"},
		{"vulnerable":true,"criteria":"cpe:2.3:a:ivanti:connect_secure:22.7:r2.3:*:*:*:*:*:*"}]}]}]}`
	)
	for _, c := range []struct {
		name  string
		raw   string
		asset store.Asset
		yours bool     // the first line is the asset's own
		want  []string // the lines, in order
	}{
		// The upstream kernel is a package like any other: its ranges from OSV.
		{"kernel", kernel, store.Asset{Name: "Linux Kernel", Ecosystem: "Linux", Version: "6.8.1"}, true,
			[]string{"corrigée en 6.12.113 (affectée à partir de 6.7.0)", "corrigée en 5.15.223 (affectée à partir de 5.11.0)"}},
		// At its latest release, an asset is in the last interval of a range
		// that ends affected, the rule of osv.Vuln.Unfixed: an interval affected
		// up to a version and followed by a fixed one is not its own.
		{"OSV, ranges of the latest release", latest, store.Asset{PURL: "pkg:npm/x", Version: "latest"}, true, []string{
			"affectée jusqu'à 4.2 incluse, sans version corrigée indiquée (affectée à partir de 4.0)",
			"affectée jusqu'à 1.0 incluse, sans version corrigée indiquée",
			"corrigée en 2.5 (affectée à partir de 2.0)", "corrigée en 3.1 (affectée à partir de 3.0)"}},
		{"OSV", osvRaw, store.Asset{PURL: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}, true,
			[]string{"corrigée en 2.15.0 (affectée à partir de 2.13.0)", "corrigée en 2.12.2 (affectée à partir de 2.4)"}},
		{"NVD", nvdRaw, store.Asset{CPE: "cpe:2.3:o:fortinet:fortios:7.2.4:*:*:*:*:*:*:*", Version: "7.2.4"}, true, []string{
			"corrigée en 7.2.5 (affectée à partir de 7.2.0)",
			"affectée jusqu'à 7.0.12 incluse, sans version corrigée indiquée (affectée à partir de 7.0.0)"}},
		{"whole vendor", nvdRaw, store.Asset{CPE: "cpe:2.3:*:fortinet:*:*:*:*:*:*:*:*:*"}, false, []string{
			"fortios : corrigée en 7.2.5 (affectée à partir de 7.2.0)",
			"fortios : affectée jusqu'à 7.0.12 incluse, sans version corrigée indiquée (affectée à partir de 7.0.0)",
			"fortiproxy : corrigée en 7.0.10"}},
		// At the latest release, the ranges without a fixed version are the
		// asset's: an open one for OSV, an unbounded one for the NVD.
		{"OSV latest", openRaw, store.Asset{PURL: "pkg:npm/left", Version: "latest"}, true,
			[]string{"aucune version corrigée indiquée (affectée à partir de 2.0.0)", "corrigée en 1.2.0"}},
		{"OSV open range", openRaw, store.Asset{PURL: "pkg:npm/left@1.1.0"}, true,
			[]string{"corrigée en 1.2.0", "aucune version corrigée indiquée (affectée à partir de 2.0.0)"}},
		{"by name, latest", nvdOpen, store.Asset{Name: "Ivanti Connect Secure", Version: "latest", Kind: "product"}, true,
			[]string{"connect_secure : aucune version corrigée indiquée (affectée à partir de 22.7)", "connect_secure : corrigée en 22.7"}},
		{"by name", nvdOpen, store.Asset{Name: "Connect Secure", Version: "22.6R1", Kind: "product"}, true,
			[]string{"connect_secure : corrigée en 22.7", "connect_secure : aucune version corrigée indiquée (affectée à partir de 22.7)"}},
		{"release named", nvdRelease, store.Asset{Name: "Connect Secure", Version: "22.7R2.3", Kind: "product"}, true, []string{
			"connect_secure : version 22.7 r2.3 citée comme affectée, sans version corrigée indiquée", "connect_secure : corrigée en 22.7"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			lines := tracking.Fixes(c.raw, c.asset)
			var texts []string
			for i, l := range lines {
				texts = append(texts, l.Text)
				if l.Yours != (c.yours && i == 0) {
					t.Errorf("line %d %q: yours %v", i, l.Text, l.Yours)
				}
			}
			if !slices.Equal(texts, c.want) {
				t.Errorf("lines\n%q\nwant\n%q", texts, c.want)
			}
		})
	}
}

// What the database keeps of an advisory is enough to tell the versions fixing it.
func TestFixLinesAfterCompact(t *testing.T) {
	var v osv.Vuln
	if err := json.Unmarshal([]byte(`{"id":"UBUNTU-CVE-1","affected":[{"package":{"name":"linux","ecosystem":"Ubuntu:22.04:LTS"},
		"versions":["5.15.0-1.1"],"ecosystem_specific":{"binaries":[]},
		"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"5.15.0-3.3"}]}]}]}`), &v); err != nil {
		t.Fatal(err)
	}
	lines := tracking.Fixes(string(v.Compact()), store.Asset{Name: "linux", Ecosystem: "Ubuntu:22.04:LTS", Version: "5.15.0-2.2"})
	if len(lines) != 1 || !lines[0].Yours || !strings.Contains(lines[0].Text, "5.15.0-3.3") {
		t.Errorf("lines = %+v", lines)
	}
}

// The versions fixing a finding are those ending the ranges that hold the
// asset's version; none for an asset kept at its latest release.
func TestFixedIn(t *testing.T) {
	raw := `{"affected":[{"package":{"purl":"pkg:npm/lodash"},"ranges":[
		{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]},
		{"type":"SEMVER","events":[{"introduced":"5.0.0"},{"fixed":"5.0.2"}]},
		{"type":"SEMVER","events":[{"introduced":"6.0.0"}]}]},
		{"package":{"purl":"pkg:npm/lodash-es"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}`
	for _, c := range []struct {
		asset store.Asset
		want  string
	}{
		{store.Asset{PURL: "pkg:npm/lodash@4.17.15"}, "4.17.21"},
		{store.Asset{PURL: "pkg:npm/lodash@4.17.15", Version: "5.0.1"}, "5.0.2"}, // the Version field decides
		{store.Asset{PURL: "pkg:npm/lodash@6.1.0"}, ""},                          // an open range: no fix known
		{store.Asset{PURL: "pkg:npm/lodash", Version: "latest"}, ""},
		{store.Asset{PURL: "pkg:npm/lodash@4.17.21"}, ""}, // not affected: nothing of its own
	} {
		if got := tracking.FixedIn(raw, c.asset); got != c.want {
			t.Errorf("%+v: %q, want %q", c.asset, got, c.want)
		}
	}
	// Several ranges holding the version: each fix once, in order.
	overlap := `{"affected":[{"package":{"purl":"pkg:npm/x"},"ranges":[
		{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.0"}]},
		{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"1.1.5"}]},
		{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.0"}]}]}]}`
	if got := tracking.FixedIn(overlap, store.Asset{PURL: "pkg:npm/x@1.1.0"}); got != "1.2.0, 1.1.5" {
		t.Errorf("overlap: %q", got)
	}
	// A CPE takes the end of the NVD range.
	nvdRaw := `{"configurations":[{"nodes":[{"cpeMatch":[
		{"vulnerable":true,"criteria":"cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*","versionStartIncluding":"7.2.0","versionEndExcluding":"7.2.5"}]}]}]}`
	if got := tracking.FixedIn(nvdRaw, store.Asset{CPE: "cpe:2.3:o:fortinet:fortios:7.2.4:*:*:*:*:*:*:*", Version: "7.2.4"}); got != "7.2.5" {
		t.Errorf("NVD: %q", got)
	}
	if got := tracking.FixedIn("not json", store.Asset{PURL: "pkg:npm/x@1.0.0"}); got != "" {
		t.Errorf("unreadable advisory: %q", got)
	}
}
