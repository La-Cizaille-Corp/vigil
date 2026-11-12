package inventory

import (
	"fmt"
	"strings"
	"testing"

	"github.com/La-Cizaille-Corp/vigil/internal/store"
)

func TestNormalizeTakesVersionFromPURL(t *testing.T) {
	a := store.Asset{Name: " lodash ", Kind: "package", PURL: "pkg:npm/lodash@4.17.15?repository_url=x"}
	Normalize(&a)
	if a.Name != "lodash" || a.Version != "4.17.15" || a.Criticality != "medium" {
		t.Fatalf("unexpected asset: %+v", a)
	}
}

func TestNormalizeReadsThePURLVersion(t *testing.T) {
	for purl, want := range map[string]string{
		"pkg:deb/debian/libssl3@1%3A3.0.11-1%7Edeb12u2?distro=debian-12": "1:3.0.11-1~deb12u2",
		"pkg:npm/@babel/core@7.0.0":                                      "7.0.0",
		"pkg:npm/@babel/core":                                            "",
		"pkg:npm/lodash@LATEST":                                          Latest,
	} {
		a := store.Asset{PURL: purl}
		Normalize(&a)
		if a.Version != want {
			t.Errorf("version of %s = %q, want %q", purl, a.Version, want)
		}
	}
}

// The Version field overrides the purl: an edit of the purl alone must bring
// it along, or that edit would have no effect.
func TestFollowPURL(t *testing.T) {
	old := store.Asset{PURL: "pkg:npm/lodash@4.17.15", Version: "4.17.15"}
	cases := []struct {
		name, purl, version, want string
	}{
		{"purl seul", "pkg:npm/lodash@4.17.21", "4.17.15", "4.17.21"},
		{"version seule", "pkg:npm/lodash@4.17.15", "4.17.21", "4.17.21"},
		{"les deux, différents", "pkg:npm/lodash@4.17.20", "4.17.21", "4.17.21"},
		{"les deux, identiques", "pkg:npm/lodash@4.17.21", "4.17.21", "4.17.21"},
		{"rien", "pkg:npm/lodash@4.17.15", "4.17.15", "4.17.15"},
		{"version retirée du purl", "pkg:npm/lodash", "4.17.15", "4.17.15"},
		{"latest dans le purl", "pkg:npm/lodash@LATEST", "4.17.15", Latest},
	}
	for _, c := range cases {
		a := store.Asset{PURL: c.purl, Version: c.version}
		FollowPURL(&a, old)
		if a.Version != c.want {
			t.Errorf("%s: version = %q, want %q", c.name, a.Version, c.want)
		}
	}

	// A version already overridden by an earlier edit: the purl can still move it.
	a := store.Asset{PURL: "pkg:npm/lodash@4.17.30", Version: "4.17.21"}
	FollowPURL(&a, store.Asset{PURL: "pkg:npm/lodash@4.17.15", Version: "4.17.21"})
	if a.Version != "4.17.30" {
		t.Errorf("version = %q, want 4.17.30", a.Version)
	}
}

// A purl and a Version field that disagree: the page says which one is
// checked, the field (A63).
func TestCheckedVersion(t *testing.T) {
	for _, c := range []struct {
		purl, version, want string
	}{
		{"pkg:deb/debian/libssl3@3.0.11-1~deb12u2", "3.0.19-1~deb12u2", "3.0.19-1~deb12u2"},
		{"pkg:deb/debian/libssl3@3.0.19-1~deb12u2", "3.0.19-1~deb12u2", ""},
		{"pkg:npm/%40babel/core@7.0.0", "7.0.0", ""}, // the version decoded, not the scope
		{"pkg:npm/lodash", "4.17.15", ""},
		{"", "4.17.15", ""},
	} {
		if got := CheckedVersion(store.Asset{PURL: c.purl, Version: c.version}); got != c.want {
			t.Errorf("%s with %s: %q, want %q", c.purl, c.version, got, c.want)
		}
	}
}

func TestQueryable(t *testing.T) {
	cases := []struct {
		a    store.Asset
		want bool
	}{
		{store.Asset{PURL: "pkg:npm/lodash@4.17.15"}, true},
		{store.Asset{PURL: "pkg:npm/lodash"}, false}, // no version: would match every advisory
		{store.Asset{PURL: "pkg:npm/@babel/core"}, false},
		{store.Asset{PURL: "pkg:npm/@babel/core@7.0.0"}, true},
		{store.Asset{PURL: "pkg:npm/@babel/core", Version: "7.0.0"}, true},
		{store.Asset{Ecosystem: "npm", Name: "lodash", Version: "1.0.0"}, true},
		{store.Asset{Name: "nginx", Version: "1.24"}, false},
	}
	for _, c := range cases {
		if got := Queryable(c.a); got != c.want {
			t.Errorf("Queryable(%+v) = %v, want %v", c.a, got, c.want)
		}
	}
}

// "latest" is recognised in any case, also as the version of a purl; the
// package queried then has no version.
func TestLatest(t *testing.T) {
	for _, a := range []store.Asset{
		{Name: "lodash", Kind: "package", Ecosystem: "npm", Version: "Latest"},
		{Name: "lodash", Kind: "package", PURL: "pkg:npm/lodash@latest"},
		{Name: "lodash", Kind: "package", PURL: "pkg:npm/lodash@4.17.15", Version: "LATEST"},
	} {
		Normalize(&a)
		if !IsLatest(a) || !Queryable(a) {
			t.Errorf("not latest: %+v", a)
		}
		if p := Package(a); p.PURL != "" && p.PURL != "pkg:npm/lodash" || p.PURL == "" && (p.Name != "lodash" || p.Ecosystem != "npm") {
			t.Errorf("package of %+v: %+v", a, p)
		}
	}
}

func TestByName(t *testing.T) {
	cases := []struct {
		a    store.Asset
		want bool
	}{
		{store.Asset{Name: "Ivanti Connect Secure", Version: "22.7R2"}, true},
		{store.Asset{Name: "FortiOS", Version: Latest}, true},
		{store.Asset{Name: "lodash", Ecosystem: "npm"}, true}, // no version for OSV
		{store.Asset{Name: "lodash", Ecosystem: "npm", Version: "4.17.15"}, false},
		{store.Asset{Name: "lodash", PURL: "pkg:npm/lodash"}, false},
		{store.Asset{Name: "FortiOS", CPE: "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*"}, false},
		{store.Asset{Name: "libc.so.6", Source: "sbom"}, false},
	}
	for _, c := range cases {
		if got := ByName(c.a); got != c.want {
			t.Errorf("ByName(%+v) = %v, want %v", c.a, got, c.want)
		}
	}
}

func TestValidate(t *testing.T) {
	ok := store.Asset{Name: "x", Kind: "package", Criticality: "low"}
	if err := Validate(ok); err != nil {
		t.Fatal(err)
	}
	bad := store.Asset{Name: "", Kind: "rocket", Criticality: "low", PURL: "npm/x"}
	if err := Validate(bad); err == nil {
		t.Fatal("invalid asset accepted")
	}
}

// Only a well-formed CPE 2.3 name is accepted, as nvd.SplitCPE reads it: the
// prefix alone let through CPEs that the NVD refuses at every synchronisation.
func TestValidateCPE(t *testing.T) {
	asset := func(cpe string) store.Asset {
		return store.Asset{Name: "x", Kind: "product", Criticality: "low", CPE: cpe}
	}
	for _, cpe := range []string{"", "cpe:2.3:o:fortinet:fortios:7.2.4:*:*:*:*:*:*:*", "cpe:2.3:*:fortinet:*:*:*:*:*:*:*:*:*",
		`cpe:2.3:a:lemonldap-ng:lemonldap\:\:ng:2.0.16:*:*:*:*:*:*:*`} {
		if err := Validate(asset(cpe)); err != nil {
			t.Errorf("%q refused: %v", cpe, err)
		}
	}
	for _, cpe := range []string{"cpe:2.3:", "cpe:2.3:a:nginx:nginx", "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*",
		"cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*:*", "cpe:2.3:a:nginx::1.24.0:*:*:*:*:*:*:*",
		"cpe:2.3:z:nginx:nginx:1.24.0:*:*:*:*:*:*:*", "cpe:2.3:a:nginx:nginx web:1.24.0:*:*:*:*:*:*:*",
		`cpe:2.3:a:lemonldap-ng:lemonldap::ng:2.0.16:*:*:*:*:*:*:*`} {
		if err := Validate(asset(cpe)); err == nil || !strings.Contains(err.Error(), "CPE invalide : 13 champs attendus") {
			t.Errorf("%q: %v", cpe, err)
		}
	}
}

func TestVendorProduct(t *testing.T) {
	for _, c := range []struct {
		a               store.Asset
		vendor, product string
		whole           bool
	}{
		{store.Asset{CPE: "cpe:2.3:o:fortinet:fortios:7.2.4:*:*:*:*:*:*:*"}, "fortinet", "fortios", false},
		{store.Asset{CPE: "cpe:2.3:*:fortinet:*:*:*:*:*:*:*:*:*"}, "fortinet", "", true},
		{store.Asset{CPE: `cpe:2.3:a:lemonldap-ng:lemonldap\:\:ng:2.0.16:*:*:*:*:*:*:*`}, "lemonldap-ng", `lemonldap\:\:ng`, false},
		{store.Asset{CPE: `cpe:2.3:a:lemonldap-ng:lemonldap\:\:ng:*:*:*:*:*:*:*:*`, PURL: "pkg:npm/other@1"}, "lemonldap-ng", `lemonldap\:\:ng`, false},
		{store.Asset{CPE: "cpe:2.3:bad", PURL: "pkg:npm/lodash@4.17.15"}, "", "lodash", false},
		{store.Asset{PURL: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}, "org.apache.logging.log4j", "log4j-core", false},
		{store.Asset{PURL: "pkg:npm/%40angular/core@17.0.0?x=1"}, "@angular", "core", false},
		{store.Asset{PURL: "pkg:npm/lodash@4.17.15"}, "", "lodash", false},
		// Not properly encoded: kept as written, rather than lost.
		{store.Asset{PURL: "pkg:npm/%zz/core%@1"}, "%zz", "core%", false},
		{store.Asset{Name: "sans identifiant"}, "", "", false},
	} {
		v, p := vendorProduct(c.a)
		if v != c.vendor || p != c.product || WholeVendor(c.a) != c.whole {
			t.Errorf("%+v: %q %q %v", c.a, v, p, WholeVendor(c.a))
		}
	}
}

func TestTags(t *testing.T) {
	got := ParseTags(" Prod, équipe   Web;prod ,, Site de Lyon ")
	if strings.Join(got, "|") != "prod|équipe web|site de lyon" {
		t.Errorf("tags: %q", got)
	}
	a := store.Asset{Name: "x", Kind: "package", Criticality: "low", Tags: []string{strings.Repeat("a", 41)}}
	if Validate(a) == nil {
		t.Error("tag too long accepted")
	}
	a.Tags = make([]string, maxTags+1)
	for i := range a.Tags {
		a.Tags[i] = fmt.Sprint("t", i)
	}
	if Validate(a) == nil {
		t.Error("too many tags accepted")
	}
}

func TestVendorName(t *testing.T) {
	for _, c := range []struct {
		in   store.Asset
		want string
	}{
		{store.Asset{CPE: "cpe:2.3:a:palo_alto_networks:pan-os:*:*:*:*:*:*:*:*"}, "Palo Alto Networks"},
		{store.Asset{CPE: `cpe:2.3:a:lemonldap-ng:lemonldap\:\:ng:*:*:*:*:*:*:*:*`}, "Lemonldap-ng"},
		// A vendor whose name the CPE escapes reads without its backslashes.
		{store.Asset{CPE: `cpe:2.3:a:at\&t:connect_mobile:*:*:*:*:*:*:*:*`}, "At&t"},
		{store.Asset{CPE: `cpe:2.3:*:o\'reilly_media:*:*:*:*:*:*:*:*:*`}, "O'reilly Media"},
		{store.Asset{PURL: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}, "org.apache.logging.log4j"},
		{store.Asset{PURL: "pkg:pypi/django@4.2"}, "Paquets PyPI"},
		{store.Asset{PURL: "pkg:golang/stdlib@1.22.0"}, "Paquets golang"},
		{store.Asset{Name: "manual"}, ""},
	} {
		if got := VendorName(c.in); got != c.want {
			t.Errorf("VendorName(%+v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestPackageOfDistribution(t *testing.T) {
	if got := Package(store.Asset{Name: "Linux Kernel", Ecosystem: "Linux"}); got.Name != "Kernel" || got.Ecosystem != "Linux" {
		t.Errorf("the upstream kernel = %+v", got)
	}
	if got := Package(store.Asset{PURL: "pkg:deb/debian/linux-image-amd64@6.1.76-1?distro=debian-12"}); got.Name != "linux" || got.Ecosystem != "Debian:12" || got.PURL != "" {
		t.Errorf("package of a purl with a release = %+v", got)
	}
	if got := Package(store.Asset{PURL: "pkg:deb/debian/linux-image-amd64@6.1.76-1"}); got.PURL != "pkg:deb/debian/linux" {
		t.Errorf("package of a purl = %+v", got)
	}
	for a, want := range map[*store.Asset]bool{
		{Name: "linux", Ecosystem: "Debian", Version: "6.1.76-1"}:                 true,
		{Name: "linux", Ecosystem: "Debian:12", Version: "6.1.76-1"}:              false,
		{Name: "openssl", PURL: "pkg:deb/debian/openssl@3.0.11"}:                  true,
		{Name: "openssl", PURL: "pkg:deb/debian/openssl@3.0.11?distro=debian-12"}: false,
		{Name: "lodash", PURL: "pkg:npm/lodash@4.17.15"}:                          false,
		{Name: "kernel", Ecosystem: "Red Hat", Version: "5.14.0-362.el9"}:         false,
		{Name: "linux", Ecosystem: "Debian"}:                                      false,
	} {
		if got := WholeDistribution(*a); got != want {
			t.Errorf("WholeDistribution(%+v) = %v", *a, got)
		}
	}
}
