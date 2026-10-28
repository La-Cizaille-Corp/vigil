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

func TestQueryable(t *testing.T) {
	cases := []struct {
		a    store.Asset
		want bool
	}{
		{store.Asset{PURL: "pkg:npm/lodash@4.17.15"}, true},
		{store.Asset{PURL: "pkg:npm/lodash"}, false}, // no version: would match every advisory
		{store.Asset{Ecosystem: "npm", Name: "lodash", Version: "1.0.0"}, true},
		{store.Asset{Name: "nginx", Version: "1.24"}, false},
	}
	for _, c := range cases {
		if got := Queryable(c.a); got != c.want {
			t.Errorf("Queryable(%+v) = %v, want %v", c.a, got, c.want)
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

func TestVendorProduct(t *testing.T) {
	for _, c := range []struct {
		a               store.Asset
		vendor, product string
		whole           bool
	}{
		{store.Asset{CPE: "cpe:2.3:o:fortinet:fortios:7.2.4:*:*:*:*:*:*:*"}, "fortinet", "fortios", false},
		{store.Asset{CPE: "cpe:2.3:*:fortinet:*:*:*:*:*:*:*:*:*"}, "fortinet", "", true},
		{store.Asset{PURL: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}, "org.apache.logging.log4j", "log4j-core", false},
		{store.Asset{PURL: "pkg:npm/%40angular/core@17.0.0?x=1"}, "@angular", "core", false},
		{store.Asset{PURL: "pkg:npm/lodash@4.17.15"}, "", "lodash", false},
		{store.Asset{Name: "sans identifiant"}, "", "", false},
	} {
		v, p := VendorProduct(c.a)
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
	a.Tags = make([]string, MaxTags+1)
	for i := range a.Tags {
		a.Tags[i] = fmt.Sprint("t", i)
	}
	if Validate(a) == nil {
		t.Error("too many tags accepted")
	}
}
