package inventory

import (
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
