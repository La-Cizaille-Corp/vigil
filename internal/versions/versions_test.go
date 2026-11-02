package versions

import "testing"

func TestCompare(t *testing.T) {
	ordered := []string{"10.0", "9.5.5", "9.5.3", "8.19.23", "1.4.1", "1.4.0", "1.4.0-rc1", "1.4.0-beta1"}
	for i := 0; i+1 < len(ordered); i++ {
		if Compare(ordered[i], ordered[i+1]) <= 0 || Compare(ordered[i+1], ordered[i]) >= 0 {
			t.Errorf("%s should rank above %s", ordered[i], ordered[i+1])
		}
	}
	for _, pair := range [][2]string{ // higher first
		{"22.7R2.3", "22.7"}, {"22.7R2.9", "22.7R2.3"}, {"22.8", "22.7R2.9"}, {"9.5p1", "9.5"},
		{"1.1.1w", "1.1.1"}, {"2.4.0-r1", "2.4.0"}, {"2.0", "2.0a1"}, {"3.0", "3.0-M1"}, {"8u151", "8"},
	} {
		if Compare(pair[0], pair[1]) <= 0 || Compare(pair[1], pair[0]) >= 0 {
			t.Errorf("%s should rank above %s", pair[0], pair[1])
		}
	}
	for _, pair := range [][2]string{{"2019", "2019"}, {"22.8R2", "22.8r2"}} {
		if Compare(pair[0], pair[1]) != 0 {
			t.Errorf("%s and %s should be equal", pair[0], pair[1])
		}
	}
}

func TestRangeHolds(t *testing.T) {
	cases := []struct {
		r    Range
		v    string
		want bool
	}{
		{Range{Start: "2.4.0", Fixed: "2.4.69"}, "2.4.68", true},
		{Range{Start: "2.4.0", Fixed: "2.4.69"}, "2.4.69", false},
		{Range{Start: "2.4.0", Fixed: "2.4.69"}, "2.2.34", false},
		{Range{Fixed: "22.7"}, "22.7R2.3", false},
		{Range{Start: "7.2.0", LastAffected: "7.2.13"}, "7.2.13", true},
		{Range{Start: "7.2.0", StartOpen: true}, "7.2.0", false},
		{Range{Start: "0"}, "99", true},
		{Range{}, "", false},
	}
	for _, c := range cases {
		if got := c.r.Holds(c.v); got != c.want {
			t.Errorf("%+v holds %q = %v, want %v", c.r, c.v, got, c.want)
		}
	}
}
