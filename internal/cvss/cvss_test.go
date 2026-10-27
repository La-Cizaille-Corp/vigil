package cvss

import "testing"

func TestBaseScore(t *testing.T) {
	for vector, want := range map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H":                    10.0, // Log4Shell
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H":                    9.8,
		"CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H":                    6.6, // CVE-2020-8203 (lodash)
		"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N":                    6.1, // typical reflected XSS
		"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N":                    5.5,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N":                    0,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P":                9.8, // temporal metrics ignored
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N": Unknown,
		"CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H":                    Unknown,
		"garbage": Unknown,
	} {
		if got := BaseScore(vector); got != want {
			t.Errorf("%s = %v, want %v", vector, got, want)
		}
	}
}

func TestSeverity(t *testing.T) {
	for score, want := range map[float64]string{9.8: "CRITICAL", 7: "HIGH", 5.5: "MEDIUM", 0.1: "LOW", -1: ""} {
		if got := Severity(score); got != want {
			t.Errorf("%v = %q, want %q", score, got, want)
		}
	}
}
