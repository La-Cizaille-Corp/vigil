package inventory

import (
	"strings"
	"testing"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/store"
)

func TestCSVRowRoundTrip(t *testing.T) {
	in := []store.Asset{
		{Name: "lodash", Version: "4.17.15", Kind: "package", Criticality: "high", PURL: "pkg:npm/lodash@4.17.15", TrackSince: "2026-07-01"},
		{Name: "FortiOS", Version: "7.2.4", Kind: "os", Criticality: "critical", CPE: "cpe:2.3:o:fortinet:fortios:7.2.4:*:*:*:*:*:*:*",
			Owner: "réseau", Notes: "=HYPERLINK(\"http://evil\")"},
	}
	records := [][]string{CSVColumns}
	for _, a := range in {
		records = append(records, CSVRow(a))
	}
	if got := records[2][12]; got != `'=HYPERLINK("http://evil")` {
		t.Errorf("formula not neutralised: %q", got)
	}
	out, err := AssetsFromCSV(records, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 || out[0].TrackSince != "2026-07-01" || out[1].TrackSince != "" || out[1].Notes != in[1].Notes ||
		out[1].CPE != in[1].CPE || out[1].Owner != "réseau" {
		t.Errorf("round trip: %+v", out)
	}
}

// A spreadsheet saved in French: French headers and labels, blank lines.
func TestCSVFrenchHeaders(t *testing.T) {
	records := [][]string{
		{"Nom", "Version", "Type", "Criticité", "Responsable", "cpe"},
		{"Exchange", "2019", "Produit", "Haute", "Messagerie", "cpe:2.3:a:microsoft:exchange_server:2019:*:*:*:*:*:*:*"},
		{"", "", "", "", "", ""},
		{"nginx", "1.24.0", "technologie", "moyenne"},
	}
	now := time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC)
	out, err := AssetsFromCSV(records, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 || out[0].Kind != "product" || out[0].Criticality != "high" || out[1].Kind != "technology" ||
		out[0].TrackSince != DefaultSince(now) || out[0].Source != "manual" {
		t.Errorf("assets: %+v", out)
	}
}

func TestCSVErrors(t *testing.T) {
	for name, records := range map[string][][]string{
		"no header": {{"lodash", "4.17.15"}},
		"bad kind":  {{"name", "kind"}, {"lodash", "librairie"}},
		"bad purl":  {{"name", "purl"}, {"lodash", "npm/lodash"}},
		"empty":     {{"name"}},
		"nothing":   nil,
	} {
		if _, err := AssetsFromCSV(records, time.Now()); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	_, err := AssetsFromCSV([][]string{{"name", "kind"}, {"ok", "os"}, {"bad", "librairie"}}, time.Now())
	if err == nil || !strings.Contains(err.Error(), "ligne 3") {
		t.Errorf("line number missing: %v", err)
	}
}

func TestCSVCell(t *testing.T) {
	for in, want := range map[string]string{
		"lodash":               "lodash",
		"=1+2":                 "'=1+2",
		"-2 versions":          "'-2 versions",
		"Overflow;=1+cmd|' /C": "Overflow;'=1+cmd|' /C",
		"a,@SUM(A1)":           "a,'@SUM(A1)",
		"x\t+1":                "x\t'+1",
		"a, -b":                "a, -b", // a space before the sign: text for spreadsheets
	} {
		if got := CSVCell(in); got != want {
			t.Errorf("CSVCell(%q) = %q, want %q", in, got, want)
		}
	}
}
