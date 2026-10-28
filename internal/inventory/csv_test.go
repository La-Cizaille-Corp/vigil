package inventory

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/store"
)

func TestCSVRoundTrip(t *testing.T) {
	in := []store.Asset{
		{Name: "lodash", Version: "4.17.15", Kind: "package", Criticality: "high", PURL: "pkg:npm/lodash@4.17.15", TrackSince: "2026-07-01"},
		{Name: "FortiOS", Version: "7.2.4", Kind: "os", Criticality: "critical", CPE: "cpe:2.3:o:fortinet:fortios:7.2.4:*:*:*:*:*:*:*",
			Owner: "réseau", Notes: "=HYPERLINK(\"http://evil\")"},
	}
	var b bytes.Buffer
	if err := WriteCSV(&b, in); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), `"'=HYPERLINK(""http://evil"")"`) {
		t.Errorf("formula not neutralised:\n%s", b.String())
	}
	out, err := ReadCSV(&b, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 || out[0].TrackSince != "2026-07-01" || out[1].TrackSince != "" || out[1].Notes != in[1].Notes ||
		out[1].CPE != in[1].CPE || out[1].Owner != "réseau" {
		t.Errorf("round trip: %+v", out)
	}
}

// A spreadsheet saved as CSV in French: semicolons, BOM, French headers and labels.
func TestCSVFrenchSpreadsheet(t *testing.T) {
	file := "\xef\xbb\xbfNom;Version;Type;Criticité;Responsable;cpe\r\n" +
		"Exchange;2019;Produit;Haute;Messagerie;cpe:2.3:a:microsoft:exchange_server:2019:*:*:*:*:*:*:*\r\n" +
		";;;;;\r\n" +
		"nginx;1.24.0;technologie;moyenne;;\r\n"
	now := time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC)
	out, err := ReadCSV(strings.NewReader(file), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 || out[0].Kind != "product" || out[0].Criticality != "high" || out[1].Kind != "technology" ||
		out[0].TrackSince != DefaultSince(now) || out[0].Source != "manual" {
		t.Errorf("assets: %+v", out)
	}
}

func TestCSVErrors(t *testing.T) {
	for name, file := range map[string]string{
		"no header":    "lodash,4.17.15\n",
		"bad kind":     "name,kind\nlodash,librairie\n",
		"bad purl":     "name,purl\nlodash,npm/lodash\n",
		"empty":        "name\n",
		"quoted error": "name\n\"unterminated\n",
	} {
		if _, err := ReadCSV(strings.NewReader(file), time.Now()); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	_, err := ReadCSV(strings.NewReader("name,kind\nok,os\nbad,librairie\n"), time.Now())
	if err == nil || !strings.Contains(err.Error(), "ligne 3") {
		t.Errorf("line number missing: %v", err)
	}
}
