package inventory

import (
	"bytes"
	"encoding/csv"
	"slices"
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
	rows := [][]string{CSVColumns}
	for _, a := range in {
		rows = append(rows, CSVRow(a))
	}
	records, err := ReadCSV(strings.NewReader(writeCSV(t, rows...)))
	if err != nil {
		t.Fatal(err)
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

// An import refused says what to write instead: the values accepted, one
// error a line, each with its line number (audit UX 7.3, A88).
func TestCSVErrorsSayWhatToWrite(t *testing.T) {
	_, err := AssetsFromCSV([][]string{{"name", "kind", "criticality", "purl"},
		{"lodash", "librairie", "énorme", "pkg:npm"}, {"", "Paquet"}}, time.Now())
	if err == nil {
		t.Fatal("accepted")
	}
	want := []string{
		"ligne 2 (lodash) : type « librairie » inconnu : Paquet / dépendance, Technologie, Produit ou Système d'exploitation attendu",
		"ligne 2 (lodash) : criticité « énorme » inconnue : Faible, Moyenne, Haute ou Critique attendue",
		"ligne 2 (lodash) : purl incomplet : pkg:type/nom@version attendu, par exemple pkg:npm/lodash@4.17.21",
		"ligne 3 : le nom est obligatoire",
	}
	if got := strings.Split(err.Error(), "\n"); !slices.Equal(got, want) {
		t.Errorf("errors:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	// The short words of the labels are accepted, as the codes are.
	out, err := AssetsFromCSV([][]string{{"name", "kind"}, {"lodash", "Paquet"}, {"debian", "OS"}, {"x", "dépendance"}}, time.Now())
	if err != nil || out[0].Kind != "package" || out[1].Kind != "os" || out[2].Kind != "package" {
		t.Errorf("short labels: %+v, %v", out, err)
	}

	// A file that is not CSV says where, in French.
	if _, err := ReadCSV(strings.NewReader("name;notes\nlodash;a \"b\" c\n")); err == nil ||
		err.Error() != "fichier CSV illisible, ligne 2 : guillemet dans une cellule qui ne commence pas par un guillemet" {
		t.Errorf("bare quote: %v", err)
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
		"a, -b":                "a, '-b", // a spreadsheet that trims cells drops the space
		"prod, =1+1":           "prod, '=1+1",
		"a,  -b":               "a,  '-b",
		"x\n =1":               "x\n '=1",
		" =1":                  " '=1",
		"voir\n=1+1":           "voir\n'=1+1",
		"a\r@SUM(A1)":          "a\r'@SUM(A1)",
		"a;\t=b":               "a;'\t'=b",
		"'=1":                  "''=1", // so that the import gives back the apostrophe
		", '=1":                ", ''=1",
		"2.0 - 2.5":            "2.0 - 2.5", // a space alone starts no cell
		"a = b":                "a = b",
		"x @y":                 "x @y",
		"Apache - HTTP, +1":    "Apache - HTTP, '+1",
		"l'actif 'principal'":  "l'actif 'principal'",
		"option '--force'":     "option '--force'",
		"Überflow;=x":          "Überflow;'=x",
	} {
		if got := CSVCell(in); got != want {
			t.Errorf("CSVCell(%q) = %q, want %q", in, got, want)
		}
		if got := csvValue(want); got != in {
			t.Errorf("csvValue(%q) = %q, want %q", want, got, in)
		}
	}
}

// writeCSV writes rows as the exports do (web.writeCSV): semicolons, every
// cell neutralised by CSVCell.
func writeCSV(t *testing.T, rows ...[]string) string {
	t.Helper()
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	w.Comma = ';'
	for _, row := range rows {
		cells := make([]string, len(row))
		for i, v := range row {
			cells[i] = CSVCell(v)
		}
		if err := w.Write(cells); err != nil {
			t.Fatal(err)
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// An export opened by a spreadsheet that splits on another separator than
// the file's, or on line breaks, and maybe trims cells, has no cell starting
// a formula. Splitting on spaces is not covered (see cellBreaks).
func TestCSVCellOtherSeparators(t *testing.T) {
	notes := "voir ticket\n=HYPERLINK(\"https://evil.example\",\"x\")\r+1 ; -2,@3\t=4,  =5\n =6 2.0 - 2.5"
	file := writeCSV(t, CSVRow(store.Asset{Name: "lodash", Notes: notes, Tags: []string{"prod", "=1+1", "-x"}}))
	for _, sep := range []rune{',', ';', '\t'} {
		r := csv.NewReader(strings.NewReader(file))
		r.Comma, r.LazyQuotes, r.FieldsPerRecord, r.TrimLeadingSpace = sep, true, -1, true
		records, err := r.ReadAll()
		if err != nil {
			t.Fatalf("separator %q: %v", sep, err)
		}
		for _, rec := range records {
			for _, cell := range rec {
				if cell != "" && strings.ContainsRune(formulaTriggers, rune(cell[0])) {
					t.Errorf("separator %q: cell %q starts a formula\nfile: %q", sep, cell, file)
				}
			}
		}
	}
	if got := writeCSV(t, CSVRow(store.Asset{Tags: []string{"prod", "=1+1"}})); !strings.HasSuffix(got, ";prod, '=1+1\n") {
		t.Errorf("tags cell: %q", got)
	}
}

// An export read back by the import gives the exported values, apostrophes
// and formulas included: the import removes exactly what the export adds.
func TestCSVExportImportExact(t *testing.T) {
	in := store.Asset{Name: "@scope/pkg", Kind: "package", Criticality: "medium", Owner: "équipe; -sécurité",
		Project: "+projet", Notes: "a;-b\nvoir ticket\n=HYPERLINK(\"https://evil.example\")\n'=déjà neutralisé, l'actif 'principal', option '--force'" +
			"\n =1 et a,  -b, , '=2\n2.0 - 2.5, a = b, x @y",
		Tags: []string{"prod", "=1+1", "-x", "@équipe", "'-y"}}
	r := csv.NewReader(strings.NewReader(writeCSV(t, CSVColumns, CSVRow(in))))
	r.Comma = ';'
	records, err := r.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	out, err := AssetsFromCSV(records, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	got := out[0]
	if got.Name != in.Name || got.Owner != in.Owner || got.Project != in.Project || got.Notes != in.Notes ||
		!slices.Equal(got.Tags, in.Tags) {
		t.Errorf("round trip:\n got %q %q %q %q %q\nwant %q %q %q %q %q", got.Name, got.Owner, got.Project, got.Notes, got.Tags,
			in.Name, in.Owner, in.Project, in.Notes, in.Tags)
	}
}

// A file is read with or without the byte order mark that spreadsheet
// software on Windows puts in front, and with the separator its header uses.
func TestReadCSV(t *testing.T) {
	want := [][]string{{"name", "version"}, {"lodash", "4.17.15"}, {"nginx"}}
	for name, file := range map[string]string{
		"semicolons":         "name;version\nlodash;4.17.15\nnginx\n",
		"semicolons and BOM": "\xef\xbb\xbfname;version\nlodash;4.17.15\nnginx\n",
		"commas and BOM":     "\xef\xbb\xbfname,version\r\nlodash,4.17.15\r\nnginx\r\n",
		"tabs":               "name\tversion\nlodash\t4.17.15\nnginx\n",
	} {
		got, err := ReadCSV(strings.NewReader(file))
		if err != nil || !slices.EqualFunc(got, want, slices.Equal) {
			t.Errorf("%s: %q, %v", name, got, err)
		}
	}
	if _, err := ReadCSV(strings.NewReader("name\n" + strings.Repeat("x", MaxCSVBytes))); err == nil || err.Error() != "fichier supérieur à 2 Mo" {
		t.Errorf("file past the bound: %v", err)
	}
	if _, err := ReadCSV(strings.NewReader("name;notes\nlodash;\"open quote\n")); err == nil || !strings.HasPrefix(err.Error(), "fichier CSV illisible") {
		t.Errorf("unreadable file: %v", err)
	}
	// What the exports write, ReadCSV reads back.
	rows := [][]string{{"lodash", "a;b\n\"c\""}}
	if got, err := ReadCSV(strings.NewReader(writeCSV(t, append([][]string{{"name", "notes"}}, rows...)...))); err != nil ||
		len(got) != 2 || got[0][0] != "name" || !slices.Equal(got[1], rows[0]) {
		t.Errorf("written then read: %q, %v", got, err)
	}
}
