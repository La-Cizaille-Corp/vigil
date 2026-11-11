package inventory

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/store"
)

// The CSV file itself is read and written by the web package; this file only
// maps rows to assets, so that the inventory package keeps no I/O.

// CSVColumns are the columns of an inventory export, in order. An import
// needs a header row with at least "name"; French headers are accepted too.
var CSVColumns = []string{"name", "version", "kind", "criticality", "owner", "project",
	"purl", "ecosystem", "cpe", "cpe_mode", "cpe_from", "track_since", "notes", "tags"}

// csvAliases maps French headers to columns.
var csvAliases = map[string]string{
	"nom": "name", "type": "kind", "criticité": "criticality", "criticite": "criticality",
	"responsable": "owner", "projet": "project", "écosystème": "ecosystem", "ecosysteme": "ecosystem",
	"suivi depuis": "track_since", "étiquettes": "tags", "etiquettes": "tags",
}

// MaxCSVRows bounds an import.
const MaxCSVRows = 5000

// CSVRow is the export row of an asset, in the order of CSVColumns, with
// every cell neutralised against formula injection (see CSVCell).
func CSVRow(a store.Asset) []string {
	row := []string{a.Name, a.Version, a.Kind, a.Criticality, a.Owner, a.Project,
		a.PURL, a.Ecosystem, a.CPE, a.CPEMode, a.CPEFrom, a.TrackSince, a.Notes, strings.Join(a.Tags, ", ")}
	for i := range row {
		row[i] = CSVCell(row[i])
	}
	return row
}

// formulaTriggers start a formula in spreadsheet software.
const formulaTriggers = "=+-@\t\r"

// cellBreaks are the characters after which a spreadsheet may start a new
// cell or line inside a value: the separators it may split on instead of the
// file's (Excel in French splits on ";", the import dialogs of Excel and
// LibreOffice offer comma, semicolon, tab and space), and line breaks. A space
// also covers a spreadsheet that trims cells: tags are joined with ", ".
const cellBreaks = ",;\t\r\n "

// startsFormula reports whether s, past any apostrophes, starts with a
// formula trigger: the text CSVCell puts an apostrophe in front of.
func startsFormula(s string) bool {
	s = strings.TrimLeft(s, "'")
	return s != "" && strings.IndexByte(formulaTriggers, s[0]) >= 0
}

// CSVCell protects a value against formula injection.
//
// SECURITY: spreadsheet software runs a cell starting with =, +, -, @, tab or
// carriage return, so every place a cell may start (the start of the value
// and the position after each of cellBreaks) gets an apostrophe in front of
// such a character. Apostrophes already there before one are counted in
// (startsFormula), so that the import can remove exactly what was added
// (csvValue). All these characters are ASCII: walking bytes leaves UTF-8 intact.
func CSVCell(v string) string {
	var b strings.Builder
	b.Grow(len(v))
	cellStart := true
	for i := 0; i < len(v); i++ {
		if cellStart && startsFormula(v[i:]) {
			b.WriteByte('\'')
		}
		b.WriteByte(v[i])
		cellStart = strings.IndexByte(cellBreaks, v[i]) >= 0
	}
	return b.String()
}

// csvValue undoes CSVCell: it removes the apostrophe CSVCell put at a cell
// start, and only that one, so that an export read back gives the values
// that were exported.
func csvValue(v string) string {
	var b strings.Builder
	b.Grow(len(v))
	cellStart := true
	for i := 0; i < len(v); i++ {
		if cellStart && v[i] == '\'' && startsFormula(v[i+1:]) {
			cellStart = false // the character it protected is in the same cell
			continue
		}
		b.WriteByte(v[i])
		cellStart = strings.IndexByte(cellBreaks, v[i]) >= 0
	}
	return b.String()
}

// AssetsFromCSV turns CSV records (header row first) into assets. Kinds and
// criticalities may be given by code or French label. Without a track_since
// column, assets get the default tracked period; with it, an empty cell
// means the whole history. Every row is checked: on any error, no asset is
// returned, and the error gives the line numbers.
func AssetsFromCSV(records [][]string, now time.Time) ([]store.Asset, error) {
	if len(records) == 0 {
		return nil, errors.New("fichier CSV vide")
	}
	index := map[string]int{}
	for i, h := range records[0] {
		h = strings.ToLower(strings.TrimSpace(h))
		if alias, ok := csvAliases[h]; ok {
			h = alias
		}
		index[h] = i
	}
	if _, ok := index["name"]; !ok {
		return nil, errors.New("la première ligne doit nommer les colonnes, dont « name » (ou « nom »)")
	}
	_, hasSince := index["track_since"]
	if len(records)-1 > MaxCSVRows {
		return nil, fmt.Errorf("%d lignes au plus", MaxCSVRows)
	}

	var assets []store.Asset
	var errs []error
	for n, rec := range records[1:] {
		line := n + 2
		cell := func(col string) string {
			if i, ok := index[col]; ok && i < len(rec) {
				return strings.TrimSpace(csvValue(rec[i]))
			}
			return ""
		}
		if strings.TrimSpace(strings.Join(rec, "")) == "" {
			continue // blank line
		}
		a := store.Asset{
			Name: cell("name"), Version: cell("version"), Owner: cell("owner"), Project: cell("project"),
			PURL: cell("purl"), Ecosystem: cell("ecosystem"), CPE: cell("cpe"), CPEFrom: cell("cpe_from"),
			Notes: cell("notes"), Source: "manual", Tags: ParseTags(cell("tags")),
			Kind:        optionValue(Kinds, cell("kind"), "package"),
			Criticality: optionValue(Criticalities, cell("criticality"), "medium"),
			CPEMode:     optionValue(CPEModes, cell("cpe_mode"), ""),
			TrackSince:  DefaultSince(now),
		}
		if hasSince {
			a.TrackSince = cell("track_since")
		}
		Normalize(&a)
		if err := Validate(a); err != nil {
			errs = append(errs, fmt.Errorf("ligne %d (%s) : %w", line, a.Name, err))
			if len(errs) == 10 {
				errs = append(errs, errors.New("…"))
				break
			}
			continue
		}
		assets = append(assets, a)
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	if len(assets) == 0 {
		return nil, errors.New("aucun actif dans le fichier")
	}
	return assets, nil
}

// optionValue accepts a code or a French label, case-insensitively; an
// empty cell gives def. An unknown value is returned as is, so that
// Validate reports it.
func optionValue(options []Option, v, def string) string {
	if v == "" {
		return def
	}
	for _, o := range options {
		if strings.EqualFold(v, o.Value) || strings.EqualFold(v, o.Label) {
			return o.Value
		}
	}
	return v
}
