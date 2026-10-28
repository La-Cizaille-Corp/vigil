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

// midFieldFormulas neutralises a formula that would start in the middle of a
// field: a spreadsheet that splits lines on another separator than the file's
// (Excel in French splits on ";") starts a new cell after it.
var midFieldFormulas = func() *strings.Replacer {
	var pairs []string
	for _, sep := range []string{",", ";", "\t"} {
		for _, t := range formulaTriggers {
			pairs = append(pairs, sep+string(t), sep+"'"+string(t))
		}
	}
	return strings.NewReplacer(pairs...)
}()

// CSVCell protects a value against formula injection: a cell starting with
// =, +, -, @, tab or carriage return is run by spreadsheet software, so it
// gets a leading apostrophe; so does such a character right after a
// separator inside the value.
func CSVCell(v string) string {
	v = midFieldFormulas.Replace(v)
	if v != "" && strings.ContainsRune(formulaTriggers, rune(v[0])) {
		return "'" + v
	}
	return v
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
				return strings.TrimPrefix(strings.TrimSpace(rec[i]), "'") // undo CSVCell
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
