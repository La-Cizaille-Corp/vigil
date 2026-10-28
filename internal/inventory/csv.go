package inventory

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/store"
)

// CSVColumns are the columns of an inventory export, in order. An import
// needs a header row with at least "name"; French headers are accepted too.
var CSVColumns = []string{"name", "version", "kind", "criticality", "owner", "project",
	"purl", "ecosystem", "cpe", "cpe_mode", "cpe_from", "track_since", "notes"}

// csvAliases maps French headers to columns.
var csvAliases = map[string]string{
	"nom": "name", "type": "kind", "criticité": "criticality", "criticite": "criticality",
	"responsable": "owner", "projet": "project", "écosystème": "ecosystem", "ecosysteme": "ecosystem",
	"suivi depuis": "track_since",
}

// MaxCSVRows bounds an import.
const MaxCSVRows = 5000

// WriteCSV writes assets with a header row. Cells that a spreadsheet would
// run as a formula are neutralised (see CSVCell).
func WriteCSV(w io.Writer, assets []store.Asset) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(CSVColumns); err != nil {
		return err
	}
	for _, a := range assets {
		row := []string{a.Name, a.Version, a.Kind, a.Criticality, a.Owner, a.Project,
			a.PURL, a.Ecosystem, a.CPE, a.CPEMode, a.CPEFrom, a.TrackSince, a.Notes}
		for i := range row {
			row[i] = CSVCell(row[i])
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// CSVCell protects a value against formula injection: a cell starting with
// =, +, -, @, tab or carriage return is run by spreadsheet software.
func CSVCell(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		return "'" + v
	}
	return v
}

// ReadCSV reads assets from a CSV file (comma, semicolon or tab separated,
// as written by spreadsheet software). Kinds and criticalities may be given
// by code or French label. Without a track_since column, assets get the
// default tracked period; with it, an empty cell means the whole history.
// Every row is checked: on any error, no asset is returned.
func ReadCSV(r io.Reader, now time.Time) ([]store.Asset, error) {
	br := bufio.NewReader(r)
	if bom, _ := br.Peek(3); bytes.Equal(bom, []byte{0xEF, 0xBB, 0xBF}) {
		_, _ = br.Discard(3)
	}
	first, _ := br.Peek(4096)
	header, _, _ := bytes.Cut(first, []byte("\n"))
	cr := csv.NewReader(br)
	cr.Comma = ','
	if n := bytes.Count(header, []byte(";")); n > bytes.Count(header, []byte(",")) {
		cr.Comma = ';'
	} else if bytes.Count(header, []byte("\t")) > bytes.Count(header, []byte(",")) {
		cr.Comma = '\t'
	}
	cr.FieldsPerRecord = -1
	names, err := cr.Read()
	if err != nil {
		return nil, errors.New("fichier CSV vide ou illisible")
	}
	index := map[string]int{}
	for i, h := range names {
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

	var assets []store.Asset
	var errs []error
	for line := 2; ; line++ {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("ligne %d : %w", line, err)
		}
		if len(assets) >= MaxCSVRows {
			return nil, fmt.Errorf("%d lignes au plus", MaxCSVRows)
		}
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
			Notes: cell("notes"), Source: "manual",
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
