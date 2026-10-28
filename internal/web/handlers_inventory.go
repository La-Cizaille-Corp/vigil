package web

import (
	"bytes"
	"cmp"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/La-Cizaille-Corp/vigil/internal/inventory"
	"github.com/La-Cizaille-Corp/vigil/internal/sources/nvd"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
)

// maxCSVBytes bounds an inventory CSV upload.
const maxCSVBytes = 2 << 20

// --- CPE search -------------------------------------------------------------

// cpeChoice is a dictionary entry offered to create an asset.
type cpeChoice struct {
	Title, CPE string
	Use        string // link to the prefilled asset form
	version    string
}

// cpeProduct is one product under one vendor name, as found in the dictionary.
type cpeProduct struct {
	Title        string // product name, without version
	Vendor, Name string
	Whole        cpeChoice   // every version of the product
	Versions     int         // distinct versions referenced
	Latest       time.Time   // when its newest entry was added
	Old          bool        // no entry added for years: the vendor name changed, most likely
	Choices      []cpeChoice // single versions, newest entries first
}

// cpeVendor groups the products found under one vendor name.
type cpeVendor struct {
	Name     string    // vendor field of the CPE
	Title    string    // display name
	Whole    cpeChoice // every product of the vendor
	Old      bool      // every product found is an old name
	Products []cpeProduct
}

const (
	// oldProduct: a product with no entry added for that long is shown as an
	// old name (e.g. elasticsearch:elasticsearch, replaced by elastic).
	oldProduct     = 3 * 365 * 24 * time.Hour
	maxCPEProducts = 12
	maxCPEChoices  = 12
	// maxCPEChoicesEach bounds the versions of each product when several match.
	maxCPEChoicesEach = 5
)

// cpeSearch looks a product up in the NVD CPE dictionary, so that nobody has
// to write a CPE name by hand.
func (s *Server) cpeSearch(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	data := map[string]any{"Query": q}
	if len(q) > 100 {
		q = q[:100]
	}
	if q != "" {
		if s.Syncer == nil || s.Syncer.NVD == nil {
			s.render(w, r, http.StatusServiceUnavailable, "cpe", page{Title: "Trouver un CPE",
				Error: "La recherche dans la NVD n'est pas disponible.", Data: data})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		products, err := s.Syncer.NVD.SearchCPE(ctx, q)
		if err != nil {
			s.Log.Warn("recherche CPE", "err", err)
			s.render(w, r, http.StatusBadGateway, "cpe", page{Title: "Trouver un CPE", Error: err.Error(), Data: data})
			return
		}
		_, versions := nvd.SplitQuery(q)
		data["Vendors"] = cpeVendors(cpeProducts(products, versions, time.Now()))
		data["Searched"] = true
	}
	s.render(w, r, http.StatusOK, "cpe", page{Title: "Trouver un CPE", Data: data})
}

// cpeProducts groups dictionary entries by product and vendor name, current
// names first: those still receiving entries, the most recent first. Versions
// offered are the newest entries, or those of the versions searched for.
func cpeProducts(entries []nvd.Product, versions []string, now time.Time) []cpeProduct {
	entries = slices.Clone(entries)
	slices.SortStableFunc(entries, func(a, b nvd.Product) int { return b.Created.Compare(a.Created) })
	groups := map[string]*cpeProduct{}
	seen := map[string]bool{} // product + version
	var out []*cpeProduct
	for _, e := range entries {
		key := e.Part + ":" + e.Vendor + ":" + e.Name
		kind := "product"
		if e.Part == "o" {
			kind = "os"
		}
		g := groups[key]
		if g == nil {
			title := productTitle(e)
			whole := e.WholeProduct()
			g = &cpeProduct{Title: title, Vendor: e.Vendor, Name: e.Name, Latest: e.Created,
				Whole: cpeChoice{Title: title, CPE: whole, Use: prefill(title, "", kind, whole, "all")}}
			groups[key] = g
			out = append(out, g)
		}
		if e.Version == "*" || e.Version == "-" {
			continue
		}
		if !seen[key+":"+e.Version] {
			seen[key+":"+e.Version] = true
			g.Versions++
		}
		if versionMatches(e.Version, versions) {
			g.Choices = append(g.Choices, cpeChoice{Title: e.Title, CPE: e.CPE, version: e.Version,
				Use: prefill(g.Title, e.Version, kind, e.CPE, "")})
		}
	}
	for _, g := range out {
		g.Old = !g.Latest.IsZero() && now.Sub(g.Latest) > oldProduct
		if g.Old && len(versions) == 0 {
			g.Choices = nil // an old name: its versions only distract
			continue
		}
		// Highest versions first: 9.5.5 before 9.5.3 before 8.19.23.
		slices.SortStableFunc(g.Choices, func(a, b cpeChoice) int { return compareVersions(b.version, a.version) })
		limit := maxCPEChoices
		if len(out) > 1 {
			limit = maxCPEChoicesEach // several products: keep the page short
		}
		g.Choices = g.Choices[:min(len(g.Choices), limit)]
	}
	// Current names first, then old ones; most recent first within each.
	slices.SortStableFunc(out, func(a, b *cpeProduct) int {
		if a.Old != b.Old {
			if a.Old {
				return 1
			}
			return -1
		}
		return b.Latest.Compare(a.Latest)
	})
	result := make([]cpeProduct, 0, min(len(out), maxCPEProducts))
	for _, g := range out[:min(len(out), maxCPEProducts)] {
		result = append(result, *g)
	}
	return result
}

// cpeVendors groups products by vendor, keeping their order: vendors with a
// current product first.
func cpeVendors(products []cpeProduct) []cpeVendor {
	var out []cpeVendor
	index := map[string]int{}
	for _, p := range products {
		i, ok := index[p.Vendor]
		if !ok {
			title := inventory.VendorTitle(p.Vendor)
			whole := nvd.WholeVendor(p.Vendor)
			i = len(out)
			index[p.Vendor] = i
			out = append(out, cpeVendor{Name: p.Vendor, Title: title, Old: true,
				Whole: cpeChoice{Title: title, CPE: whole, Use: prefill(title+" (tous les produits)", "", "product", whole, "all")}})
		}
		out[i].Products = append(out[i].Products, p)
		out[i].Old = out[i].Old && p.Old
	}
	return out
}

// compareVersions orders version strings by their numbers, then their
// letters: 9.5.5 > 9.5.3 > 8.19.23, 10.0 > 9.9, 1.4.0 > 1.4.0-beta1.
func compareVersions(a, b string) int {
	pa, pb := versionParts(a), versionParts(b)
	for i := 0; i < min(len(pa), len(pb)); i++ {
		x, y := pa[i], pb[i]
		xn, xerr := strconv.Atoi(x)
		yn, yerr := strconv.Atoi(y)
		switch {
		case xerr == nil && yerr == nil && xn != yn:
			return cmp.Compare(xn, yn)
		case (xerr == nil) != (yerr == nil):
			if xerr == nil { // a number ranks above a pre-release label
				return 1
			}
			return -1
		case x != y:
			return strings.Compare(x, y)
		}
	}
	// One is a prefix of the other: more numbers rank higher (1.4.1 > 1.4),
	// a pre-release label lower (1.4.0 > 1.4.0-beta1).
	switch {
	case len(pa) > len(pb):
		return extraRank(pa[len(pb)])
	case len(pb) > len(pa):
		return -extraRank(pb[len(pa)])
	}
	return 0
}

func extraRank(part string) int {
	if _, err := strconv.Atoi(part); err == nil {
		return 1
	}
	return -1
}

// versionParts splits a version into runs of digits and runs of letters.
func versionParts(v string) []string {
	var parts []string
	start := -1
	digit := false
	for i, r := range v {
		isDigit, isLetter := r >= '0' && r <= '9', unicode.IsLetter(r)
		if !isDigit && !isLetter {
			if start >= 0 {
				parts = append(parts, v[start:i])
			}
			start = -1
			continue
		}
		if start >= 0 && isDigit != digit {
			parts = append(parts, v[start:i])
			start = -1
		}
		if start < 0 {
			start, digit = i, isDigit
		}
	}
	if start >= 0 {
		parts = append(parts, v[start:])
	}
	return parts
}

// versionMatches reports whether version is one of wanted, or starts with
// one of them ("7.2" matches 7.2.4); any version matches when none is wanted.
func versionMatches(version string, wanted []string) bool {
	if len(wanted) == 0 {
		return true
	}
	for _, w := range wanted {
		if version == w || strings.HasPrefix(version, w+".") || strings.HasPrefix(version, w+"-") {
			return true
		}
	}
	return false
}

// productTitle is the dictionary title of an entry without its version
// ("Microsoft Exchange Server 2019 Cumulative Update 14" → "Microsoft
// Exchange Server"), or the vendor and product names.
func productTitle(e nvd.Product) string {
	if e.Version != "*" && e.Version != "-" {
		if i := strings.Index(e.Title, " "+e.Version); i > 0 {
			return e.Title[:i]
		}
	}
	if e.Title != "" && (e.Version == "*" || e.Version == "-") {
		return e.Title
	}
	return strings.ReplaceAll(e.Vendor+" "+e.Name, "_", " ")
}

func prefill(name, version, kind, cpe, mode string) string {
	q := url.Values{"name": {name}, "kind": {kind}, "cpe": {cpe}}
	if version != "" {
		q.Set("version", version)
	}
	if mode != "" {
		q.Set("cpe_mode", mode)
	}
	return "/assets?" + q.Encode() + "#ajouter"
}

// prefilledAssetForm is the new-asset form, prefilled from a CPE search. The
// values are only suggestions: they are validated when the form is posted.
func prefilledAssetForm(q url.Values) store.Asset {
	a := defaultAssetForm()
	if q.Get("cpe") == "" {
		return a
	}
	a.Name, a.Version, a.CPE = q.Get("name"), q.Get("version"), q.Get("cpe")
	if k := q.Get("kind"); inventory.Label(inventory.Kinds, k) != k {
		a.Kind = k
	}
	if m := q.Get("cpe_mode"); inventory.Label(inventory.CPEModes, m) != m {
		a.CPEMode = m
	}
	inventory.Normalize(&a)
	return a
}

// --- CSV --------------------------------------------------------------------

// assetCSV exports the inventory (or one project) for spreadsheets.
func (s *Server) assetCSV(w http.ResponseWriter, r *http.Request) {
	assets, err := s.Store.ListAssets(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	project := r.URL.Query().Get("project")
	if project != "" {
		var kept []store.Asset
		for _, a := range assets {
			if a.Project == project {
				kept = append(kept, a)
			}
		}
		assets = kept
	}
	cw := csvDownload(w, "vigil-inventaire")
	_ = cw.Write(inventory.CSVColumns)
	for _, a := range assets {
		_ = cw.Write(inventory.CSVRow(a))
	}
	cw.Flush()
	if err := cw.Error(); err != nil {
		s.Log.Warn("export CSV", "err", err)
	}
}

// assetCSVImport adds the assets of a CSV file. Rows identical to an existing
// asset (same name, version, purl, CPE and project) are skipped, so that the
// same file can be imported again after adding lines to it.
func (s *Server) assetCSVImport(w http.ResponseWriter, r *http.Request) {
	file, _, err := r.FormFile("csv") // body bounded by limitBody
	if err != nil {
		s.renderAssets(w, r, http.StatusBadRequest, defaultAssetForm(), "Fichier CSV manquant ou trop volumineux (2 Mo max).")
		return
	}
	defer file.Close()
	records, err := readCSV(file)
	var assets []store.Asset
	if err == nil {
		assets, err = inventory.AssetsFromCSV(records, time.Now())
	}
	if err != nil {
		s.renderAssets(w, r, http.StatusBadRequest, defaultAssetForm(), "Import CSV refusé, aucun actif ajouté : "+err.Error())
		return
	}
	existing, err := s.Store.ListAssets(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	key := func(a store.Asset) string {
		return strings.ToLower(strings.Join([]string{a.Name, a.Version, a.PURL, a.CPE, a.Project}, "\x00"))
	}
	known := map[string]bool{}
	for _, a := range existing {
		known[key(a)] = true
	}
	added, skipped := 0, 0
	for _, a := range assets {
		if known[key(a)] {
			skipped++
			continue
		}
		known[key(a)] = true
		if _, err := s.Store.CreateAsset(r.Context(), a); err != nil {
			s.serverError(w, r, err)
			return
		}
		added++
	}
	sess, _ := sessionFrom(r.Context())
	s.audit(r, sess.User.ID, "csv_import", fmt.Sprintf("+%d, %d déjà présents", added, skipped))
	if added > 0 {
		go s.runSync()
	}
	redirect(w, r, "/assets", "csv-imported")
}

// readCSV reads a CSV file as written by spreadsheet software: optional
// UTF-8 BOM, comma, semicolon (Excel in French) or tab separated.
func readCSV(r io.Reader) ([][]string, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxCSVBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxCSVBytes {
		return nil, errors.New("fichier supérieur à 2 Mo")
	}
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
	header, _, _ := bytes.Cut(data, []byte("\n"))
	cr := csv.NewReader(bytes.NewReader(data))
	commas := bytes.Count(header, []byte(","))
	switch {
	case bytes.Count(header, []byte(";")) > commas:
		cr.Comma = ';'
	case bytes.Count(header, []byte("\t")) > commas:
		cr.Comma = '\t'
	}
	cr.FieldsPerRecord = -1 // short rows are allowed, missing cells are empty
	records, err := cr.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("fichier CSV illisible : %w", err)
	}
	return records, nil
}

// csvDownload starts a CSV download named after base and today's date. The
// separator is a semicolon, with decimal commas: what Excel expects in French,
// and what the import reads back.
func csvDownload(w http.ResponseWriter, base string) *csv.Writer {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-%s.csv"`, base, time.Now().Format("20060102")))
	// A BOM lets spreadsheet software detect UTF-8 (accents in French labels).
	_, _ = w.Write([]byte{0xEF, 0xBB, 0xBF})
	cw := csv.NewWriter(w)
	cw.Comma = ';'
	return cw
}
