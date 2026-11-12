package web

import (
	"context"
	"encoding/csv"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/choice"
	"github.com/La-Cizaille-Corp/vigil/internal/clip"
	"github.com/La-Cizaille-Corp/vigil/internal/inventory"
	"github.com/La-Cizaille-Corp/vigil/internal/sources/nvd"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
	"github.com/La-Cizaille-Corp/vigil/internal/versions"
)

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
	q = clip.Prefix(q, 100)
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
			s.Log.Warn("cpe search failed", "err", err)
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
func cpeProducts(entries []nvd.Product, wanted []string, now time.Time) []cpeProduct {
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
		if versionMatches(e.Version, wanted) {
			g.Choices = append(g.Choices, cpeChoice{Title: e.Title, CPE: e.CPE, version: e.Version,
				Use: prefill(g.Title, e.Version, kind, e.CPE, "")})
		}
	}
	for _, g := range out {
		g.Old = !g.Latest.IsZero() && now.Sub(g.Latest) > oldProduct
		if g.Old && len(wanted) == 0 {
			g.Choices = nil // an old name: its versions only distract
			continue
		}
		// Highest versions first: 9.5.5 before 9.5.3 before 8.19.23.
		slices.SortStableFunc(g.Choices, func(a, b cpeChoice) int { return versions.Compare(b.version, a.version) })
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
	return strings.ReplaceAll(nvd.Unescape(e.Vendor)+" "+nvd.Unescape(e.Name), "_", " ")
}

func prefill(name, version, kind, cpe, mode string) string {
	q := url.Values{"name": {name}, "kind": {kind}, "cpe": {cpe}}
	if version != "" {
		q.Set("version", version)
	}
	if mode != "" {
		q.Set("cpe_mode", mode)
	}
	return "/assets/new?" + q.Encode() + "#" + addPackage
}

// prefilledAssetForm is the new-asset form, prefilled from a CPE search. The
// values are only suggestions: they are validated when the form is posted.
func prefilledAssetForm(q url.Values) store.Asset {
	a := defaultAssetForm()
	if q.Get("cpe") == "" {
		return a
	}
	a.Name, a.Version, a.CPE = q.Get("name"), q.Get("version"), q.Get("cpe")
	if k := q.Get("kind"); choice.Has(inventory.Kinds, k) {
		a.Kind = k
	}
	if m := q.Get("cpe_mode"); choice.Has(inventory.CPEModes, m) {
		a.CPEMode = m
	}
	inventory.Normalize(&a)
	return a
}

// --- CSV --------------------------------------------------------------------

// assetCSV exports the inventory (or one project) for spreadsheets.
func (s *Server) assetCSV(w http.ResponseWriter, r *http.Request) {
	assets, err := s.Store.ListAssets(r.Context(), readScope(r))
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
	rows := make([][]string, 0, len(assets))
	for _, a := range assets {
		rows = append(rows, inventory.CSVRow(a))
	}
	s.writeCSV(w, "vigil-inventaire", inventory.CSVColumns, rows)
}

// assetCSVImport adds the assets of a CSV file, all or none. Rows identical
// to an existing asset (same name, version, purl, CPE and project) are
// skipped, so that the same file can be imported again after adding lines to
// it.
func (s *Server) assetCSVImport(w http.ResponseWriter, r *http.Request) {
	file, _, err := r.FormFile("csv") // a body past its bound is refused before (see require)
	if err != nil {
		s.renderNewAsset(w, r, http.StatusBadRequest, defaultAssetForm(), addCSV, "Fichier CSV manquant.")
		return
	}
	defer file.Close()
	records, err := inventory.ReadCSV(file)
	var assets []store.Asset
	if err == nil {
		assets, err = inventory.AssetsFromCSV(records, time.Now())
	}
	if err != nil {
		s.renderNewAsset(w, r, http.StatusBadRequest, defaultAssetForm(), addCSV, "Import CSV refusé, aucun actif ajouté :\n"+err.Error())
		return
	}
	existing, err := s.Store.ListAssets(r.Context(), writeScope(r))
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
	var fresh []store.Asset
	for _, a := range assets {
		if !known[key(a)] {
			known[key(a)] = true
			fresh = append(fresh, a)
		}
	}
	added, skipped := len(fresh), len(assets)-len(fresh)
	// One transaction: a failure in the middle adds none, as the page says.
	if added > 0 {
		_, err := s.Store.CreateAssets(r.Context(), writeScope(r), fresh)
		if msg, refused := outsideGroups(err); refused {
			s.renderNewAsset(w, r, http.StatusBadRequest, defaultAssetForm(), addCSV, "Import CSV refusé, aucun actif ajouté : "+msg)
			return
		}
		if err != nil {
			s.serverError(w, r, err)
			return
		}
	}
	s.audit(r, "csv_import", "added", added, "skipped", skipped)
	if added > 0 {
		s.syncInBackground(0)
	}
	redirect(w, r, "/assets", "csv-imported")
}

// writeCSV sends header and rows as a CSV download named after base and
// today's date: every export goes through it. The separator is a semicolon,
// with decimal commas written by the caller: what Excel expects in French,
// and what inventory.ReadCSV reads back. A failure, a client gone most often,
// stops the writing and is logged once, at the end.
//
// SECURITY: every cell is neutralised here against formula injection
// (inventory.CSVCell): no export can forget it.
func (s *Server) writeCSV(w http.ResponseWriter, base string, header []string, rows [][]string) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-%s.csv"`, base, time.Now().Format("20060102")))
	// A BOM lets spreadsheet software detect UTF-8 (accents in French labels).
	_, _ = w.Write([]byte{0xEF, 0xBB, 0xBF}) // a failure fails the writes below too
	cw := csv.NewWriter(w)
	cw.Comma = ';'
	cells := make([]string, 0, len(header))
	for _, row := range append([][]string{header}, rows...) {
		cells = cells[:0]
		for _, v := range row {
			cells = append(cells, inventory.CSVCell(v))
		}
		if cw.Write(cells) != nil {
			break // the error stays: cw.Error reports it below
		}
	}
	cw.Flush()
	if err := cw.Error(); err != nil {
		s.Log.Warn("csv export failed", "err", err)
	}
}
