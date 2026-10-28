package web

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

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
}

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
		ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
		defer cancel()
		products, err := s.Syncer.NVD.SearchCPE(ctx, q, 50)
		if err != nil {
			s.Log.Warn("recherche CPE", "err", err)
			s.render(w, r, http.StatusBadGateway, "cpe", page{Title: "Trouver un CPE", Error: err.Error(), Data: data})
			return
		}
		data["Products"], data["Wholes"] = cpeChoices(products)
		data["Searched"] = true
	}
	s.render(w, r, http.StatusOK, "cpe", page{Title: "Trouver un CPE", Data: data})
}

// cpeChoices offers each version found, then each product as a whole.
func cpeChoices(products []nvd.Product) (versions, wholes []cpeChoice) {
	seen := map[string]bool{}
	for _, p := range products {
		kind := "product"
		if p.Part == "o" {
			kind = "os"
		}
		name := strings.TrimSpace(strings.TrimSuffix(p.Title, " "+p.Version))
		if p.Version != "*" && p.Version != "-" {
			versions = append(versions, cpeChoice{Title: p.Title, CPE: p.CPE, Use: prefill(name, p.Version, kind, p.CPE, "")})
		}
		whole := p.WholeProduct()
		if !seen[whole] {
			seen[whole] = true
			wholes = append(wholes, cpeChoice{Title: name, CPE: whole, Use: prefill(name, "", kind, whole, "all")})
		}
	}
	return versions, wholes
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
	csvHeaders(w, "vigil-inventaire")
	if err := inventory.WriteCSV(w, assets); err != nil {
		s.Log.Warn("export CSV", "err", err)
	}
}

// assetCSVImport adds the assets of a CSV file. Rows identical to an existing
// asset (same name, version, purl, CPE and project) are skipped, so that the
// same file can be imported again after adding lines to it.
func (s *Server) assetCSVImport(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxCSVBytes+64<<10)
	file, _, err := r.FormFile("csv")
	if err != nil {
		s.renderAssets(w, r, http.StatusBadRequest, defaultAssetForm(), "Fichier CSV manquant ou trop volumineux (2 Mo max).")
		return
	}
	defer file.Close()
	assets, err := inventory.ReadCSV(file, time.Now())
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

// csvHeaders starts a CSV download named after base and today's date.
func csvHeaders(w http.ResponseWriter, base string) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-%s.csv"`, base, time.Now().Format("20060102")))
	// A BOM lets spreadsheet software detect UTF-8 (accents in French labels).
	_, _ = w.Write([]byte{0xEF, 0xBB, 0xBF})
}
