package web

import (
	"fmt"
	"net/http"

	"github.com/La-Cizaille-Corp/vigil/internal/store"
	"github.com/La-Cizaille-Corp/vigil/internal/tracking"
	"github.com/La-Cizaille-Corp/vigil/internal/vex"
)

// vexExport downloads every analysis (or one project's) as CycloneDX VEX.
func (s *Server) vexExport(w http.ResponseWriter, r *http.Request) {
	project := r.URL.Query().Get("project")
	findings, err := s.Store.ListFindings(r.Context(), store.FindingFilter{Project: project})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/vnd.cyclonedx+json")
	w.Header().Set("Content-Disposition", `attachment; filename="vigil.vex.json"`)
	if err := vex.Export(w, findings, s.Version); err != nil {
		s.Log.Error("vex export", "err", err)
	}
}

// vexImport applies the analyses of an uploaded VEX to matching findings.
func (s *Server) vexImport(w http.ResponseWriter, r *http.Request) {
	file, _, err := r.FormFile("vex")
	if err != nil {
		http.Error(w, "Fichier VEX manquant ou trop volumineux.", http.StatusBadRequest)
		return
	}
	defer file.Close()
	statements, err := vex.Parse(file)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	findings, err := s.Store.ListFindings(r.Context(), store.FindingFilter{})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	sess, _ := sessionFrom(r.Context())
	applied, ignored := 0, 0
	for _, st := range statements {
		f, ok := vex.Match(st, findings)
		if !ok || tracking.ValidateStatus(st.State, st.Justification, st.Detail) != nil {
			ignored++
			continue
		}
		if f.Status == st.State && f.Justification == st.Justification {
			continue
		}
		if err := s.Store.SetFindingStatus(r.Context(), f.ID, sess.User.ID, st.State, st.Justification,
			"Import VEX : "+st.Detail); err != nil {
			s.serverError(w, r, err)
			return
		}
		applied++
	}
	s.audit(r, sess.User.ID, "vex_import", fmt.Sprintf("%d appliquées, %d ignorées", applied, ignored))
	redirect(w, r, "/findings", "vex-imported")
}
