package web

import (
	"net/http"

	"github.com/La-Cizaille-Corp/vigil/internal/clip"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
	"github.com/La-Cizaille-Corp/vigil/internal/tracking"
	"github.com/La-Cizaille-Corp/vigil/internal/vex"
)

// vexExport downloads every analysis (or one project's) as CycloneDX VEX.
func (s *Server) vexExport(w http.ResponseWriter, r *http.Request) {
	project := r.URL.Query().Get("project")
	findings, err := s.Store.ListFindings(r.Context(), readScope(r), store.FindingFilter{Project: project})
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
		s.renderFindings(w, r, http.StatusBadRequest, "Fichier VEX manquant ou trop volumineux.")
		return
	}
	defer file.Close()
	statements, err := vex.Parse(file)
	if err != nil {
		s.renderFindings(w, r, http.StatusBadRequest, err.Error())
		return
	}
	findings, err := s.Store.ListFindings(r.Context(), writeScope(r), store.FindingFilter{})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	idx := vex.NewIndex(findings)
	var changes []store.StatusChange
	ignored := 0
	for _, st := range statements {
		f, ok := idx.Match(st)
		comment := clip.Text("Import VEX : "+st.Detail, tracking.MaxComment)
		if !ok || tracking.ValidateStatus(st.State, st.Justification, comment) != nil {
			ignored++
			continue
		}
		if f.Status == st.State && f.Justification == st.Justification {
			continue
		}
		changes = append(changes, store.StatusChange{ID: f.ID, Status: st.State, Justification: st.Justification, Comment: comment})
	}
	// One transaction for the whole document: the analyses are applied
	// together or not at all.
	sess, _ := sessionFrom(r.Context())
	applied, err := s.Store.SetFindingStatuses(r.Context(), writeScope(r), sess.User.ID, changes)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "vex_import", "applied", applied, "ignored", ignored)
	redirect(w, r, "/findings", "vex-imported")
}
