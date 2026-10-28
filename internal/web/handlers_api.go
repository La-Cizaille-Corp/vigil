package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/La-Cizaille-Corp/vigil/internal/auth"
	"github.com/La-Cizaille-Corp/vigil/internal/sbom"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
)

// tokenPrefix makes Vigil tokens recognizable by secret scanners.
const tokenPrefix = "vgl_"

// apiSBOM replaces the components of a project with an uploaded SBOM:
//
//	PUT /api/v1/projects/{project}/sbom
//	Authorization: Bearer vgl_...
//	body: CycloneDX or SPDX JSON
func (s *Server) apiSBOM(w http.ResponseWriter, r *http.Request) {
	ip := "api:" + s.clientIP(r)
	if !s.limiter.Allowed(ip) {
		apiError(w, http.StatusTooManyRequests, "trop de tentatives, réessayez plus tard")
		return
	}
	secret, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || !strings.HasPrefix(secret, tokenPrefix) {
		s.limiter.Fail(ip)
		apiError(w, http.StatusUnauthorized, "jeton manquant")
		return
	}
	tok, err := s.Store.APITokenByHash(r.Context(), auth.HashToken(secret))
	if errors.Is(err, store.ErrNotFound) {
		s.limiter.Fail(ip)
		apiError(w, http.StatusUnauthorized, "jeton invalide")
		return
	}
	if err != nil {
		s.Log.Error("api token lookup", "err", err)
		apiError(w, http.StatusInternalServerError, "erreur interne")
		return
	}
	// SECURITY: a token can only write the project it was issued for.
	project := r.PathValue("project")
	if project != tok.Project {
		apiError(w, http.StatusForbidden, "ce jeton n'est pas autorisé pour ce projet")
		return
	}
	doc, err := sbom.Parse(r.Body)
	if err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	res, err := s.Store.ReplaceProjectAssets(r.Context(), project, doc.Assets)
	if err != nil {
		s.Log.Error("api sbom import", "err", err)
		apiError(w, http.StatusInternalServerError, "erreur interne")
		return
	}
	s.audit(r, 0, "sbom_import_api", fmt.Sprintf("%s (jeton %q): %s +%d =%d -%d (%d ignorés)",
		project, tok.Name, doc.Format, res.Added, res.Kept, res.Removed, doc.Skipped))
	if s.Syncer != nil {
		go s.runSync()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"project": project, "format": doc.Format,
		"added": res.Added, "kept": res.Kept, "removed": res.Removed, "skipped": doc.Skipped,
	})
}

func apiError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v) // #nosec G104 -- the client may have gone away; nothing to do
}

// --- token management (admin) --------------------------------------------

func (s *Server) tokenCreate(w http.ResponseWriter, r *http.Request) {
	t := store.APIToken{
		Name:    strings.TrimSpace(r.PostFormValue("name")),
		Project: strings.TrimSpace(r.PostFormValue("project")),
	}
	if t.Name == "" || len(t.Name) > 100 || t.Project == "" || len(t.Project) > 200 || strings.ContainsAny(t.Project, "/?#") {
		s.renderSettings(w, r, http.StatusBadRequest, "Indiquez un nom et un projet (sans / ? #).")
		return
	}
	raw, err := auth.NewToken()
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	secret := tokenPrefix + raw
	sess, _ := sessionFrom(r.Context())
	if _, err := s.Store.CreateAPIToken(r.Context(), t, auth.HashToken(secret), sess.User.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, sess.User.ID, "api_token_create", t.Name+" → "+t.Project)
	// SECURITY: the secret is displayed once, on the page this redirects to.
	s.keepOnce(r, secret)
	redirect(w, r, "/settings", "token-created")
}

func (s *Server) tokenDelete(w http.ResponseWriter, r *http.Request) {
	s.byID(w, r, s.audited(r, "api_token_delete", "", func(id int64) error { return s.Store.DeleteAPIToken(r.Context(), id) }),
		"/settings", "token-deleted")
}
