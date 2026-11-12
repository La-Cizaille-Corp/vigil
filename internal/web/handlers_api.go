package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/La-Cizaille-Corp/vigil/internal/auth"
	"github.com/La-Cizaille-Corp/vigil/internal/clip"
	"github.com/La-Cizaille-Corp/vigil/internal/inventory"
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
	// SECURITY: the attempt is counted before the token check, as for a login,
	// and by the same key (an IPv6 /64 is one client); a valid token takes it
	// back.
	key := s.clientKey(r, "api")
	if !s.limiter.Take(key) {
		apiError(w, http.StatusTooManyRequests, "trop de tentatives, réessayez plus tard")
		return
	}
	secret, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || !strings.HasPrefix(secret, tokenPrefix) {
		apiError(w, http.StatusUnauthorized, "jeton manquant")
		return
	}
	tok, err := s.Store.APITokenByHash(r.Context(), auth.HashToken(secret))
	if errors.Is(err, store.ErrNotFound) {
		apiError(w, http.StatusUnauthorized, "jeton invalide")
		return
	}
	s.limiter.Forgive(key)
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
	res, err := s.Store.ReplaceProjectAssets(r.Context(), tokenScope(tok), project, doc.Assets)
	if err != nil {
		s.Log.Error("api sbom import", "err", err)
		apiError(w, http.StatusInternalServerError, "erreur interne")
		return
	}
	s.audit(r, "sbom_import_api", "project", project, "token", tok.Name, "format", doc.Format,
		"added", res.Added, "kept", res.Kept, "removed", res.Removed, "skipped", doc.Skipped)
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
	if t.Name == "" || !clip.Fits(t.Name, maxNameLen) || t.Project == "" || !clip.Fits(t.Project, inventory.MaxProjectLen) ||
		strings.ContainsAny(t.Project, "/?#") {
		s.renderSettings(w, r, http.StatusBadRequest, "Indiquez un nom et un projet (sans / ? #).")
		return
	}
	// The group, if one is chosen, is looked up before the token is made.
	var group store.Group
	if id := groupParam(r.PostForm); id != 0 {
		var err error
		if group, err = s.Store.Group(r.Context(), readScope(r), id); err != nil {
			s.storeError(w, r, err)
			return
		}
	}
	raw, err := auth.NewToken()
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	secret := tokenPrefix + raw
	sess, _ := sessionFrom(r.Context())
	id, err := s.Store.CreateAPIToken(r.Context(), t, auth.HashToken(secret), sess.User.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "api_token_create", "id", id, "name", t.Name, "project", t.Project)
	if err := s.addProjectToGroup(r, group, t.Project); err != nil {
		s.serverError(w, r, err)
		return
	}
	// SECURITY: the secret is displayed once, on the page this redirects to.
	s.keepOnce(r, onceToken, secret)
	redirect(w, r, "/settings", "token-created")
}

// addProjectToGroup adds the project of a new token to the group g chosen in
// the form, if any (ID 0: none), so that the components it pushes are seen
// by the accounts of that group (A68); a group already naming it is left as
// it is.
func (s *Server) addProjectToGroup(r *http.Request, g store.Group, project string) error {
	if g.ID == 0 || slices.Contains(g.Projects, project) {
		return nil
	}
	projects := append(g.Projects, project)
	if err := s.Store.SetGroupRules(r.Context(), g.ID, g.Tags, projects); err != nil {
		return err
	}
	s.audit(r, "group_rules", "id", g.ID, "tags", strings.Join(g.Tags, ","), "projects", strings.Join(projects, ","))
	return nil
}

func (s *Server) tokenDelete(w http.ResponseWriter, r *http.Request) {
	s.change(w, r, change{action: "api_token_delete", to: "/settings", msg: "token-deleted",
		apply: func(id int64) error { return s.Store.DeleteAPIToken(r.Context(), id) }})
}
