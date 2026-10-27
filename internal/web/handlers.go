package web

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/auth"
	"github.com/La-Cizaille-Corp/vigil/internal/digest"
	"github.com/La-Cizaille-Corp/vigil/internal/inventory"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
	"github.com/La-Cizaille-Corp/vigil/internal/tracking"
)

// --- first run and authentication -----------------------------------------

// setupAllowed: the first admin can only be created from the machine itself,
// so that an exposed server cannot be claimed by someone else.
func (s *Server) setupAllowed(r *http.Request) (bool, error) {
	n, err := s.Store.CountUsers(r.Context())
	return n == 0 && isLoopback(r), err
}

func (s *Server) setupForm(w http.ResponseWriter, r *http.Request) {
	ok, err := s.setupAllowed(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.render(w, r, http.StatusOK, "setup", page{Title: "Première configuration"})
}

func (s *Server) setupSubmit(w http.ResponseWriter, r *http.Request) {
	ok, err := s.setupAllowed(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if !ok {
		http.Error(w, "Configuration déjà effectuée.", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	username, password := r.PostFormValue("username"), r.PostFormValue("password")
	if username == "" || len(username) > 64 {
		s.render(w, r, http.StatusBadRequest, "setup", page{Title: "Première configuration", Error: "Nom d'utilisateur invalide."})
		return
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		s.render(w, r, http.StatusBadRequest, "setup", page{Title: "Première configuration", Error: err.Error()})
		return
	}
	id, err := s.Store.CreateUser(r.Context(), username, hash, auth.RoleAdmin)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, id, "setup", "compte administrateur initial créé")
	s.startSession(w, r, id)
}

func (s *Server) loginForm(w http.ResponseWriter, r *http.Request) {
	if ok, _ := s.setupAllowed(r); ok {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	s.render(w, r, http.StatusOK, "login", page{Title: "Connexion"})
}

func (s *Server) loginSubmit(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !s.limiter.Allowed(ip) {
		s.render(w, r, http.StatusTooManyRequests, "login", page{Title: "Connexion",
			Error: "Trop de tentatives. Réessayez dans quelques minutes."})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	username, password := r.PostFormValue("username"), r.PostFormValue("password")

	user, err := s.Store.UserByName(r.Context(), username)
	valid := false
	switch {
	case errors.Is(err, store.ErrNotFound):
		auth.VerifyDummy(password)
	case err != nil:
		s.serverError(w, r, err)
		return
	default:
		valid, err = auth.VerifyPassword(password, user.PasswordHash)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
	}
	if valid {
		if valid, err = s.checkTOTP(r, user.ID, r.PostFormValue("code")); err != nil {
			s.serverError(w, r, err)
			return
		}
	}
	if !valid {
		s.limiter.Fail(ip)
		s.audit(r, 0, "login_failed", "ip="+ip)
		// SECURITY: same message whether the user exists or not.
		s.render(w, r, http.StatusUnauthorized, "login", page{Title: "Connexion", Error: "Identifiants invalides."})
		return
	}
	s.limiter.Reset(ip)
	s.audit(r, user.ID, "login", "ip="+ip)
	s.startSession(w, r, user.ID)
}

func (s *Server) startSession(w http.ResponseWriter, r *http.Request, userID int64) {
	token, err := auth.NewToken()
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	csrf, err := auth.NewToken()
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	expires := time.Now().Add(sessionDuration)
	if err := s.Store.CreateSession(r.Context(), auth.HashToken(token), userID, csrf, expires); err != nil {
		s.serverError(w, r, err)
		return
	}
	// #nosec G124 -- Secure is set whenever the UI is served over HTTPS; a
	// local instance on http://127.0.0.1 cannot use Secure cookies.
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   s.SecureCookies,
		SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		if err := s.Store.DeleteSession(r.Context(), auth.HashToken(c.Value)); err != nil {
			s.Log.Error("delete session", "err", err)
		}
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, // #nosec G124 -- see startSession
		HttpOnly: true, Secure: s.SecureCookies, SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// --- dashboard ------------------------------------------------------------

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	counts, err := s.Store.CountFindingsByStatus(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	recent, err := s.Store.ListFindings(ctx, store.FindingFilter{Since: time.Now().Add(-7 * 24 * time.Hour)})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	digest.SortByPriority(recent)
	assets, err := s.Store.ListAssets(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	exploited, err := s.Store.ListFindings(ctx, store.FindingFilter{KEV: true})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "dashboard", page{Title: "Tableau de bord", Data: map[string]any{
		"Counts": counts, "Recent": recent, "AssetCount": len(assets), "KEVCount": len(exploited),
	}})
}

// --- assets ---------------------------------------------------------------

func assetFromForm(r *http.Request) store.Asset {
	a := store.Asset{
		Name:        r.PostFormValue("name"),
		Kind:        r.PostFormValue("kind"),
		Ecosystem:   r.PostFormValue("ecosystem"),
		Version:     r.PostFormValue("version"),
		PURL:        r.PostFormValue("purl"),
		CPE:         r.PostFormValue("cpe"),
		CPEMode:     r.PostFormValue("cpe_mode"),
		CPEFrom:     r.PostFormValue("cpe_from"),
		Criticality: r.PostFormValue("criticality"),
		Owner:       r.PostFormValue("owner"),
		Notes:       r.PostFormValue("notes"),
		Project:     r.PostFormValue("project"),
	}
	inventory.Normalize(&a)
	return a
}

func (s *Server) assetList(w http.ResponseWriter, r *http.Request) {
	s.renderAssets(w, r, http.StatusOK, defaultAssetForm(), "")
}

func (s *Server) renderAssets(w http.ResponseWriter, r *http.Request, status int, form store.Asset, formErr string) {
	assets, err := s.Store.ListAssets(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	project := r.URL.Query().Get("project")
	if project != "" {
		var filtered []store.Asset
		for _, a := range assets {
			if a.Project == project {
				filtered = append(filtered, a)
			}
		}
		assets = filtered
	}
	projects, err := s.Store.ListProjects(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, status, "assets", page{Title: "Inventaire", Error: formErr,
		Data: map[string]any{"Assets": assets, "Form": form, "Projects": projects, "Project": project}})
}

func (s *Server) assetCreate(w http.ResponseWriter, r *http.Request) {
	a := assetFromForm(r)
	if err := inventory.Validate(a); err != nil {
		s.renderAssets(w, r, http.StatusBadRequest, a, err.Error())
		return
	}
	id, err := s.Store.CreateAsset(r.Context(), a)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	sess, _ := sessionFrom(r.Context())
	s.audit(r, sess.User.ID, "asset_create", strconv.FormatInt(id, 10))
	redirect(w, r, "/assets", "asset-created")
}

func (s *Server) loadAsset(w http.ResponseWriter, r *http.Request) (store.Asset, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.notFound(w)
		return store.Asset{}, false
	}
	a, err := s.Store.Asset(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		s.notFound(w)
		return a, false
	}
	if err != nil {
		s.serverError(w, r, err)
		return a, false
	}
	return a, true
}

func (s *Server) assetEdit(w http.ResponseWriter, r *http.Request) {
	a, ok := s.loadAsset(w, r)
	if !ok {
		return
	}
	findings, err := s.Store.ListFindings(r.Context(), store.FindingFilter{AssetID: a.ID})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "asset", page{Title: inventory.Describe(a),
		Data: map[string]any{"Form": a, "Findings": findings}})
}

func (s *Server) assetUpdate(w http.ResponseWriter, r *http.Request) {
	old, ok := s.loadAsset(w, r)
	if !ok {
		return
	}
	a := assetFromForm(r)
	a.ID = old.ID
	if err := inventory.Validate(a); err != nil {
		s.render(w, r, http.StatusBadRequest, "asset", page{Title: inventory.Describe(old), Error: err.Error(),
			Data: map[string]any{"Form": a}})
		return
	}
	if err := s.Store.UpdateAsset(r.Context(), a); err != nil {
		s.serverError(w, r, err)
		return
	}
	sess, _ := sessionFrom(r.Context())
	s.audit(r, sess.User.ID, "asset_update", strconv.FormatInt(a.ID, 10))
	redirect(w, r, "/assets", "asset-updated")
}

func (s *Server) assetDelete(w http.ResponseWriter, r *http.Request) {
	a, ok := s.loadAsset(w, r)
	if !ok {
		return
	}
	if err := s.Store.DeleteAsset(r.Context(), a.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	sess, _ := sessionFrom(r.Context())
	s.audit(r, sess.User.ID, "asset_delete", inventory.Describe(a))
	redirect(w, r, "/assets", "asset-deleted")
}

// --- findings -------------------------------------------------------------

func (s *Server) findingList(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	if inventory.Label(tracking.Statuses, status) == status {
		status = "" // unknown value: show everything
	}
	kev := r.URL.Query().Get("kev") == "1"
	findings, err := s.Store.ListFindings(r.Context(), store.FindingFilter{Status: status, KEV: kev})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	digest.SortByPriority(findings)
	s.render(w, r, http.StatusOK, "findings", page{Title: "Vulnérabilités",
		Data: map[string]any{"Findings": findings, "Status": status, "KEV": kev}})
}

func (s *Server) loadFinding(w http.ResponseWriter, r *http.Request) (store.Finding, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.notFound(w)
		return store.Finding{}, false
	}
	f, err := s.Store.Finding(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		s.notFound(w)
		return f, false
	}
	if err != nil {
		s.serverError(w, r, err)
		return f, false
	}
	return f, true
}

func (s *Server) findingShow(w http.ResponseWriter, r *http.Request) {
	s.renderFinding(w, r, http.StatusOK, "")
}

func (s *Server) renderFinding(w http.ResponseWriter, r *http.Request, status int, formErr string) {
	f, ok := s.loadFinding(w, r)
	if !ok {
		return
	}
	v, err := s.Store.Vulnerability(r.Context(), f.VulnID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	events, err := s.Store.FindingEvents(r.Context(), f.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, status, "finding", page{Title: f.VulnID, Error: formErr,
		Data: map[string]any{"Finding": f, "Vuln": v, "Events": events}})
}

func (s *Server) findingUpdate(w http.ResponseWriter, r *http.Request) {
	f, ok := s.loadFinding(w, r)
	if !ok {
		return
	}
	status, justif, comment := r.PostFormValue("status"), r.PostFormValue("justification"), r.PostFormValue("comment")
	if status != "not_affected" {
		justif = ""
	}
	if err := tracking.ValidateStatus(status, justif, comment); err != nil {
		s.renderFinding(w, r, http.StatusBadRequest, err.Error())
		return
	}
	sess, _ := sessionFrom(r.Context())
	if err := s.Store.SetFindingStatus(r.Context(), f.ID, sess.User.ID, status, justif, comment); err != nil {
		s.serverError(w, r, err)
		return
	}
	redirect(w, r, "/findings/"+strconv.FormatInt(f.ID, 10), "status-updated")
}

// --- sync and digests -----------------------------------------------------

func (s *Server) syncNow(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	s.audit(r, sess.User.ID, "sync", "manuel")
	go s.runSync()
	redirect(w, r, "/", "sync-started")
}

// runSync matches the inventory against vulnerability sources in the
// background; it is a no-op when a sync is already running.
func (s *Server) runSync() {
	ctx, cancel := context.WithTimeout(s.background(), 15*time.Minute)
	defer cancel()
	if _, err := s.Syncer.Run(ctx); err != nil && !errors.Is(err, tracking.ErrRunning) {
		s.Log.Error("sync failed", "err", err)
	}
}

func (s *Server) digestList(w http.ResponseWriter, r *http.Request) {
	list, err := s.Store.ListDigests(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "digests", page{Title: "Digests", Data: list})
}

func (s *Server) digestCreate(w http.ResponseWriter, r *http.Request) {
	d, err := digest.Generate(r.Context(), s.Store)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	msg := "digest-created"
	if hooks, err := s.Store.ListWebhooks(r.Context()); err == nil && len(hooks) > 0 {
		msg = "digest-sent"
		if err := s.Notifier.SendDigest(r.Context(), d, s.digestLink(d)); err != nil {
			msg = "digest-webhook"
		}
	}
	redirect(w, r, "/digests/"+strconv.FormatInt(d.ID, 10), msg)
}

func (s *Server) loadDigest(w http.ResponseWriter, r *http.Request) (store.Digest, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.notFound(w)
		return store.Digest{}, false
	}
	d, err := s.Store.Digest(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		s.notFound(w)
		return d, false
	}
	if err != nil {
		s.serverError(w, r, err)
		return d, false
	}
	return d, true
}

func (s *Server) digestShow(w http.ResponseWriter, r *http.Request) {
	d, ok := s.loadDigest(w, r)
	if !ok {
		return
	}
	s.render(w, r, http.StatusOK, "digest", page{Title: "Digest du " + d.CreatedAt.Local().Format("02/01/2006"), Data: d})
}

func (s *Server) digestMarkdown(w http.ResponseWriter, r *http.Request) {
	d, ok := s.loadDigest(w, r)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Content-Disposition",
		`attachment; filename="vigil-digest-`+d.CreatedAt.Format("2006-01-02")+`.md"`)
	_, _ = w.Write([]byte(d.Markdown)) // a client that disconnects is not an error
}

// digestLink is the absolute URL of a digest, or "" when BaseURL is unknown.
func (s *Server) digestLink(d store.Digest) string {
	if s.BaseURL == "" {
		return ""
	}
	return strings.TrimRight(s.BaseURL, "/") + "/digests/" + strconv.FormatInt(d.ID, 10)
}
