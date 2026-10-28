package web

import (
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"slices"
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
// SECURITY: behind a reverse proxy every request comes from the proxy, often
// on the same host, so loopback proves nothing: the CLI must be used instead.
func (s *Server) setupAllowed(r *http.Request) (bool, error) {
	if s.BehindProxy {
		return false, nil
	}
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
	ip := s.clientIP(r)
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
	now := time.Now()
	stats, err := s.Store.DashboardStats(ctx, now)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	counts, err := s.Store.CountFindingsByStatus(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	recent, err := s.Store.ListFindings(ctx, store.FindingFilter{Since: now.Add(-7 * 24 * time.Hour)})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	digest.SortByPriority(recent)
	recentTotal := len(recent)
	recent = recent[:min(len(recent), 10)]
	assets, err := s.Store.ListAssets(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	tracked := 0
	for _, a := range assets {
		if trackingSource(a) != "" {
			tracked++
		}
	}
	coverage := -1
	if len(assets) > 0 {
		coverage = 100 * tracked / len(assets)
	}
	sla, err := s.Store.SLA(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "dashboard", page{Title: "Tableau de bord", Data: map[string]any{
		"Stats": stats, "Counts": counts, "Severe": stats.OpenBySeverity["CRITICAL"] + stats.OpenBySeverity["HIGH"], "Recent": recent, "RecentTotal": recentTotal,
		"Assets": len(assets), "Tracked": tracked, "Coverage": coverage,
		"Donut": newDonut(stats.OpenBySeverity), "Weekly": newWeeklyChart(stats.Weeks),
		"TopAssets": newAssetChart(stats.TopAssets), "OpenQuery": openFindings, "SLA": sla,
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
		TrackSince:  r.PostFormValue("track_since"),
		Criticality: r.PostFormValue("criticality"),
		Owner:       r.PostFormValue("owner"),
		Notes:       r.PostFormValue("notes"),
		Project:     r.PostFormValue("project"),
		Tags:        inventory.ParseTags(r.PostFormValue("tags")),
	}
	inventory.Normalize(&a)
	return a
}

func (s *Server) assetList(w http.ResponseWriter, r *http.Request) {
	s.renderAssets(w, r, http.StatusOK, prefilledAssetForm(r.URL.Query()), "")
}

func (s *Server) renderAssets(w http.ResponseWriter, r *http.Request, status int, form store.Asset, formErr string) {
	assets, err := s.Store.ListAssets(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	project, tag := r.URL.Query().Get("project"), r.URL.Query().Get("tag")
	if project != "" || tag != "" {
		var filtered []store.Asset
		for _, a := range assets {
			if (project == "" || a.Project == project) && (tag == "" || slices.Contains(a.Tags, tag)) {
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
	tags, err := s.Store.AssetTags(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, status, "assets", page{Title: "Inventaire", Error: formErr,
		Data: map[string]any{"Assets": assets, "Form": form, "Projects": projects, "Project": project, "Tags": tags, "Tag": tag}})
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
	go s.runAssetSync(id)
	redirect(w, r, "/assets/"+strconv.FormatInt(id, 10), "asset-created")
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
		findings, ferr := s.Store.ListFindings(r.Context(), store.FindingFilter{AssetID: a.ID})
		if ferr != nil {
			s.serverError(w, r, ferr)
			return
		}
		s.render(w, r, http.StatusBadRequest, "asset", page{Title: inventory.Describe(old), Error: err.Error(),
			Data: map[string]any{"Form": a, "Findings": findings}})
		return
	}
	if err := s.Store.UpdateAsset(r.Context(), a); err != nil {
		s.serverError(w, r, err)
		return
	}
	sess, _ := sessionFrom(r.Context())
	s.audit(r, sess.User.ID, "asset_update", strconv.FormatInt(a.ID, 10))
	go s.runAssetSync(a.ID)
	redirect(w, r, "/assets/"+strconv.FormatInt(a.ID, 10), "asset-updated")
}

func (s *Server) assetScan(w http.ResponseWriter, r *http.Request) {
	a, ok := s.loadAsset(w, r)
	if !ok {
		return
	}
	sess, _ := sessionFrom(r.Context())
	s.audit(r, sess.User.ID, "asset_scan", strconv.FormatInt(a.ID, 10))
	go s.runAssetSync(a.ID)
	redirect(w, r, "/assets/"+strconv.FormatInt(a.ID, 10), "scan-started")
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
	s.renderFindings(w, r, http.StatusOK, "")
}

// renderFindings shows the vulnerability list filtered by the query string,
// with formErr when a form of the page (VEX import) was rejected.
func (s *Server) renderFindings(w http.ResponseWriter, r *http.Request, status int, formErr string) {
	f := findingFilterFrom(r.URL.Query())
	findings, err := s.Store.ListFindings(r.Context(), f)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if f.Sort == "" {
		digest.SortByPriority(findings)
	}
	projects, err := s.Store.ListProjects(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	tags, err := s.Store.AssetTags(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, status, "findings", page{Title: "Vulnérabilités", Error: formErr, Data: map[string]any{
		"Findings": findings, "Filter": f, "Projects": projects, "Tags": tags, "Query": r.URL.RawQuery,
		"MinEPSSPercent": f.MinEPSS * 100, "Next": "/findings?" + r.URL.Query().Encode(),
		// Re-encoded from the parsed query: a safe relative link with the same filters.
		"CSVLink": template.URL("/findings.csv?" + r.URL.Query().Encode()), // #nosec G203 -- fixed path, encoded values
	}})
}

// findingCSV exports the filtered vulnerability list for spreadsheets.
func (s *Server) findingCSV(w http.ResponseWriter, r *http.Request) {
	f := findingFilterFrom(r.URL.Query())
	findings, err := s.Store.ListFindings(r.Context(), f)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if f.Sort == "" {
		digest.SortByPriority(findings)
	}
	cw := csvDownload(w, "vigil-vulnerabilites")
	_ = cw.Write([]string{"id", "vulnerabilite", "alias", "severite", "cvss", "epss", "exploitee_kev", "actif", "version",
		"projet", "statut", "justification", "commentaire", "detectee_le", "echeance", "hors_delai", "resume", "lien"})
	base := strings.TrimRight(s.BaseURL, "/")
	for _, fd := range findings {
		due, link := "", ""
		if !fd.Due.IsZero() {
			due = fd.Due.Format(time.DateOnly)
		}
		if base != "" {
			link = base + "/findings/" + strconv.FormatInt(fd.ID, 10)
		}
		row := []string{strconv.FormatInt(fd.ID, 10), fd.VulnID, strings.Join(fd.Aliases, " "),
			tracking.SeverityLabel(fd.Severity), formatScore(fd.CVSS, 1), formatScore(fd.EPSS*100, 1),
			yesNo(fd.KEV), fd.AssetName, fd.AssetVersion, fd.AssetProject,
			inventory.Label(tracking.Statuses, fd.Status), inventory.Label(tracking.Justifications, fd.Justification),
			fd.Comment, fd.FirstSeen.Format(time.DateOnly), due, yesNo(fd.Late), fd.Summary, link}
		for i := range row {
			row[i] = inventory.CSVCell(row[i])
		}
		if err := cw.Write(row); err != nil {
			s.Log.Warn("export CSV", "err", err)
			return
		}
	}
	cw.Flush()
}

func formatScore(v float64, decimals int) string {
	if v < 0 {
		return ""
	}
	return strings.Replace(strconv.FormatFloat(v, 'f', decimals, 64), ".", ",", 1)
}

func yesNo(b bool) string {
	if b {
		return "oui"
	}
	return "non"
}

// maxBulk bounds the findings updated at once.
const maxBulk = 500

// findingBulk applies one triage decision to the selected findings.
func (s *Server) findingBulk(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Formulaire invalide.", http.StatusBadRequest)
		return
	}
	next := r.PostFormValue("next")
	// SECURITY: only a findings list URL, never an external redirect.
	if !strings.HasPrefix(next, "/findings?") && next != "/findings" {
		next = "/findings"
	}
	status, justif, comment := r.PostFormValue("status"), r.PostFormValue("justification"), r.PostFormValue("comment")
	if status != "not_affected" {
		justif = ""
	}
	ids := r.PostForm["id"]
	if len(ids) == 0 || len(ids) > maxBulk {
		s.renderFindingsAt(w, r, next, fmt.Sprintf("Cochez entre 1 et %d vulnérabilités.", maxBulk))
		return
	}
	if err := tracking.ValidateStatus(status, justif, comment); err != nil {
		s.renderFindingsAt(w, r, next, err.Error())
		return
	}
	var list []int64
	for _, raw := range ids {
		if id, err := strconv.ParseInt(raw, 10, 64); err == nil {
			list = append(list, id)
		}
	}
	sess, _ := sessionFrom(r.Context())
	done, err := s.Store.SetFindingsStatus(r.Context(), list, sess.User.ID, status, justif, comment)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, sess.User.ID, "finding_bulk", fmt.Sprintf("%d → %s", done, status))
	sep := "&"
	if !strings.Contains(next, "?") {
		sep = "?"
	}
	http.Redirect(w, r, next+sep+"msg=bulk-updated", http.StatusSeeOther)
}

// renderFindingsAt shows the list at next (its filters) with an error.
func (s *Server) renderFindingsAt(w http.ResponseWriter, r *http.Request, next, formErr string) {
	if u, err := url.Parse(next); err == nil {
		r.URL.RawQuery = u.RawQuery
	}
	s.renderFindings(w, r, http.StatusBadRequest, formErr)
}

// findingFilterFrom reads the filter form. Unknown values are dropped, so a
// crafted URL can only narrow the list.
func findingFilterFrom(q url.Values) store.FindingFilter {
	keep := func(values []string, allowed []inventory.Option) []string {
		var out []string
		for _, v := range values {
			if inventory.Label(allowed, v) != v {
				out = append(out, v)
			}
		}
		return out
	}
	number := func(key string, maxValue float64) float64 {
		v, err := strconv.ParseFloat(strings.ReplaceAll(q.Get(key), ",", "."), 64)
		if err != nil || v < 0 || v > maxValue {
			return 0
		}
		return v
	}
	f := store.FindingFilter{
		Statuses:   keep(q["status"], tracking.Statuses),
		Severities: keep(q["severity"], severities),
		Kinds:      keep(q["kind"], inventory.Kinds),
		KEV:        q.Get("kev") == "1",
		Priority:   q.Get("priority") == "1",
		Overdue:    q.Get("overdue") == "1",
		MinCVSS:    number("cvss", 10),
		MinEPSS:    number("epss", 100) / 100, // entered as a percentage
		Project:    q.Get("project"),
		Tag:        strings.ToLower(strings.TrimSpace(q.Get("tag"))),
		Search:     strings.TrimSpace(q.Get("q")),
		Sort:       q.Get("sort"),
	}
	if len(f.Tag) > 100 {
		f.Tag = ""
	}
	if len(f.Search) > 200 {
		f.Search = f.Search[:200]
	}
	if inventory.Label(sortOrders, f.Sort) == f.Sort {
		f.Sort = ""
	}
	return f
}

var severities = tracking.Severities

var sortOrders = []inventory.Option{
	{Value: "", Label: "Priorité (KEV, EPSS, sévérité)"}, {Value: "cvss", Label: "Score CVSS"},
	{Value: "epss", Label: "Probabilité EPSS"}, {Value: "recent", Label: "Plus récentes"},
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
	mentions, err := s.Store.MentionsOf(r.Context(), append([]string{v.ID}, v.Aliases...), 10)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, status, "finding", page{Title: f.VulnID, Error: formErr,
		Data: map[string]any{"Finding": f, "Vuln": v, "Events": events, "Mentions": mentions}})
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
	back := r.PostFormValue("next")
	if !syncTargets[back] {
		back = "/"
	}
	if s.syncStatus().Running {
		redirect(w, r, back, "sync-running")
		return
	}
	sess, _ := sessionFrom(r.Context())
	s.audit(r, sess.User.ID, "sync", "manuel")
	go s.runSync()
	redirect(w, r, back, "sync-started")
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
	if hooks, err := s.Store.ListWebhooks(r.Context()); err == nil && slices.ContainsFunc(hooks, func(h store.Webhook) bool { return h.Enabled }) {
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
	s.render(w, r, http.StatusOK, "digest", page{Title: "Digest du " + d.CreatedAt.Local().Format("02/01/2006 15:04"), Data: d})
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
