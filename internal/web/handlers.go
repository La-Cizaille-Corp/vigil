package web

import (
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/auth"
	"github.com/La-Cizaille-Corp/vigil/internal/choice"
	"github.com/La-Cizaille-Corp/vigil/internal/clip"
	"github.com/La-Cizaille-Corp/vigil/internal/digest"
	"github.com/La-Cizaille-Corp/vigil/internal/fr"
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
	// A proxy forwarding headers while -behind-proxy is missing would make
	// every request look local.
	if s.BehindProxy || r.Header.Get("X-Forwarded-For") != "" || r.Header.Get("Forwarded") != "" ||
		r.Header.Get("X-Real-Ip") != "" {
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
	username, password := r.PostFormValue("username"), r.PostFormValue("password")
	if username == "" || !clip.Fits(username, auth.MaxUsernameLength) {
		s.render(w, r, http.StatusBadRequest, "setup", page{Title: "Première configuration", Error: "Nom d'utilisateur invalide."})
		return
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		s.render(w, r, http.StatusBadRequest, "setup", page{Title: "Première configuration", Error: err.Error()})
		return
	}
	id, err := s.Store.CreateFirstAdmin(r.Context(), username, hash)
	if errors.Is(err, store.ErrExists) { // another request created it meanwhile
		http.Error(w, "Configuration déjà effectuée.", http.StatusForbidden)
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.auditAs(r, id, "setup", "id", id)
	s.startSession(w, r, id)
}

func (s *Server) loginForm(w http.ResponseWriter, r *http.Request) {
	ok, err := s.setupAllowed(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if ok {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	s.render(w, r, http.StatusOK, "login", page{Title: "Connexion"})
}

func (s *Server) loginSubmit(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	username, password := r.PostFormValue("username"), r.PostFormValue("password")
	// SECURITY: no account has a longer password (see auth.HashPassword):
	// it is refused before argon2 runs, so it costs nothing to check.
	if len(password) > auth.MaxPasswordBytes {
		s.render(w, r, http.StatusBadRequest, "login", page{Title: "Connexion", Error: "Mot de passe trop long."})
		return
	}
	// SECURITY: the attempt is counted before the slow password check, so
	// that parallel requests cannot all get through, per address and per
	// account name (existing or not), so that spreading guesses over many
	// addresses does not help. A success only cancels its own attempt.
	// The name is cut to the longest valid username, so that the limiter's
	// memory stays bounded whatever is posted.
	ipKey, userKey := s.clientKey(r, "login"), "user:"+strings.ToLower(clip.Text(username, auth.MaxUsernameLength))
	if !s.limiter.Take(ipKey) {
		s.render(w, r, http.StatusTooManyRequests, "login", page{Title: "Connexion",
			Error: "Trop de tentatives. Réessayez dans quelques minutes."})
		return
	}
	if !s.accounts.Take(userKey) {
		s.limiter.Forgive(ipKey)
		s.render(w, r, http.StatusTooManyRequests, "login", page{Title: "Connexion",
			Error: "Trop de tentatives. Réessayez dans quelques minutes."})
		return
	}

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
		// SECURITY: the typed name is kept only when an account bears it,
		// disabled or not: a password typed in the name field would otherwise
		// end up in the database and the service log. The lookup runs on
		// every failure, in a single query whether the name exists or not.
		detail := []any{"ip", ip}
		if a, err := s.Store.AnyUserByName(r.Context(), username); err == nil {
			detail = append(detail, "user", a.Username)
		} else if !errors.Is(err, store.ErrNotFound) {
			s.Log.Warn("failed login: account lookup", "err", err)
		}
		s.audit(r, "login_failed", detail...)
		// SECURITY: same message whether the user exists or not.
		s.render(w, r, http.StatusUnauthorized, "login", page{Title: "Connexion", Error: "Identifiants invalides."})
		return
	}
	s.limiter.Forgive(ipKey)
	s.accounts.Reset(userKey)
	s.auditAs(r, user.ID, "login", "ip", ip)
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
		Name:     s.cookieName(),
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
	if c, err := r.Cookie(s.cookieName()); err == nil {
		if err := s.Store.DeleteSession(r.Context(), auth.HashToken(c.Value)); err != nil {
			s.Log.Error("delete session", "err", err)
		}
	}
	http.SetCookie(w, &http.Cookie{Name: s.cookieName(), Value: "", Path: "/", MaxAge: -1, // #nosec G124 -- see startSession
		HttpOnly: true, Secure: s.SecureCookies, SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// --- dashboard ------------------------------------------------------------

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	now := time.Now()
	stats, err := s.Store.DashboardStats(ctx, readScope(r), now)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	counts, err := s.Store.CountFindingsByStatus(ctx, readScope(r))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	recent, err := s.Store.ListFindings(ctx, readScope(r), store.FindingFilter{Since: daysAgo(now, recentDays), Now: now})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	// The open ones, as the list it links to (A84).
	recent = keepLevel(recent, levelOpen)
	tracking.SortByPriority(recent)
	recentTotal := len(recent)
	recent = recent[:min(len(recent), 10)]
	assets, err := s.Store.ListAssets(ctx, readScope(r))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	tracked, byName := 0, 0
	for _, a := range assets {
		if trackingSource(a) != "" {
			tracked++
		}
		if inventory.ByName(a) {
			byName++
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
	s.render(w, r, http.StatusOK, "dashboard", page{Title: "Tableau de bord", Refresh: s.syncStatus().Running, Data: map[string]any{
		"Stats": stats, "Counts": counts, "Severe": stats.OpenBySeverity["CRITICAL"] + stats.OpenBySeverity["HIGH"], "Recent": recent, "RecentTotal": recentTotal,
		"RecentDays": recentDays, "Assets": len(assets), "Tracked": tracked, "ByName": byName, "Coverage": coverage,
		"Donut": newDonut(stats.OpenBySeverity), "Weekly": newWeeklyChart(stats.Weeks),
		"TopAssets": newAssetChart(stats.TopAssets), "SLA": sla,
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

// assetList shows the inventory; ?retired=1 shows the components dropped
// from their project's SBOM, kept for their history.
func (s *Server) assetList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	retiredView := r.URL.Query().Get("retired") == "1"
	sc, group := listScope(r, r.URL.Query())
	retired, err := s.Store.ListRetiredAssets(ctx, sc)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	assets := retired
	if !retiredView {
		if assets, err = s.Store.ListAssets(ctx, sc); err != nil {
			s.serverError(w, r, err)
			return
		}
	}
	q := r.URL.Query()
	project, tag, search := q.Get("project"), tagParam(q), clip.Prefix(strings.TrimSpace(q.Get("q")), 200)
	loads, err := s.Store.AssetLoads(ctx, sc)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	load := map[int64]store.AssetLoad{}
	for _, l := range loads {
		load[l.ID] = l
	}
	var rows []assetRow
	for _, a := range assets {
		if (project == "" || a.Project == project) && (tag == "" || slices.Contains(a.Tags, tag)) && assetMatches(a, search) {
			rows = append(rows, assetRow{Asset: a, Urgent: load[a.ID].Urgent, Open: load[a.ID].Total()})
		}
	}
	order := orderFrom(q, assetColumnList, "")
	sortRows(rows, assetColumnList, order)
	projects, err := s.Store.ListProjects(r.Context(), readScope(r))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	tags, err := s.Store.ListAssetTags(r.Context(), readScope(r))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	groups, err := s.Store.ListGroups(ctx, readScope(r))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "assets", page{Title: "Inventaire",
		Data: map[string]any{"Assets": rows, "Projects": projects, "Project": project, "Tags": tags, "Tag": tag,
			"Groups": groups, "Group": group, "Query": search,
			"RetiredView": retiredView, "Retired": len(retired), "Sort": q.Get("sort"), "Dir": q.Get("dir"),
			"Head": sortHeaders(assetColumnList, "/assets", q, order)}})
}

// assetMatches tells whether the name, purl or CPE of an asset holds text,
// any case: the search of the inventory (A86).
func assetMatches(a store.Asset, text string) bool {
	text = strings.ToLower(text)
	return slices.ContainsFunc([]string{a.Name, a.PURL, a.CPE}, func(v string) bool { return strings.Contains(strings.ToLower(v), text) })
}

// assetNew shows the ways to add assets: CPE search, form, SBOM and CSV
// imports. The form may be prefilled from a CPE search result.
func (s *Server) assetNew(w http.ResponseWriter, r *http.Request) {
	s.renderNewAsset(w, r, http.StatusOK, prefilledAssetForm(r.URL.Query()), "")
}

func (s *Server) renderNewAsset(w http.ResponseWriter, r *http.Request, status int, form store.Asset, formErr string) {
	f, err := s.newAssetForm(r, form)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, status, "asset_new", page{Title: "Ajouter des actifs", Error: formErr, Data: map[string]any{"Form": f}})
}

func (s *Server) assetCreate(w http.ResponseWriter, r *http.Request) {
	a := assetFromForm(r)
	if err := inventory.Validate(a); err != nil {
		s.renderNewAsset(w, r, http.StatusBadRequest, a, err.Error())
		return
	}
	id, err := s.Store.CreateAsset(r.Context(), writeScope(r), a)
	if msg, refused := outsideGroups(err); refused {
		s.renderNewAsset(w, r, http.StatusBadRequest, a, msg)
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "asset_create", "id", id)
	go s.runAssetSync(id)
	redirect(w, r, assetPath(id), "asset-created")
}

// assetPath is the page of an asset.
func assetPath(id int64) string { return "/assets/" + strconv.FormatInt(id, 10) }

func (s *Server) assetEdit(w http.ResponseWriter, r *http.Request) {
	a, ok := load(s, w, r, inScope(r, s.Store.Asset))
	if !ok {
		return
	}
	s.renderAsset(w, r, http.StatusOK, a, a, "")
}

// assetFirst is the number of open vulnerabilities the page of an asset shows,
// the most urgent ones; its list holds them all (A86).
const assetFirst = 10

// renderAsset shows an asset, then its vulnerabilities by level, each count a
// link to the list of the asset at that level, and the most urgent open ones
// (A86); then its dismissal rules, with the vulnerabilities holding the text
// searched in the query string if any, a page of them at a time (A85), to see
// what a rule would set aside. The edit form is folded; it opens on the values
// refused when there are some (form != a).
func (s *Server) renderAsset(w http.ResponseWriter, r *http.Request, status int, a, form store.Asset, formErr string) {
	q := r.URL.Query()
	// The list of the asset as the vulnerability list reads it, so that each
	// count is the length of the list it leads to.
	l, err := s.listedFindings(r, url.Values{"asset": {strconv.FormatInt(a.ID, 10)}, "level": {levelAll}})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	first := keepLevel(l.Findings, levelOpen)
	first = first[:min(len(first), assetFirst)]
	// What a rule of the text searched would set aside, for those who may create one.
	query := clip.Prefix(strings.TrimSpace(q.Get("q")), maxRuleText)
	var matching []store.Finding
	if sess, _ := sessionFrom(r.Context()); query != "" && auth.RoleAtLeast(sess.User.Role, auth.RoleAnalyst) {
		if matching, err = s.Store.ListFindings(r.Context(), readScope(r), store.FindingFilter{AssetID: a.ID, Matching: query}); err != nil {
			s.serverError(w, r, err)
			return
		}
		tracking.SortByPriority(matching)
	}
	rules, err := s.Store.ListDismissalRules(r.Context(), readScope(r), a.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	groups, err := s.Store.ListAssetGroups(r.Context(), readScope(r), a.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	f, err := s.newAssetForm(r, form)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	shown, pages := paginate(matching, q, assetPath(a.ID))
	s.render(w, r, status, "asset", page{Title: inventory.Describe(a), Error: formErr,
		Data: map[string]any{"Asset": a, "Form": f, "Editing": !reflect.DeepEqual(form, a),
			"Levels": l.Levels, "Counters": append(slices.Clone(l.Levels.Open[1:]), l.Levels.Closed...), "First": first,
			"Matching": shown, "Pager": pages, "Query": query, "Rules": rules, "Groups": groups}})
}

// A rule text is short, and long enough not to set aside everything by mistake.
const (
	minRuleText = 3
	maxRuleText = 100
)

// fitsRule tells whether text can be the text of a dismissal rule.
func fitsRule(text string) bool {
	return !clip.Fits(text, minRuleText-1) && clip.Fits(text, maxRuleText)
}

// dismissalCreate sets aside the vulnerabilities of an asset holding a text.
func (s *Server) dismissalCreate(w http.ResponseWriter, r *http.Request) {
	a, ok := load(s, w, r, inScope(r, s.Store.Asset))
	if !ok {
		return
	}
	text := strings.TrimSpace(r.PostFormValue("text"))
	if !fitsRule(text) {
		s.renderAsset(w, r, http.StatusBadRequest, a, a, fmt.Sprintf("Indiquez un texte de %d à %d caractères.", minRuleText, maxRuleText))
		return
	}
	if err := s.Store.CreateDismissalRule(r.Context(), writeScope(r), a.ID, text); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "dismissal_create", "asset", a.ID, "text", text)
	redirect(w, r, assetPath(a.ID), "rule-created")
}

// dismissalDelete removes a rule: what it set aside is to analyse again.
func (s *Server) dismissalDelete(w http.ResponseWriter, r *http.Request) {
	a, ok := load(s, w, r, inScope(r, s.Store.Asset))
	if !ok {
		return
	}
	id, ok := s.pathID(w, r, "rule")
	if !ok {
		return
	}
	if err := s.Store.DeleteDismissalRule(r.Context(), writeScope(r), a.ID, id); err != nil {
		s.storeError(w, r, err)
		return
	}
	s.audit(r, "dismissal_delete", "id", id, "asset", a.ID)
	redirect(w, r, assetPath(a.ID), "rule-deleted")
}

func (s *Server) assetUpdate(w http.ResponseWriter, r *http.Request) {
	old, ok := load(s, w, r, inScope(r, s.Store.Asset))
	if !ok {
		return
	}
	a := assetFromForm(r)
	a.ID = old.ID
	inventory.FollowPURL(&a, old)
	if err := inventory.Validate(a); err != nil {
		s.renderAsset(w, r, http.StatusBadRequest, old, a, err.Error())
		return
	}
	err := s.Store.UpdateAsset(r.Context(), writeScope(r), a)
	if msg, refused := outsideGroups(err); refused {
		s.renderAsset(w, r, http.StatusBadRequest, old, a, msg)
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "asset_update", "id", a.ID)
	go s.runAssetSync(a.ID)
	redirect(w, r, assetPath(a.ID), "asset-updated")
}

// assetFullHistory tracks the whole history of an asset: the vulnerabilities
// published before its tracked period are reported too.
func (s *Server) assetFullHistory(w http.ResponseWriter, r *http.Request) {
	a, ok := load(s, w, r, inScope(r, s.Store.Asset))
	if !ok {
		return
	}
	a.TrackSince = ""
	if err := s.Store.UpdateAsset(r.Context(), writeScope(r), a); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "asset_update", "id", a.ID, "full_history", true)
	go s.runAssetSync(a.ID)
	redirect(w, r, assetPath(a.ID), "asset-updated")
}

func (s *Server) assetScan(w http.ResponseWriter, r *http.Request) {
	a, ok := load(s, w, r, inScope(r, s.Store.Asset))
	if !ok {
		return
	}
	if !a.Retired.IsZero() { // no longer in its project: checking it would reopen its findings
		redirect(w, r, assetPath(a.ID), "")
		return
	}
	s.audit(r, "asset_scan", "id", a.ID)
	go s.runAssetSync(a.ID)
	redirect(w, r, assetPath(a.ID), "scan-started")
}

func (s *Server) assetDelete(w http.ResponseWriter, r *http.Request) {
	a, ok := load(s, w, r, inScope(r, s.Store.Asset))
	if !ok {
		return
	}
	err := s.Store.DeleteAsset(r.Context(), writeScope(r), a.ID)
	if msg, refused := outsideGroups(err); refused {
		s.renderAsset(w, r, http.StatusBadRequest, a, a, msg)
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "asset_delete", "id", a.ID, "asset", inventory.Describe(a))
	redirect(w, r, "/assets", "asset-deleted")
}

// --- findings -------------------------------------------------------------

func (s *Server) findingList(w http.ResponseWriter, r *http.Request) {
	if fromPriority(w, r, "/findings") {
		return
	}
	s.renderFindings(w, r, http.StatusOK, "", bulkForm{})
}

// fromPriority sends a list asked with ?priority=1, the box of the urgent
// findings until 0.4 (links of the alerts already sent, bookmarks), to the
// level that replaced it, ?level=urgent (A84), at path, and reports whether
// it did.
func fromPriority(w http.ResponseWriter, r *http.Request, path string) bool {
	q := r.URL.Query()
	if !q.Has("priority") {
		return false
	}
	if q.Get("priority") == "1" {
		q.Set("level", tracking.LevelUrgent)
	}
	q.Del("priority")
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	// SECURITY: a fixed path of this site; only the query string, encoded, comes from the request.
	http.Redirect(w, r, path, http.StatusMovedPermanently) // #nosec G710 -- fixed local path, encoded query
	return true
}

// findingList is a vulnerability list as a query string describes it, whole:
// filtered, at its level and in its order. A page cuts it afterwards: its
// counts, export and decisions on the whole list go by all of it (A85).
type findingList struct {
	Findings []store.Finding
	Filter   store.FindingFilter
	Levels   levelNav
	Order    listOrder
	Group    int64 // the group the list is filtered by, 0 for none
}

// listedFindings reads the vulnerability list described by q: the list page,
// its export, a decision on the whole list and the next vulnerability of a
// list all read it here, so that they agree.
func (s *Server) listedFindings(r *http.Request, q url.Values) (findingList, error) {
	sc, group := listScope(r, q)
	l := findingList{Filter: findingFilterFrom(q), Order: orderFrom(q, findingColumnList, defaultFindingOrder), Group: group}
	findings, err := s.Store.ListFindings(r.Context(), sc, l.Filter)
	if err != nil {
		return l, err
	}
	level := listLevel(q)
	l.Levels = levelLinks(findings, q, level)
	l.Findings = keepLevel(findings, level)
	sortRows(l.Findings, findingColumnList, l.Order)
	return l, nil
}

// listPath is v when it is a vulnerability list of this site, else the
// default list: the return address of a form (next) or of a vulnerability
// page (back). SECURITY: it comes from the browser, and is never an
// external site nor another page.
func listPath(v string) string {
	if v == "/findings" || strings.HasPrefix(v, "/findings?") {
		return v
	}
	return "/findings"
}

// listURL is the address of the vulnerability list described by q, its
// message aside: where a form returns, and a vulnerability page leads back.
func listURL(q url.Values) string {
	kept := without(q, "msg")
	if len(kept) == 0 {
		return "/findings"
	}
	return "/findings?" + kept.Encode()
}

// Scopes of a bulk decision: the boxes ticked, or the whole list filtered.
const (
	bulkRows = "rows"
	bulkList = "list"
)

// bulkConfirmAbove is the size of a list from which a decision on all of it
// asks to be confirmed, with the number it changes (A85).
const bulkConfirmAbove = 50

// bulkForm is the bulk triage panel of a vulnerability list: what was chosen,
// shown again when the decision is refused or waits for its confirmation
// (A85), so that nothing has to be ticked or chosen twice.
type bulkForm struct {
	Open                           bool // the panel is unfolded
	Scope                          string
	Status, Justification, Comment string
	Checked                        map[int64]bool
	Err, Field                     string // why it was refused, and the field at fault ("scope" or that of a tracking.StatusError)
	Confirm                        int    // the findings of the list a confirmation applies the decision to
}

// renderFindings shows the vulnerability list filtered by the query string,
// one page of it, with formErr when the VEX import of the page was rejected,
// and the bulk panel as b leaves it.
func (s *Server) renderFindings(w http.ResponseWriter, r *http.Request, status int, formErr string, b bulkForm) {
	q := r.URL.Query()
	l, err := s.listedFindings(r, q)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	shown, pages := paginate(l.Findings, q, "/findings")
	projects, err := s.Store.ListProjects(r.Context(), readScope(r))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	tags, err := s.Store.ListAssetTags(r.Context(), readScope(r))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	groups, err := s.Store.ListGroups(r.Context(), readScope(r))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	sess, _ := sessionFrom(r.Context())
	analyst := auth.RoleAtLeast(sess.User.Role, auth.RoleAnalyst)
	f, back := l.Filter, listURL(q)
	more := moreFilters(f)
	if l.Group != 0 {
		more++
	}
	asset, err := s.filteredAsset(r, f.AssetID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	var noise noiseOffer
	if analyst {
		noise = noiseLinks(l.Findings, f.Search)
	}
	s.render(w, r, status, "findings", page{Title: "Vulnérabilités", Error: formErr, Data: map[string]any{
		"Filter": f, "Projects": projects, "Tags": tags, "Groups": groups, "Group": l.Group, "Pager": pages, "Bulk": b, "Confirm": bulkConfirmAbove,
		"MinEPSSPercent": f.MinEPSS * 100, "Next": back, "Asset": asset, "Noise": noise,
		"AllAssets": listURL(without(q, "asset", "page")),
		"Table": findingRows{List: shown, Head: sortHeaders(findingColumnList, "/findings", q, l.Order), Sortable: true,
			Select: analyst && len(shown) > 0, Checked: b.Checked, Back: back},
		"Sort": q.Get("sort"), "Dir": q.Get("dir"),
		"Levels": l.Levels, "Level": q.Get("level"), "Since": sinceDays(q), "More": more,
		// Re-encoded from the parsed query: a safe relative link with the same filters, every page.
		"CSVLink": template.URL("/findings.csv?" + without(q, "msg", "page").Encode()), // #nosec G203 -- fixed path, encoded values
	}})
}

// assetFilter is the asset a vulnerability list is filtered by (?asset=),
// named only when the account sees it.
type assetFilter struct {
	ID   int64
	Name string // name and version, "" when not found
}

// filteredAsset reads the asset a list is filtered by in the scope of the
// request (A86). SECURITY: an asset outside of it is not found, as one that
// does not exist, and its list is empty, as the scope is in the query of the
// list too: neither its name nor its vulnerabilities show.
func (s *Server) filteredAsset(r *http.Request, id int64) (assetFilter, error) {
	if id == 0 {
		return assetFilter{}, nil
	}
	a, err := s.Store.Asset(r.Context(), readScope(r), id)
	if errors.Is(err, store.ErrNotFound) {
		return assetFilter{ID: id}, nil
	}
	if err != nil {
		return assetFilter{}, err
	}
	return assetFilter{ID: id, Name: inventory.Describe(a)}, nil
}

// noiseOffer offers to set aside, asset by asset, the vulnerabilities a search
// of the list found (A86): a link to the page of each asset, which shows what
// the rule of that text would set aside before it is created (A61).
type noiseOffer struct {
	Text  string
	Links []noiseLink
	More  int // assets left out of Links
}

// noiseLink leads to the rule of a text on one asset.
type noiseLink struct {
	Asset string // name and version
	Href  string
	N     int // findings of the list on that asset
}

// maxNoiseLinks bounds the assets a search offers to set aside noise on.
const maxNoiseLinks = 5

// noiseLinks is the offer for the findings of a list searched for text: their
// assets, the one with the most first, when text can be a rule. An asset
// whose name holds the text is left out: the search found its findings by its
// name, which a rule does not read.
func noiseLinks(findings []store.Finding, text string) noiseOffer {
	if !fitsRule(text) {
		return noiseOffer{}
	}
	o, index, lower := noiseOffer{Text: text}, map[int64]int{}, strings.ToLower(text)
	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.AssetName), lower) {
			continue
		}
		i, ok := index[f.AssetID]
		if !ok {
			i, index[f.AssetID] = len(o.Links), len(o.Links)
			o.Links = append(o.Links, noiseLink{Asset: inventory.Describe(store.Asset{Name: f.AssetName, Version: f.AssetVersion}),
				Href: assetPath(f.AssetID) + "?q=" + url.QueryEscape(text) + "#bruit"})
		}
		o.Links[i].N++
	}
	slices.SortStableFunc(o.Links, func(a, b noiseLink) int { return b.N - a.N })
	if len(o.Links) > maxNoiseLinks {
		o.More, o.Links = len(o.Links)-maxNoiseLinks, o.Links[:maxNoiseLinks]
	}
	return o
}

// findingCSV exports the filtered vulnerability list for spreadsheets: all of
// it, whatever the page shown.
func (s *Server) findingCSV(w http.ResponseWriter, r *http.Request) {
	if fromPriority(w, r, "/findings.csv") {
		return
	}
	l, err := s.listedFindings(r, r.URL.Query())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	base := strings.TrimRight(s.BaseURL, "/")
	rows := make([][]string, 0, len(l.Findings))
	for _, fd := range l.Findings {
		due, link := "", ""
		if !fd.Due.IsZero() {
			due = fd.Due.Format(time.DateOnly)
		}
		if base != "" {
			link = base + "/findings/" + strconv.FormatInt(fd.ID, 10)
		}
		rows = append(rows, []string{strconv.FormatInt(fd.ID, 10), fd.VulnID, strings.Join(fd.Aliases, " "),
			tracking.SeverityLabel(fd.Severity), fr.Score(fd.CVSS), fr.Score(fd.EPSS * 100),
			yesNo(fd.KEV), fd.AssetName, fd.AssetVersion, fd.FixedIn, fd.AssetProject,
			choice.Label(tracking.Statuses, fd.Status), choice.Label(tracking.Justifications, fd.Justification),
			fd.Comment, fd.FirstSeen.Format(time.DateOnly), due, yesNo(fd.Late), fd.Summary, link})
	}
	s.writeCSV(w, "vigil-vulnerabilites", []string{"id", "vulnerabilite", "alias", "severite", "cvss", "epss", "exploitee_kev",
		"actif", "version", "corrigee_en", "projet", "statut", "justification", "commentaire", "detectee_le", "echeance",
		"hors_delai", "resume", "lien"}, rows)
}

func yesNo(b bool) string {
	if b {
		return "oui"
	}
	return "non"
}

// maxBulk bounds the findings ticked for one decision.
const maxBulk = 500

// findingBulk applies one triage decision to the findings ticked, or to the
// whole list they come from (next): then, as the dismissal rules (A61), what
// someone already decided does not change, and beyond bulkConfirmAbove the
// decision asks to be confirmed with its number first. A refused decision
// shows the list again with what was ticked and chosen (A85).
func (s *Server) findingBulk(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Formulaire invalide.", http.StatusBadRequest)
		return
	}
	next := listPath(r.PostFormValue("next"))
	status, justif, comment := triageFromForm(r)
	b := bulkForm{Open: true, Scope: r.PostFormValue("scope"), Status: status, Justification: r.PostFormValue("justification"),
		Comment: comment, Checked: map[int64]bool{}}
	if b.Scope != bulkList {
		b.Scope = bulkRows
	}
	var ids []int64
	for _, raw := range r.PostForm["id"] {
		if id, err := strconv.ParseInt(raw, 10, 64); err == nil && !b.Checked[id] {
			b.Checked[id] = true
			ids = append(ids, id)
		}
	}
	refuse := func(field, msg string) {
		b.Field, b.Err = field, sentences(msg)
		s.renderFindingsAt(w, r, next, http.StatusBadRequest, b)
	}
	if err := tracking.ValidateStatus(status, justif, comment); err != nil {
		field := "status"
		var se *tracking.StatusError
		if errors.As(err, &se) {
			field = se.Field
		}
		refuse(field, err.Error())
		return
	}
	var changes []store.StatusChange
	detail := []any{"status", status}
	switch b.Scope {
	case bulkList:
		u, err := url.Parse(next)
		if err != nil {
			refuse("scope", "liste introuvable")
			return
		}
		l, err := s.listedFindings(r, u.Query())
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		if len(l.Findings) == 0 {
			refuse("scope", "cette liste est vide")
			return
		}
		if len(l.Findings) > bulkConfirmAbove && r.PostFormValue("confirm") != strconv.Itoa(len(l.Findings)) {
			b.Confirm = len(l.Findings)
			s.renderFindingsAt(w, r, next, http.StatusOK, b)
			return
		}
		for _, f := range l.Findings {
			changes = append(changes, store.StatusChange{ID: f.ID, Status: status, Justification: justif, Comment: comment, KeepDecided: true})
		}
		detail = append(detail, "list", len(l.Findings))
	default:
		if len(ids) == 0 || len(ids) > maxBulk {
			refuse("scope", fmt.Sprintf("cochez entre 1 et %d vulnérabilités, ou choisissez toute la liste filtrée", maxBulk))
			return
		}
		for _, id := range ids {
			changes = append(changes, store.StatusChange{ID: id, Status: status, Justification: justif, Comment: comment})
		}
	}
	sess, _ := sessionFrom(r.Context())
	done, err := s.Store.SetFindingStatuses(r.Context(), writeScope(r), sess.User.ID, changes)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "finding_bulk", append([]any{"count", done}, detail...)...)
	msg := "bulk-updated"
	if b.Scope == bulkList {
		msg = "bulk-list-updated"
	}
	redirect(w, r, next, msg)
}

// triageFromForm reads a triage decision: a status, its justification, kept
// for « not affected » only (as in VEX), and a comment.
func triageFromForm(r *http.Request) (status, justif, comment string) {
	status, justif, comment = r.PostFormValue("status"), r.PostFormValue("justification"), r.PostFormValue("comment")
	if status != store.StatusNotAffected {
		justif = ""
	}
	return status, justif, comment
}

// renderFindingsAt shows the list at next (its filters and page) with the
// bulk panel as b leaves it.
func (s *Server) renderFindingsAt(w http.ResponseWriter, r *http.Request, next string, status int, b bulkForm) {
	if u, err := url.Parse(next); err == nil {
		r.URL.Path, r.URL.RawQuery = "/findings", u.RawQuery
	}
	s.renderFindings(w, r, status, "", b)
}

// findingFilterFrom reads the filter form. Unknown values and duplicates are
// dropped, so a crafted URL can only narrow the list (see choice.KnownOnly).
func findingFilterFrom(q url.Values) store.FindingFilter {
	number := func(key string, maxValue float64) float64 {
		v, err := strconv.ParseFloat(strings.ReplaceAll(q.Get(key), ",", "."), 64)
		if err != nil || v < 0 || v > maxValue {
			return 0
		}
		return v
	}
	f := store.FindingFilter{
		Statuses:   choice.KnownOnly(tracking.Statuses, q["status"]),
		Severities: choice.KnownOnly(severities, q["severity"]),
		Kinds:      choice.KnownOnly(inventory.Kinds, q["kind"]),
		KEV:        q.Get("kev") == "1",
		Overdue:    q.Get("overdue") == "1",
		MinCVSS:    number("cvss", 10),
		MinEPSS:    number("epss", 100) / 100, // entered as a percentage
		Project:    q.Get("project"),
		Tag:        tagParam(q),
		Search:     strings.TrimSpace(q.Get("q")),
		AssetID:    idParam(q, "asset"),
	}
	if days := sinceDays(q); days > 0 {
		f.Since = daysAgo(time.Now(), days)
	}
	f.Search = clip.Prefix(f.Search, 200)
	return f
}

// recentDays is the period of the dashboard's new vulnerabilities, which
// links to the list detected over as many days (?since=).
const recentDays = 7

// maxSinceDays bounds the period of a list, in days: ten years.
const maxSinceDays = 3650

// sinceDays reads the period of a list (?since=7: detected in the last 7
// days), 0 for none or a value out of 1..maxSinceDays.
func sinceDays(q url.Values) int {
	days, err := strconv.Atoi(q.Get("since"))
	if err != nil || days < 1 || days > maxSinceDays {
		return 0
	}
	return days
}

// daysAgo is the time days before now.
func daysAgo(now time.Time, days int) time.Time {
	return now.Add(-time.Duration(days) * 24 * time.Hour)
}

// moreFilters counts the filters set in the folded part of the filter form,
// for its title (« Plus de filtres (2 appliqués) »).
func moreFilters(f store.FindingFilter) int {
	n := 0
	for _, set := range []bool{len(f.Statuses) > 0, len(f.Severities) > 0, len(f.Kinds) > 0, f.KEV, f.Overdue,
		f.MinCVSS > 0, f.MinEPSS > 0, f.Project != "", f.Tag != "", !f.Since.IsZero()} {
		if set {
			n++
		}
	}
	return n
}

// without is a copy of the query q without keys: a link that keeps the
// filters of a list, not its message or its level.
func without(q url.Values, keys ...string) url.Values {
	kept := url.Values{}
	for k, v := range q {
		if !slices.Contains(keys, k) {
			kept[k] = v
		}
	}
	return kept
}

// tagParam reads the tag filter of a list as tags are stored (see
// inventory.NormalizeTags); a tag longer than inventory.MaxTagLen, which no
// asset can bear, filters nothing.
func tagParam(q url.Values) string {
	tags := inventory.NormalizeTags([]string{q.Get("tag")})
	if len(tags) == 0 || !clip.Fits(tags[0], inventory.MaxTagLen) {
		return ""
	}
	return tags[0]
}

var severities = tracking.Severities

// findingPath is the page of a vulnerability found on an asset.
func findingPath(id int64) string { return "/findings/" + strconv.FormatInt(id, 10) }

func (s *Server) findingShow(w http.ResponseWriter, r *http.Request) {
	s.renderFinding(w, r, http.StatusOK, "")
}

func (s *Server) renderFinding(w http.ResponseWriter, r *http.Request, status int, formErr string) {
	f, ok := load(s, w, r, inScope(r, s.Store.Finding))
	if !ok {
		return
	}
	v, err := s.Store.Vulnerability(r.Context(), f.VulnID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	events, err := s.Store.ListFindingEvents(r.Context(), readScope(r), f.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	mentions, err := s.Store.ListMentions(r.Context(), append([]string{v.ID}, v.Aliases...), 10)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	asset, err := s.Store.Asset(r.Context(), readScope(r), f.AssetID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	back := listBack(r)
	next, err := s.following(r, back, f.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if then, err := strconv.ParseInt(r.URL.Query().Get("then"), 10, 64); next == 0 && err == nil && then > 0 && then != f.ID {
		next = then // the one that followed it before it left the list (findingUpdate)
	}
	data := map[string]any{"Finding": f, "Vuln": v, "Events": events, "Mentions": mentions, "Fixes": tracking.Fixes(v.Raw, asset),
		"ByName": inventory.ByName(asset), "Latest": inventory.IsLatest(asset), "Back": back, "Following": next,
		// The deadline CISA set, passed while the vulnerability is still open (A86).
		"KEVLate": f.Open() && len(v.KEVDue) >= len(time.DateOnly) && v.KEVDue[:len(time.DateOnly)] < time.Now().Format(time.DateOnly),
		"CVE":     findingCVE(f)}
	if err := s.foldedFindings(r, f, asset, data); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, status, "finding", page{Title: findingTitle(f), Error: formErr, Data: data})
}

// foldedFindings adds to the page of a finding what one finding per CVE (A80)
// links it to. A finding shown lists the other advisories of its CVE folded
// into it, and the grouped advisories naming it, with the decision a user may
// have taken on one. A folded finding names the finding kept, or, for a
// grouped advisory, the findings of its CVEs, with a form applying its
// decision to them by the batch triage.
func (s *Server) foldedFindings(r *http.Request, f store.Finding, asset store.Asset, data map[string]any) error {
	ctx, sc := r.Context(), readScope(r)
	cves := tracking.CVEs(f.VulnID, f.Aliases)
	switch {
	case f.FoldedInto == 0:
		folded, err := s.Store.ListFoldedInto(ctx, sc, f.ID)
		if err != nil {
			return err
		}
		notices, err := s.Store.ListNotices(ctx, sc, f.AssetID, cves)
		if err != nil {
			return err
		}
		data["Folded"], data["Notices"] = folded, tracking.GroupedNotices(notices, asset)
	case f.FoldedInto > 0:
		kept, err := s.Store.Finding(ctx, sc, f.FoldedInto)
		if err != nil {
			return err
		}
		data["Kept"] = kept
	default:
		rows, err := s.Store.ListFindings(ctx, sc, store.FindingFilter{AssetID: f.AssetID, CVEs: cves})
		if err != nil {
			return err
		}
		var apply []int64 // only a decision taken is applied
		for _, row := range rows {
			if f.Status != store.StatusInTriage && (row.Status != f.Status || row.Justification != f.Justification) && len(apply) < maxBulk {
				apply = append(apply, row.ID)
			}
		}
		data["Grouped"], data["CVEFindings"], data["Apply"] = true, len(rows), apply
		data["ApplyComment"] = clip.Text("Décision de l'avis groupé "+f.VulnID+" : "+f.Comment, tracking.MaxComment)
	}
	return nil
}

// listBack is the vulnerability list a vulnerability page was opened from
// (?back=, then the field back of its form), "" for none (A85).
func listBack(r *http.Request) string {
	if v := r.FormValue("back"); v != "" {
		return listPath(v)
	}
	return ""
}

// following is the vulnerability after id in the list back, in its order and
// over all its pages: 0 when id is the last one, or not in it.
func (s *Server) following(r *http.Request, back string, id int64) (int64, error) {
	u, err := url.Parse(back)
	if back == "" || err != nil {
		return 0, nil
	}
	l, err := s.listedFindings(r, u.Query())
	if err != nil {
		return 0, err
	}
	for i, f := range l.Findings {
		if f.ID == id && i+1 < len(l.Findings) {
			return l.Findings[i+1].ID, nil
		}
	}
	return 0, nil
}

// findingUpdate records a triage decision. Opened from a list, the page comes
// back with that list and the vulnerability that followed this one in it,
// read before the decision may take it out of the list (A85).
func (s *Server) findingUpdate(w http.ResponseWriter, r *http.Request) {
	f, ok := load(s, w, r, inScope(r, s.Store.Finding))
	if !ok {
		return
	}
	status, justif, comment := triageFromForm(r)
	if err := tracking.ValidateStatus(status, justif, comment); err != nil {
		s.renderFinding(w, r, http.StatusBadRequest, err.Error())
		return
	}
	back := listBack(r)
	next, err := s.following(r, back, f.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	sess, _ := sessionFrom(r.Context())
	if err := s.Store.SetFindingStatus(r.Context(), writeScope(r), f.ID, sess.User.ID, status, justif, comment); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "finding_update", "id", f.ID, "status", status)
	to := findingPath(f.ID)
	if back != "" {
		to += "?back=" + url.QueryEscape(back)
		if next > 0 {
			to += "&then=" + strconv.FormatInt(next, 10)
		}
	}
	redirect(w, r, to, "status-updated")
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
	s.audit(r, "sync", "trigger", "manual")
	go s.runSync()
	redirect(w, r, back, "sync-started")
}

// digestList shows the digests the account may read (A68): every one for an
// account that sees everything, those of its groups otherwise; it may
// generate one for the whole inventory or for one of its groups.
func (s *Server) digestList(w http.ResponseWriter, r *http.Request) {
	s.renderDigests(w, r, http.StatusOK, "")
}

func (s *Server) renderDigests(w http.ResponseWriter, r *http.Request, status int, formErr string) {
	list, err := s.Store.ListDigests(r.Context(), readScope(r))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	groups, err := s.Store.ListGroups(r.Context(), readScope(r))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, status, "digests", page{Title: "Digests", Error: formErr, Data: map[string]any{"Digests": list, "Groups": groups}})
}

// digestCreate generates the digest of the whole inventory or of a group of
// the account, and sends it to the notification channels of what it covers.
// They are read first: when they cannot be, nothing is generated, rather than
// a digest said to be done and sent to no one.
func (s *Server) digestCreate(w http.ResponseWriter, r *http.Request) {
	var group store.Group
	if id := groupParam(r.PostForm); id != 0 {
		var err error
		if group, err = s.Store.Group(r.Context(), readScope(r), id); err != nil {
			s.storeError(w, r, err)
			return
		}
	} else if sess, _ := sessionFrom(r.Context()); sess.User.Restricted() {
		s.renderDigests(w, r, http.StatusBadRequest, "Choisissez un de vos groupes : le digest de tout l'inventaire est réservé aux comptes qui le voient.")
		return
	}
	hooks, err := s.Store.ListWebhooks(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d, err := digest.Generate(r.Context(), s.Store, group)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	msg := "digest-created"
	if slices.ContainsFunc(hooks, func(h store.Webhook) bool { return h.Enabled && h.Group == group.ID }) {
		msg = "digest-sent"
		if err := s.Notifier.SendDigest(r.Context(), d, s.digestLink(d)); err != nil {
			msg = "digest-webhook"
		}
	}
	detail := []any{"id", d.ID}
	if group.ID != 0 {
		detail = append(detail, "group", group.Name)
	}
	s.audit(r, "digest_create", detail...)
	redirect(w, r, digestPath(d.ID), msg)
}

// digestPath is the page of a digest.
func digestPath(id int64) string { return "/digests/" + strconv.FormatInt(id, 10) }

func (s *Server) digestShow(w http.ResponseWriter, r *http.Request) {
	d, ok := load(s, w, r, inScope(r, s.Store.Digest))
	if !ok {
		return
	}
	title := "Digest du " + fr.DateTime(d.CreatedAt)
	if d.GroupName != "" {
		title += " — " + d.GroupName
	}
	s.render(w, r, http.StatusOK, "digest", page{Title: title, Data: d})
}

func (s *Server) digestMarkdown(w http.ResponseWriter, r *http.Request) {
	d, ok := load(s, w, r, inScope(r, s.Store.Digest))
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Content-Disposition",
		`attachment; filename="vigil-digest-`+d.CreatedAt.Format(time.DateOnly)+`.md"`)
	_, _ = w.Write([]byte(d.Markdown)) // a client that disconnects is not an error
}

// digestLink is the absolute URL of a digest, or "" when BaseURL is unknown.
func (s *Server) digestLink(d store.Digest) string {
	if s.BaseURL == "" {
		return ""
	}
	return strings.TrimRight(s.BaseURL, "/") + digestPath(d.ID)
}
