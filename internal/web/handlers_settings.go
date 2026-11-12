package web

import (
	"context"
	"net/http"
	"strconv"

	"github.com/La-Cizaille-Corp/vigil/internal/auth"
	"github.com/La-Cizaille-Corp/vigil/internal/cti"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
)

// The settings are sub-pages, one by subject, with a menu of those the
// account may open (A89), instead of one page of 3,500 px where the channels
// came fourth.

// settingsSection is a sub-page of the settings.
type settingsSection struct {
	group, label, path string
}

// settingsSections are the sub-pages of the settings, in the order of their
// menu. Who may open one is the role of its route: the menu reads it from the
// route table (see Handler), so that it never offers a page that refuses.
var settingsSections = []settingsSection{
	{"Alertes", "Notifications", "/settings/webhooks"},
	{"Alertes", "Délais de traitement", "/settings/sla"},
	{"Veille", "Filtres de veille", "/settings/watch"},
	{"Veille", "Flux", "/settings/feeds"},
	{"Accès", "Utilisateurs", "/settings/users"},
	{"Accès", "Groupes", "/settings/groups"},
	{"Accès", "Jetons d'API", "/settings/tokens"},
	{"Accès", "Journal d'audit", "/settings/audit"},
}

// settingsPages are the templates of the settings, by the sub-page each
// belongs to: render gives them the menu.
var settingsPages = map[string]string{
	"settings_webhooks": "/settings/webhooks",
	"settings_sla":      "/settings/sla",
	"settings_watch":    "/settings/watch",
	"settings_feeds":    "/settings/feeds",
	"users":             "/settings/users",
	"groups":            "/settings/groups",
	"group":             "/settings/groups",
	"settings_tokens":   "/settings/tokens",
	"audit":             "/settings/audit",
}

// The forms of the settings refused with their values, by their id (A88,
// A89): the message shows in the form, which the browser comes back to.
const (
	formWatch = "filtres"
	formNews  = "collecte"
	formFeed  = "nouveau-flux"
	formHook  = "nouveau-canal"
	formSLA   = "delais"
	formToken = "nouveau-jeton"
)

// settingsMenu is the data of the "settingsNav" template.
type settingsMenu struct {
	Groups []settingsMenuGroup
}

// settingsMenuGroup is a heading of the menu with its sub-pages.
type settingsMenuGroup struct {
	Label string
	Links []settingsLink
}

// settingsLink is a sub-page in the menu.
type settingsLink struct {
	Label, Href string
	Current     bool
	Failing     int // feeds whose last collection failed, on the entry of the feeds
}

// settingsMenuFor is the menu of an account of role on the sub-page current:
// the sub-pages its role opens, the feeds in failure counted on theirs.
func (s *Server) settingsMenuFor(ctx context.Context, role, current string) (settingsMenu, error) {
	feeds, err := s.Store.ListFeeds(ctx)
	if err != nil {
		return settingsMenu{}, err
	}
	failing := 0
	for _, f := range feeds {
		if f.Enabled && f.LastError != "" {
			failing++
		}
	}
	var m settingsMenu
	for _, sec := range settingsSections {
		if !s.opens(role, sec.path) {
			continue
		}
		if n := len(m.Groups); n == 0 || m.Groups[n-1].Label != sec.group {
			m.Groups = append(m.Groups, settingsMenuGroup{Label: sec.group})
		}
		link := settingsLink{Label: sec.label, Href: sec.path, Current: sec.path == current}
		if sec.path == "/settings/feeds" {
			link.Failing = failing
		}
		g := &m.Groups[len(m.Groups)-1]
		g.Links = append(g.Links, link)
	}
	return m, nil
}

// opens reports whether role may open the page at path, as the route table
// says.
func (s *Server) opens(role, path string) bool {
	least, ok := s.pageRoles["GET "+path]
	return ok && (least == public || auth.RoleAtLeast(role, least))
}

// settingsHome leads to the first sub-page of the settings the account may
// open: the notifications for an administrator, the watch for the others.
func (s *Server) settingsHome(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	for _, sec := range settingsSections {
		if s.opens(sess.User.Role, sec.path) {
			redirect(w, r, sec.path, "")
			return
		}
	}
	s.notFound(w)
}

// --- watch filters ----------------------------------------------------------

func (s *Server) watchSettings(w http.ResponseWriter, r *http.Request) {
	s.renderWatch(w, r, http.StatusOK, "")
}

// renderWatch shows the countries, sectors and regulations watched, with
// formErr in their form.
func (s *Server) renderWatch(w http.ResponseWriter, r *http.Request, status int, formErr string) {
	watch, err := cti.WatchedFilter(r.Context(), s.Store)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	regs, err := cti.WatchedRegulations(r.Context(), s.Store)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	watch.Regulations = regs.Regulations
	s.render(w, r, status, "settings_watch", page{Title: "Filtres de veille", Error: formErr, ErrorAt: formWatch, Data: watch})
}

// --- feeds ------------------------------------------------------------------

// feedForm is the form of a new feed: what was typed, shown again when it is
// refused.
type feedForm struct {
	Name, URL string
	Tags      tagSelection
}

// feedFormFrom reads the form of a new feed as it was typed.
func feedFormFrom(r *http.Request) feedForm {
	return feedForm{Name: r.PostFormValue("name"), URL: r.PostFormValue("url"), Tags: tagsFromForm(r)}
}

func (s *Server) feedSettings(w http.ResponseWriter, r *http.Request) {
	s.renderFeeds(w, r, http.StatusOK, feedForm{}, "", "")
}

// renderFeeds shows the feeds and how often they are collected, form in the
// form of a new feed, and formErr in the form at.
func (s *Server) renderFeeds(w http.ResponseWriter, r *http.Request, status int, form feedForm, at, formErr string) {
	feeds, err := s.Store.ListFeeds(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	perDay, err := cti.NewsPerDay(r.Context(), s.Store)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, status, "settings_feeds", page{Title: "Flux de veille", Error: formErr, ErrorAt: at, Data: map[string]any{
		"Feeds": feeds, "NewsPerDay": perDay, "NewsFrequencies": cti.NewsFrequencies, "Form": form}})
}

// --- notifications ----------------------------------------------------------

func (s *Server) webhookSettings(w http.ResponseWriter, r *http.Request) {
	s.renderWebhooks(w, r, http.StatusOK, store.Webhook{Digests: true, Alerts: "priority"}, "")
}

// renderWebhooks shows the notification channels, form in the form of a new
// one, and formErr there. SECURITY: form holds the URL typed by the
// administrator only when that channel was refused, not saved; a saved one is
// never shown again (see notify.Target).
func (s *Server) renderWebhooks(w http.ResponseWriter, r *http.Request, status int, form store.Webhook, formErr string) {
	hooks, err := s.Store.ListWebhooks(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	groups, err := s.Store.ListGroups(r.Context(), readScope(r))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, status, "settings_webhooks", page{Title: "Notifications", Error: formErr, ErrorAt: formHook, Data: map[string]any{
		"Webhooks": hooks, "Groups": groups, "Mail": s.Notifier != nil && s.Notifier.Mail != nil, "Form": form}})
}

// --- deadlines --------------------------------------------------------------

// slaForm is the form of the deadlines, as typed.
type slaForm struct {
	Critical, High, Medium, Low string
}

func (s *Server) slaSettings(w http.ResponseWriter, r *http.Request) {
	sla, err := s.Store.SLA(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.renderSLA(w, r, http.StatusOK, slaForm{strconv.Itoa(sla.Critical), strconv.Itoa(sla.High), strconv.Itoa(sla.Medium),
		strconv.Itoa(sla.Low)}, "")
}

// renderSLA shows the deadlines saved, form in their form and formErr there;
// deadlines that do not decrease from Basse to Critique are pointed out
// (audit UX 8.3).
func (s *Server) renderSLA(w http.ResponseWriter, r *http.Request, status int, form slaForm, formErr string) {
	sla, err := s.Store.SLA(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, status, "settings_sla", page{Title: "Délais de traitement", Error: formErr, ErrorAt: formSLA,
		Data: map[string]any{"Form": form, "SLA": sla, "Ordered": sla.Ordered()}})
}

// --- API tokens -------------------------------------------------------------

// tokenForm is the form of a new API token, as typed.
type tokenForm struct {
	Name, Project string
	Group         int64
}

func (s *Server) tokenSettings(w http.ResponseWriter, r *http.Request) {
	s.renderTokens(w, r, http.StatusOK, tokenForm{}, "")
}

// renderTokens shows the API tokens, the one just created first (audit UX
// 1.4), form in the form of a new one and formErr there.
func (s *Server) renderTokens(w http.ResponseWriter, r *http.Request, status int, form tokenForm, formErr string) {
	tokens, err := s.Store.ListAPITokens(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	groups, err := s.Store.ListGroups(r.Context(), readScope(r))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, status, "settings_tokens", page{Title: "Jetons d'API", Error: formErr, ErrorAt: formToken, Data: map[string]any{
		"Tokens": tokens, "NewToken": s.newToken(r), "BaseURL": s.BaseURL, "Groups": groups, "Form": form}})
}
