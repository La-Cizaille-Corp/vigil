package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/auth"
	"github.com/La-Cizaille-Corp/vigil/internal/choice"
	"github.com/La-Cizaille-Corp/vigil/internal/clip"
	"github.com/La-Cizaille-Corp/vigil/internal/cti"
	"github.com/La-Cizaille-Corp/vigil/internal/inventory"
	"github.com/La-Cizaille-Corp/vigil/internal/netsafe"
	"github.com/La-Cizaille-Corp/vigil/internal/notify"
	"github.com/La-Cizaille-Corp/vigil/internal/sbom"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
)

// --- CTI ------------------------------------------------------------------

func (s *Server) ctiList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter := store.CTIFilter{Countries: choice.KnownOnly(cti.Countries, q["country"]), Sectors: choice.KnownOnly(cti.Sectors, q["sector"]),
		Regulations: choice.KnownOnly(cti.Regulations, q["regulation"])}
	watched, regulatory := false, q.Get("view") == "regulatory"
	switch {
	case regulatory:
		var err error
		if filter, err = cti.WatchedRegulations(r.Context(), s.Store); err != nil {
			s.serverError(w, r, err)
			return
		}
	case len(filter.Countries) == 0 && len(filter.Sectors) == 0 && len(filter.Regulations) == 0 && q.Get("all") == "":
		var err error
		if filter, err = cti.WatchedFilter(r.Context(), s.Store); err != nil {
			s.serverError(w, r, err)
			return
		}
		watched = len(filter.Countries) > 0 || len(filter.Sectors) > 0
	}
	filter.Concerning = q.Get("concerning") == "1"
	items, err := s.Store.ListCTIItems(r.Context(), readScope(r), filter)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	title := "Veille menaces"
	if regulatory {
		title = "Veille réglementaire"
	}
	s.render(w, r, http.StatusOK, "cti", page{Title: title, Data: map[string]any{
		"Items": items, "Filter": filter, "Watched": watched, "Regulatory": regulatory, "All": q.Get("all") != "",
		"Concerning": filter.Concerning,
	}})
}

// ctiRefresh starts a collection of the feeds in the background, unless one
// is in progress: like syncNow, a second request is refused, not queued.
func (s *Server) ctiRefresh(w http.ResponseWriter, r *http.Request) {
	if s.CTI.Running() {
		redirect(w, r, "/cti", "cti-running")
		return
	}
	s.audit(r, "cti_refresh", "trigger", "manual")
	go func() {
		ctx, cancel := context.WithTimeout(s.background(), 10*time.Minute)
		defer cancel()
		if _, err := s.CTI.Run(ctx); err != nil && !errors.Is(err, cti.ErrRunning) {
			s.Log.Error("cti failed", "err", err)
		}
	}()
	redirect(w, r, "/cti", "cti-started")
}

// --- settings -------------------------------------------------------------

func (s *Server) settings(w http.ResponseWriter, r *http.Request) {
	s.renderSettings(w, r, http.StatusOK, "")
}

func (s *Server) renderSettings(w http.ResponseWriter, r *http.Request, status int, formErr string) {
	ctx := r.Context()
	watch, err := cti.WatchedFilter(ctx, s.Store)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	regs, err := cti.WatchedRegulations(ctx, s.Store)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	watch.Regulations = regs.Regulations
	feeds, err := s.Store.ListFeeds(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	var hooks []store.Webhook
	var tokens []store.APIToken
	if sess, _ := sessionFrom(ctx); auth.RoleAtLeast(sess.User.Role, auth.RoleAdmin) {
		if hooks, err = s.Store.ListWebhooks(ctx); err != nil {
			s.serverError(w, r, err)
			return
		}
		if tokens, err = s.Store.ListAPITokens(ctx); err != nil {
			s.serverError(w, r, err)
			return
		}
	}
	sla, err := s.Store.SLA(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	newsPerDay, err := cti.NewsPerDay(ctx, s.Store)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, status, "settings", page{Title: "Paramètres", Error: formErr, Data: map[string]any{
		"Watch": watch, "Feeds": feeds, "Webhooks": hooks, "NewsPerDay": newsPerDay, "NewsFrequencies": cti.NewsFrequencies,
		"Tokens": tokens, "NewToken": s.newToken(r), "BaseURL": s.BaseURL,
		"SLA": sla, "Mail": s.Notifier != nil && s.Notifier.Mail != nil,
	}})
}

func (s *Server) saveWatch(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Formulaire invalide.", http.StatusBadRequest)
		return
	}
	if err := cti.SaveWatched(r.Context(), s.Store, r.PostForm["country"], r.PostForm["sector"], r.PostForm["regulation"]); err != nil {
		s.serverError(w, r, err)
		return
	}
	countries, sectors, regulations := feedTagsFromForm(r) // what was saved: the known values
	s.audit(r, "watch_update", "countries", countries, "sectors", sectors, "regulations", regulations)
	redirect(w, r, "/settings", "watch-saved")
}

// feedTagsFromForm reads the tags a feed applies to its items, or the watched
// ones: several countries, sectors and regulations each, known values only.
func feedTagsFromForm(r *http.Request) (country, sectors, regulations string) {
	return strings.Join(choice.KnownOnly(cti.Countries, r.PostForm["country"]), ","),
		strings.Join(choice.KnownOnly(cti.Sectors, r.PostForm["sector"]), ","),
		strings.Join(choice.KnownOnly(cti.Regulations, r.PostForm["regulation"]), ",")
}

func (s *Server) feedCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Formulaire invalide.", http.StatusBadRequest)
		return
	}
	f := store.Feed{
		Name:    strings.TrimSpace(r.PostFormValue("name")),
		URL:     strings.TrimSpace(r.PostFormValue("url")),
		Enabled: true,
	}
	f.Country, f.Sectors, f.Regulations = feedTagsFromForm(r)
	if f.Name == "" || !clip.Fits(f.Name, maxNameLen) {
		s.renderSettings(w, r, http.StatusBadRequest, "Nom de flux invalide.")
		return
	}
	if err := netsafe.ValidateURL(f.URL); err != nil {
		s.renderSettings(w, r, http.StatusBadRequest, err.Error())
		return
	}
	id, err := s.Store.CreateFeed(r.Context(), f)
	if errors.Is(err, store.ErrExists) {
		s.renderSettings(w, r, http.StatusBadRequest, "Ce flux existe déjà.")
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "feed_create", "id", id, "name", f.Name, "url", maskURL(f.URL))
	redirect(w, r, "/settings", "feed-created")
}

// feedUpdate changes the tags of a feed and applies them to the items
// already collected.
func (s *Server) feedUpdate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Formulaire invalide.", http.StatusBadRequest)
		return
	}
	f, ok := load(s, w, r, s.Store.Feed)
	if !ok {
		return
	}
	f.Country, f.Sectors, f.Regulations = feedTagsFromForm(r)
	err := s.Store.UpdateFeedTags(r.Context(), f.ID, f.Country, f.Sectors, f.Regulations)
	if err == nil {
		err = cti.Retag(r.Context(), s.Store, f)
	}
	if err != nil {
		s.storeError(w, r, err)
		return
	}
	s.audit(r, "feed_update", "id", f.ID, "name", f.Name, "url", maskURL(f.URL))
	redirect(w, r, "/settings", "feed-updated")
}

func (s *Server) feedToggle(w http.ResponseWriter, r *http.Request) {
	enabled := r.PostFormValue("enabled") == "1"
	msg := "feed-disabled"
	if enabled {
		msg = "feed-enabled"
	}
	s.change(w, r, change{action: "feed_toggle", detail: []any{"enabled", enabled}, to: "/settings", msg: msg,
		apply: func(id int64) error { return s.Store.SetFeedEnabled(r.Context(), id, enabled) }})
}

func (s *Server) feedDelete(w http.ResponseWriter, r *http.Request) {
	s.change(w, r, change{action: "feed_delete", to: "/settings", msg: "feed-deleted",
		apply: func(id int64) error { return s.Store.DeleteFeed(r.Context(), id) }})
}

func (s *Server) webhookCreate(w http.ResponseWriter, r *http.Request) {
	h := store.Webhook{
		Name:    strings.TrimSpace(r.PostFormValue("name")),
		Kind:    r.PostFormValue("kind"),
		URL:     strings.TrimSpace(r.PostFormValue("url")),
		Enabled: true,
		Digests: r.PostFormValue("digests") == "1",
		Alerts:  r.PostFormValue("alerts"),
	}
	if err := notify.ValidateWebhook(h); err != nil {
		s.renderSettings(w, r, http.StatusBadRequest, err.Error())
		return
	}
	if h.Kind == "email" && (s.Notifier == nil || s.Notifier.Mail == nil) {
		s.renderSettings(w, r, http.StatusBadRequest,
			"Aucun serveur SMTP n'est configuré : démarrez Vigil avec -smtp-addr et -smtp-from (voir docs/INSTALL.md).")
		return
	}
	id, err := s.Store.CreateWebhook(r.Context(), h)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	// SECURITY: a webhook URL is a secret, only its host is audited.
	s.audit(r, "webhook_create", "id", id, "target", notify.Target(h))
	redirect(w, r, "/settings", "hook-created")
}

func (s *Server) webhookToggle(w http.ResponseWriter, r *http.Request) {
	enabled := r.PostFormValue("enabled") == "1"
	msg := "hook-disabled"
	if enabled {
		msg = "hook-enabled"
	}
	s.change(w, r, change{action: "webhook_toggle", detail: []any{"enabled", enabled}, to: "/settings", msg: msg,
		apply: func(id int64) error { return s.Store.SetWebhookEnabled(r.Context(), id, enabled) }})
}

// newsFrequency chooses how many times a day the feeds are collected.
func (s *Server) newsFrequency(w http.ResponseWriter, r *http.Request) {
	n, err := strconv.Atoi(r.PostFormValue("per_day"))
	if err != nil || !slices.Contains(cti.NewsFrequencies, n) {
		s.renderSettings(w, r, http.StatusBadRequest, "Fréquence de collecte invalide.")
		return
	}
	if err := s.Store.SetSetting(r.Context(), cti.SettingNewsPerDay, strconv.Itoa(n)); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "news_frequency", "per_day", n)
	redirect(w, r, "/settings", "news-updated")
}

// webhookTest sends a short message to a channel, to check its settings without
// waiting for an alert; the result shows in the state of the channel.
func (s *Server) webhookTest(w http.ResponseWriter, r *http.Request) {
	h, ok := load(s, w, r, s.Store.Webhook)
	if !ok {
		return
	}
	if s.Notifier == nil {
		s.notFound(w)
		return
	}
	msg, sent := "hook-test-sent", true
	if err := s.Notifier.SendTest(r.Context(), h); err != nil {
		msg, sent = "hook-test-failed", false
	}
	s.audit(r, "webhook_test", "id", h.ID, "target", notify.Target(h), "sent", sent)
	redirect(w, r, "/settings", msg)
}

// webhookDelivery chooses what a channel receives: digests, alerts or both.
func (s *Server) webhookDelivery(w http.ResponseWriter, r *http.Request) {
	alerts := r.PostFormValue("alerts")
	if !choice.Has(notify.AlertOptions, alerts) {
		http.Error(w, "Niveau d'alerte invalide.", http.StatusBadRequest)
		return
	}
	digests := r.PostFormValue("digests") == "1"
	s.change(w, r, change{action: "webhook_delivery", detail: []any{"digests", digests, "alerts", alerts}, to: "/settings",
		msg: "hook-updated", apply: func(id int64) error { return s.Store.SetWebhookDelivery(r.Context(), id, digests, alerts) }})
}

// slaSave sets the remediation deadlines by severity.
func (s *Server) slaSave(w http.ResponseWriter, r *http.Request) {
	days := func(key string) int {
		v, err := strconv.Atoi(strings.TrimSpace(r.PostFormValue(key)))
		if err != nil {
			return -1
		}
		return v
	}
	l := store.SLA{Critical: days("critical"), High: days("high"), Medium: days("medium"), Low: days("low")}
	if !l.Valid() {
		s.renderSettings(w, r, http.StatusBadRequest, fmt.Sprintf("Indiquez des délais entre 0 (aucun) et %d jours.", store.MaxSLADays))
		return
	}
	if err := s.Store.SetSLA(r.Context(), l); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "sla_update", "critical", l.Critical, "high", l.High, "medium", l.Medium, "low", l.Low)
	redirect(w, r, "/settings", "sla-saved")
}

// auditList shows the most recent entries of the audit log.
func (s *Server) auditList(w http.ResponseWriter, r *http.Request) {
	entries, err := s.Store.ListAudit(r.Context(), 500)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "audit", page{Title: "Journal d'audit", Data: entries})
}

func (s *Server) webhookDelete(w http.ResponseWriter, r *http.Request) {
	s.change(w, r, change{action: "webhook_delete", to: "/settings", msg: "hook-deleted",
		apply: func(id int64) error { return s.Store.DeleteWebhook(r.Context(), id) }})
}

// maskURL keeps the scheme and host of a URL: feed URLs may carry an access
// key in their path or query.
func maskURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "(URL)"
	}
	return u.Scheme + "://" + u.Host + "/…"
}

// --- SBOM -----------------------------------------------------------------

func (s *Server) sbomImport(w http.ResponseWriter, r *http.Request) {
	file, _, err := r.FormFile("sbom")
	if err != nil {
		s.renderNewAsset(w, r, http.StatusBadRequest, defaultAssetForm(), "Fichier SBOM manquant ou trop volumineux.")
		return
	}
	defer file.Close()
	doc, err := sbom.Parse(file)
	if err != nil {
		s.renderNewAsset(w, r, http.StatusBadRequest, defaultAssetForm(), err.Error())
		return
	}
	project := strings.TrimSpace(r.PostFormValue("project"))
	if project == "" {
		project = doc.Name
	}
	if project == "" || !clip.Fits(project, inventory.MaxProjectLen) {
		s.renderNewAsset(w, r, http.StatusBadRequest, defaultAssetForm(), "Indiquez un nom de projet.")
		return
	}
	res, err := s.Store.ReplaceProjectAssets(r.Context(), writeScope(r), project, doc.Assets)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "sbom_import", "project", project, "format", doc.Format,
		"added", res.Added, "kept", res.Kept, "removed", res.Removed, "skipped", doc.Skipped)
	go s.runSync()
	redirect(w, r, "/assets?project="+url.QueryEscape(project), "sbom-imported")
}

// defaultAssetForm prefills the form of a new asset: it is checked for the
// vulnerabilities of the last 120 days (see inventory.DefaultWindow).
func defaultAssetForm() store.Asset {
	return store.Asset{Kind: "package", Criticality: "medium", TrackSince: inventory.DefaultSince(time.Now())}
}
