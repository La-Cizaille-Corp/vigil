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

// ctiList shows a view of the watch: the most recent news of it
// (store.MaxCTIItems), a page at a time by day, with the number of news of
// each view (A87).
func (s *Server) ctiList(w http.ResponseWriter, r *http.Request) {
	ctx, q := r.Context(), r.URL.Query()
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
	filter := store.CTIFilter{Countries: choice.KnownOnly(cti.Countries, q["country"]), Sectors: choice.KnownOnly(cti.Sectors, q["sector"]),
		Regulations: choice.KnownOnly(cti.Regulations, q["regulation"])}
	watched, regulatory, all := false, q.Get("view") == "regulatory", q.Get("all") != ""
	switch {
	case regulatory:
		filter = regs
	case len(filter.Countries) == 0 && len(filter.Sectors) == 0 && len(filter.Regulations) == 0 && !all:
		filter = watch
		watched = len(filter.Countries) > 0 || len(filter.Sectors) > 0
	}
	filter.Concerning = q.Get("concerning") == "1"
	filter.Limit = store.MaxCTIItems
	items, err := s.Store.ListCTIItems(ctx, readScope(r), filter)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	total, err := s.Store.CountCTIItems(ctx, readScope(r), filter)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	// The views, the one concerning the inventory first: the most useful.
	concerning := filter.Concerning
	views := []levelLink{
		{Level: "concerning", Label: "Qui concernent mon inventaire", Href: "/cti?all=1&concerning=1", Active: concerning},
		{Level: "threats", Label: "Veille menaces", Href: "/cti", Active: !regulatory && !all && !concerning},
		{Level: "regulatory", Label: "Veille réglementaire", Href: "/cti?view=regulatory", Active: regulatory && !concerning},
		{Level: "all", Label: "Toutes les actualités", Href: "/cti?all=1", Active: all && !concerning},
	}
	for i, f := range []store.CTIFilter{{Concerning: true}, watch, regs, {}} {
		if views[i].N, err = s.Store.CountCTIItems(ctx, readScope(r), f); err != nil {
			s.serverError(w, r, err)
			return
		}
	}
	shown, pages := paginate(items, q, "/cti")
	title := "Veille menaces"
	if regulatory {
		title = "Veille réglementaire"
	}
	s.render(w, r, http.StatusOK, "cti", page{Title: title, Data: map[string]any{
		"Days": newsDays(shown), "Pager": pages, "Total": total, "Views": views,
		"Filter": filter, "Watched": watched, "Regulatory": regulatory, "All": all, "Concerning": concerning,
	}})
}

// newsDay is the news of one day on a page of the watch, most recent first.
type newsDay struct {
	Day   time.Time
	Items []store.CTIItem
}

// newsDays groups news, most recent first, by the day they were published.
func newsDays(items []store.CTIItem) []newsDay {
	var days []newsDay
	for _, it := range items {
		day := it.Published.Local().Format(time.DateOnly)
		if n := len(days); n == 0 || days[n-1].Day.Local().Format(time.DateOnly) != day {
			days = append(days, newsDay{Day: it.Published})
		}
		days[len(days)-1].Items = append(days[len(days)-1].Items, it)
	}
	return days
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

// --- settings (sub-pages in handlers_settings.go) -------------------------

// saveWatch sets the watched countries, sectors and regulations: a setting
// common to every account, so that an account restricted to groups may not
// change what the others see (A68, D4).
func (s *Server) saveWatch(w http.ResponseWriter, r *http.Request) {
	if sess, _ := sessionFrom(r.Context()); sess.User.Restricted() {
		s.renderWatch(w, r, http.StatusForbidden,
			"Les filtres de veille sont communs à tous les comptes : seul un compte qui voit tout l'inventaire peut les changer.")
		return
	}
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
	redirect(w, r, "/settings/watch#contenu", "watch-saved")
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
	// A refusal shows the form again as typed, its message in it (A89).
	refuse := func(msg string) { s.renderFeeds(w, r, http.StatusBadRequest, feedFormFrom(r), formFeed, msg) }
	if f.Name == "" || !clip.Fits(f.Name, maxNameLen) {
		refuse("Nom de flux invalide : 1 à 100 caractères.")
		return
	}
	if err := netsafe.ValidateURL(f.URL); err != nil {
		refuse(err.Error())
		return
	}
	id, err := s.Store.CreateFeed(r.Context(), f)
	if errors.Is(err, store.ErrExists) {
		refuse("Ce flux existe déjà.")
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "feed_create", "id", id, "name", f.Name, "url", maskURL(f.URL))
	redirect(w, r, "/settings/feeds#contenu", "feed-created")
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
	redirect(w, r, "/settings/feeds", "feed-updated")
}

func (s *Server) feedToggle(w http.ResponseWriter, r *http.Request) {
	enabled := r.PostFormValue("enabled") == "1"
	msg := "feed-disabled"
	if enabled {
		msg = "feed-enabled"
	}
	s.change(w, r, change{action: "feed_toggle", detail: []any{"enabled", enabled}, to: "/settings/feeds", msg: msg,
		apply: func(id int64) error { return s.Store.SetFeedEnabled(r.Context(), id, enabled) }})
}

func (s *Server) feedDelete(w http.ResponseWriter, r *http.Request) {
	s.change(w, r, change{action: "feed_delete", to: "/settings/feeds", msg: "feed-deleted",
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
	group, ok := s.channelGroup(w, r)
	if !ok {
		return
	}
	h.Group = group.ID
	// A refusal shows the form again as typed, its message in it (A89).
	if err := notify.ValidateWebhook(h); err != nil {
		s.renderWebhooks(w, r, http.StatusBadRequest, h, err.Error())
		return
	}
	if h.Kind == "email" && (s.Notifier == nil || s.Notifier.Mail == nil) {
		s.renderWebhooks(w, r, http.StatusBadRequest, h,
			"Aucun serveur SMTP n'est configuré : démarrez Vigil avec -smtp-addr et -smtp-from (voir docs/INSTALL.md).")
		return
	}
	id, err := s.Store.CreateWebhook(r.Context(), h)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	// SECURITY: a webhook URL is a secret, only its host is audited.
	detail := []any{"id", id, "target", notify.Target(h)}
	if group.ID != 0 {
		detail = append(detail, "group", group.Name)
	}
	s.audit(r, "webhook_create", detail...)
	redirect(w, r, "/settings/webhooks#contenu", "hook-created")
}

// channelGroup reads the group a channel is limited to (A68): the zero Group
// for the whole inventory. It answers 404 itself for a group that does not
// exist, and reports whether the request goes on.
func (s *Server) channelGroup(w http.ResponseWriter, r *http.Request) (store.Group, bool) {
	id := groupParam(r.PostForm)
	if id == 0 {
		return store.Group{}, true
	}
	g, err := s.Store.Group(r.Context(), readScope(r), id)
	if err != nil {
		s.storeError(w, r, err)
		return g, false
	}
	return g, true
}

func (s *Server) webhookToggle(w http.ResponseWriter, r *http.Request) {
	enabled := r.PostFormValue("enabled") == "1"
	msg := "hook-disabled"
	if enabled {
		msg = "hook-enabled"
	}
	s.change(w, r, change{action: "webhook_toggle", detail: []any{"enabled", enabled}, to: "/settings/webhooks", msg: msg,
		apply: func(id int64) error { return s.Store.SetWebhookEnabled(r.Context(), id, enabled) }})
}

// newsFrequency chooses how many times a day the feeds are collected.
func (s *Server) newsFrequency(w http.ResponseWriter, r *http.Request) {
	n, err := strconv.Atoi(r.PostFormValue("per_day"))
	if err != nil || !slices.Contains(cti.NewsFrequencies, n) {
		s.renderFeeds(w, r, http.StatusBadRequest, feedForm{}, formNews, "Fréquence de collecte invalide.")
		return
	}
	if err := s.Store.SetSetting(r.Context(), cti.SettingNewsPerDay, strconv.Itoa(n)); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "news_frequency", "per_day", n)
	redirect(w, r, "/settings/feeds#contenu", "news-updated")
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
	redirect(w, r, "/settings/webhooks", msg)
}

// webhookDelivery chooses what a channel receives: digests, alerts or both,
// of the whole inventory or of a group.
func (s *Server) webhookDelivery(w http.ResponseWriter, r *http.Request) {
	alerts := r.PostFormValue("alerts")
	if !choice.Has(notify.AlertOptions, alerts) {
		http.Error(w, "Niveau d'alerte invalide.", http.StatusBadRequest)
		return
	}
	digests := r.PostFormValue("digests") == "1"
	group, ok := s.channelGroup(w, r)
	if !ok {
		return
	}
	s.change(w, r, change{action: "webhook_delivery", detail: []any{"digests", digests, "alerts", alerts, "group", group.Name},
		to: "/settings/webhooks", msg: "hook-updated",
		apply: func(id int64) error { return s.Store.SetWebhookDelivery(r.Context(), id, digests, alerts, group.ID) }})
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
		typed := slaForm{r.PostFormValue("critical"), r.PostFormValue("high"), r.PostFormValue("medium"), r.PostFormValue("low")}
		s.renderSLA(w, r, http.StatusBadRequest, typed, fmt.Sprintf("Indiquez des délais entre 0 (aucun) et %d jours.", store.MaxSLADays))
		return
	}
	if err := s.Store.SetSLA(r.Context(), l); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "sla_update", "critical", l.Critical, "high", l.High, "medium", l.Medium, "low", l.Low)
	redirect(w, r, "/settings/sla#contenu", "sla-saved")
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
	s.change(w, r, change{action: "webhook_delete", to: "/settings/webhooks", msg: "hook-deleted",
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
		s.renderNewAsset(w, r, http.StatusBadRequest, defaultAssetForm(), addSBOM, "Fichier SBOM manquant ou trop volumineux (20 Mo au plus).")
		return
	}
	defer file.Close()
	doc, err := sbom.Parse(file)
	if err != nil {
		s.renderNewAsset(w, r, http.StatusBadRequest, defaultAssetForm(), addSBOM, "Import refusé, aucun actif modifié : "+err.Error())
		return
	}
	project := strings.TrimSpace(r.PostFormValue("project"))
	if project == "" {
		project = doc.Name
	}
	if project == "" || !clip.Fits(project, inventory.MaxProjectLen) {
		s.renderNewAsset(w, r, http.StatusBadRequest, defaultAssetForm(), addSBOM, "Indiquez un nom de projet : le SBOM n'en donne pas.")
		return
	}
	res, err := s.Store.ReplaceProjectAssets(r.Context(), writeScope(r), project, doc.Assets)
	if refusal := sbomRefusal(project, err); refusal != "" {
		s.renderNewAsset(w, r, http.StatusBadRequest, defaultAssetForm(), addSBOM, refusal)
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "sbom_import", "project", project, "format", doc.Format,
		"added", res.Added, "kept", res.Kept, "removed", res.Removed, "skipped", doc.Skipped)
	go s.runSync()
	redirect(w, r, "/assets?project="+url.QueryEscape(project), "sbom-imported")
}

// sbomRefusal explains an SBOM import refused to an account restricted to
// groups (A68), "" for any other outcome: its components go to the groups
// naming the project, which must exist and all be the account's.
func sbomRefusal(project string, err error) string {
	var e *store.OutsideGroupsError
	if !errors.As(err, &e) {
		return ""
	}
	if len(e.ForeignProjects) > 0 {
		return "Import refusé : le projet « " + project + " » relève d'un groupe dont vous ne faites pas partie. " +
			"Un compte qui voit tout l'inventaire peut l'importer."
	}
	return "Import refusé : le projet « " + project + " » ne fait partie d'aucun de vos groupes. " +
		"Un administrateur peut l'ajouter à l'un d'eux (Paramètres → Groupes)."
}

// defaultAssetForm prefills the form of a new asset: it is checked for the
// vulnerabilities of the last 120 days (see inventory.DefaultWindow).
func defaultAssetForm() store.Asset {
	return store.Asset{Kind: "package", Criticality: "medium", TrackSince: inventory.DefaultSince(time.Now())}
}
