package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

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
	filter := store.CTIFilter{Countries: knownOnly(cti.Countries, q["country"]), Sectors: knownOnly(cti.Sectors, q["sector"]),
		Regulations: knownOnly(cti.Regulations, q["regulation"])}
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
	items, err := s.Store.ListCTIItems(r.Context(), filter)
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
	}})
}

func (s *Server) ctiRefresh(w http.ResponseWriter, r *http.Request) {
	go func() {
		ctx, cancel := context.WithTimeout(s.background(), 10*time.Minute)
		defer cancel()
		if _, err := s.CTI.Run(ctx); err != nil {
			s.Log.Error("cti failed", "err", err)
		}
	}()
	redirect(w, r, "/cti", "cti-started")
}

func knownOnly(tags []cti.Tag, values []string) []string {
	var out []string
	for _, v := range values {
		if cti.Known(tags, v) {
			out = append(out, v)
		}
	}
	return out
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
	if sess, _ := sessionFrom(ctx); sess.User.Role == "admin" {
		if hooks, err = s.Store.ListWebhooks(ctx); err != nil {
			s.serverError(w, r, err)
			return
		}
		if tokens, err = s.Store.ListAPITokens(ctx); err != nil {
			s.serverError(w, r, err)
			return
		}
	}
	s.render(w, r, status, "settings", page{Title: "Paramètres", Error: formErr, Data: map[string]any{
		"Watch": watch, "Feeds": feeds, "Webhooks": hooks,
		"Tokens": tokens, "NewToken": newTokenFrom(ctx), "BaseURL": s.BaseURL,
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
	redirect(w, r, "/settings", "watch-saved")
}

// feedTagsFromForm reads the tags a feed applies to its items: several
// countries, sectors and regulations each.
func feedTagsFromForm(r *http.Request) (country, sectors, regulations string) {
	return strings.Join(knownOnly(cti.Countries, r.PostForm["country"]), ","),
		strings.Join(knownOnly(cti.Sectors, r.PostForm["sector"]), ","),
		strings.Join(knownOnly(cti.Regulations, r.PostForm["regulation"]), ",")
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
	if f.Name == "" || len(f.Name) > 100 {
		s.renderSettings(w, r, http.StatusBadRequest, "Nom de flux invalide.")
		return
	}
	if err := netsafe.ValidateURL(f.URL); err != nil {
		s.renderSettings(w, r, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := s.Store.CreateFeed(r.Context(), f); err != nil {
		s.renderSettings(w, r, http.StatusBadRequest, "Ce flux existe déjà.")
		return
	}
	sess, _ := sessionFrom(r.Context())
	s.audit(r, sess.User.ID, "feed_create", f.URL)
	redirect(w, r, "/settings", "feed-created")
}

// feedUpdate changes the tags of a feed and applies them to the items
// already collected.
func (s *Server) feedUpdate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Formulaire invalide.", http.StatusBadRequest)
		return
	}
	s.byID(w, r, func(id int64) error {
		country, sectors, regulations := feedTagsFromForm(r)
		if err := s.Store.UpdateFeedTags(r.Context(), id, country, sectors, regulations); err != nil {
			return err
		}
		feeds, err := s.Store.ListFeeds(r.Context())
		if err != nil {
			return err
		}
		for _, f := range feeds {
			if f.ID == id {
				sess, _ := sessionFrom(r.Context())
				s.audit(r, sess.User.ID, "feed_update", f.URL)
				return cti.Retag(r.Context(), s.Store, f)
			}
		}
		return nil
	}, "/settings", "feed-updated")
}

func (s *Server) feedToggle(w http.ResponseWriter, r *http.Request) {
	enabled := r.PostFormValue("enabled") == "1"
	msg := "feed-disabled"
	if enabled {
		msg = "feed-enabled"
	}
	s.byID(w, r, func(id int64) error { return s.Store.SetFeedEnabled(r.Context(), id, enabled) }, "/settings", msg)
}

func (s *Server) feedDelete(w http.ResponseWriter, r *http.Request) {
	s.byID(w, r, func(id int64) error { return s.Store.DeleteFeed(r.Context(), id) }, "/settings", "feed-deleted")
}

func (s *Server) webhookCreate(w http.ResponseWriter, r *http.Request) {
	h := store.Webhook{
		Name:    strings.TrimSpace(r.PostFormValue("name")),
		Kind:    r.PostFormValue("kind"),
		URL:     strings.TrimSpace(r.PostFormValue("url")),
		Enabled: true,
	}
	if err := notify.ValidateWebhook(h); err != nil {
		s.renderSettings(w, r, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := s.Store.CreateWebhook(r.Context(), h); err != nil {
		s.serverError(w, r, err)
		return
	}
	sess, _ := sessionFrom(r.Context())
	// SECURITY: the URL is a secret, only its host is audited.
	s.audit(r, sess.User.ID, "webhook_create", notify.MaskURL(h.URL))
	redirect(w, r, "/settings", "hook-created")
}

func (s *Server) webhookToggle(w http.ResponseWriter, r *http.Request) {
	enabled := r.PostFormValue("enabled") == "1"
	msg := "hook-disabled"
	if enabled {
		msg = "hook-enabled"
	}
	s.byID(w, r, func(id int64) error { return s.Store.SetWebhookEnabled(r.Context(), id, enabled) }, "/settings", msg)
}

func (s *Server) webhookDelete(w http.ResponseWriter, r *http.Request) {
	s.byID(w, r, func(id int64) error { return s.Store.DeleteWebhook(r.Context(), id) }, "/settings", "hook-deleted")
}

// byID runs action on the {id} path value and redirects with msg.
func (s *Server) byID(w http.ResponseWriter, r *http.Request, action func(int64) error, to, msg string) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.notFound(w)
		return
	}
	err = action(id)
	if errors.Is(err, store.ErrNotFound) {
		s.notFound(w)
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	redirect(w, r, to, msg)
}

// --- SBOM -----------------------------------------------------------------

func (s *Server) sbomImport(w http.ResponseWriter, r *http.Request) {
	file, _, err := r.FormFile("sbom")
	if err != nil {
		s.renderAssets(w, r, http.StatusBadRequest, defaultAssetForm(), "Fichier SBOM manquant ou trop volumineux.")
		return
	}
	defer file.Close()
	doc, err := sbom.Parse(file)
	if err != nil {
		s.renderAssets(w, r, http.StatusBadRequest, defaultAssetForm(), err.Error())
		return
	}
	project := strings.TrimSpace(r.PostFormValue("project"))
	if project == "" {
		project = doc.Name
	}
	if project == "" || len(project) > 200 {
		s.renderAssets(w, r, http.StatusBadRequest, defaultAssetForm(), "Indiquez un nom de projet.")
		return
	}
	res, err := s.Store.ReplaceProjectAssets(r.Context(), project, doc.Assets)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	sess, _ := sessionFrom(r.Context())
	s.audit(r, sess.User.ID, "sbom_import", fmt.Sprintf("%s: %s +%d =%d -%d (%d ignorés)",
		project, doc.Format, res.Added, res.Kept, res.Removed, doc.Skipped))
	go s.runSync()
	redirect(w, r, "/assets?project="+url.QueryEscape(project), "sbom-imported")
}

// defaultAssetForm prefills the form of a new asset: it is checked for the
// vulnerabilities of the last 120 days (see inventory.DefaultWindow).
func defaultAssetForm() store.Asset {
	return store.Asset{Kind: "package", Criticality: "medium", TrackSince: inventory.DefaultSince(time.Now())}
}
