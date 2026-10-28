// Package web serves the HTML user interface.
package web

import (
	"context"
	"embed"
	"errors"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/auth"
	"github.com/La-Cizaille-Corp/vigil/internal/cti"
	"github.com/La-Cizaille-Corp/vigil/internal/digest"
	"github.com/La-Cizaille-Corp/vigil/internal/inventory"
	"github.com/La-Cizaille-Corp/vigil/internal/notify"
	"github.com/La-Cizaille-Corp/vigil/internal/sbom"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
	"github.com/La-Cizaille-Corp/vigil/internal/tracking"
)

//go:embed templates/*.html
var templatesFS embed.FS

//go:embed static
var staticFS embed.FS

const (
	sessionCookie   = "vigil_session"
	sessionDuration = 12 * time.Hour
	maxFormBytes    = 64 << 10
	// maxPasswordBytes bounds the argon2 input on password change.
	maxPasswordBytes = 1024
	maxUploadBytes   = sbom.MaxSize + 1<<20 // file plus multipart overhead
)

// Server holds the dependencies of the HTTP handlers.
type Server struct {
	Store    *store.Store
	Syncer   *tracking.Syncer
	CTI      *cti.Collector
	Notifier *notify.Notifier
	Log      *slog.Logger
	// Version is reported in exported documents.
	Version string
	// BaseURL is the public address of the UI, used in webhook messages.
	BaseURL string
	// Context is cancelled when the server stops; background jobs started
	// from a request (sync, CTI collection) use it instead of the request's.
	Context context.Context
	// SecureCookies must be true whenever the UI is reached over HTTPS.
	SecureCookies bool
	// BehindProxy disables the web setup page (see setupAllowed).
	BehindProxy bool

	pages   map[string]*template.Template
	limiter *auth.Limiter
}

// Handler builds the routes and middleware.
func (s *Server) Handler() (http.Handler, error) {
	if err := s.parseTemplates(); err != nil {
		return nil, err
	}
	s.limiter = auth.NewLimiter(5, 15*time.Minute)

	static, _ := fs.Sub(staticFS, "static")
	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))

	mux.HandleFunc("GET /setup", s.setupForm)
	mux.HandleFunc("POST /setup", s.setupSubmit)
	mux.HandleFunc("GET /login", s.loginForm)
	mux.HandleFunc("POST /login", s.loginSubmit)
	mux.Handle("POST /logout", s.require(auth.RoleViewer, s.logout))

	mux.Handle("GET /account", s.require(auth.RoleViewer, s.account))
	mux.Handle("POST /account/totp/start", s.require(auth.RoleViewer, s.totpStart))
	mux.Handle("POST /account/totp/confirm", s.require(auth.RoleViewer, s.totpConfirm))
	mux.Handle("POST /account/totp/disable", s.require(auth.RoleViewer, s.totpDisable))
	mux.Handle("POST /account/password", s.require(auth.RoleViewer, s.passwordChange))

	mux.Handle("GET /{$}", s.require(auth.RoleViewer, s.dashboard))
	mux.Handle("GET /assets", s.require(auth.RoleViewer, s.assetList))
	mux.Handle("GET /assets.csv", s.require(auth.RoleViewer, s.assetCSV))
	mux.Handle("POST /assets/import-csv", s.require(auth.RoleAnalyst, s.assetCSVImport))
	mux.Handle("GET /assets/cpe", s.require(auth.RoleAnalyst, s.cpeSearch))
	mux.Handle("POST /assets", s.require(auth.RoleAnalyst, s.assetCreate))
	mux.Handle("GET /assets/{id}", s.require(auth.RoleViewer, s.assetEdit))
	mux.Handle("POST /assets/{id}", s.require(auth.RoleAnalyst, s.assetUpdate))
	mux.Handle("POST /assets/{id}/delete", s.require(auth.RoleAnalyst, s.assetDelete))
	mux.Handle("POST /assets/{id}/scan", s.require(auth.RoleAnalyst, s.assetScan))
	mux.Handle("GET /findings", s.require(auth.RoleViewer, s.findingList))
	mux.Handle("GET /findings.csv", s.require(auth.RoleViewer, s.findingCSV))
	mux.Handle("POST /findings/bulk", s.require(auth.RoleAnalyst, s.findingBulk))
	mux.Handle("GET /findings/vex", s.require(auth.RoleViewer, s.vexExport))
	mux.Handle("POST /findings/vex", s.require(auth.RoleAnalyst, s.vexImport))
	mux.Handle("GET /findings/{id}", s.require(auth.RoleViewer, s.findingShow))
	mux.Handle("POST /findings/{id}", s.require(auth.RoleAnalyst, s.findingUpdate))
	mux.Handle("POST /sync", s.require(auth.RoleAnalyst, s.syncNow))
	mux.Handle("GET /digests", s.require(auth.RoleViewer, s.digestList))
	mux.Handle("POST /digests", s.require(auth.RoleAnalyst, s.digestCreate))
	mux.Handle("GET /digests/{id}", s.require(auth.RoleViewer, s.digestShow))
	mux.Handle("GET /digests/{id}/markdown", s.require(auth.RoleViewer, s.digestMarkdown))

	mux.Handle("POST /assets/import", s.require(auth.RoleAnalyst, s.sbomImport))
	mux.Handle("GET /cti", s.require(auth.RoleViewer, s.ctiList))
	mux.Handle("POST /cti/refresh", s.require(auth.RoleAnalyst, s.ctiRefresh))
	mux.Handle("GET /settings", s.require(auth.RoleViewer, s.settings))
	mux.Handle("POST /settings/watch", s.require(auth.RoleAnalyst, s.saveWatch))
	mux.Handle("POST /settings/feeds", s.require(auth.RoleAdmin, s.feedCreate))
	mux.Handle("POST /settings/feeds/{id}", s.require(auth.RoleAdmin, s.feedUpdate))
	mux.Handle("POST /settings/feeds/{id}/toggle", s.require(auth.RoleAdmin, s.feedToggle))
	mux.Handle("POST /settings/feeds/{id}/delete", s.require(auth.RoleAdmin, s.feedDelete))
	mux.Handle("POST /settings/webhooks", s.require(auth.RoleAdmin, s.webhookCreate))
	mux.Handle("POST /settings/webhooks/{id}", s.require(auth.RoleAdmin, s.webhookDelivery))
	mux.Handle("POST /settings/webhooks/{id}/toggle", s.require(auth.RoleAdmin, s.webhookToggle))
	mux.Handle("POST /settings/sla", s.require(auth.RoleAdmin, s.slaSave))
	mux.Handle("GET /settings/audit", s.require(auth.RoleAdmin, s.auditList))
	mux.Handle("POST /settings/webhooks/{id}/delete", s.require(auth.RoleAdmin, s.webhookDelete))
	mux.Handle("POST /settings/tokens", s.require(auth.RoleAdmin, s.tokenCreate))
	mux.Handle("POST /settings/tokens/{id}/delete", s.require(auth.RoleAdmin, s.tokenDelete))

	// Token-authenticated API for CI pipelines (no session, no CSRF: no cookie is used).
	mux.HandleFunc("PUT /api/v1/projects/{project}/sbom", s.apiSBOM)

	return securityHeaders(sameOrigin(limitBody(mux))), nil
}

func (s *Server) parseTemplates() error {
	funcs := template.FuncMap{
		"date":      func(t time.Time) string { return t.Local().Format("02/01/2006 15:04") },
		"isoDate":   isoDate,
		"sevLabel":  tracking.SeverityLabel,
		"roleLabel": func(v string) string { return inventory.Label(roles, v) },
		"tracking":  trackingSource,
		"vendorOf": func(a store.Asset) string {
			v, _ := inventory.VendorProduct(a)
			return v
		},
		"wholeVendor": inventory.WholeVendor,
		"knownTags":   s.knownTags,
		"syncStatus":  s.syncStatus,
		"tags":        splitTags,
		"dict3": func(countries, sectors, regulations []string) tagSelection {
			return tagSelection{countries, sectors, regulations}
		},
		"kindLabel":     func(v string) string { return inventory.Label(inventory.Kinds, v) },
		"critLabel":     func(v string) string { return inventory.Label(inventory.Criticalities, v) },
		"statusLabel":   func(v string) string { return inventory.Label(tracking.Statuses, v) },
		"justifLabel":   func(v string) string { return inventory.Label(tracking.Justifications, v) },
		"can":           auth.RoleAtLeast,
		"join":          strings.Join,
		"hasPrefix":     strings.HasPrefix,
		"lower":         strings.ToLower,
		"days":          formatDays,
		"kinds":         func() []inventory.Option { return inventory.Kinds },
		"criticalities": func() []inventory.Option { return inventory.Criticalities },
		"cpeModes":      func() []inventory.Option { return inventory.CPEModes },
		"severities":    func() []inventory.Option { return severities },
		"sortOrders":    func() []inventory.Option { return sortOrders },
		"cvss": func(v float64) string {
			if v < 0 {
				return ""
			}
			return strconv.FormatFloat(v, 'f', 1, 64)
		},
		"ecosystems":       func() []string { return inventory.Ecosystems },
		"statuses":         func() []inventory.Option { return tracking.Statuses },
		"justifs":          func() []inventory.Option { return tracking.Justifications },
		"queryable":        inventory.Queryable,
		"epss":             digest.FormatEPSS,
		"countryLabel":     func(v string) string { return cti.Label(cti.Countries, v) },
		"sectorLabel":      func(v string) string { return cti.Label(cti.Sectors, v) },
		"countries":        func() []cti.Tag { return cti.Countries },
		"sectors":          func() []cti.Tag { return cti.Sectors },
		"regulations":      func() []cti.Tag { return cti.Regulations },
		"regulationLabel":  func(v string) string { return cti.Label(cti.Regulations, v) },
		"webhookKinds":     func() []inventory.Option { return notify.Kinds },
		"webhookKindLabel": func(v string) string { return inventory.Label(notify.Kinds, v) },
		"target":           notify.Target,
		"alertOptions":     func() []inventory.Option { return notify.AlertOptions },
		"alertLabel":       func(v string) string { return inventory.Label(notify.AlertOptions, v) },
		"findingRows": func(list []store.Finding, selectable bool) map[string]any {
			return map[string]any{"List": list, "Select": selectable}
		},
		"has": func(list []string, v string) bool {
			for _, x := range list {
				if x == v {
					return true
				}
			}
			return false
		},
		// SECURITY: digest HTML is produced by html/template from stored data
		// (see package digest), so it is already escaped.
		"trustedDigest": func(s string) template.HTML { return template.HTML(s) }, // #nosec G203 -- escaped at generation
	}
	pages, err := fs.Glob(templatesFS, "templates/*.html")
	if err != nil {
		return err
	}
	s.pages = map[string]*template.Template{}
	for _, p := range pages {
		name := strings.TrimSuffix(strings.TrimPrefix(p, "templates/"), ".html")
		if name == "layout" || name == "partials" {
			continue
		}
		t, err := template.New(name).Funcs(funcs).ParseFS(templatesFS,
			"templates/layout.html", "templates/partials.html", p)
		if err != nil {
			return err
		}
		s.pages[name] = t
	}
	return nil
}

// page is the data passed to every template.
type page struct {
	Path  string // of the request, to mark the current menu entry
	Title string
	User  *store.User
	CSRF  string
	Flash string
	Error string
	Data  any
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, name string, p page) {
	if sess, ok := sessionFrom(r.Context()); ok {
		p.User, p.CSRF = &sess.User, sess.CSRFToken
	}
	if p.Flash == "" {
		p.Flash = flashes[r.URL.Query().Get("msg")]
	}
	p.Path = r.URL.Path
	p.Error = sentences(p.Error)
	t, ok := s.pages[name]
	if !ok {
		s.serverError(w, r, errors.New("unknown template "+name))
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := t.ExecuteTemplate(w, "layout", p); err != nil {
		s.Log.Error("render template", "template", name, "err", err)
	}
}

// flashes maps fixed keys to messages, so no user input is ever reflected.
var flashes = map[string]string{ // #nosec G101 -- message keys, not credentials
	"asset-created":    "Actif ajouté ; recherche de ses vulnérabilités lancée, actualisez la page dans quelques instants.",
	"asset-updated":    "Actif enregistré ; recherche de ses vulnérabilités relancée, actualisez la page dans quelques instants.",
	"asset-deleted":    "Actif supprimé.",
	"scan-started":     "Recherche des vulnérabilités de l'actif lancée ; actualisez la page dans quelques instants.",
	"status-updated":   "Statut mis à jour.",
	"sync-started":     "Synchronisation lancée ; actualisez la page dans quelques instants.",
	"sync-running":     "Une synchronisation est déjà en cours ; actualisez la page dans quelques instants.",
	"digest-created":   "Digest généré.",
	"digest-sent":      "Digest généré et envoyé aux canaux de notification.",
	"digest-webhook":   "Digest généré, mais au moins un canal de notification a échoué (détail dans Paramètres, visible par un administrateur).",
	"cti-started":      "Collecte des flux lancée ; actualisez la page dans quelques instants.",
	"watch-saved":      "Filtres de veille enregistrés.",
	"feed-created":     "Flux ajouté.",
	"feed-updated":     "Étiquettes du flux enregistrées ; elles s'appliquent aussi aux actualités déjà collectées.",
	"feed-enabled":     "Flux activé.",
	"feed-disabled":    "Flux désactivé.",
	"feed-deleted":     "Flux supprimé.",
	"hook-created":     "Canal de notification ajouté.",
	"hook-updated":     "Canal de notification enregistré.",
	"hook-enabled":     "Canal de notification activé.",
	"hook-disabled":    "Canal de notification désactivé.",
	"hook-deleted":     "Canal de notification supprimé.",
	"csv-imported":     "Inventaire importé ; synchronisation lancée, actualisez la page dans quelques instants.",
	"bulk-updated":     "Statut appliqué aux vulnérabilités sélectionnées.",
	"sla-saved":        "Délais de traitement enregistrés ; les échéances sont recalculées.",
	"sbom-imported":    "SBOM importé ; synchronisation lancée, actualisez la page dans quelques instants.",
	"password-changed": "Mot de passe modifié ; vos autres sessions ont été fermées.",
	"token-deleted":    "Jeton révoqué.",
	"totp-enabled":     "Double authentification activée.",
	"totp-disabled":    "Double authentification désactivée.",
	"vex-imported":     "VEX importé : les analyses correspondantes ont été appliquées.",
}

func redirect(w http.ResponseWriter, r *http.Request, path, msg string) {
	if msg != "" {
		path += "?msg=" + url.QueryEscape(msg)
	}
	http.Redirect(w, r, path, http.StatusSeeOther)
}

func (s *Server) serverError(w http.ResponseWriter, r *http.Request, err error) {
	// SECURITY: details go to the log, the client gets a generic message.
	s.Log.Error("request failed", "method", r.Method, "path", r.URL.Path, "err", err)
	http.Error(w, "Erreur interne.", http.StatusInternalServerError)
}

func (s *Server) notFound(w http.ResponseWriter) {
	http.Error(w, "Introuvable.", http.StatusNotFound)
}

// clientIP is the client address used for rate limiting and the audit log.
// Behind a reverse proxy (-behind-proxy), it is the last address of
// X-Forwarded-For: the one the proxy itself appended. Earlier entries come
// from the client and can be forged; the last one cannot, because Vigil is
// then only reachable through the proxy. Without this, every user would share
// the proxy address, and five failed logins would lock everyone out.
func (s *Server) clientIP(r *http.Request) string {
	if s.BehindProxy {
		forwarded := r.Header.Values("X-Forwarded-For")
		if n := len(forwarded); n > 0 {
			hops := strings.Split(forwarded[n-1], ",")
			if ip := net.ParseIP(strings.TrimSpace(hops[len(hops)-1])); ip != nil {
				return ip.String()
			}
		}
	}
	return remoteHost(r)
}

// remoteHost is the address of the TCP peer: the proxy, if there is one.
func remoteHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func isLoopback(r *http.Request) bool {
	ip := net.ParseIP(remoteHost(r))
	return ip != nil && ip.IsLoopback()
}

// background returns the server lifetime context.
func (s *Server) background() context.Context {
	if s.Context != nil {
		return s.Context
	}
	return context.Background()
}

// audit records an action in the audit log; a failure is logged, never
// silently ignored, but does not fail the user's request.
func (s *Server) audit(r *http.Request, userID int64, action, detail string) {
	if err := s.Store.Audit(r.Context(), userID, action, detail); err != nil {
		s.Log.Error("audit log write failed", "action", action, "err", err)
	}
}

// PurgeSessions deletes expired sessions periodically until ctx is done.
func (s *Server) PurgeSessions(ctx context.Context) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.Store.DeleteExpiredSessions(ctx); err != nil {
				s.Log.Warn("purge sessions", "err", err)
			}
		}
	}
}
