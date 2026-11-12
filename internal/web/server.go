// Package web serves the HTML user interface.
package web

import (
	"context"
	"embed"
	"errors"
	"fmt"
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
	// sessionCookie is the session cookie name over plain HTTP; over HTTPS the
	// __Host- prefix forbids a sibling domain or a plain-HTTP page to plant one.
	sessionCookie   = "vigil_session"
	secureCookie    = "__Host-vigil_session"
	sessionDuration = 12 * time.Hour
	maxFormBytes    = 64 << 10
	maxUploadBytes  = sbom.MaxSize + 1<<20 // file plus multipart overhead
	// maxNameLen is the longest name of a feed or an API token, in characters.
	maxNameLen = 100
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
	// LocalOnly is set when the UI listens on the loopback interface in plain
	// HTTP: requests must then name the machine (see checkHost).
	LocalOnly bool
	// AuditRetention, when set, is how long audit entries are kept.
	AuditRetention time.Duration

	pages    map[string]*template.Template
	once     onceStore     // values shown once after a redirect
	limiter  *auth.Limiter // failed attempts per client (see clientKey), or per user from a session
	accounts *auth.Limiter // failed sign-ins per account name
}

// Handler builds the routes and middleware.
func (s *Server) Handler() (http.Handler, error) {
	if err := s.parseTemplates(); err != nil {
		return nil, err
	}
	s.limiter = auth.NewLimiter(5, 15*time.Minute)
	s.accounts = auth.NewLimiter(10, 15*time.Minute)

	static, _ := fs.Sub(staticFS, "static")
	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))

	for _, rt := range s.routes() {
		switch {
		case rt.role == public:
			mux.HandleFunc(rt.pattern, rt.handler)
		case auth.ValidRole(rt.role):
			mux.Handle(rt.pattern, s.require(rt.role, rt.handler))
		default: // SECURITY: a route without a known role is refused, not left open
			return nil, fmt.Errorf("route %s: unknown role %q", rt.pattern, rt.role)
		}
	}

	return securityHeaders(s.checkHost(sameOrigin(limitBody(mux)))), nil
}

// public marks the routes reached without a session: sign-in, first setup and
// the token-authenticated API, which check their caller themselves.
const public = "public"

// route is one entry of the UI: its pattern, the least role it requires (or
// public) and its handler.
type route struct {
	pattern string
	role    string
	handler http.HandlerFunc
}

// routes lists every route of the UI, so that tests can go through all of
// them. SECURITY: the role is checked server-side on each one (see require).
func (s *Server) routes() []route {
	return []route{
		{"GET /setup", public, s.setupForm},
		{"POST /setup", public, s.setupSubmit},
		{"GET /login", public, s.loginForm},
		{"POST /login", public, s.loginSubmit},
		{"POST /logout", auth.RoleViewer, s.logout},
		{"GET /account", auth.RoleViewer, s.account},
		{"POST /account/totp/start", auth.RoleViewer, s.totpStart},
		{"POST /account/totp/confirm", auth.RoleViewer, s.totpConfirm},
		{"POST /account/totp/disable", auth.RoleViewer, s.totpDisable},
		{"POST /account/password", auth.RoleViewer, s.passwordChange},
		{"POST /account/sessions/close-others", auth.RoleViewer, s.closeOtherSessions},
		{"GET /{$}", auth.RoleViewer, s.dashboard},
		{"GET /assets", auth.RoleViewer, s.assetList},
		{"GET /assets.csv", auth.RoleViewer, s.assetCSV},
		{"POST /assets/import-csv", auth.RoleAnalyst, s.assetCSVImport},
		{"GET /assets/cpe", auth.RoleAnalyst, s.cpeSearch},
		{"GET /assets/new", auth.RoleAnalyst, s.assetNew},
		{"POST /assets", auth.RoleAnalyst, s.assetCreate},
		{"GET /assets/{id}", auth.RoleViewer, s.assetEdit},
		{"POST /assets/{id}", auth.RoleAnalyst, s.assetUpdate},
		{"POST /assets/{id}/delete", auth.RoleAnalyst, s.assetDelete},
		{"POST /assets/{id}/scan", auth.RoleAnalyst, s.assetScan},
		{"POST /assets/{id}/full-history", auth.RoleAnalyst, s.assetFullHistory},
		{"POST /assets/{id}/dismissals", auth.RoleAnalyst, s.dismissalCreate},
		{"POST /assets/{id}/dismissals/{rule}/delete", auth.RoleAnalyst, s.dismissalDelete},
		{"GET /findings", auth.RoleViewer, s.findingList},
		{"GET /findings.csv", auth.RoleViewer, s.findingCSV},
		{"POST /findings/bulk", auth.RoleAnalyst, s.findingBulk},
		{"GET /findings/vex", auth.RoleViewer, s.vexExport},
		{"POST /findings/vex", auth.RoleAnalyst, s.vexImport},
		{"GET /findings/{id}", auth.RoleViewer, s.findingShow},
		{"POST /findings/{id}", auth.RoleAnalyst, s.findingUpdate},
		{"POST /sync", auth.RoleAnalyst, s.syncNow},
		{"GET /digests", auth.RoleViewer, s.digestList},
		{"POST /digests", auth.RoleAnalyst, s.digestCreate},
		{"GET /digests/{id}", auth.RoleViewer, s.digestShow},
		{"GET /digests/{id}/markdown", auth.RoleViewer, s.digestMarkdown},
		{"POST /assets/import", auth.RoleAnalyst, s.sbomImport},
		{"GET /cti", auth.RoleViewer, s.ctiList},
		{"POST /cti/refresh", auth.RoleAnalyst, s.ctiRefresh},
		{"GET /settings", auth.RoleViewer, s.settings},
		{"POST /settings/watch", auth.RoleAnalyst, s.saveWatch},
		{"POST /settings/feeds", auth.RoleAdmin, s.feedCreate},
		{"POST /settings/news", auth.RoleAdmin, s.newsFrequency},
		{"POST /settings/feeds/{id}", auth.RoleAdmin, s.feedUpdate},
		{"POST /settings/feeds/{id}/toggle", auth.RoleAdmin, s.feedToggle},
		{"POST /settings/feeds/{id}/delete", auth.RoleAdmin, s.feedDelete},
		{"POST /settings/webhooks", auth.RoleAdmin, s.webhookCreate},
		{"POST /settings/webhooks/{id}", auth.RoleAdmin, s.webhookDelivery},
		{"POST /settings/webhooks/{id}/toggle", auth.RoleAdmin, s.webhookToggle},
		{"POST /settings/webhooks/{id}/test", auth.RoleAdmin, s.webhookTest},
		{"POST /settings/sla", auth.RoleAdmin, s.slaSave},
		{"GET /settings/audit", auth.RoleAdmin, s.auditList},
		{"GET /settings/users", auth.RoleAdmin, s.userList},
		{"POST /settings/users", auth.RoleAdmin, s.userCreate},
		{"POST /settings/users/{id}/role", auth.RoleAdmin, s.userRole},
		{"POST /settings/users/{id}/disable", auth.RoleAdmin, s.userDisable},
		{"POST /settings/users/{id}/enable", auth.RoleAdmin, s.userEnable},
		{"POST /settings/users/{id}/password", auth.RoleAdmin, s.userPassword},
		{"POST /settings/users/{id}/totp-reset", auth.RoleAdmin, s.userTOTPReset},
		{"POST /settings/users/totp-policy", auth.RoleAdmin, s.userTOTPPolicy},
		{"GET /sync", auth.RoleViewer, s.syncPage},
		{"POST /settings/webhooks/{id}/delete", auth.RoleAdmin, s.webhookDelete},
		{"POST /settings/tokens", auth.RoleAdmin, s.tokenCreate},
		{"POST /settings/tokens/{id}/delete", auth.RoleAdmin, s.tokenDelete},
		// Token-authenticated API for CI pipelines (no session, no CSRF: no cookie is used).
		{"PUT /api/v1/projects/{project}/sbom", public, s.apiSBOM},
	}
}

func (s *Server) parseTemplates() error {
	funcs := template.FuncMap{
		"date":        func(t time.Time) string { return t.Local().Format("02/01/2006 15:04") },
		"isoDate":     isoDate,
		"sevLabel":    tracking.SeverityLabel,
		"roleLabel":   func(v string) string { return inventory.Label(roles, v) },
		"roles":       func() []inventory.Option { return roles },
		"maskURL":     maskURL,
		"syncFor":     s.syncFor,
		"tracking":    trackingSource,
		"vendorOf":    inventory.VendorName,
		"wholeVendor": inventory.WholeVendor,
		"knownTags":   s.knownTags,
		"aliases":     aliasList,
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
		"cvss": func(v float64) string {
			if v < 0 {
				return ""
			}
			return strconv.FormatFloat(v, 'f', 1, 64)
		},
		"ecosystems":        func() []string { return inventory.Ecosystems },
		"statuses":          func() []inventory.Option { return tracking.Statuses },
		"justifs":           func() []inventory.Option { return tracking.Justifications },
		"queryable":         inventory.Queryable,
		"byName":            inventory.ByName,
		"wholeDistribution": inventory.WholeDistribution,
		"epss":              digest.FormatEPSS,
		"countryLabel":      func(v string) string { return cti.Label(cti.Countries, v) },
		"sectorLabel":       func(v string) string { return cti.Label(cti.Sectors, v) },
		"countries":         func() []cti.Tag { return cti.Countries },
		"sectors":           func() []cti.Tag { return cti.Sectors },
		"regulations":       func() []cti.Tag { return cti.Regulations },
		"regulationLabel":   func(v string) string { return cti.Label(cti.Regulations, v) },
		"webhookKinds":      func() []inventory.Option { return notify.Kinds },
		"webhookKindLabel":  func(v string) string { return inventory.Label(notify.Kinds, v) },
		"target":            notify.Target,
		"alertOptions":      func() []inventory.Option { return notify.AlertOptions },
		"alertLabel":        func(v string) string { return inventory.Label(notify.AlertOptions, v) },
		"findingRows": func(list []store.Finding, selectable bool) map[string]any {
			return map[string]any{"List": list, "Select": selectable, "Head": plainHeaders(findingColumnList)}
		},
		"sortedFindingRows": func(list []store.Finding, selectable bool, head []sortHeader) map[string]any {
			return map[string]any{"List": list, "Select": selectable, "Head": head, "Sortable": true}
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
	Path    string // of the request, to mark the current menu entry
	Refresh bool   // reload the page every few seconds (a sync is running)
	Title   string
	User    *store.User
	CSRF    string
	Flash   string
	Error   string
	Data    any
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
	"asset-created":     "Actif ajouté ; recherche de ses vulnérabilités lancée : « suivre l'avancement » ci-dessous.",
	"asset-updated":     "Actif enregistré ; recherche de ses vulnérabilités relancée : « suivre l'avancement » ci-dessous.",
	"asset-deleted":     "Actif supprimé.",
	"scan-started":      "Recherche des vulnérabilités de l'actif lancée : « suivre l'avancement » ci-dessous.",
	"status-updated":    "Statut mis à jour.",
	"sync-started":      "Synchronisation lancée : « suivre l'avancement » ci-dessous.",
	"sync-running":      "Une synchronisation est déjà en cours : « suivre l'avancement » ci-dessous.",
	"digest-created":    "Digest généré.",
	"digest-sent":       "Digest généré et envoyé aux canaux de notification.",
	"digest-webhook":    "Digest généré, mais au moins un canal de notification a échoué (détail dans Paramètres, visible par un administrateur).",
	"cti-started":       "Collecte des flux lancée ; actualisez la page dans quelques instants.",
	"cti-running":       "Une collecte des flux est déjà en cours ; actualisez la page dans quelques instants.",
	"watch-saved":       "Filtres de veille enregistrés.",
	"feed-created":      "Flux ajouté.",
	"feed-updated":      "Étiquettes du flux enregistrées ; elles s'appliquent aussi aux actualités déjà collectées.",
	"feed-enabled":      "Flux activé.",
	"feed-disabled":     "Flux désactivé.",
	"feed-deleted":      "Flux supprimé.",
	"hook-created":      "Canal de notification ajouté.",
	"rule-created":      "Règle enregistrée : ces vulnérabilités sont écartées, les prochaines aussi.",
	"rule-deleted":      "Règle supprimée : ses vulnérabilités sont de nouveau à analyser.",
	"hook-test-sent":    "Message de test envoyé : vérifiez qu'il est bien arrivé.",
	"hook-test-failed":  "Le message de test a échoué : la raison figure dans l'état du canal.",
	"news-updated":      "Fréquence de collecte des flux enregistrée.",
	"hook-updated":      "Canal de notification enregistré.",
	"hook-enabled":      "Canal de notification activé.",
	"hook-disabled":     "Canal de notification désactivé.",
	"hook-deleted":      "Canal de notification supprimé.",
	"csv-imported":      "Inventaire importé ; synchronisation lancée : « suivre l'avancement » ci-dessous.",
	"bulk-updated":      "Statut appliqué aux vulnérabilités sélectionnées.",
	"sla-saved":         "Délais de traitement enregistrés ; les échéances sont recalculées.",
	"sbom-imported":     "SBOM importé ; synchronisation lancée : « suivre l'avancement » ci-dessous.",
	"password-changed":  "Mot de passe modifié ; vos autres sessions ont été fermées.",
	"sessions-closed":   "Vos autres sessions ont été fermées ; celle-ci reste ouverte.",
	"token-deleted":     "Jeton révoqué.",
	"token-created":     "Jeton créé.",
	"user-created":      "Compte créé.",
	"password-reset":    "Mot de passe provisoire généré ; les sessions de l'utilisateur sont fermées.",
	"user-updated":      "Rôle modifié ; il s'applique aussitôt.",
	"user-disabled":     "Compte désactivé ; ses sessions sont fermées.",
	"user-enabled":      "Compte réactivé.",
	"user-totp-reset":   "Double authentification retirée ; les sessions de l'utilisateur sont fermées.",
	"totp-required":     "La double authentification est obligatoire pour votre compte : configurez-la pour continuer.",
	"totp-policy-saved": "Règle de double authentification enregistrée.",
	"totp-enabled":      "Double authentification activée.",
	"totp-disabled":     "Double authentification désactivée.",
	"vex-imported":      "VEX importé : les analyses correspondantes ont été appliquées.",
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

// clientKey is the rate-limiting key of the client of r for one kind of
// attempt (sign-in, API token): every limit by address goes through it.
// SECURITY: an IPv6 client counts by /64 (see limitKey), wherever it knocks.
func (s *Server) clientKey(r *http.Request, scope string) string {
	return scope + ":" + limitKey(s.clientIP(r))
}

// limitKey is the rate-limiting key of a client address: an IPv6 client
// usually owns a whole /64, so it counts as one.
func limitKey(addr string) string {
	ip := net.ParseIP(addr)
	if ip == nil || ip.To4() != nil {
		return addr
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// cookieName is the name of the session cookie (see sessionCookie).
func (s *Server) cookieName() string {
	if s.SecureCookies {
		return secureCookie
	}
	return sessionCookie
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
// audit records an action of the signed-in user, or of the system (user 0)
// for a request without a session: the API, a failed login.
func (s *Server) audit(r *http.Request, action, detail string) {
	sess, _ := sessionFrom(r.Context())
	s.auditAs(r, sess.User.ID, action, detail)
}

// auditAs records an action of a user whose session does not exist yet: the
// first setup, a login.
func (s *Server) auditAs(r *http.Request, userID int64, action, detail string) {
	// The journal keeps a copy outside the database: shipped to a log server,
	// it survives a lost or altered database. SECURITY: the detail may hold a
	// typed username or feed name; line breaks are removed so that it cannot
	// forge another log entry, whatever the log handler.
	line := strings.ReplaceAll(strings.ReplaceAll(detail, "\n", " "), "\r", " ")
	s.Log.Info("audit", "action", action, "user_id", userID, "detail", line, "ip", s.clientIP(r))
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
			if s.AuditRetention > 0 {
				if n, err := s.Store.PurgeAudit(ctx, time.Now().Add(-s.AuditRetention)); err != nil {
					s.Log.Warn("purge audit log", "err", err)
				} else if n > 0 {
					s.Log.Info("audit log purged", "entries", n)
				}
			}
		}
	}
}
