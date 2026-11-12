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
	"maps"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/auth"
	"github.com/La-Cizaille-Corp/vigil/internal/choice"
	"github.com/La-Cizaille-Corp/vigil/internal/clip"
	"github.com/La-Cizaille-Corp/vigil/internal/cti"
	"github.com/La-Cizaille-Corp/vigil/internal/fr"
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
	// maxExcerpt is the longest summary of a news item of the watch, in
	// characters: a source may give 2 000.
	maxExcerpt = 300
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

	// pageRoles is the least role of each route, by pattern: what a menu
	// may offer (see opens).
	pageRoles map[string]string
}

// Handler builds the routes and middleware.
func (s *Server) Handler() (http.Handler, error) {
	if err := s.parseTemplates(); err != nil {
		return nil, err
	}
	s.limiter = auth.NewLimiter(5, 15*time.Minute)
	s.accounts = auth.NewLimiter(10, 15*time.Minute)

	static, err := fs.Sub(staticFS, "static")
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))

	s.pageRoles = map[string]string{}
	for _, rt := range s.routes() {
		s.pageRoles[rt.pattern] = rt.role
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
		{"GET /settings", auth.RoleViewer, s.settingsHome},
		{"GET /settings/watch", auth.RoleViewer, s.watchSettings},
		{"POST /settings/watch", auth.RoleAnalyst, s.saveWatch},
		{"GET /settings/feeds", auth.RoleViewer, s.feedSettings},
		{"POST /settings/feeds", auth.RoleAdmin, s.feedCreate},
		{"POST /settings/news", auth.RoleAdmin, s.newsFrequency},
		{"POST /settings/feeds/{id}", auth.RoleAdmin, s.feedUpdate},
		{"POST /settings/feeds/{id}/toggle", auth.RoleAdmin, s.feedToggle},
		{"POST /settings/feeds/{id}/delete", auth.RoleAdmin, s.feedDelete},
		{"GET /settings/webhooks", auth.RoleAdmin, s.webhookSettings},
		{"POST /settings/webhooks", auth.RoleAdmin, s.webhookCreate},
		{"POST /settings/webhooks/{id}", auth.RoleAdmin, s.webhookDelivery},
		{"POST /settings/webhooks/{id}/toggle", auth.RoleAdmin, s.webhookToggle},
		{"POST /settings/webhooks/{id}/test", auth.RoleAdmin, s.webhookTest},
		{"GET /settings/sla", auth.RoleAdmin, s.slaSettings},
		{"POST /settings/sla", auth.RoleAdmin, s.slaSave},
		{"GET /settings/audit", auth.RoleAdmin, s.auditList},
		{"GET /settings/users", auth.RoleAdmin, s.userList},
		{"POST /settings/users", auth.RoleAdmin, s.userCreate},
		{"POST /settings/users/{id}/role", auth.RoleAdmin, s.userRole},
		{"POST /settings/users/{id}/access", auth.RoleAdmin, s.userAccess},
		{"GET /settings/groups", auth.RoleAdmin, s.groupList},
		{"POST /settings/groups", auth.RoleAdmin, s.groupCreate},
		{"GET /settings/groups/{id}", auth.RoleAdmin, s.groupShow},
		{"POST /settings/groups/{id}", auth.RoleAdmin, s.groupRename},
		{"POST /settings/groups/{id}/rules", auth.RoleAdmin, s.groupRules},
		{"POST /settings/groups/{id}/delete", auth.RoleAdmin, s.groupDelete},
		{"POST /settings/users/{id}/disable", auth.RoleAdmin, s.userDisable},
		{"POST /settings/users/{id}/enable", auth.RoleAdmin, s.userEnable},
		{"POST /settings/users/{id}/password", auth.RoleAdmin, s.userPassword},
		{"POST /settings/users/{id}/totp-reset", auth.RoleAdmin, s.userTOTPReset},
		{"POST /settings/users/totp-policy", auth.RoleAdmin, s.userTOTPPolicy},
		{"GET /sync", auth.RoleViewer, s.syncPage},
		{"POST /settings/webhooks/{id}/delete", auth.RoleAdmin, s.webhookDelete},
		{"GET /settings/tokens", auth.RoleAdmin, s.tokenSettings},
		{"POST /settings/tokens", auth.RoleAdmin, s.tokenCreate},
		{"POST /settings/tokens/{id}/delete", auth.RoleAdmin, s.tokenDelete},
		// Token-authenticated API for CI pipelines (no session, no CSRF: no cookie is used).
		{"PUT /api/v1/projects/{project}/sbom", public, s.apiSBOM},
	}
}

func (s *Server) parseTemplates() error {
	funcs := template.FuncMap{
		"isoDate":     isoDate,
		"roleLabel":   func(v string) string { return choice.Label(auth.Roles, v) },
		"roles":       func() []choice.Option { return auth.Roles },
		"maskURL":     maskURL,
		"syncFor":     s.syncFor,
		"tracking":    trackingSource,
		"vendorOf":    inventory.VendorName,
		"wholeVendor": inventory.WholeVendor,
		"tags":        splitTags,
		"dict3": func(countries, sectors, regulations []string) tagSelection {
			return tagSelection{countries, sectors, regulations}
		},
		"link":              func(href, text string) textLink { return textLink{href, text} },
		"errorAt":           errorAt,
		"keyGroups":         keyGroups,
		"accessForm":        accessForm,
		"newAccessForm":     newAccessForm,
		"kindLabel":         func(v string) string { return choice.Label(inventory.Kinds, v) },
		"critLabel":         func(v string) string { return choice.Label(inventory.Criticalities, v) },
		"justifLabel":       func(v string) string { return choice.Label(tracking.Justifications, v) },
		"can":               auth.RoleAtLeast,
		"passwordHelp":      func() string { return auth.PasswordHelp },
		"hasPrefix":         strings.HasPrefix,
		"lower":             strings.ToLower,
		"kinds":             func() []choice.Option { return inventory.Kinds },
		"criticalities":     func() []choice.Option { return inventory.Criticalities },
		"cpeModes":          func() []choice.Option { return inventory.CPEModes },
		"severities":        func() []choice.Option { return severities },
		"ecosystems":        func() []string { return inventory.Ecosystems },
		"statuses":          func() []choice.Option { return tracking.Statuses },
		"justifs":           func() []choice.Option { return tracking.Justifications },
		"byName":            inventory.ByName,
		"wholeDistribution": inventory.WholeDistribution,
		"checkedVersion":    inventory.CheckedVersion,
		"excerpt":           func(s string) string { return clip.Excerpt(s, maxExcerpt) }, // a news summary, cut and said to be (A87)
		"countryLabel":      func(v string) string { return choice.Label(cti.Countries, v) },
		"sectorLabel":       func(v string) string { return choice.Label(cti.Sectors, v) },
		"countries":         func() []choice.Option { return cti.Countries },
		"sectors":           func() []choice.Option { return cti.Sectors },
		"regulations":       func() []choice.Option { return cti.Regulations },
		"regulationLabel":   func(v string) string { return choice.Label(cti.Regulations, v) },
		"webhookKinds":      func() []choice.Option { return notify.Kinds },
		"webhookKindLabel":  func(v string) string { return choice.Label(notify.Kinds, v) },
		"target":            notify.Target,
		"alertOptions":      func() []choice.Option { return notify.AlertOptions },
		// A list that is not sorted by its reader (dashboard, asset page); the
		// vulnerability list builds its own findingRows.
		"findingRows": func(list []store.Finding) findingRows {
			return findingRows{List: list, Head: plainHeaders(findingColumnList)}
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
	// Dates, numbers and the words of the findings, as in the digest.
	maps.Copy(funcs, fr.Funcs())
	maps.Copy(funcs, tracking.TemplateFuncs())
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

// findingRows is the data of the findingTable template.
type findingRows struct {
	List     []store.Finding
	Head     []sortHeader
	Sortable bool
	Sort     sortChoice     // the order chosen from a list on a phone, when Sortable
	Select   bool           // checkboxes bound to the form id="bulk" of the page
	Checked  map[int64]bool // boxes ticked, when a bulk decision is shown again
	Back     string         // the list a row's page leads back to (?back=), "" for none
	Reset    string         // the list without its filters, when they leave it empty
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
	// ErrorAt is the id of the form the Error is about: the page shows it
	// there (errorAt), not at its top, and the address of the form ends with
	// that #id, so that the browser comes back to it (A88).
	ErrorAt string
	Menu    *settingsMenu // on a page of the settings, the menu of their sub-pages (A89)
	Data    any
}

// errorAt is the error of p when it is about the form id, else "".
func errorAt(p page, id string) string {
	if p.ErrorAt != id {
		return ""
	}
	return p.Error
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
	if current, ok := settingsPages[name]; ok && p.User != nil {
		menu, err := s.settingsMenuFor(r.Context(), p.User.Role, current)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		p.Menu = &menu
	}
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
	"asset-created":     "Actif ajouté ; Vigil cherche ses vulnérabilités dans OSV, par son paquet et sa version : « suivre l'avancement » ci-dessous.",
	"asset-created-cpe": "Actif ajouté ; Vigil cherche ses vulnérabilités dans la NVD, par son CPE : « suivre l'avancement » ci-dessous.",
	// The two below explain what is missing (audit UX 7.2, A88).
	"asset-created-name": "Actif ajouté sans purl, CPE ni version : Vigil cherche son nom dans les descriptions des CVE de la NVD. " +
		"Moins précise, cette recherche donne des résultats à vérifier ; une version avec un écosystème, ou un CPE, rend la détection exacte.",
	"asset-created-none": "Actif ajouté, mais Vigil ne peut pas le vérifier : son purl ne donne pas de version. " +
		"Indiquez-la dans le champ Version (ou latest) pour qu'OSV soit interrogé.",
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
	"bulk-list-updated": "Statut appliqué à la liste ; ce que quelqu'un avait déjà décidé n'a pas changé.",
	"sla-saved":         "Délais de traitement enregistrés ; les échéances sont recalculées.",
	"sbom-imported":     "SBOM importé ; synchronisation lancée : « suivre l'avancement » ci-dessous.",
	"password-changed":  "Mot de passe modifié ; vos autres sessions ont été fermées.",
	"sessions-closed":   "Vos autres sessions ont été fermées ; celle-ci reste ouverte.",
	"token-deleted":     "Jeton révoqué.",
	"token-created":     "Jeton créé : copiez-le ci-dessous, il ne sera plus affiché.",
	"user-created":      "Compte créé.",
	"password-reset":    "Mot de passe provisoire généré ; les sessions de l'utilisateur sont fermées.",
	"user-updated":      "Rôle modifié ; il s'applique aussitôt.",
	"access-updated":    "Accès modifié ; il s'applique aussitôt.",
	"group-created":     "Groupe créé : choisissez ses étiquettes et ses projets.",
	"group-renamed":     "Groupe renommé.",
	"group-rules-saved": "Règles enregistrées ; elles s'appliquent aussitôt.",
	"group-deleted":     "Groupe supprimé ; ses actifs restent dans l'inventaire.",
	"user-disabled":     "Compte désactivé ; ses sessions sont fermées.",
	"user-enabled":      "Compte réactivé.",
	"user-totp-reset":   "Double authentification retirée ; les sessions de l'utilisateur sont fermées.",
	"totp-required":     "La double authentification est obligatoire pour votre compte : configurez-la pour continuer.",
	"totp-policy-saved": "Règle de double authentification enregistrée.",
	"totp-enabled":      "Double authentification activée.",
	"totp-disabled":     "Double authentification désactivée.",
	"vex-imported":      "VEX importé : les analyses correspondantes ont été appliquées.",
}

// redirect sends the browser to path once a form is done, with the message
// msg (a key of flashes) if any; path may already hold a query string, and
// end with a #fragment. A form whose address ends with one (A88) gives one
// here too: the browser would otherwise keep it, and land on the form
// instead of the message.
func redirect(w http.ResponseWriter, r *http.Request, path, msg string) {
	path, fragment, _ := strings.Cut(path, "#")
	if msg != "" {
		sep := "?"
		if strings.Contains(path, "?") {
			sep = "&"
		}
		path += sep + "msg=" + url.QueryEscape(msg)
	}
	if fragment != "" {
		path += "#" + fragment
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

// storeError answers a failed call to the store: 404 when the object does
// not exist, 500 otherwise.
func (s *Server) storeError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, store.ErrNotFound) {
		s.notFound(w)
		return
	}
	s.serverError(w, r, err)
}

// pathID reads the identifier named key in the path of r; a malformed one
// is answered 404, as no object bears it.
func (s *Server) pathID(w http.ResponseWriter, r *http.Request, key string) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue(key), 10, 64)
	if err != nil {
		s.notFound(w)
		return 0, false
	}
	return id, true
}

// load reads the object named by the {id} path value with get (inScope binds
// the lookups of the inventory to the scope of the request): 404 when no
// object bears it, 500 when the store fails.
func load[T any](s *Server, w http.ResponseWriter, r *http.Request, get func(context.Context, int64) (T, error)) (T, bool) {
	var v T
	id, ok := s.pathID(w, r, "id")
	if !ok {
		return v, false
	}
	v, err := get(r.Context(), id)
	if err != nil {
		s.storeError(w, r, err)
		return v, false
	}
	return v, true
}

// change is a modification of the object named by the {id} path value, made
// by (*Server).change.
type change struct {
	action  string // in the audit log
	detail  []any  // key-value pairs of the audit entry, after the id (see store.AuditDetail)
	to, msg string // where the browser goes once it is made, with which message
	apply   func(id int64) error
	// refuse, when set, answers an error the user can do something about,
	// and reports whether it did (see userChange); any other is 404 or 500.
	refuse func(error) bool
}

// change applies c to the {id} path value, writes it to the audit log once it
// succeeded, then redirects.
func (s *Server) change(w http.ResponseWriter, r *http.Request, c change) {
	id, ok := s.pathID(w, r, "id")
	if !ok {
		return
	}
	if err := c.apply(id); err != nil {
		if c.refuse == nil || !c.refuse(err) {
			s.storeError(w, r, err)
		}
		return
	}
	s.audit(r, c.action, append([]any{"id", id}, c.detail...)...)
	redirect(w, r, c.to, c.msg)
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

// audit records an action of the signed-in user, or of the system (user 0)
// for a request without a session: the API, a failed login. Its detail is
// the key-value pairs kv (see store.AuditDetail). A failure to write it is
// logged, never silently ignored, but does not fail the user's request.
func (s *Server) audit(r *http.Request, action string, kv ...any) {
	sess, _ := sessionFrom(r.Context())
	s.auditAs(r, sess.User.ID, action, kv...)
}

// auditAs records an action of a user whose session does not exist yet: the
// first setup, a login.
func (s *Server) auditAs(r *http.Request, userID int64, action string, kv ...any) {
	// The journal keeps a copy outside the database: shipped to a log server,
	// it survives a lost or altered database. SECURITY: the detail may hold a
	// typed username or feed name; AuditDetail quotes a value holding a line
	// break, so that it cannot forge another log entry, whatever the log
	// handler. Line breaks are still removed from the copy sent to the
	// journal: a no-op for a detail made by AuditDetail, it keeps the barrier
	// at the point where the journal is written, where code scanning sees it.
	detail := store.AuditDetail(kv...)
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
