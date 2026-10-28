package web

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/La-Cizaille-Corp/vigil/internal/auth"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
)

type ctxKey struct{}

func sessionFrom(ctx context.Context) (store.Session, bool) {
	s, ok := ctx.Value(ctxKey{}).(store.Session)
	return s, ok
}

// require authenticates the request, checks the role and, for state-changing
// methods, the CSRF token.
func (s *Server) require(role string, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(s.cookieName())
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		sess, err := s.Store.SessionByHash(r.Context(), auth.HashToken(cookie.Value))
		if errors.Is(err, store.ErrNotFound) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		// SECURITY: authorization is checked server-side on every route.
		// SECURITY: where a second factor is required, an account without one
		// can only reach its own page, to set it up.
		if !sess.User.TOTP && !totpExempt(r.URL.Path) {
			required, err := s.totpRequired(r, sess.User.Role)
			if err != nil {
				s.serverError(w, r, err)
				return
			}
			if required {
				redirect(w, r, "/account", "totp-required")
				return
			}
		}
		if !auth.RoleAtLeast(sess.User.Role, role) {
			http.Error(w, "Accès refusé.", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			// SECURITY: synchronizer token pattern against CSRF.
			if !auth.EqualTokens(r.PostFormValue("csrf"), sess.CSRFToken) {
				http.Error(w, "Jeton CSRF invalide.", http.StatusForbidden)
				return
			}
		}
		next(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, sess)))
	})
}

// totpExempt lists what an account without its required second factor may
// still reach: its own page, where the factor is set up, and sign-out.
func totpExempt(path string) bool {
	return path == "/account" || strings.HasPrefix(path, "/account/") || path == "/logout"
}

// totpRequired reports whether the TOTP policy applies to role.
func (s *Server) totpRequired(r *http.Request, role string) (bool, error) {
	policy, err := s.Store.TOTPPolicy(r.Context())
	return policy == store.TOTPEveryone || policy == store.TOTPAdmins && role == auth.RoleAdmin, err
}

// localHosts are the names a browser uses for this machine.
var localHosts = map[string]bool{"localhost": true, "127.0.0.1": true, "::1": true}

// checkHost rejects, on a local instance, requests addressed to another host
// name. SECURITY: a web page can make its own domain resolve to 127.0.0.1
// (DNS rebinding); its requests then reach Vigil with that domain as Host and
// Origin, which look same-origin, and could claim the first-run setup.
func (s *Server) checkHost(next http.Handler) http.Handler {
	allowed := map[string]bool{}
	if u, err := url.Parse(s.BaseURL); err == nil && u.Hostname() != "" {
		allowed[strings.ToLower(u.Hostname())] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.ToLower(strings.Trim(host, "[]"))
		if s.LocalOnly && !localHosts[host] && !allowed[host] {
			http.Error(w, "Hôte non autorisé : ouvrez Vigil par http://127.0.0.1 ou http://localhost.", http.StatusMisdirectedRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// sameOrigin rejects cross-site state-changing requests based on the Origin
// header (defence in depth with SameSite cookies and CSRF tokens; it also
// protects the login and setup forms which have no session yet).
func sameOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if origin := r.Header.Get("Origin"); origin != "" {
				u, err := url.Parse(origin)
				if err != nil || u.Host != r.Host {
					http.Error(w, "Origine refusée.", http.StatusForbidden)
					return
				}
			}
			if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
				http.Error(w, "Origine refusée.", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// securityHeaders sets the OWASP-recommended response headers.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy",
			"default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin") // "no-referrer" makes browsers send "Origin: null" on form posts
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
		h.Set("Cache-Control", "no-store")
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

// limitBody bounds request bodies: small forms everywhere, larger uploads on
// the import routes only.
func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limit := int64(maxFormBytes)
		switch {
		case r.URL.Path == "/assets/import" || r.URL.Path == "/findings/vex" || strings.HasPrefix(r.URL.Path, "/api/v1/"):
			limit = maxUploadBytes
		case r.URL.Path == "/assets/import-csv":
			limit = maxCSVBytes + 64<<10 // file plus multipart overhead
		}
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		next.ServeHTTP(w, r)
	})
}
