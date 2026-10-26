package web

import (
	"context"
	"errors"
	"net/http"
	"net/url"

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
		cookie, err := r.Cookie(sessionCookie)
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
		if !auth.RoleAtLeast(sess.User.Role, role) {
			http.Error(w, "Accès refusé.", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
			// SECURITY: synchronizer token pattern against CSRF.
			if !auth.EqualTokens(r.PostFormValue("csrf"), sess.CSRFToken) {
				http.Error(w, "Jeton CSRF invalide.", http.StatusForbidden)
				return
			}
		}
		next(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, sess)))
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
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cache-Control", "no-store")
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}
