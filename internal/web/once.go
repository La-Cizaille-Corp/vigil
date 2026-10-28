package web

import (
	"net/http"
	"sync"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/auth"
)

// onceTTL bounds how long a one-time value waits for its page.
const onceTTL = 2 * time.Minute

// onceStore holds values shown once (a new API token, a temporary password)
// between a form and the page it redirects to, so that reloading that page
// neither posts the form again nor shows the value twice. Values are keyed by
// session and never written to disk.
type onceStore struct {
	mu sync.Mutex
	m  map[string]onceValue
}

type onceValue struct {
	v       any
	expires time.Time
}

// keepOnce stores v for the next takeOnce of the same session.
func (s *Server) keepOnce(r *http.Request, v any) {
	key := s.onceKey(r)
	if key == "" {
		return
	}
	s.once.mu.Lock()
	defer s.once.mu.Unlock()
	if s.once.m == nil {
		s.once.m = map[string]onceValue{}
	}
	now := time.Now()
	for k, o := range s.once.m { // few entries: one per session at most
		if now.After(o.expires) {
			delete(s.once.m, k)
		}
	}
	s.once.m[key] = onceValue{v, now.Add(onceTTL)}
}

// takeOnce returns and forgets the value kept for this session, if any.
func (s *Server) takeOnce(r *http.Request) any {
	key := s.onceKey(r)
	s.once.mu.Lock()
	defer s.once.mu.Unlock()
	o, ok := s.once.m[key]
	delete(s.once.m, key)
	if !ok || key == "" || time.Now().After(o.expires) {
		return nil
	}
	return o.v
}

// onceKey identifies the session of r by the hash of its cookie.
func (s *Server) onceKey(r *http.Request) string {
	c, err := r.Cookie(s.cookieName())
	if err != nil {
		return ""
	}
	return auth.HashToken(c.Value)
}
