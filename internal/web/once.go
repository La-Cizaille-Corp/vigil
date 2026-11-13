package web

import (
	"net/http"
	"sync"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/auth"
)

// onceTTL bounds how long a one-time value waits for its page.
const onceTTL = 2 * time.Minute

// onceKind names what a one-time value is, hence the page that shows it.
// Each kind has its own slot per session: a page takes only its own kind,
// so that visiting another page, or one rendered with an error, does not
// lose a value before it is shown.
type onceKind string

const (
	onceToken    onceKind = "token"    // a new API token, shown by /settings/tokens
	oncePassword onceKind = "password" // a temporary password, shown by /settings/users
)

// onceStore holds values shown once (a new API token, a temporary password)
// between a form and the page it redirects to, so that reloading that page
// neither posts the form again nor shows the value twice. Values are keyed by
// session and kind, and never written to disk.
type onceStore struct {
	mu sync.Mutex
	m  map[onceSlot]onceValue
}

type onceSlot struct {
	session string // hash of the session cookie
	kind    onceKind
}

type onceValue struct {
	v       any
	expires time.Time
}

// keepOnce stores v for the next takeOnce of the same session and kind.
func (s *Server) keepOnce(r *http.Request, kind onceKind, v any) {
	slot, ok := s.onceSlot(r, kind)
	if !ok {
		return
	}
	s.once.mu.Lock()
	defer s.once.mu.Unlock()
	if s.once.m == nil {
		s.once.m = map[onceSlot]onceValue{}
	}
	now := time.Now()
	for k, o := range s.once.m { // few entries: one per session and kind at most
		if now.After(o.expires) {
			delete(s.once.m, k)
		}
	}
	s.once.m[slot] = onceValue{v, now.Add(onceTTL)}
}

// takeOnce returns and forgets the value of this kind kept for this session,
// if any. Values of other kinds stay for their own page.
func (s *Server) takeOnce(r *http.Request, kind onceKind) any {
	slot, ok := s.onceSlot(r, kind)
	if !ok {
		return nil
	}
	s.once.mu.Lock()
	defer s.once.mu.Unlock()
	o, ok := s.once.m[slot]
	delete(s.once.m, slot)
	if !ok || time.Now().After(o.expires) {
		return nil
	}
	return o.v
}

// onceSlot identifies the session of r, by the hash of its cookie, and the
// kind of value; false without a session cookie.
func (s *Server) onceSlot(r *http.Request, kind onceKind) (onceSlot, bool) {
	c, err := r.Cookie(s.cookieName())
	if err != nil {
		return onceSlot{}, false
	}
	return onceSlot{auth.HashToken(c.Value), kind}, true
}
