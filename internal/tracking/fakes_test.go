package tracking_test

import (
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/La-Cizaille-Corp/vigil/internal/sources/epss"
	"github.com/La-Cizaille-Corp/vigil/internal/sources/kev"
	"github.com/La-Cizaille-Corp/vigil/internal/sources/nvd"
	"github.com/La-Cizaille-Corp/vigil/internal/sources/osv"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
	"github.com/La-Cizaille-Corp/vigil/internal/tracking"
)

// fakeSources is a fake of the sources a synchroniser asks, served by a test
// server closed at the end of the test. Its handler answers one request at a
// time, so that it notes what it is asked without a lock of its own; the test
// reads that once the synchronisation has returned, and changes what the
// handler answers within locked. The answer is written once the handler has
// returned: a synchroniser that asks KEV while it reads a page of OSV does not
// wait for that page to be answered. The server counts the requests it answers
// and the bytes it sends, by kind (see kind).
type fakeSources struct {
	srv *httptest.Server

	mu       sync.Mutex // held while the handler answers
	requests map[string]int
	bytes    map[string]int
}

// serveSources starts the fake sources that answer with h.
func serveSources(tb testing.TB, h http.HandlerFunc) *fakeSources {
	tb.Helper()
	f := &fakeSources{requests: map[string]int{}, bytes: map[string]int{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		answer := httptest.NewRecorder()
		f.locked(func() {
			h(answer, r)
			f.requests[kind(r.URL.Path)]++
			f.bytes[kind(r.URL.Path)] += answer.Body.Len()
		})
		res := answer.Result()
		maps.Copy(w.Header(), res.Header)
		w.WriteHeader(res.StatusCode)
		w.Write(answer.Body.Bytes())
	}))
	tb.Cleanup(f.srv.Close)
	return f
}

// kind names a request to the sources by its path: querybatch, query or vulns
// for OSV, kev, epss, and "" for the NVD, asked at the root.
func kind(path string) string {
	k, _, _ := strings.Cut(strings.TrimPrefix(strings.TrimPrefix(path, "/v1"), "/"), "/")
	return k
}

// locked runs change while no request is answered.
func (f *fakeSources) locked(change func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	change()
}

// counts returns the requests answered and the bytes sent, by kind, since the
// last call.
func (f *fakeSources) counts() (requests, bytes map[string]int) {
	f.locked(func() {
		requests, bytes = f.requests, f.bytes
		f.requests, f.bytes = map[string]int{}, map[string]int{}
	})
	return requests, bytes
}

// osvSyncer returns a synchroniser of st and the fake sources it asks: OSV,
// at the root of a server that answers with h, and with enrich, KEV at /kev
// and EPSS at /epss of the same server.
func osvSyncer(tb testing.TB, st *store.Store, h http.HandlerFunc, enrich bool) (*tracking.Syncer, *fakeSources) {
	tb.Helper()
	f := serveSources(tb, h)
	s := &tracking.Syncer{Store: st, Log: slog.New(slog.DiscardHandler),
		OSV: &osv.Client{URL: f.srv.URL, HTTP: f.srv.Client(), UserAgent: "vigil-test"}}
	if enrich {
		s.KEV = &kev.Client{URL: f.srv.URL + "/kev", HTTP: f.srv.Client()}
		s.EPSS = &epss.Client{URL: f.srv.URL + "/epss", HTTP: f.srv.Client()}
	}
	return s, f
}

// nvdSyncer returns a synchroniser of st and the fake sources it asks: the
// NVD, CVE API and CPE dictionary, at the root of a server that answers with
// h. OSV fails the test if it is asked: it is never the real one.
func nvdSyncer(tb testing.TB, st *store.Store, h http.HandlerFunc) (*tracking.Syncer, *fakeSources) {
	tb.Helper()
	f := serveSources(tb, h)
	unexpected := serveSources(tb, func(w http.ResponseWriter, r *http.Request) {
		tb.Errorf("OSV asked for %s: the test expects the NVD alone", r.URL.Path)
		w.WriteHeader(http.StatusTeapot)
	})
	return &tracking.Syncer{Store: st, Log: slog.New(slog.DiscardHandler),
		OSV: &osv.Client{URL: unexpected.srv.URL, HTTP: unexpected.srv.Client()},
		NVD: &nvd.Client{URL: f.srv.URL, CPEURL: f.srv.URL, HTTP: f.srv.Client()}}, f
}

// sameSources returns a synchroniser of st that asks the sources of s.
func sameSources(s *tracking.Syncer, st *store.Store) *tracking.Syncer {
	return &tracking.Syncer{Store: st, Log: s.Log, OSV: s.OSV, NVD: s.NVD, KEV: s.KEV, EPSS: s.EPSS}
}
