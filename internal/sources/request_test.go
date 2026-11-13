package sources_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/limit"
	"github.com/La-Cizaille-Corp/vigil/internal/netsafe"
	"github.com/La-Cizaille-Corp/vigil/internal/sources"
)

// serve starts a fake source that answers with h, closed at the end of the
// test. The clients of the sources are tested in their own packages.
func serve(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

// get returns a GET request for url, made as every source makes it.
func get(t *testing.T, url string) *http.Request {
	t.Helper()
	req, err := sources.NewRequest(context.Background(), http.MethodGet, url, "vigil-test", nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

// The common form of every source: the request says who asks and sends JSON;
// only a 200 is an answer, read within its bound and decoded; a refusal says
// why in one short line, never with the raw answer.
func TestDo(t *testing.T) {
	var got *http.Request
	var sent []byte
	srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		got = r
		sent, _ = io.ReadAll(r.Body)
		switch r.URL.Path {
		case "/ok":
			io.WriteString(w, `{"id":"A"}`)
		case "/key": // the NVD
			w.Header().Set("message", "Invalid apiKey.")
			w.WriteHeader(http.StatusNotFound)
		case "/query": // OSV
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, `{"code":3,"message":"Invalid\n\tquery.\u0007 "}`)
		case "/long":
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, `{"message":"`+strings.Repeat("é", 300)+`"}`)
		case "/page":
			w.WriteHeader(http.StatusBadGateway)
			io.WriteString(w, "<html><body>Bad gateway</body></html>")
		case "/busy":
			w.WriteHeader(http.StatusTooManyRequests)
		case "/cut":
			io.WriteString(w, `{"id":`)
		}
	})
	type doc struct{ ID string }
	do := func(path string, max int64, body any) (doc, error) {
		t.Helper()
		var out doc
		req, err := sources.NewRequest(context.Background(), http.MethodPost, srv.URL+path, "vigil-test", body)
		if err != nil {
			t.Fatal(err)
		}
		return out, sources.Do(srv.Client(), req, max, &out)
	}

	out, err := do("/ok", 10, map[string]string{"q": "x"})
	if err != nil || out.ID != "A" {
		t.Fatalf("answer: %+v, %v", out, err)
	}
	if got.Header.Get("User-Agent") != "vigil-test" || got.Header.Get("Accept") != "application/json" ||
		got.Header.Get("Content-Type") != "application/json" || string(sent) != `{"q":"x"}` {
		t.Errorf("request: %v, body %s", got.Header, sent)
	}
	if _, err := do("/ok", 10, nil); err != nil || got.Header.Get("Content-Type") != "" || len(sent) != 0 {
		t.Errorf("request without a body: %v, %v, %q", err, got.Header, sent)
	}

	var tooLarge *limit.TooLargeError
	for _, c := range []struct {
		path      string
		max       int64
		code      int
		want      string
		temporary bool
	}{
		{"/key", 10, 404, "HTTP 404 (Invalid apiKey.)", false},
		{"/query", 10, 400, "HTTP 400 (Invalid query.)", false},
		{"/long", 10, 400, "HTTP 400 (" + strings.Repeat("é", 199) + "…)", false},
		{"/page", 10, 502, "HTTP 502", true},
		{"/busy", 10, 429, "HTTP 429", true},
		{"/ok", 9, 0, "réponse supérieure à 9 octets", false},
		{"/cut", 10, 0, "réponse illisible : unexpected end of JSON input", false},
	} {
		_, err := do(c.path, c.max, nil)
		if err == nil || err.Error() != c.want || sources.Temporary(err) != c.temporary {
			t.Errorf("%s: %v (temporary %v), want %q (temporary %v)", c.path, err, sources.Temporary(err), c.want, c.temporary)
		}
		var status *sources.StatusError
		if errors.As(err, &status) != (c.code != 0) || c.code != 0 && status.Code != c.code {
			t.Errorf("%s: status %+v, want %d", c.path, status, c.code)
		}
		if c.max == 9 && !errors.As(err, &tooLarge) {
			t.Errorf("%s: %T, want a *limit.TooLargeError", c.path, err)
		}
	}

	// The network: sending again may succeed.
	req := get(t, srv.URL+"/ok")
	srv.Close()
	if err := sources.Do(srv.Client(), req, 10, new(doc)); err == nil || !sources.Temporary(err) {
		t.Errorf("unreachable server: %v (temporary %v)", err, sources.Temporary(err))
	}
	if sources.Temporary(errors.New("other")) || sources.Temporary(nil) {
		t.Error("an error that is not of a request is not temporary")
	}
}

// A body read as a stream fails at its bound: cut there, a document must not
// pass for a whole one.
func TestOpenBound(t *testing.T) {
	srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"id": strings.Repeat("a", 100)})
	})
	body, err := sources.Open(srv.Client(), get(t, srv.URL), 50)
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	var out map[string]string
	var tooLarge *limit.TooLargeError
	if err := json.NewDecoder(body).Decode(&out); !errors.As(err, &tooLarge) || tooLarge.Max != 50 {
		t.Errorf("stream past its bound: %v", err)
	}
}

// A body cut by the network while read as a stream is a temporary failure:
// asked again, the answer may come whole. A body that ends early but cleanly
// is a malformed answer, which would come back the same.
func TestOpenCut(t *testing.T) {
	srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/short" {
			io.WriteString(w, `{"id":`)
			return
		}
		w.Header().Set("Content-Length", "1000") // more than is sent: the connection is lost
		io.WriteString(w, `{"id":`)
		w.(http.Flusher).Flush()
		if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
			conn.Close()
		}
	})
	for path, temporary := range map[string]bool{"/cut": true, "/short": false} {
		body, err := sources.Open(srv.Client(), get(t, srv.URL+path), 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]string
		err = json.NewDecoder(body).Decode(&out)
		body.Close()
		if err == nil || sources.Temporary(err) != temporary {
			t.Errorf("%s: %v (temporary %v), want temporary %v", path, err, sources.Temporary(err), temporary)
		}
	}
}

// A redirect refused by netsafe.CheckRedirect, to plain HTTP or one too many,
// is not a failure of the network: it is not sent again, for it would be
// refused the same way.
func TestRefusedRedirectIsDefinite(t *testing.T) {
	ctx := context.Background()
	plain := serve(t, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, `{"id":"A"}`) })
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/insecure":
			http.Redirect(w, r, plain.URL, http.StatusFound)
		case "/loop":
			http.Redirect(w, r, srv.URL+"/loop", http.StatusFound)
		}
	}))
	t.Cleanup(srv.Close)
	client := srv.Client()
	client.CheckRedirect = netsafe.CheckRedirect()
	for path, want := range map[string]string{"/insecure": "redirection vers une URL non https refusée", "/loop": "trop de redirections"} {
		calls := 0
		err := sources.Retry(ctx, []time.Duration{0, 0}, func() (bool, error) {
			calls++
			req, err := sources.NewRequest(ctx, http.MethodGet, srv.URL+path, "vigil-test", nil)
			if err != nil {
				t.Fatal(err)
			}
			err = sources.Do(client, req, 100, new(map[string]string))
			return sources.Temporary(err), err
		})
		if err == nil || !strings.Contains(err.Error(), want) || sources.Temporary(err) || calls != 1 {
			t.Errorf("%s: %d calls, %v (temporary %v), want one call and %q", path, calls, err, sources.Temporary(err), want)
		}
	}
}

// A temporary failure is tried again after each delay, a definite one is not;
// tested without waiting, with delays of zero.
func TestRetry(t *testing.T) {
	ctx := context.Background()
	failing := errors.New("failure")
	run := func(delays []time.Duration, temporary bool, failures int) (int, error) {
		calls := 0
		err := sources.Retry(ctx, delays, func() (bool, error) {
			calls++
			if calls <= failures {
				return temporary, failing
			}
			return false, nil
		})
		return calls, err
	}
	zero := []time.Duration{0, 0}
	for _, c := range []struct {
		name      string
		delays    []time.Duration
		temporary bool
		failures  int
		calls     int
		err       error
	}{
		{"success", zero, true, 0, 1, nil},
		{"one temporary failure", zero, true, 1, 2, nil},
		{"lasting failure", zero, true, 5, 3, failing},
		{"definite failure", zero, false, 5, 1, failing},
		{"no delays", nil, true, 5, 1, failing},
	} {
		if calls, err := run(c.delays, c.temporary, c.failures); calls != c.calls || err != c.err {
			t.Errorf("%s: %d calls, %v; want %d, %v", c.name, calls, err, c.calls, c.err)
		}
	}

	// A cancelled context stops the attempts, even before a long wait.
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	calls := 0
	err := sources.Retry(cancelled, []time.Duration{time.Hour}, func() (bool, error) {
		calls++
		return true, failing
	})
	if calls != 1 || err != failing {
		t.Errorf("cancelled: %d calls, %v", calls, err)
	}
	start := time.Now()
	if err := sources.Sleep(cancelled, time.Hour); !errors.Is(err, context.Canceled) || time.Since(start) > time.Minute {
		t.Errorf("Sleep on a cancelled context: %v after %v", err, time.Since(start))
	}
	if err := sources.Sleep(ctx, 0); err != nil {
		t.Errorf("Sleep(0) = %v", err)
	}
}

// Get asks again after a temporary failure, once without delays, and decodes
// the answer; a request it cannot make is not sent.
func TestGet(t *testing.T) {
	ctx := context.Background()
	var calls atomic.Int32
	srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1)%2 == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		io.WriteString(w, `{"id":"`+r.Header.Get("User-Agent")+`"}`)
	})
	var out struct{ ID string }
	if err := sources.Get(ctx, srv.Client(), srv.URL, "vigil-test", []time.Duration{0}, 100, &out); err != nil || out.ID != "vigil-test" || calls.Load() != 2 {
		t.Errorf("temporary failure: %d calls, %+v, %v", calls.Load(), out, err)
	}
	if err := sources.Get(ctx, srv.Client(), srv.URL, "vigil-test", nil, 100, &out); err == nil || !sources.Temporary(err) || calls.Load() != 3 {
		t.Errorf("without delays: %d calls, %v", calls.Load(), err)
	}
	if err := sources.Get(ctx, srv.Client(), "http://\x7f", "vigil-test", []time.Duration{0}, 100, &out); err == nil || calls.Load() != 3 {
		t.Errorf("invalid address: %d calls, %v", calls.Load(), err)
	}
}

// The public API of a source is asked again after its delays, or the common
// ones; a test server or a mirror at once, as many times.
func TestDelays(t *testing.T) {
	own := []time.Duration{10 * time.Second, 30 * time.Second}
	for _, c := range []struct {
		url    string
		delays []time.Duration
		want   []time.Duration
	}{
		{"", own, own},
		{"https://api.example", own, own},
		{"http://127.0.0.1:1234", own, []time.Duration{0, 0}},
		{"", nil, []time.Duration{5 * time.Second, 15 * time.Second}},
		{"http://127.0.0.1:1234", nil, []time.Duration{0, 0}},
	} {
		if got := sources.Delays(c.url, "https://api.example", c.delays); !slices.Equal(got, c.want) {
			t.Errorf("Delays(%q, %v) = %v, want %v", c.url, c.delays, got, c.want)
		}
	}
}
