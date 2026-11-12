package sources_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/netsafe"
	"github.com/La-Cizaille-Corp/vigil/internal/sources"
)

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

	var tooLarge *netsafe.TooLargeError
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
			t.Errorf("%s: %T, want a *netsafe.TooLargeError", c.path, err)
		}
	}

	// The network: sending again may succeed.
	req, _ := sources.NewRequest(context.Background(), http.MethodGet, srv.URL+"/ok", "vigil-test", nil)
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
	req, _ := sources.NewRequest(context.Background(), http.MethodGet, srv.URL, "vigil-test", nil)
	body, err := sources.Open(srv.Client(), req, 50)
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	var out map[string]string
	var tooLarge *netsafe.TooLargeError
	if err := json.NewDecoder(body).Decode(&out); !errors.As(err, &tooLarge) || tooLarge.Max != 50 {
		t.Errorf("stream past its bound: %v", err)
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
	defer srv.Close()
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
