package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestSourceRedirects: the clients given to the fixed sources follow
// redirects in HTTPS only, OSV included, and the NVD key never leaves its host.
func TestSourceRedirects(t *testing.T) {
	ctx := context.Background()
	sv := newServices(nil, slog.New(slog.NewTextHandler(io.Discard, nil)), false, nil, "")

	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"id":"GHSA-x"}`)
	}))
	defer plain.Close()
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+r.URL.Path, http.StatusFound)
	}))
	defer secure.Close()
	o := sv.syncer.OSV
	o.BaseURL, o.HTTP.Transport = secure.URL, secure.Client().Transport
	if v, err := o.Vuln(ctx, "GHSA-x"); err == nil {
		t.Errorf("OSV followed a redirect to %s: %q", plain.URL, v.ID)
	}

	keys := map[string]string{}
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		keys["other"] = r.Header.Get("apiKey")
		io.WriteString(w, `{"totalResults":0,"vulnerabilities":[]}`)
	}))
	defer other.Close()
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/again?"+r.URL.RawQuery, http.StatusFound)
			return
		}
		keys["again"] = r.Header.Get("apiKey")
		http.Redirect(w, r, other.URL+"/final?"+r.URL.RawQuery, http.StatusFound)
	}))
	defer origin.Close()
	n := sv.syncer.NVD
	n.URL, n.APIKey, n.HTTP.Transport = origin.URL+"/start", "secret", origin.Client().Transport
	if _, err := n.ForKeyword(ctx, "fortios", time.Time{}); err != nil {
		t.Fatal(err)
	}
	if keys["again"] != "secret" || keys["other"] != "" {
		t.Errorf("NVD key seen on the same host: %q, on another host: %q", keys["again"], keys["other"])
	}
}
