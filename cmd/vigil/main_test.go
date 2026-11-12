package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

// S16: vigil user add refuses a name that differs from an existing one only
// by case, and says why.
func TestUserAddIgnoresCase(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db := filepath.Join(dir, "vigil.db")
	add := func(name string) error {
		t.Helper()
		f, err := os.CreateTemp(dir, "password")
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if _, err := f.WriteString("a-strong-password\n"); err != nil {
			t.Fatal(err)
		}
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			t.Fatal(err)
		}
		stdin := os.Stdin
		os.Stdin = f
		defer func() { os.Stdin = stdin }()
		return runUser(ctx, []string{"add", "-db", db, "-username", name, "-role", "viewer"})
	}
	if err := add("alice"); err != nil {
		t.Fatal(err)
	}
	if err := add("Alice"); err == nil || !strings.Contains(err.Error(), "majuscules et minuscules") {
		t.Errorf("case variant of an existing name: %v", err)
	}
}
