package main

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/sources/osv"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
)

// TestSourceRedirects: the clients given to the fixed sources follow
// redirects in HTTPS only, OSV included, and the NVD key never leaves its host.
func TestSourceRedirects(t *testing.T) {
	ctx := context.Background()
	_, opts := newCommand("sync", true)
	if err := opts.parse(nil); err != nil {
		t.Fatal(err)
	}
	sv := opts.services(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	// One client for the sources, and a copy for OSV with its own time limit.
	s := sv.syncer
	if s.KEV.HTTP != s.NVD.HTTP || s.EPSS.HTTP != s.NVD.HTTP || s.OSV.HTTP == s.NVD.HTTP ||
		s.OSV.HTTP.Timeout != osv.Timeout || s.OSV.HTTP.CheckRedirect == nil {
		t.Errorf("source clients: OSV %+v, NVD %+v", s.OSV.HTTP, s.NVD.HTTP)
	}

	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"id":"GHSA-x"}`)
	}))
	defer plain.Close()
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+r.URL.Path, http.StatusFound)
	}))
	defer secure.Close()
	o := sv.syncer.OSV
	o.URL, o.HTTP.Transport = secure.URL, secure.Client().Transport
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

// A68: vigil user add without -groups gives access to everything, as before
// the groups; with -groups, to the groups named, at the case of their
// letters; vigil user set-access changes it. An unknown group is refused.
func TestUserAccessFromTheCommandLine(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db := filepath.Join(dir, "vigil.db")
	stdin := os.Stdin
	t.Cleanup(func() { os.Stdin = stdin })
	user := func(args ...string) error {
		t.Helper()
		in := filepath.Join(dir, "password")
		if err := os.WriteFile(in, []byte("a-strong-password\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		f, err := os.Open(in)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		os.Stdin = f
		return runUser(ctx, append(args, "-db", db))
	}
	if err := user("add", "-username", "script"); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateGroup(ctx, "Équipe web"); err != nil {
		t.Fatal(err)
	}
	st.Close()
	if err := user("add", "-username", "camille", "-groups", "ÉQUIPE WEB"); err != nil {
		t.Fatal(err)
	}
	if err := user("add", "-username", "dom", "-groups", "Équipe web,Inconnu"); err == nil || !strings.Contains(err.Error(), `"Inconnu"`) {
		t.Errorf("unknown group: %v", err)
	}
	for _, args := range [][]string{{"-username", "script"}, {"-username", "script", "-all", "-groups", "x"}} {
		if err := user(append([]string{"set-access"}, args...)...); err == nil {
			t.Errorf("set-access %v accepted", args)
		}
	}
	if err := user("set-access", "-username", "script", "-groups", ""); err != nil {
		t.Fatal(err)
	}
	if err := user("set-access", "-username", "camille", "-all"); err != nil {
		t.Fatal(err)
	}
	st, err = store.Open(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	for name, want := range map[string]store.Access{"script": {}, "camille": {All: true}} {
		u, err := st.AnyUserByName(ctx, name)
		if err != nil || u.Access.All != want.All || len(u.Access.Groups) != 0 {
			t.Errorf("%s: %+v, %v", name, u.Access, err)
		}
	}
	if _, err := st.AnyUserByName(ctx, "dom"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("account created with an unknown group: %v", err)
	}
	entries, _ := st.ListAudit(ctx, 10)
	var details []string
	for _, e := range entries {
		details = append(details, e.Action+" "+e.Detail)
	}
	for _, want := range []string{`user_create id=2 user=camille role=analyst access=groups groups="Équipe web" source=cli`,
		`user_access id=1 user=script access=groups groups="" source=cli`, "user_access id=2 user=camille access=all source=cli"} {
		if !slices.Contains(details, want) {
			t.Errorf("audit misses %q: %q", want, details)
		}
	}
}

// S14 (ASVS V2.1.7): vigil user add and reset-password refuse one of the most
// common passwords, whatever its case, before the database is even opened.
func TestUserCommandsRefuseCommonPassword(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "vigil.db")
	stdin := os.Stdin
	t.Cleanup(func() { os.Stdin = stdin })
	for _, args := range [][]string{
		{"add", "-db", db, "-username", "bob"},
		{"reset-password", "-db", db, "-username", "bob"},
	} {
		in := filepath.Join(dir, "password")
		if err := os.WriteFile(in, []byte("Qwerty123456\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		f, err := os.Open(in)
		if err != nil {
			t.Fatal(err)
		}
		os.Stdin = f
		err = runUser(context.Background(), args)
		f.Close()
		if err == nil || !strings.Contains(err.Error(), "fait partie des plus courants") {
			t.Errorf("vigil user %s with a common password: %v", args[0], err)
		}
	}
	if _, err := os.Stat(db); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("database opened: %v", err)
	}
}
