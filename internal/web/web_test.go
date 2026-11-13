package web

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/auth"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
	"github.com/La-Cizaille-Corp/vigil/internal/storetest"
)

func TestAuthenticationAndAuthorization(t *testing.T) {
	st, base := newBareServer(t, nil)
	admin := newClient(t, base)

	if code, _ := admin.get("/assets"); code != http.StatusSeeOther {
		t.Fatalf("anonymous access: %d", code)
	}
	if code := admin.post("/setup", url.Values{"username": {"admin"}, "password": {"short"}, "confirm": {"short"}}); code != http.StatusBadRequest {
		t.Fatalf("weak password accepted: %d", code)
	}
	if code := admin.post("/setup", url.Values{"username": {"admin"}, "password": {testPassword}, "confirm": {testPassword}}); code != http.StatusSeeOther {
		t.Fatalf("setup: %d", code)
	}
	if code := newClient(t, base).post("/setup", url.Values{"username": {"evil"}, "password": {testPassword}, "confirm": {testPassword}}); code != http.StatusForbidden {
		t.Fatalf("second setup allowed: %d", code)
	}

	asset := url.Values{"name": {"lodash"}, "kind": {"package"}, "criticality": {"high"}}
	if code := admin.post("/assets", asset); code != http.StatusForbidden {
		t.Fatalf("missing CSRF accepted: %d", code)
	}
	token := admin.csrf()
	asset.Set("csrf", token)
	if code := admin.post("/assets", asset, "Origin", "https://evil.example"); code != http.StatusForbidden {
		t.Fatalf("cross-origin request accepted: %d", code)
	}
	if code := admin.post("/assets", asset); code != http.StatusSeeOther {
		t.Fatalf("create asset: %d", code)
	}

	// A viewer can read but not write.
	addUser(t, st, "viewer", auth.RoleViewer)
	viewer := newClient(t, base)
	if code := viewer.post("/login", url.Values{"username": {"viewer"}, "password": {"wrong-password"}}); code != http.StatusUnauthorized {
		t.Fatalf("wrong password: %d", code)
	}
	if code := viewer.post("/login", url.Values{"username": {"viewer"}, "password": {testPassword}}); code != http.StatusSeeOther {
		t.Fatalf("viewer login: %d", code)
	}
	if code, body := viewer.get("/assets"); code != http.StatusOK || !strings.Contains(body, "lodash") {
		t.Fatalf("viewer read: %d", code)
	}
	if code := viewer.post("/assets", url.Values{"csrf": {viewer.csrf()}, "name": {"x"}, "kind": {"package"}}); code != http.StatusForbidden {
		t.Fatalf("viewer write allowed: %d", code)
	}
	if code := viewer.post("/settings/webhooks", url.Values{"csrf": {viewer.csrf()}}); code != http.StatusForbidden {
		t.Fatalf("viewer admin action allowed: %d", code)
	}
}

// The policy of the pages is the one written in THREAT_MODEL.md, to the
// letter; HSTS is sent over TLS only (see TestHSTSOverTLS).
func TestSecurityHeaders(t *testing.T) {
	_, base := newBareServer(t, nil)
	resp, err := http.Get(base + "/login")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	for _, h := range []string{"Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy"} {
		if resp.Header.Get(h) == "" {
			t.Errorf("missing header %s", h)
		}
	}
	const csp = "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
	if got := resp.Header.Get("Content-Security-Policy"); got != csp {
		t.Errorf("Content-Security-Policy: %q, want %q", got, csp)
	}
	if got := resp.Header.Get("Strict-Transport-Security"); got != "" {
		t.Errorf("HSTS in clear text: %q", got)
	}
}

// W4 of the 0.5.0 review: a page served over TLS asks the browser to keep to it.
func TestHSTSOverTLS(t *testing.T) {
	srv := &Server{Store: storetest.Open(t), Log: slog.New(slog.DiscardHandler)}
	h, err := srv.Handler()
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewTLSServer(h)
	defer ts.Close()
	resp, err := ts.Client().Get(ts.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := resp.Header.Get("Strict-Transport-Security"); got != "max-age=31536000" {
		t.Errorf("Strict-Transport-Security: %q", got)
	}
}

// W4 of the 0.5.0 review: the sign-in and first-run forms have no session to
// carry a CSRF token. A post from another site is refused before them, and
// opens no session nor creates an account.
func TestLoginAndSetupRefuseOtherSites(t *testing.T) {
	ctx := context.Background()
	for name, header := range map[string][2]string{
		"foreign origin": {"Origin", "https://evil.example"},
		"null origin":    {"Origin", "null"},
		"cross-site":     {"Sec-Fetch-Site", "cross-site"},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(storetest.TempDir(t), "web.db")
			st := storetest.OpenAt(t, path)
			base := serve(t, st, nil)
			sessions := func() int {
				t.Helper()
				db, err := sql.Open("sqlite", path)
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				var n int
				if err := db.QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&n); err != nil {
					t.Fatal(err)
				}
				return n
			}
			c := newClient(t, base)
			setup := url.Values{"username": {"evil"}, "password": {testPassword}, "confirm": {testPassword}}
			if code := c.post("/setup", setup, header[0], header[1]); code != http.StatusForbidden {
				t.Errorf("setup: %d, want 403", code)
			}
			if n, err := st.CountUsers(ctx); err != nil || n != 0 {
				t.Errorf("accounts after a refused setup: %d, %v", n, err)
			}
			addUser(t, st, "admin", auth.RoleAdmin)
			login := url.Values{"username": {"admin"}, "password": {testPassword}}
			if code := c.post("/login", login, header[0], header[1]); code != http.StatusForbidden {
				t.Errorf("login: %d, want 403", code)
			}
			if n := sessions(); n != 0 {
				t.Errorf("%d sessions after refused posts", n)
			}
			if code, _ := c.send(http.MethodGet, "/assets", nil); code != http.StatusSeeOther {
				t.Errorf("signed in by a refused post: %d", code)
			}
			// The same sign-in from the site itself opens a session.
			if code := c.post("/login", login); code != http.StatusSeeOther || sessions() != 1 {
				t.Errorf("login from the site: %d, %d sessions", code, sessions())
			}
		})
	}
}

// W4 of the 0.5.0 review: signing out ends the session on the server, not
// only in the browser: its cookie, kept elsewhere, leads to the sign-in page.
func TestLogoutEndsTheSession(t *testing.T) {
	st, base := newServerWith(t, nil)
	c := loginAs(t, base, "analyst", testPassword)
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	var cookie *http.Cookie
	for _, k := range c.http.Jar.Cookies(u) {
		if k.Name == sessionCookie {
			cookie = k
		}
	}
	if cookie == nil {
		t.Fatal("no session cookie after login")
	}
	if code, to := c.send(http.MethodPost, "/logout", url.Values{"csrf": {c.csrf()}}); code != http.StatusSeeOther || to != "/login" {
		t.Fatalf("logout: %d %s", code, to)
	}
	if _, err := st.Session(context.Background(), auth.HashToken(cookie.Value)); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("session after logout: %v", err)
	}
	stolen := newClient(t, base)
	stolen.http.Jar.SetCookies(u, []*http.Cookie{{Name: sessionCookie, Value: cookie.Value}})
	if code, to := stolen.send(http.MethodGet, "/assets", nil); code != http.StatusSeeOther || to != "/login" {
		t.Errorf("old cookie after logout: %d %s", code, to)
	}
}

func TestAPISBOMToken(t *testing.T) {
	st, base := newBareServer(t, nil)
	ctx := context.Background()
	secret := "vgl_test-secret-value"
	if _, err := st.CreateAPIToken(ctx, store.APIToken{Name: "ci", Project: "app"}, auth.HashToken(secret), 0); err != nil {
		t.Fatal(err)
	}
	bom := `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
		{"type":"library","name":"lodash","version":"4.17.15","purl":"pkg:npm/lodash@4.17.15"}]}`
	for _, c := range []struct {
		what, project, token string
		want                 int
	}{
		{"no token", "app", "", http.StatusUnauthorized},
		{"wrong token", "app", "vgl_wrong", http.StatusUnauthorized},
		{"token used for another project", "other", secret, http.StatusForbidden},
		{"upload", "app", secret, http.StatusOK},
	} {
		if code := putSBOM(t, base, c.project, c.token, bom); code != c.want {
			t.Fatalf("%s: %d, want %d", c.what, code, c.want)
		}
	}
	assets, err := st.ListAssets(ctx, store.Everything)
	if err != nil || len(assets) != 1 || assets[0].Project != "app" {
		t.Fatalf("assets = %+v, %v", assets, err)
	}
}

func TestTOTPLogin(t *testing.T) {
	st, base := newBareServer(t, nil)
	enableTOTP(t, st, addUser(t, st, "alice", auth.RoleViewer))

	login := url.Values{"username": {"alice"}, "password": {testPassword}}
	if code := newClient(t, base).post("/login", login); code != http.StatusUnauthorized {
		t.Fatalf("login without code: %d", code)
	}
	login.Set("code", "000000")
	if code := newClient(t, base).post("/login", login); code != http.StatusUnauthorized {
		t.Fatalf("login with wrong code: %d", code)
	}
}

func TestFindingFilters(t *testing.T) {
	st, base := newBareServer(t, nil)
	seed := func(asset, vuln, sev string, score float64) {
		id := storetest.Asset(t, st, store.Asset{Name: asset, Kind: "package", Criticality: "high", Source: "manual"})
		storetest.Finding(t, st, id, store.Vulnerability{ID: vuln, Summary: "summary of " + vuln, Severity: sev, CVSS: score}, time.Now())
	}
	seed("log4j-core", "CVE-2021-44228", "CRITICAL", 10)
	seed("lodash", "CVE-2020-8203", "HIGH", 7.4)
	seed("openssl", "CVE-2023-0001", "LOW", 3.1)

	c := newClient(t, base)
	c.post("/setup", url.Values{"username": {"admin"}, "password": {testPassword}, "confirm": {testPassword}})
	for query, want := range map[string][]string{
		"":                      {"CVE-2021-44228", "CVE-2020-8203", "CVE-2023-0001"},
		"cvss=7":                {"CVE-2021-44228", "CVE-2020-8203"},
		"severity=LOW":          {"CVE-2023-0001"},
		"q=log4j":               {"CVE-2021-44228"},
		"q=%25":                 {}, // LIKE wildcard is escaped
		"status=resolved":       {},
		"severity=BOGUS&cvss=x": {"CVE-2021-44228", "CVE-2020-8203", "CVE-2023-0001"},
	} {
		code, body := c.get("/findings?" + query)
		if code != http.StatusOK {
			t.Fatalf("%s: %d", query, code)
		}
		got := 0
		for _, id := range []string{"CVE-2021-44228", "CVE-2020-8203", "CVE-2023-0001"} {
			if strings.Contains(body, ">"+id+"<") {
				got++
			}
		}
		if got != len(want) {
			t.Errorf("%q: %d results, want %d", query, got, len(want))
		}
		for _, id := range want {
			if !strings.Contains(body, ">"+id+"<") {
				t.Errorf("%q: missing %s", query, id)
			}
		}
	}
}

func TestSetupDisabledBehindProxy(t *testing.T) {
	_, base := newBareServer(t, func(s *Server) { s.BehindProxy = true })
	// The request comes from 127.0.0.1, like any request relayed by a local proxy.
	if code := newClient(t, base).post("/setup", url.Values{"username": {"evil"}, "password": {testPassword}, "confirm": {testPassword}}); code != http.StatusForbidden {
		t.Fatalf("setup behind proxy: %d", code)
	}
}

// Wrong codes on the form that turns the second factor off are limited per
// account (the replay of a code: TestUseTOTPStep in package store).
func TestTOTPBruteForce(t *testing.T) {
	st, base := newServerWith(t, nil)
	c := loginAs(t, base, "admin", testPassword)
	user, err := st.UserByName(context.Background(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	enableTOTP(t, st, user.ID)
	token := c.csrf()
	code := 0
	for range 6 {
		code = c.post("/account/totp/disable", url.Values{"csrf": {token}, "code": {"000000"}})
	}
	if code != http.StatusTooManyRequests {
		t.Fatalf("brute force not limited: %d", code)
	}
}
