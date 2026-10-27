package web

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/auth"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
)

type client struct {
	t    *testing.T
	base string
	http *http.Client
}

func newTestServer(t *testing.T) (*store.Store, string) {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "web.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	srv := &Server{Store: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	h, err := srv.Handler()
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return st, ts.URL
}

func newClient(t *testing.T, base string) *client {
	jar, _ := cookiejar.New(nil)
	return &client{t: t, base: base, http: &http.Client{
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func (c *client) get(path string) (int, string) {
	resp, err := c.http.Get(c.base + path)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func (c *client) post(path string, form url.Values, headers ...string) int {
	req, _ := http.NewRequest(http.MethodPost, c.base+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func (c *client) csrf() string {
	_, body := c.get("/assets")
	m := csrfRe.FindStringSubmatch(body)
	if m == nil {
		c.t.Fatal("no CSRF token in page")
	}
	return m[1]
}

func TestAuthenticationAndAuthorization(t *testing.T) {
	st, base := newTestServer(t)
	admin := newClient(t, base)

	if code, _ := admin.get("/assets"); code != http.StatusSeeOther {
		t.Fatalf("anonymous access: %d", code)
	}
	if code := admin.post("/setup", url.Values{"username": {"admin"}, "password": {"short"}}); code != http.StatusBadRequest {
		t.Fatalf("weak password accepted: %d", code)
	}
	if code := admin.post("/setup", url.Values{"username": {"admin"}, "password": {"a-strong-password"}}); code != http.StatusSeeOther {
		t.Fatalf("setup: %d", code)
	}
	if code := newClient(t, base).post("/setup", url.Values{"username": {"evil"}, "password": {"a-strong-password"}}); code != http.StatusForbidden {
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
	hash, _ := auth.HashPassword("viewer-password")
	st.CreateUser(context.Background(), "viewer", hash, auth.RoleViewer)
	viewer := newClient(t, base)
	if code := viewer.post("/login", url.Values{"username": {"viewer"}, "password": {"wrong-password"}}); code != http.StatusUnauthorized {
		t.Fatalf("wrong password: %d", code)
	}
	if code := viewer.post("/login", url.Values{"username": {"viewer"}, "password": {"viewer-password"}}); code != http.StatusSeeOther {
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

func TestSecurityHeaders(t *testing.T) {
	_, base := newTestServer(t)
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
}

func TestLoginRateLimit(t *testing.T) {
	st, base := newTestServer(t)
	hash, _ := auth.HashPassword("a-strong-password")
	st.CreateUser(context.Background(), "admin", hash, auth.RoleAdmin)
	c := newClient(t, base)
	for i := 0; i < 5; i++ {
		c.post("/login", url.Values{"username": {"admin"}, "password": {"wrong"}})
	}
	if code := c.post("/login", url.Values{"username": {"admin"}, "password": {"a-strong-password"}}); code != http.StatusTooManyRequests {
		t.Fatalf("rate limit not applied: %d", code)
	}
}

func TestAPISBOMToken(t *testing.T) {
	st, base := newTestServer(t)
	ctx := context.Background()
	secret := "vgl_test-secret-value"
	if _, err := st.CreateAPIToken(ctx, store.APIToken{Name: "ci", Project: "app"}, auth.HashToken(secret), 0); err != nil {
		t.Fatal(err)
	}
	bom := `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
		{"type":"library","name":"lodash","version":"4.17.15","purl":"pkg:npm/lodash@4.17.15"}]}`
	put := func(project, token string) int {
		req, _ := http.NewRequest(http.MethodPut, base+"/api/v1/projects/"+project+"/sbom", strings.NewReader(bom))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := put("app", ""); code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", code)
	}
	if code := put("app", "vgl_wrong"); code != http.StatusUnauthorized {
		t.Fatalf("wrong token: %d", code)
	}
	if code := put("other", secret); code != http.StatusForbidden {
		t.Fatalf("token used for another project: %d", code)
	}
	if code := put("app", secret); code != http.StatusOK {
		t.Fatalf("upload: %d", code)
	}
	assets, _ := st.ListAssets(ctx)
	if len(assets) != 1 || assets[0].Project != "app" {
		t.Fatalf("assets = %+v", assets)
	}
}

func TestTOTPLogin(t *testing.T) {
	st, base := newTestServer(t)
	ctx := context.Background()
	hash, _ := auth.HashPassword("a-strong-password")
	id, _ := st.CreateUser(ctx, "alice", hash, auth.RoleViewer)
	secret, _ := auth.NewTOTPSecret()
	st.SetTOTPPending(ctx, id, secret)
	st.EnableTOTP(ctx, id, 0)

	login := url.Values{"username": {"alice"}, "password": {"a-strong-password"}}
	if code := newClient(t, base).post("/login", login); code != http.StatusUnauthorized {
		t.Fatalf("login without code: %d", code)
	}
	login.Set("code", "000000")
	if code := newClient(t, base).post("/login", login); code != http.StatusUnauthorized {
		t.Fatalf("login with wrong code: %d", code)
	}
}

func TestFindingFilters(t *testing.T) {
	st, base := newTestServer(t)
	ctx := context.Background()
	seed := func(asset, vuln, sev string, score float64) {
		id, err := st.CreateAsset(ctx, store.Asset{Name: asset, Kind: "package", Criticality: "high", Source: "manual"})
		if err != nil {
			t.Fatal(err)
		}
		st.UpsertVulnerability(ctx, store.Vulnerability{ID: vuln, Summary: "summary of " + vuln, Severity: sev, CVSS: score})
		if _, err := st.ObserveFinding(ctx, id, vuln, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	seed("log4j-core", "CVE-2021-44228", "CRITICAL", 10)
	seed("lodash", "CVE-2020-8203", "HIGH", 7.4)
	seed("openssl", "CVE-2023-0001", "LOW", 3.1)

	c := newClient(t, base)
	c.post("/setup", url.Values{"username": {"admin"}, "password": {"a-strong-password"}})
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
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "proxy.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	srv := &Server{Store: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), BehindProxy: true}
	h, err := srv.Handler()
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(h)
	defer ts.Close()
	// The request comes from 127.0.0.1, like any request relayed by a local proxy.
	if code := newClient(t, ts.URL).post("/setup", url.Values{"username": {"evil"}, "password": {"a-strong-password"}}); code != http.StatusForbidden {
		t.Fatalf("setup behind proxy: %d", code)
	}
}

func TestTOTPReplayAndBruteForce(t *testing.T) {
	st, base := newTestServer(t)
	ctx := context.Background()
	c := newClient(t, base)
	c.post("/setup", url.Values{"username": {"admin"}, "password": {"a-strong-password"}})
	user, _ := st.UserByName(ctx, "admin")
	secret, _ := auth.NewTOTPSecret()
	st.SetTOTPPending(ctx, user.ID, secret)
	st.EnableTOTP(ctx, user.ID, 0)

	if ok, _ := st.UseTOTPStep(ctx, user.ID, 100); !ok {
		t.Fatal("first use refused")
	}
	if ok, _ := st.UseTOTPStep(ctx, user.ID, 100); ok {
		t.Fatal("step replayed")
	}
	// Wrong codes on the disable form are rate limited per user.
	token := c.csrf()
	code := 0
	for i := 0; i < 6; i++ {
		code = c.post("/account/totp/disable", url.Values{"csrf": {token}, "code": {"000000"}})
	}
	if code != http.StatusTooManyRequests {
		t.Fatalf("brute force not limited: %d", code)
	}
}
