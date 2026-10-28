package web

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/La-Cizaille-Corp/vigil/internal/auth"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
)

func (c *client) postBody(path string, form url.Values, headers ...string) (int, string) {
	req, _ := http.NewRequest(http.MethodPost, c.base+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// A page that makes its own domain resolve to 127.0.0.1 (DNS rebinding)
// reaches a local instance with that domain as Host: it is refused.
func TestHostCheck(t *testing.T) {
	_, base := newServerWith(t, func(s *Server) { s.LocalOnly = true })
	for host, want := range map[string]int{
		"rebind.attacker.example:8080":      http.StatusMisdirectedRequest,
		strings.TrimPrefix(base, "http://"): http.StatusSeeOther,
		"localhost:8080":                    http.StatusSeeOther,
	} {
		req, _ := http.NewRequest(http.MethodGet, base+"/", nil)
		req.Host = host
		resp, err := http.DefaultTransport.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("Host %s: %d, want %d", host, resp.StatusCode, want)
		}
	}
}

// A reverse proxy configured without -behind-proxy makes every request look
// local: the first-run setup must not be reachable through it.
func TestSetupRefusesForwardedRequests(t *testing.T) {
	st, base := newTestServer(t)
	code := newClient(t, base).post("/setup", url.Values{"username": {"x"}, "password": {"a-strong-password"}},
		"X-Forwarded-For", "203.0.113.7")
	if n, _ := st.CountUsers(context.Background()); code != http.StatusForbidden || n != 0 {
		t.Fatalf("setup through a proxy: %d, %d users", code, n)
	}
}

// A successful login from the same address does not reset the failures of
// another account, and guesses spread over many addresses still hit the
// per-account limit.
func TestLoginLimits(t *testing.T) {
	st, base := newTestServer(t)
	hash, _ := auth.HashPassword("a-strong-password")
	st.CreateUser(context.Background(), "admin", hash, auth.RoleAdmin)
	st.CreateUser(context.Background(), "eve", hash, auth.RoleViewer)
	c := newClient(t, base)
	for range 4 {
		c.post("/login", url.Values{"username": {"admin"}, "password": {"guess"}})
	}
	if code := c.post("/login", url.Values{"username": {"eve"}, "password": {"a-strong-password"}}); code != http.StatusSeeOther {
		t.Fatalf("eve login: %d", code)
	}
	c.post("/login", url.Values{"username": {"admin"}, "password": {"guess"}})
	if code := c.post("/login", url.Values{"username": {"admin"}, "password": {"a-strong-password"}}); code != http.StatusTooManyRequests {
		t.Errorf("a valid login of another account reset the address counter: %d", code)
	}

	_, base = newServerWith(t, func(s *Server) { s.BehindProxy = true })
	c = newClient(t, base)
	for i := range 10 {
		c.post("/login", url.Values{"username": {"admin"}, "password": {"guess"}}, "X-Forwarded-For", "198.51.100."+itoa(int64(i+1)))
	}
	if code := c.post("/login", url.Values{"username": {"admin"}, "password": {"a-strong-password"}},
		"X-Forwarded-For", "203.0.113.50"); code != http.StatusTooManyRequests {
		t.Errorf("per-account limit not applied: %d", code)
	}
	if code := c.post("/login", url.Values{"username": {"analyst"}, "password": {"a-strong-password"}},
		"X-Forwarded-For", "203.0.113.50"); code != http.StatusSeeOther {
		t.Errorf("other account blocked: %d", code)
	}
}

func TestLimitKeys(t *testing.T) {
	if k := limitKey("2001:db8:1:2:3:4:5:6"); k != "2001:db8:1:2::/64" {
		t.Errorf("IPv6 key = %s", k)
	}
	if k := limitKey("203.0.113.9"); k != "203.0.113.9" {
		t.Errorf("IPv4 key = %s", k)
	}
	if n := len([]rune(truncate(strings.Repeat("a", 70000), 64))); n != 65 {
		t.Errorf("account key length = %d", n)
	}
}

var passwordRe = regexp.MustCompile(`<code>([A-Za-z0-9]{5}(?:-[A-Za-z0-9]{5}){3})</code>`)

// Administrators manage accounts in the UI: creation with a one-time
// password, role change, deactivation that ends sessions, password reset.
func TestUserAdministration(t *testing.T) {
	st, base := newServerWith(t, nil)
	ctx := context.Background()
	admin := loginAs(t, base, "admin", "a-strong-password")
	token := admin.csrf()

	// The password is shown once, on the page the form redirects to: a
	// reload neither posts the form again nor shows it twice.
	code := admin.post("/settings/users", url.Values{"csrf": {token}, "username": {"bob"}, "role": {"analyst"}})
	_, body := admin.get("/settings/users")
	m := passwordRe.FindStringSubmatch(body)
	if code != http.StatusSeeOther || m == nil {
		t.Fatalf("create user: %d, password shown: %v", code, m != nil)
	}
	if _, again := admin.get("/settings/users"); passwordRe.MatchString(again) {
		t.Error("temporary password shown twice")
	}
	bob := loginAs(t, base, "bob", m[1])
	if code, _ := bob.get("/settings/users"); code != http.StatusForbidden {
		t.Errorf("analyst reached user administration: %d", code)
	}

	b, _ := st.AccountByName(ctx, "bob")
	path := "/settings/users/" + itoa(b.ID)
	if code := admin.post(path+"/role", url.Values{"csrf": {token}, "role": {"viewer"}}); code != http.StatusSeeOther {
		t.Fatalf("role change: %d", code)
	}
	if code := bob.post("/assets", url.Values{"csrf": {bob.csrf()}, "name": {"x"}, "kind": {"package"}}); code != http.StatusForbidden {
		t.Errorf("demoted user still writes: %d", code)
	}
	if code := admin.post(path+"/disable", url.Values{"csrf": {token}}); code != http.StatusSeeOther {
		t.Fatalf("disable: %d", code)
	}
	if code, _ := bob.get("/"); code != http.StatusSeeOther {
		t.Errorf("session of a disabled user still open: %d", code)
	}
	if code := newClient(t, base).post("/login", url.Values{"username": {"bob"}, "password": {m[1]}}); code != http.StatusUnauthorized {
		t.Errorf("disabled user signed in: %d", code)
	}

	a, _ := st.AccountByName(ctx, "admin")
	if code, _ := admin.postBody("/settings/users/"+itoa(a.ID)+"/disable", url.Values{"csrf": {token}}); code != http.StatusBadRequest {
		t.Errorf("admin disabled their own account: %d", code)
	}
	admin.post(path+"/enable", url.Values{"csrf": {token}})
	code = admin.post(path+"/password", url.Values{"csrf": {token}})
	_, body = admin.get("/settings/users")
	if m = passwordRe.FindStringSubmatch(body); code != http.StatusSeeOther || m == nil {
		t.Fatalf("password reset: %d", code)
	}
	loginAs(t, base, "bob", m[1])

	audit, _ := st.ListAudit(ctx, 50)
	seen := map[string]bool{}
	for _, e := range audit {
		seen[e.Action] = true
	}
	for _, action := range []string{"user_create", "user_role", "user_disable", "user_enable", "password_reset"} {
		if !seen[action] {
			t.Errorf("%s not audited", action)
		}
	}
}

// Enabling the second factor takes the password; an active one cannot be
// replaced by starting a new enrolment.
func TestTOTPEnrolmentNeedsPassword(t *testing.T) {
	st, base := newServerWith(t, nil)
	ctx := context.Background()
	c := loginAs(t, base, "analyst", "a-strong-password")
	token := c.csrf()
	c.post("/account/totp/start", url.Values{"csrf": {token}})
	code, body := c.postBody("/account/totp/confirm", url.Values{"csrf": {token}, "code": {"000000"}, "password": {"wrong"}})
	if code != http.StatusBadRequest || !strings.Contains(body, "Mot de passe incorrect") {
		t.Errorf("confirmation without the password: %d", code)
	}

	u, _ := st.UserByName(ctx, "analyst")
	secret, _ := auth.NewTOTPSecret()
	st.SetTOTPPending(ctx, u.ID, secret)
	st.EnableTOTP(ctx, u.ID, 0)
	c.post("/account/totp/start", url.Values{"csrf": {token}})
	if active, pending, _, _ := st.UserTOTP(ctx, u.ID); active != secret || pending != "" {
		t.Error("a new enrolment started while the second factor is active")
	}
}

// Over HTTPS the session cookie carries the __Host- prefix.
func TestSecureCookieName(t *testing.T) {
	_, base := newServerWith(t, func(s *Server) { s.SecureCookies = true })
	resp, err := newClient(t, base).http.PostForm(base+"/login", url.Values{"username": {"admin"}, "password": {"a-strong-password"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if c := resp.Cookies(); len(c) != 1 || c[0].Name != "__Host-vigil_session" || !c[0].Secure {
		t.Errorf("cookies: %+v", c)
	}
}

// Revoking an API token and deleting a channel are audited.
func TestSettingsChangesAudited(t *testing.T) {
	st, base := newServerWith(t, nil)
	ctx := context.Background()
	admin := loginAs(t, base, "admin", "a-strong-password")
	id, _ := st.CreateAPIToken(ctx, store.APIToken{Name: "ci", Project: "app"}, "hash", 0)
	if code := admin.post("/settings/tokens/"+itoa(id)+"/delete", url.Values{"csrf": {admin.csrf()}}); code != http.StatusSeeOther {
		t.Fatalf("revoke: %d", code)
	}
	audit, _ := st.ListAudit(ctx, 10)
	if len(audit) == 0 || audit[0].Action != "api_token_delete" || audit[0].Username != "admin" {
		t.Errorf("revocation not audited: %+v", audit)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
