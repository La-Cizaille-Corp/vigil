package web

import (
	"context"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/La-Cizaille-Corp/vigil/internal/auth"
	"github.com/La-Cizaille-Corp/vigil/internal/clip"
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
	code := newClient(t, base).post("/setup", url.Values{"username": {"x"}, "password": {"a-strong-password"}, "confirm": {"a-strong-password"}},
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
	st.CreateUser(context.Background(), "admin", hash, auth.RoleAdmin, store.Access{All: true})
	st.CreateUser(context.Background(), "eve", hash, auth.RoleViewer, store.Access{All: true})
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
	if n := len([]rune(clip.Text(strings.Repeat("a", 70000), 64))); n != 64 {
		t.Errorf("account key length = %d", n)
	}
}

// S5: the API counted bad tokens per exact address, while sign-in counts an
// IPv6 /64 as one client: guesses spread over a /64 were never slowed down.
// Both now take the same key, each in its own scope.
func TestAPILimiterCountsIPv6Block(t *testing.T) {
	_, base := newServerWith(t, func(s *Server) { s.BehindProxy = true })
	put := func(from string) int { return putSBOM(t, base, "p", "vgl_wrong", "{}", "X-Forwarded-For", from) }
	var codes []int
	for i := 1; i <= 7; i++ {
		codes = append(codes, put("2001:db8::"+strconv.Itoa(i)))
	}
	if want := []int{401, 401, 401, 401, 401, 429, 429}; !slices.Equal(codes, want) {
		t.Errorf("7 bad tokens from one /64: %v, want %v", codes, want)
	}
	if code := put("2001:db8:0:1::1"); code != http.StatusUnauthorized {
		t.Errorf("another /64 blocked: %d", code)
	}
	// The API and sign-in keep separate counts.
	if code := newClient(t, base).post("/login", url.Values{"username": {"admin"}, "password": {"a-strong-password"}},
		"X-Forwarded-For", "2001:db8::9"); code != http.StatusSeeOther {
		t.Errorf("sign-in from the /64 blocked by the API: %d", code)
	}
}

// R2: limits are counted in characters, as the forms and A65 say: a name of
// 40 « é » (80 bytes) was refused as longer than 64.
func TestLengthsCountCharacters(t *testing.T) {
	_, base := newServerWith(t, nil)
	admin := loginAs(t, base, "admin", "a-strong-password")
	token := admin.csrf()
	for n, want := range map[int]int{40: http.StatusSeeOther, 64: http.StatusSeeOther, 65: http.StatusBadRequest} {
		name := strings.Repeat("é", n)
		if code := admin.post("/settings/users", url.Values{"csrf": {token}, "username": {name}, "role": {auth.RoleViewer}, "access": {"all"}}); code != want {
			t.Errorf("username of %d accented characters: %d, want %d", n, code, want)
		}
	}
	if code := admin.post("/settings/tokens", url.Values{"csrf": {token}, "name": {strings.Repeat("é", 100)},
		"project": {strings.Repeat("é", 200)}}); code != http.StatusSeeOther {
		t.Errorf("token of 100 and 200 accented characters: %d", code)
	}
	if code := admin.post("/settings/tokens", url.Values{"csrf": {token}, "name": {strings.Repeat("é", 101)},
		"project": {"app"}}); code != http.StatusBadRequest {
		t.Errorf("token name of 101 characters: %d", code)
	}
	bom := `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
		{"type":"library","name":"lodash","version":"4.17.15","purl":"pkg:npm/lodash@4.17.15"}]}`
	if code, _ := admin.upload("/assets/import", "sbom", "bom.json", bom,
		url.Values{"csrf": {token}, "project": {strings.Repeat("é", 200)}}); code != http.StatusSeeOther {
		t.Errorf("SBOM project of 200 accented characters: %d", code)
	}

	_, fresh := newTestServer(t)
	if code := newClient(t, fresh).post("/setup", url.Values{"username": {strings.Repeat("é", 40)},
		"password": {"a-strong-password"}, "confirm": {"a-strong-password"}}); code != http.StatusSeeOther {
		t.Errorf("setup with a name of 40 accented characters: %d", code)
	}
}

// S14: the 1,024-byte bound on passwords applied only to the account forms;
// setup and sign-in took up to the whole form, and a password set at setup
// could be one no other form accepts.
func TestPasswordMaxBytes(t *testing.T) {
	long := strings.Repeat("a", 1025)
	st, fresh := newTestServer(t)
	if code := newClient(t, fresh).post("/setup", url.Values{"username": {"root"}, "password": {long}, "confirm": {long}}); code != http.StatusBadRequest {
		t.Errorf("setup with a 1,025-byte password: %d", code)
	}
	if n, _ := st.CountUsers(context.Background()); n != 0 {
		t.Errorf("%d account created", n)
	}

	_, base := newServerWith(t, nil)
	c := newClient(t, base)
	if code, body := c.postBody("/login", url.Values{"username": {"admin"}, "password": {long}}); code != http.StatusBadRequest ||
		!strings.Contains(body, "Mot de passe trop long.") {
		t.Errorf("sign-in with a 1,025-byte password: %d", code)
	}
	admin := loginAs(t, base, "admin", "a-strong-password")
	if code, body := admin.postBody("/account/password", url.Values{"csrf": {admin.csrf()}, "current": {"a-strong-password"},
		"new": {long}, "confirm": {long}}); code != http.StatusBadRequest || !strings.Contains(body, "Mot de passe trop long.") {
		t.Errorf("password change to 1,025 bytes: %d", code)
	}
}

// S14 (ASVS V2.1.7): setup and the account page refuse one of the most common
// passwords, whatever its case, with a message that says why.
func TestCommonPasswordForms(t *testing.T) {
	const why = "fait partie des plus courants"
	st, fresh := newTestServer(t)
	if code, body := newClient(t, fresh).postBody("/setup", url.Values{"username": {"root"},
		"password": {"Qwerty123456"}, "confirm": {"Qwerty123456"}}); code != http.StatusBadRequest || !strings.Contains(body, why) {
		t.Errorf("setup with a common password: %d", code)
	}
	if n, _ := st.CountUsers(context.Background()); n != 0 {
		t.Errorf("%d account created", n)
	}

	_, base := newServerWith(t, nil)
	admin := loginAs(t, base, "admin", "a-strong-password")
	if code, body := admin.postBody("/account/password", url.Values{"csrf": {admin.csrf()}, "current": {"a-strong-password"},
		"new": {"QWERTYUIOPASDFGH"}, "confirm": {"QWERTYUIOPASDFGH"}}); code != http.StatusBadRequest || !strings.Contains(body, why) {
		t.Errorf("password change to a common password: %d", code)
	}
	loginAs(t, base, "admin", "a-strong-password") // unchanged
}

// Each page where a password is chosen says the whole rule, the common
// passwords as well as the length: setup, « Mon compte », and the temporary
// password given in Settings → Users.
func TestPasswordHelpOnEachPage(t *testing.T) {
	help := template.HTMLEscapeString(auth.PasswordHelp)
	_, fresh := newTestServer(t)
	if _, body := newClient(t, fresh).get("/setup"); !strings.Contains(body, "Mot de passe ("+help+")") {
		t.Errorf("setup page: no %q", auth.PasswordHelp)
	}

	_, base := newServerWith(t, nil)
	admin := loginAs(t, base, "admin", "a-strong-password")
	if _, body := admin.get("/account"); !strings.Contains(body, "Nouveau mot de passe ("+help+")") {
		t.Errorf("account page: no %q", auth.PasswordHelp)
	}
	if code := admin.post("/settings/users", url.Values{"csrf": {admin.csrf()}, "username": {"bob"}, "role": {"analyst"}, "access": {"all"}}); code != http.StatusSeeOther {
		t.Fatalf("create user: %d", code)
	}
	if _, body := admin.get("/settings/users"); !passwordRe.MatchString(body) || !strings.Contains(body, "("+help+")") {
		t.Errorf("temporary password: no %q beside it", auth.PasswordHelp)
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
	code := admin.post("/settings/users", url.Values{"csrf": {token}, "username": {"bob"}, "role": {"analyst"}, "access": {"all"}})
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

	b, _ := st.AnyUserByName(ctx, "bob")
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

	a, _ := st.AnyUserByName(ctx, "admin")
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

// A body past its bound (limitBody) is refused as too large, with the bound,
// before the CSRF token is looked for: it used to leave the form empty and be
// answered « Jeton CSRF invalide. ». A form without its file says so.
func TestBodyPastItsBound(t *testing.T) {
	st, base := newServerWith(t, nil)
	c := loginAs(t, base, "analyst", "a-strong-password")
	for _, tc := range []struct {
		path, field, content, want string
	}{
		{"/assets/import-csv", "csv", "name\n" + strings.Repeat("x\n", 1_100_000), "le fichier CSV doit faire 2 Mo au plus"},
		{"/assets/import", "sbom", strings.Repeat(" ", 22<<20), "le fichier doit faire 20 Mo au plus"},
		{"/findings/vex", "vex", strings.Repeat(" ", 22<<20), "le fichier doit faire 20 Mo au plus"},
	} {
		code, body := c.upload(tc.path, tc.field, "f", tc.content, url.Values{"csrf": {c.csrf()}})
		if code != http.StatusRequestEntityTooLarge || !strings.Contains(body, "Envoi trop volumineux : "+tc.want+".") {
			t.Errorf("%s past its bound: %d %.80q", tc.path, code, body)
		}
	}
	code, body := c.postBody("/findings/bulk", url.Values{"csrf": {c.csrf()}, "comment": {strings.Repeat("x", 70<<10)}})
	if code != http.StatusRequestEntityTooLarge || !strings.Contains(body, "un formulaire fait 64 Kio au plus") {
		t.Errorf("form past its bound: %d %.80q", code, body)
	}
	if assets, _ := st.ListAssets(context.Background(), store.Everything); len(assets) != 0 {
		t.Errorf("assets added: %d", len(assets))
	}
	// Within its bound, an upload without its file says what is missing.
	if code, body := c.upload("/assets/import-csv", "other", "f", "name\nx\n", url.Values{"csrf": {c.csrf()}}); code != http.StatusBadRequest ||
		!strings.Contains(body, "Fichier CSV manquant.") {
		t.Errorf("CSV without its file: %d", code)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
