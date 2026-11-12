package web

// Regression tests of the November 2026 code audit on accounts and sign-in
// (findings S13, S16 and S17), and of API tokens whose creator is disabled.

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/La-Cizaille-Corp/vigil/internal/auth"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
)

// putSBOM sends an SBOM to the CI API with a bearer token (none if empty)
// and extra headers, and returns the status.
func putSBOM(t *testing.T, base, project, token, body string, headers ...string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut, base+"/api/v1/projects/"+project+"/sbom", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// S13: a user closes the sessions of their other browsers on demand. The
// current one stays open, other users keep theirs, and the action is audited.
func TestCloseOtherSessions(t *testing.T) {
	st, base := newServerWith(t, nil)
	c := loginAs(t, base, "analyst", "a-strong-password")
	other := loginAs(t, base, "analyst", "a-strong-password")
	admin := loginAs(t, base, "admin", "a-strong-password")
	if _, body := c.get("/account"); !strings.Contains(body, `action="/account/sessions/close-others"`) {
		t.Fatal("no button to close the other sessions on the account page")
	}

	code, to := c.postLocation("/account/sessions/close-others", url.Values{"csrf": {c.csrf()}})
	if code != http.StatusSeeOther || to != "/account?msg=sessions-closed" {
		t.Fatalf("close other sessions: %d %s", code, to)
	}
	if code, body := c.get(to); code != http.StatusOK || !strings.Contains(body, flashes["sessions-closed"]) {
		t.Errorf("current session after closing the others: %d", code)
	}
	if code, _ := other.get("/account"); code != http.StatusSeeOther {
		t.Errorf("other session still open: %d", code)
	}
	if code, _ := admin.get("/account"); code != http.StatusOK {
		t.Errorf("session of another user closed: %d", code)
	}
	audit, _ := st.ListAudit(context.Background(), 10)
	if len(audit) == 0 || audit[0].Action != "sessions_close" || audit[0].Username != "analyst" {
		t.Errorf("closing the other sessions not audited: %+v", audit)
	}
}

// S16: Settings → Users refuses a name that differs from an existing one only
// by case, and says why.
func TestUserCreateIgnoresCase(t *testing.T) {
	st, base := newServerWith(t, nil)
	admin := loginAs(t, base, "admin", "a-strong-password")
	code, body := admin.postBody("/settings/users", url.Values{"csrf": {admin.csrf()}, "username": {"Analyst"}, "role": {"viewer"}, "access": {"all"}})
	if code != http.StatusBadRequest || !strings.Contains(body, "majuscules et minuscules") {
		t.Errorf("case variant of an existing name: %d", code)
	}
	if n, _ := st.CountUsers(context.Background()); n != 2 {
		t.Errorf("%d accounts, want 2", n)
	}
}

// S17: a failed sign-in keeps the typed name in the audit log, and so in the
// service log, only when an account bears it, disabled or not: a password
// typed in the name field stays out. The answer is the same either way.
func TestFailedLoginKeepsOnlyAccountNames(t *testing.T) {
	st, base := newServerWith(t, nil)
	ctx := context.Background()
	hash, _ := auth.HashPassword("a-strong-password")
	gone, _ := st.CreateUser(ctx, "gone", hash, auth.RoleViewer, store.Access{All: true})
	if err := st.SetDisabled(ctx, gone, true); err != nil {
		t.Fatal(err)
	}
	c := newClient(t, base)
	attempts := []struct{ username, password, detail string }{
		{"my-secret-passw0rd", "", "ip=127.0.0.1"},
		{"admin", "wrong-password", "ip=127.0.0.1 user=admin"},
		{"gone", "a-strong-password", "ip=127.0.0.1 user=gone"},
		{"Admin", "wrong-password", "ip=127.0.0.1"},
	}
	var first string
	for i, a := range attempts {
		code, body := c.postBody("/login", url.Values{"username": {a.username}, "password": {a.password}})
		if code != http.StatusUnauthorized {
			t.Fatalf("%s: %d", a.username, code)
		}
		if i == 0 {
			first = body
		} else if body != first {
			t.Errorf("the answer for %q differs from the one for an unknown name", a.username)
		}
	}
	audit, _ := st.ListAudit(ctx, 10)
	if len(audit) != len(attempts) {
		t.Fatalf("%d audit entries, want %d", len(audit), len(attempts))
	}
	for i, a := range attempts {
		e := audit[len(audit)-1-i]
		if e.Action != "login_failed" || e.Detail != a.detail {
			t.Errorf("attempt as %q audited as %s %q, want %q", a.username, e.Action, e.Detail, a.detail)
		}
	}
}

// An API token stops working while the account that created it is disabled,
// and works again once the account is enabled; the token list says why. A
// token without a known creator keeps working.
func TestTokenSuspendedWithItsCreator(t *testing.T) {
	st, base := newServerWith(t, nil)
	ctx := context.Background()
	hash, _ := auth.HashPassword("a-strong-password")
	alice, _ := st.CreateUser(ctx, "alice", hash, auth.RoleAdmin, store.Access{All: true})
	const secret, orphan = "vgl_alice-token", "vgl_orphan-token"
	if _, err := st.CreateAPIToken(ctx, store.APIToken{Name: "ci-alice", Project: "app"}, auth.HashToken(secret), alice); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateAPIToken(ctx, store.APIToken{Name: "ci-orphan", Project: "app"}, auth.HashToken(orphan), 0); err != nil {
		t.Fatal(err)
	}
	const bom = `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
		{"type":"library","name":"lodash","version":"4.17.15","purl":"pkg:npm/lodash@4.17.15"}]}`
	if code := putSBOM(t, base, "app", secret, bom); code != http.StatusOK {
		t.Fatalf("token of an active account: %d", code)
	}

	if err := st.SetDisabled(ctx, alice, true); err != nil {
		t.Fatal(err)
	}
	if code := putSBOM(t, base, "app", secret, bom); code != http.StatusUnauthorized {
		t.Errorf("token of a disabled account: %d", code)
	}
	if code := putSBOM(t, base, "app", orphan, bom); code != http.StatusOK {
		t.Errorf("token without a known creator: %d", code)
	}
	admin := loginAs(t, base, "admin", "a-strong-password")
	if _, body := admin.get("/settings/tokens"); !strings.Contains(body, "suspendu : le compte alice est désactivé") {
		t.Error("the token list does not show the token suspended")
	}

	if err := st.SetDisabled(ctx, alice, false); err != nil {
		t.Fatal(err)
	}
	if code := putSBOM(t, base, "app", secret, bom); code != http.StatusOK {
		t.Errorf("token after the account is enabled again: %d", code)
	}
}
