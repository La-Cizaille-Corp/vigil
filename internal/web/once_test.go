package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// R10 (November 2026 code audit): every value shown once shared one slot per
// session. /settings, looking for a new API token, took a temporary password
// created just before, and so did a settings form refused with an error: the
// password was lost without being shown. The users page took a new token the
// same way. Each value now waits for its own page, and is shown there once.
func TestOnceValueWaitsForItsPage(t *testing.T) {
	_, base := newServerWith(t, nil)
	admin := loginAs(t, base, "admin", "a-strong-password")
	token := admin.csrf()

	if code := admin.post("/settings/users", url.Values{"csrf": {token}, "username": {"bob"}, "role": {"analyst"}, "access": {"all"}}); code != http.StatusSeeOther {
		t.Fatalf("create user: %d", code)
	}
	if _, body := admin.get("/settings"); passwordRe.MatchString(body) {
		t.Error("temporary password shown by /settings")
	}
	if code, body := admin.postBody("/settings/tokens", url.Values{"csrf": {token}, "name": {""}, "project": {"app"}}); code != http.StatusBadRequest ||
		passwordRe.MatchString(body) {
		t.Errorf("refused token form: %d", code)
	}
	if _, body := admin.get("/settings/users"); !passwordRe.MatchString(body) {
		t.Fatal("temporary password lost after /settings")
	}
	if _, body := admin.get("/settings/users"); passwordRe.MatchString(body) {
		t.Error("temporary password shown twice")
	}

	if code := admin.post("/settings/tokens", url.Values{"csrf": {token}, "name": {"ci"}, "project": {"app"}}); code != http.StatusSeeOther {
		t.Fatalf("create token: %d", code)
	}
	if _, body := admin.get("/settings/users"); strings.Contains(body, tokenPrefix) {
		t.Error("API token shown by /settings/users")
	}
	if _, body := admin.get("/settings"); !strings.Contains(body, "<pre><code>"+tokenPrefix) {
		t.Fatal("API token lost after /settings/users")
	}
	if _, body := admin.get("/settings"); strings.Contains(body, tokenPrefix) {
		t.Error("API token shown twice")
	}
}
