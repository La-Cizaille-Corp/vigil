package web

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/La-Cizaille-Corp/vigil/internal/auth"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
)

var menuLinkRe = regexp.MustCompile(`<li><a href="(/settings/[a-z]+)"( aria-current="page")?>`)

// menuOf returns the sub-pages a settings page offers in its menu, and the
// current one.
func menuOf(page string) (links []string, current string) {
	start := strings.Index(page, `<nav class="settings-nav"`)
	if start < 0 {
		return nil, ""
	}
	nav := page[start : start+strings.Index(page[start:], "</nav>")]
	for _, m := range menuLinkRe.FindAllStringSubmatch(nav, -1) {
		links = append(links, m[1])
		if m[2] != "" {
			current = m[1]
		}
	}
	return links, current
}

// The settings are sub-pages with a menu; each account sees only those its
// role opens, as the route table says, and lands on the first of them; the
// feeds in failure are counted in the menu (audit UX 8.1, A89).
func TestSettingsSubpages(t *testing.T) {
	st, base := newServerWith(t, nil)
	ctx := context.Background()
	addUser(t, st, "viewer", auth.RoleViewer)
	feed, err := st.CreateFeed(ctx, store.Feed{Name: "Avis", URL: "https://example.org/feed", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.RecordFeedFetch(ctx, feed, errors.New("HTTP 503")); err != nil {
		t.Fatal(err)
	}
	group, err := st.CreateGroup(ctx, "Équipe web")
	if err != nil {
		t.Fatal(err)
	}
	all := []string{"/settings/webhooks", "/settings/sla", "/settings/watch", "/settings/feeds", "/settings/users",
		"/settings/groups", "/settings/tokens", "/settings/audit"}
	for _, c := range []struct {
		user, home string
		links      []string
	}{
		{"admin", "/settings/webhooks", all},
		{"analyst", "/settings/watch", []string{"/settings/watch", "/settings/feeds"}},
		{"viewer", "/settings/watch", []string{"/settings/watch", "/settings/feeds"}},
	} {
		client := loginAs(t, base, c.user, testPassword)
		if code, to := client.send(http.MethodGet, "/settings", nil); code != http.StatusSeeOther || to != c.home {
			t.Errorf("%s: /settings leads to %d %q, want %s", c.user, code, to, c.home)
		}
		for _, path := range c.links {
			code, page := client.get(path)
			links, current := menuOf(page)
			if code != http.StatusOK || strings.Join(links, " ") != strings.Join(c.links, " ") || current != path {
				t.Errorf("%s on %s: %d, menu %v, current %q", c.user, path, code, links, current)
			}
			if !strings.Contains(page, `<span class="danger-link small">· 1 en échec</span>`) {
				t.Errorf("%s on %s: the feed in failure is not counted", c.user, path)
			}
		}
	}
	admin := loginAs(t, base, "admin", testPassword)
	if _, page := admin.get("/settings/groups/" + itoa(group)); func() string { _, cur := menuOf(page); return cur }() != "/settings/groups" {
		t.Error("the page of a group is not under Groupes in the menu")
	}
	if _, page := admin.get("/findings"); strings.Contains(page, "settings-nav") {
		t.Error("a page outside the settings shows their menu")
	}
}

// A settings form refused shows again as it was typed, its message in it,
// where the browser comes back to (#id at the end of its address); one
// accepted leads to the top of its page, or to the token it made (audit UX
// 8.2, A89).
func TestSettingsFormsKeepInput(t *testing.T) {
	_, base := newServerWith(t, nil)
	admin := loginAs(t, base, "admin", testPassword)
	csrf := admin.csrf()

	code, page := admin.postBody("/settings/webhooks", url.Values{"csrf": {csrf}, "name": {"Équipe sécurité"}, "kind": {"teams"},
		"url": {"http://example.org/hook"}, "alerts": {"severe"}})
	form := section(page, "nouveau-canal")
	for _, want := range []string{`<form method="post" action="/settings/webhooks#nouveau-canal" class="card">`,
		`<p class="error" role="alert">`, `name="name" value="Équipe sécurité"`, `<option value="teams" selected>`,
		`name="url" value="http://example.org/hook"`, `value="severe" checked>`} {
		if code != http.StatusBadRequest || !strings.Contains(form, want) {
			t.Errorf("channel refused (%d) misses %s", code, want)
		}
	}
	if strings.Contains(form, `name="digests" value="1" checked`) {
		t.Error("the digests unticked come back ticked")
	}

	code, page = admin.postBody("/settings/feeds", url.Values{"csrf": {csrf}, "name": {"Avis"}, "url": {"ftp://example.org/feed"},
		"country": {"FR"}})
	if code != http.StatusBadRequest || !strings.Contains(page, `<details class="card" id="nouveau-flux" open>`) ||
		!strings.Contains(page, `name="url" type="url" value="ftp://example.org/feed"`) || !strings.Contains(page, `value="FR" checked`) {
		t.Errorf("feed refused: %d", code)
	}

	code, page = admin.postBody("/settings/tokens", url.Values{"csrf": {csrf}, "name": {"ci"}, "project": {"a/b"}})
	if form := section(page, "nouveau-jeton"); code != http.StatusBadRequest || !strings.Contains(form, "Indiquez un nom et un projet") ||
		!strings.Contains(form, `name="name" value="ci"`) || !strings.Contains(form, `name="project" value="a/b"`) {
		t.Errorf("token refused: %d\n%s", code, form)
	}

	code, page = admin.postBody("/settings/sla", url.Values{"csrf": {csrf}, "critical": {"-3"}, "high": {"30"}, "medium": {"90"}, "low": {"180"}})
	if form := section(page, "delais"); code != http.StatusBadRequest || !strings.Contains(form, "Indiquez des délais") ||
		!strings.Contains(form, `name="critical" min="0" max="1000" value="-3"`) {
		t.Errorf("deadlines refused: %d\n%s", code, form)
	}

	if code, to := admin.send(http.MethodPost, "/settings/webhooks", url.Values{"csrf": {csrf}, "name": {"Équipe"}, "kind": {"generic"},
		"url": {"https://example.org/hook"}, "alerts": {"priority"}}); code != http.StatusSeeOther || to != "/settings/webhooks?msg=hook-created#contenu" {
		t.Errorf("channel added: %d %q", code, to)
	}
	if code, to := admin.send(http.MethodPost, "/settings/tokens", url.Values{"csrf": {csrf}, "name": {"ci"}, "project": {"app"}}); code != http.StatusSeeOther ||
		to != "/settings/tokens?msg=token-created#jeton" {
		t.Errorf("token created: %d %q", code, to)
	}
	if _, page := admin.get("/settings/tokens?msg=token-created"); !strings.Contains(page, `<div class="card" id="jeton">`) ||
		strings.Index(page, `id="jeton"`) > strings.Index(page, "<table") {
		t.Error("the token created is not shown first")
	}
}

// Deadlines that do not decrease from Basse to Critique are saved, and
// pointed out (audit UX 8.3, A89).
func TestSLAOrderWarning(t *testing.T) {
	_, base := newServerWith(t, nil)
	admin := loginAs(t, base, "admin", testPassword)
	const warning = "ne décroissent pas de Basse à Critique"
	if _, page := admin.get("/settings/sla"); strings.Contains(page, warning) {
		t.Error("the default deadlines are said not to decrease")
	}
	if code := admin.post("/settings/sla", url.Values{"csrf": {admin.csrf()}, "critical": {"15"}, "high": {"5"}, "medium": {"90"},
		"low": {"180"}}); code != http.StatusSeeOther {
		t.Fatalf("save: %d", code)
	}
	if _, page := admin.get("/settings/sla"); !strings.Contains(page, warning) || !strings.Contains(page, "critique 15 j,\n  haute 5 j") {
		t.Errorf("no warning:\n%s", page)
	}
}

// The key of a second factor is shown in groups of four characters (audit UX
// 8.4, A89).
func TestTOTPKeyInGroups(t *testing.T) {
	st, base := newServerWith(t, nil)
	c := loginAs(t, base, "analyst", testPassword)
	c.post("/account/totp/start", url.Values{"csrf": {c.csrf()}})
	u, _ := st.UserByName(context.Background(), "analyst")
	_, pending, _, err := st.UserTOTP(context.Background(), u.ID)
	if err != nil || len(pending) < 16 {
		t.Fatalf("pending key %q, %v", pending, err)
	}
	_, page := c.get("/account")
	if want := "<pre><code>" + keyGroups(pending) + "</code></pre>"; !strings.Contains(page, want) || !strings.Contains(want, pending[:4]+" "+pending[4:8]+" ") {
		t.Errorf("key not in groups of four: %s", want)
	}
	if got := keyGroups("ABCDEFGHIJ"); got != "ABCD EFGH IJ" {
		t.Errorf("keyGroups = %q", got)
	}
}
