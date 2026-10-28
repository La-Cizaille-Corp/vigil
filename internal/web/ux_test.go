package web

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/auth"
	"github.com/La-Cizaille-Corp/vigil/internal/inventory"
)

// postLocation posts a form and returns the status and redirect target.
func (c *client) postLocation(path string, form url.Values) (int, string) {
	resp, err := c.http.PostForm(c.base+path, form)
	if err != nil {
		c.t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode, resp.Header.Get("Location")
}

func loginAs(t *testing.T, base, username, password string) *client {
	t.Helper()
	c := newClient(t, base)
	if code := c.post("/login", url.Values{"username": {username}, "password": {password}}); code != http.StatusSeeOther {
		t.Fatalf("login %s: %d", username, code)
	}
	return c
}

func TestAssetAndSyncFlow(t *testing.T) {
	st, base := newTestServer(t)
	hash, _ := auth.HashPassword("a-strong-password")
	st.CreateUser(context.Background(), "admin", hash, auth.RoleAdmin)
	c := loginAs(t, base, "admin", "a-strong-password")

	// A new asset is tracked over the last 120 days by default.
	_, body := c.get("/assets/new")
	if want := `name="track_since" value="` + inventory.DefaultSince(time.Now()) + `"`; !strings.Contains(body, want) {
		t.Errorf("default tracked period missing: %s", want)
	}
	code, loc := c.postLocation("/assets", url.Values{"csrf": {c.csrf()}, "name": {"lodash"}, "kind": {"package"},
		"criticality": {"high"}, "purl": {"pkg:npm/lodash@4.17.15"}, "track_since": {"2026-01-01"}})
	if code != http.StatusSeeOther || !strings.HasPrefix(loc, "/assets/") || !strings.Contains(loc, "msg=asset-created") {
		t.Fatalf("create: %d %s", code, loc)
	}
	assets, _ := st.ListAssets(context.Background())
	if len(assets) != 1 || assets[0].TrackSince != "2026-01-01" {
		t.Fatalf("assets: %+v", assets)
	}
	if code, _ := c.postLocation("/assets", url.Values{"csrf": {c.csrf()}, "name": {"x"}, "kind": {"package"},
		"criticality": {"high"}, "track_since": {"hier"}}); code != http.StatusBadRequest {
		t.Errorf("invalid date accepted: %d", code)
	}

	// A sync returns to the page it was started from, never elsewhere.
	for next, want := range map[string]string{"/findings": "/findings?", "https://evil.example": "/?", "/assets": "/assets?"} {
		_, loc := c.postLocation("/sync", url.Values{"csrf": {c.csrf()}, "next": {next}})
		if !strings.HasPrefix(loc, want) {
			t.Errorf("sync from %s redirected to %s", next, loc)
		}
	}
}

func TestFeedTags(t *testing.T) {
	st, base := newTestServer(t)
	ctx := context.Background()
	hash, _ := auth.HashPassword("a-strong-password")
	st.CreateUser(ctx, "admin", hash, auth.RoleAdmin)
	c := loginAs(t, base, "admin", "a-strong-password")

	form := url.Values{"csrf": {c.csrf()}, "name": {"Test"}, "url": {"https://example.org/feed.xml"},
		"country": {"FR", "EU", "XX"}, "regulation": {"nis2", "cra"}}
	if code := c.post("/settings/feeds", form); code != http.StatusSeeOther {
		t.Fatalf("create feed: %d", code)
	}
	feeds, _ := st.ListFeeds(ctx)
	var id int64
	for _, f := range feeds {
		if f.Name == "Test" {
			id = f.ID
			if f.Country != "FR,EU" || f.Regulations != "nis2,cra" {
				t.Errorf("tags: %+v", f)
			}
		}
	}
	update := url.Values{"csrf": {c.csrf()}, "sector": {"energy"}}
	if code := c.post("/settings/feeds/"+strconv.FormatInt(id, 10), update); code != http.StatusSeeOther {
		t.Fatalf("update feed: %d", code)
	}
	feeds, _ = st.ListFeeds(ctx)
	for _, f := range feeds {
		if f.ID == id && (f.Country != "" || f.Sectors != "energy" || f.Regulations != "") {
			t.Errorf("updated tags: %+v", f)
		}
	}
}

func TestPasswordChange(t *testing.T) {
	st, base := newTestServer(t)
	hash, _ := auth.HashPassword("a-strong-password")
	st.CreateUser(context.Background(), "bob", hash, auth.RoleViewer)
	c := loginAs(t, base, "bob", "a-strong-password")
	other := loginAs(t, base, "bob", "a-strong-password")

	change := func(current, next, confirm string) int {
		return c.post("/account/password", url.Values{"csrf": {c.csrf()}, "current": {current}, "new": {next}, "confirm": {confirm}})
	}
	if code := change("wrong-password", "another-strong-one", "another-strong-one"); code != http.StatusBadRequest {
		t.Errorf("wrong current password: %d", code)
	}
	if code := change("a-strong-password", "another-strong-one", "different-one-here"); code != http.StatusBadRequest {
		t.Errorf("mismatch: %d", code)
	}
	if code := change("a-strong-password", "short", "short"); code != http.StatusBadRequest {
		t.Errorf("weak password: %d", code)
	}
	if code := change("a-strong-password", "another-strong-one", "another-strong-one"); code != http.StatusSeeOther {
		t.Fatalf("change: %d", code)
	}
	if code, _ := other.get("/account"); code != http.StatusSeeOther {
		t.Errorf("other session still valid: %d", code)
	}
	loginAs(t, base, "bob", "another-strong-one")
}
