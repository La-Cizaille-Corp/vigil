package web

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/notify"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
)

// C13 of the 0.5.0 review: the new tags of a feed and their application to
// its items are one transaction. A failure on the last item used to leave the
// feed and its first items tagged, the others not.
func TestFeedUpdateIsAllOrNothing(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "web.db")
	st, base := newServerIn(t, path, nil)
	admin := loginAs(t, base, "admin", "a-strong-password")
	feed, err := st.CreateFeed(ctx, store.Feed{Name: "Avis", URL: "https://example.org/feed", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		if _, err := st.InsertCTIItem(ctx, feed, store.CTIItem{GUID: strconv.Itoa(i), Title: fmt.Sprintf("Avis %d", i),
			Link: fmt.Sprintf("https://example.org/%d", i), Published: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	breakDB(t, path, `CREATE TRIGGER no_retag BEFORE UPDATE OF sectors ON cti_items
		WHEN NEW.id = (SELECT max(id) FROM cti_items) BEGIN SELECT RAISE(ABORT, 'disk on fire'); END`)
	code := admin.post("/settings/feeds/"+strconv.FormatInt(feed, 10), url.Values{"csrf": {admin.csrf()}, "sector": {"energy"}})
	if code != http.StatusInternalServerError {
		t.Errorf("failed retag: %d", code)
	}
	if f, _ := st.Feed(ctx, feed); f.Sectors != "" {
		t.Errorf("feed tagged %q although its items could not be", f.Sectors)
	}
	items, _ := st.ListCTIItems(ctx, store.Everything, store.CTIFilter{Sectors: []string{"energy"}})
	if len(items) != 0 {
		t.Errorf("%d items tagged energy, want none", len(items))
	}
}

// W8 and C5 of the 0.5.0 review: a digest is said sent when a channel
// received it. A channel of alerts only used to make it « envoyé aux canaux
// de notification » although none had received it.
func TestDigestSaidSentOnlyWhenReceived(t *testing.T) {
	ctx := context.Background()
	hook := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer hook.Close()
	path := filepath.Join(t.TempDir(), "web.db")
	st, base := newServerIn(t, path, func(s *Server) {
		s.Notifier = &notify.Notifier{Store: s.Store, HTTP: hook.Client(), Log: s.Log}
	})
	c := loginAs(t, base, "analyst", "a-strong-password")
	generate := func() string {
		t.Helper()
		code, loc := c.postLocation("/digests", url.Values{"csrf": {c.csrf()}})
		if code != http.StatusSeeOther {
			t.Fatalf("digest: %d", code)
		}
		return loc
	}
	if _, err := st.CreateWebhook(ctx, store.Webhook{Name: "alertes", Kind: "slack", URL: hook.URL + "/alertes",
		Enabled: true, Alerts: "severe"}); err != nil {
		t.Fatal(err)
	}
	if loc := generate(); !strings.Contains(loc, "msg=digest-created") {
		t.Errorf("with a channel of alerts only: %s, want digest-created", loc)
	}
	if _, err := st.CreateWebhook(ctx, store.Webhook{Name: "digests", Kind: "slack", URL: hook.URL + "/digests",
		Enabled: true, Digests: true}); err != nil {
		t.Fatal(err)
	}
	if loc := generate(); !strings.Contains(loc, "msg=digest-sent") {
		t.Errorf("with a channel of digests: %s, want digest-sent", loc)
	}
}
