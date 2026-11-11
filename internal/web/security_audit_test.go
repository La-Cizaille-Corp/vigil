package web

// Regression tests of the November 2026 code audit (findings S1, S2 and S8).

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/auth"
	"github.com/La-Cizaille-Corp/vigil/internal/cti"
	"github.com/La-Cizaille-Corp/vigil/internal/netsafe"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
)

// postAsync posts a form without calling t.Fatal, for use from goroutines.
func (c *client) postAsync(path string, form url.Values) (int, error) {
	req, err := http.NewRequest(http.MethodPost, c.base+path, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

// S1: a feed URL may carry an access key. The settings page masks the URL
// for non-administrators; a transport error quoted it whole, and it was
// stored, logged and shown to every role.
func TestFeedErrorKeepsTheURLSecret(t *testing.T) {
	st, base := newServerWith(t, nil)
	ctx := context.Background()
	const secret = "s3cr3t-feed-key"
	feeds, err := st.ListFeeds(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range feeds { // default feeds: no network in this test
		if err := st.SetFeedEnabled(ctx, f.ID, false); err != nil {
			t.Fatal(err)
		}
	}
	// 127.0.0.1 is refused by the SSRF guard: a transport error, as a DNS
	// failure, a timeout or a TLS error would be.
	if _, err := st.CreateFeed(ctx, store.Feed{Name: "Flux payant", URL: "https://127.0.0.1:9/rss?apikey=" + secret, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	col := &cti.Collector{Store: st, HTTP: netsafe.NewClient(5*time.Second, false), UserAgent: "test",
		Log: slog.New(slog.NewTextHandler(&logs, nil))}
	if _, err := col.Run(ctx); err != nil {
		t.Fatal(err)
	}
	feeds, _ = st.ListFeeds(ctx)
	for _, f := range feeds {
		if f.Name != "Flux payant" {
			continue
		}
		if f.LastError == "" || strings.Contains(f.LastError, secret) {
			t.Errorf("stored error: %q", f.LastError)
		}
	}
	if !strings.Contains(logs.String(), "flux CTI en erreur") || strings.Contains(logs.String(), secret) {
		t.Errorf("service log: %s", strings.TrimSpace(logs.String()))
	}

	hash, _ := auth.HashPassword("a-strong-password")
	if _, err := st.CreateUser(ctx, "viewer", hash, auth.RoleViewer); err != nil {
		t.Fatal(err)
	}
	viewer := loginAs(t, base, "viewer", "a-strong-password")
	if code, body := viewer.get("/settings"); code != http.StatusOK || strings.Contains(body, secret) {
		t.Errorf("settings as viewer: %d, secret shown: %v", code, strings.Contains(body, secret))
	}
}

// The audit names the signed-in user itself; a status change, a manual feed
// collection and a manual digest were not recorded.
func TestActionsAreAudited(t *testing.T) {
	st, base := newServerWith(t, func(s *Server) {
		s.CTI = &cti.Collector{Store: s.Store, HTTP: netsafe.NewClient(time.Second, false), UserAgent: "test", Log: s.Log}
	})
	ctx := context.Background()
	feeds, _ := st.ListFeeds(ctx)
	for _, f := range feeds { // no network in this test
		st.SetFeedEnabled(ctx, f.ID, false)
	}
	_, ids := seedFindings(t, st)
	c := loginAs(t, base, "analyst", "a-strong-password")
	for path, form := range map[string]url.Values{
		fmt.Sprintf("/findings/%d", ids[0]): {"status": {"false_positive"}, "comment": {"test"}},
		"/cti/refresh":                      {},
		"/digests":                          {},
	} {
		form.Set("csrf", c.csrf())
		if code := c.post(path, form); code != http.StatusSeeOther {
			t.Fatalf("%s: %d", path, code)
		}
	}
	entries, err := st.ListAudit(ctx, 50)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for _, e := range entries {
		seen[e.Action] = e.Username
	}
	for _, action := range []string{"finding_update", "cti_refresh", "digest_create", "login"} {
		if seen[action] != "analyst" {
			t.Errorf("%s: recorded for %q", action, seen[action])
		}
	}
}

// S8: « Collecter maintenant » clicked during a collection says that one is
// in progress, as the synchronisation does, instead of queueing another
// whole collection behind it.
func TestCTIRefreshRefusedWhileRunning(t *testing.T) {
	fetched, release := make(chan struct{}, 10), make(chan struct{})
	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetched <- struct{}{}
		<-release
		w.Write([]byte(`<rss><channel></channel></rss>`))
	}))
	t.Cleanup(feed.Close)
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock) // before the feed server closes
	var collector *cti.Collector
	st, base := newServerWith(t, func(s *Server) {
		collector = &cti.Collector{Store: s.Store, HTTP: feed.Client(), UserAgent: "test", Log: s.Log}
		s.CTI = collector
	})
	ctx := context.Background()
	feeds, _ := st.ListFeeds(ctx)
	for _, f := range feeds { // no network in this test
		st.SetFeedEnabled(ctx, f.ID, false)
	}
	if _, err := st.CreateFeed(ctx, store.Feed{Name: "x", URL: feed.URL, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	c := loginAs(t, base, "analyst", "a-strong-password")
	refresh := func() string {
		_, loc := c.postLocation("/cti/refresh", url.Values{"csrf": {c.csrf()}})
		return loc
	}

	if loc := refresh(); loc != "/cti?msg=cti-started" {
		t.Fatalf("first click: %q", loc)
	}
	select {
	case <-fetched:
	case <-time.After(10 * time.Second):
		t.Fatal("the collection did not start")
	}
	if loc := refresh(); loc != "/cti?msg=cti-running" {
		t.Errorf("second click during the collection: %q, want cti-running", loc)
	}
	if _, page := c.get("/cti?msg=cti-running"); !strings.Contains(page, "Une collecte des flux est déjà en cours") {
		t.Error("no message on the page")
	}
	unblock()
	for deadline := time.Now().Add(10 * time.Second); collector.Running() && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	entries, err := st.ListAudit(ctx, 50)
	if err != nil {
		t.Fatal(err)
	}
	refreshes := 0
	for _, e := range entries {
		if e.Action == "cti_refresh" {
			refreshes++
		}
	}
	if refreshes != 1 || len(fetched) != 0 {
		t.Errorf("%d collections audited, %d more fetched; want the one that ran", refreshes, len(fetched))
	}
}

// S2: the account forms counted a failure after the slow check, so parallel
// requests all got through. Each attempt is now counted before it.
func TestAccountLimitersHoldInParallel(t *testing.T) {
	st, base := newServerWith(t, nil)
	ctx := context.Background()
	c := loginAs(t, base, "analyst", "a-strong-password")
	token := c.csrf()
	parallel := func(n int, path string, form func(i int) url.Values) (checked int) {
		codes := make([]int, n)
		var wg sync.WaitGroup
		for i := range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				code, err := c.postAsync(path, form(i))
				if err != nil {
					t.Error(err)
				}
				codes[i] = code
			}()
		}
		wg.Wait()
		for _, code := range codes {
			if code != http.StatusTooManyRequests {
				checked++
			}
		}
		return checked
	}

	if n := parallel(24, "/account/password", func(i int) url.Values {
		return url.Values{"csrf": {token}, "current": {fmt.Sprintf("wrong-guess-%02d", i)},
			"new": {"another-strong-password"}, "confirm": {"another-strong-password"}}
	}); n > 5 {
		t.Errorf("%d password guesses checked in parallel, the limit is 5", n)
	}

	user, err := st.UserByName(ctx, "analyst")
	if err != nil {
		t.Fatal(err)
	}
	secret, _ := auth.NewTOTPSecret()
	st.SetTOTPPending(ctx, user.ID, secret)
	st.EnableTOTP(ctx, user.ID, 0)
	if n := parallel(40, "/account/totp/disable", func(i int) url.Values {
		return url.Values{"csrf": {token}, "code": {fmt.Sprintf("%06d", 100000+i)}}
	}); n > 5 {
		t.Errorf("%d second-factor codes checked in parallel, the limit is 5", n)
	}

	// A right current password with a mistyped confirmation is no guess.
	other := loginAs(t, base, "admin", "a-strong-password")
	for range 6 {
		code, err := other.postAsync("/account/password", url.Values{"csrf": {other.csrf()}, "current": {"a-strong-password"},
			"new": {"another-strong-password"}, "confirm": {"a-typo"}})
		if err != nil || code != http.StatusBadRequest {
			t.Fatalf("mistyped confirmation: %d, %v", code, err)
		}
	}
}
