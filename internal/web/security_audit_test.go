package web

// Regression tests of the November 2026 code audit (findings S1 and S2).

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
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
