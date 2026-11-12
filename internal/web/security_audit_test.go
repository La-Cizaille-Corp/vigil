package web

// Regression tests of the November 2026 code audit (findings S1, S2, S6, S8 and S9).

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
	if !strings.Contains(logs.String(), "cti feed failed") || strings.Contains(logs.String(), secret) {
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

// S9: the VEX import matches through an index and writes in one transaction;
// what it applies, skips and ignores is unchanged. It passed on the code
// before the change too.
func TestVEXImportResults(t *testing.T) {
	st, base := newServerWith(t, nil)
	ctx := context.Background()
	const lodash, fortios = "pkg:npm/lodash@4.17.15", "cpe:2.3:o:fortinet:fortios:7.2.4:*:*:*:*:*:*:*"
	lib, _ := st.CreateAsset(ctx, store.Everything, store.Asset{Name: "lodash", Kind: "package", Criticality: "high", Source: "manual", PURL: lodash})
	fw, _ := st.CreateAsset(ctx, store.Everything, store.Asset{Name: "fortios", Version: "7.2.4", Kind: "os", Criticality: "high", Source: "manual", CPE: fortios})
	for _, v := range []struct {
		asset int64
		vuln  store.Vulnerability
	}{
		{lib, store.Vulnerability{ID: "GHSA-35jh-r3h4-6jhm", Aliases: []string{"CVE-2021-23337"}, Severity: "HIGH", Modified: "m"}},
		{lib, store.Vulnerability{ID: "CVE-2020-8203", Severity: "HIGH", Modified: "m"}},
		{fw, store.Vulnerability{ID: "CVE-2024-21762", Severity: "CRITICAL", Modified: "m"}},
	} {
		st.UpsertVulnerability(ctx, v.vuln)
		st.ObserveFinding(ctx, v.asset, v.vuln.ID, "", time.Now())
	}
	finding := func(asset int64, vuln string) store.Finding {
		t.Helper()
		list, _ := st.ListFindings(ctx, store.Everything, store.FindingFilter{AssetID: asset})
		for _, f := range list {
			if f.VulnID == vuln {
				return f
			}
		}
		t.Fatalf("no finding %s", vuln)
		return store.Finding{}
	}
	st.SetFindingStatus(ctx, store.Everything, finding(lib, "CVE-2020-8203").ID, 0, "exploitable", "", "à patcher")

	statement := func(id, ref, state, justification, detail string) string {
		return fmt.Sprintf(`{"id":%q,"analysis":{"state":%q,"justification":%q,"detail":%q},"affects":[{"ref":%q}]}`,
			id, state, justification, detail, ref)
	}
	doc := `{"bomFormat":"CycloneDX","specVersion":"1.5","vulnerabilities":[` + strings.Join([]string{
		statement("CVE-2021-23337", lodash, "not_affected", "code_not_reachable", "fonction non utilisée"), // through the alias
		statement("CVE-2020-8203", lodash, "exploitable", "", "déjà décidé"),                               // same decision: skipped
		statement("CVE-2024-21762", fortios, "resolved", "", "mis à jour"),                                 // by CPE
		statement("CVE-2024-21762", fortios, "false_positive", "", "finalement"),                           // then again, in order
		statement("CVE-1999-0001", lodash, "resolved", "", ""),                                             // unknown vulnerability
		statement("CVE-2020-8203", "pkg:npm/other@1.0.0", "resolved", "", ""),                              // other component
		statement("CVE-2020-8203", lodash, "not_affected", "", "sans justification"),                       // refused
	}, ",") + `]}`
	c := loginAs(t, base, "analyst", "a-strong-password")
	if code, loc := c.upload("/findings/vex", "vex", "vex.json", doc, url.Values{"csrf": {c.csrf()}}); code != http.StatusSeeOther ||
		loc != "/findings?msg=vex-imported" {
		t.Fatalf("import: %d %s", code, loc)
	}

	if f := finding(lib, "GHSA-35jh-r3h4-6jhm"); f.Status != "not_affected" || f.Justification != "code_not_reachable" ||
		f.Comment != "Import VEX : fonction non utilisée" {
		t.Errorf("by alias: %s %s %q", f.Status, f.Justification, f.Comment)
	}
	if f := finding(lib, "CVE-2020-8203"); f.Status != "exploitable" || f.Comment != "à patcher" {
		t.Errorf("unchanged decision: %s %q", f.Status, f.Comment)
	}
	f := finding(fw, "CVE-2024-21762")
	events, _ := st.FindingEvents(ctx, store.Everything, f.ID)
	if f.Status != "false_positive" || f.Comment != "Import VEX : finalement" || len(events) != 2 ||
		events[0].NewStatus != "resolved" || events[1].NewStatus != "false_positive" || events[1].Username != "analyst" {
		t.Errorf("two analyses in order: %s %q, history %+v", f.Status, f.Comment, events)
	}
	entries, _ := st.ListAudit(ctx, 10)
	if len(entries) == 0 || entries[0].Action != "vex_import" || entries[0].Detail != "3 appliquées, 3 ignorées" {
		t.Errorf("audit: %+v", entries)
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

// S6: filter values were checked but not de-duplicated, and each one adds a
// LIKE to the query: from 1,001 repeats SQLite refused the expression and
// every reader of the news page got a 500, from a crafted URL or, lastingly,
// from a watch saved with repeated values.
func TestRepeatedFilterValues(t *testing.T) {
	st, base := newServerWith(t, nil)
	c := loginAs(t, base, "analyst", "a-strong-password")
	repeated := strings.Repeat("country=FR&", 1001)
	if code, _ := c.get("/cti?" + repeated); code != http.StatusOK {
		t.Errorf("/cti with 1,001 identical countries: %d", code)
	}

	form, err := url.ParseQuery(repeated)
	if err != nil {
		t.Fatal(err)
	}
	form.Set("csrf", c.csrf())
	if code := c.post("/settings/watch", form); code != http.StatusSeeOther {
		t.Fatalf("save watch: %d", code)
	}
	if saved, _ := st.Setting(context.Background(), cti.SettingCountries); saved != "FR" {
		t.Errorf("watched countries stored as %.40q", saved)
	}
	if code, _ := c.get("/cti"); code != http.StatusOK {
		t.Errorf("/cti on the saved watch: %d", code)
	}

	f := findingFilterFrom(url.Values{"status": {"in_triage", "in_triage", "bogus"}, "kind": {"os", "os"}})
	if len(f.Statuses) != 1 || len(f.Kinds) != 1 {
		t.Errorf("finding filter kept duplicates: %v %v", f.Statuses, f.Kinds)
	}
}
