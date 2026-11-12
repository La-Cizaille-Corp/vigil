package web

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- RFC 6238 TOTP, as authenticator apps compute it
	"database/sql"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"go/ast"
	"go/token"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/auth"
	"github.com/La-Cizaille-Corp/vigil/internal/cti"
	"github.com/La-Cizaille-Corp/vigil/internal/netsafe"
	"github.com/La-Cizaille-Corp/vigil/internal/notify"
	"github.com/La-Cizaille-Corp/vigil/internal/store"

	_ "modernc.org/sqlite" // to break the test database from outside the store
)

// breakDB runs statements on the database at path through a connection of
// its own, as another process would: a trigger that fails a write, a table
// renamed away.
func breakDB(t *testing.T, path string, statements ...string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, q := range statements {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
}

// totpCodeAt is the code an authenticator shows for a secret at a time step
// (RFC 6238).
func totpCodeAt(t *testing.T, secret string, step int64) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step)) // #nosec G115 -- steps are positive
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[off:off+4])&0x7fffffff)%1_000_000)
}

// syncBuffer is a log destination that the handlers may write to while the
// test reads it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// R7: only a feed whose URL is already known is « déjà existant »; any other
// failure of the database is an internal error, not a duplicate.
func TestFeedCreateTellsDuplicateFromFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "web.db")
	_, base := newServerIn(t, path, nil)
	admin := loginAs(t, base, "admin", "a-strong-password")
	feed := func(name, u string) url.Values {
		return url.Values{"csrf": {admin.csrf()}, "name": {name}, "url": {u}}
	}
	if code := admin.post("/settings/feeds", feed("Avis", "https://example.org/feed")); code != http.StatusSeeOther {
		t.Fatalf("first feed: %d", code)
	}
	if code, body := admin.postBody("/settings/feeds", feed("Autre nom", "https://example.org/feed")); code != http.StatusBadRequest ||
		!strings.Contains(body, "Ce flux existe déjà") {
		t.Errorf("same URL again: %d, « existe déjà » shown: %v", code, strings.Contains(body, "Ce flux existe déjà"))
	}
	// A failed constraint that is not uniqueness: the write itself fails.
	breakDB(t, path, `CREATE TRIGGER no_feed BEFORE INSERT ON cti_feeds BEGIN SELECT RAISE(ABORT, 'disk on fire'); END`)
	if code, body := admin.postBody("/settings/feeds", feed("Nouveau", "https://example.net/feed")); code != http.StatusInternalServerError ||
		strings.Contains(body, "existe déjà") {
		t.Errorf("failed write: %d, « existe déjà » shown: %v", code, strings.Contains(body, "existe déjà"))
	}
}

// R7: when the channels cannot be read, the digest is not said to be done
// (it was, without being sent to anyone).
func TestDigestNotSaidDoneWhenChannelsFail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "web.db")
	st, base := newServerIn(t, path, nil)
	c := loginAs(t, base, "analyst", "a-strong-password")
	breakDB(t, path, `ALTER TABLE webhooks RENAME TO webhooks_lost`)
	code, loc := c.postLocation("/digests", url.Values{"csrf": {c.csrf()}})
	if code != http.StatusInternalServerError || strings.Contains(loc, "digest-created") {
		t.Errorf("channels unreadable: %d %q, want an error", code, loc)
	}
	if list, err := st.ListDigests(context.Background(), store.Everything); err != nil || len(list) != 0 {
		t.Errorf("digests: %d %v, want none", len(list), err)
	}
}

// R7: a change of the second factor is made even when the other sessions
// cannot be closed: the failure is logged, the change is not reported as
// failed (it was a 500 for the second factor, a warning for the password).
func TestEndOtherSessionsDoesNotFailTheChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "web.db")
	logs := &syncBuffer{}
	st, base := newServerIn(t, path, func(s *Server) { s.Log = slog.New(slog.NewTextHandler(logs, nil)) })
	ctx := context.Background()
	c := loginAs(t, base, "analyst", "a-strong-password")
	loginAs(t, base, "analyst", "a-strong-password") // another browser
	c.post("/account/totp/start", url.Values{"csrf": {c.csrf()}})
	u, _ := st.UserByName(ctx, "analyst")
	_, pending, _, err := st.UserTOTP(ctx, u.ID)
	if err != nil || pending == "" {
		t.Fatalf("enrolment not started: %v", err)
	}
	breakDB(t, path, `CREATE TRIGGER keep_sessions BEFORE DELETE ON sessions BEGIN SELECT RAISE(ABORT, 'sessions locked'); END`)
	code, loc := c.postLocation("/account/totp/confirm", url.Values{"csrf": {c.csrf()}, "password": {"a-strong-password"},
		"code": {totpCodeAt(t, pending, time.Now().Unix()/30)}})
	if code != http.StatusSeeOther || loc != "/account?msg=totp-enabled" {
		t.Errorf("second factor enabled: %d %q", code, loc)
	}
	if active, _, _, _ := st.UserTOTP(ctx, u.ID); active != pending {
		t.Error("second factor not enabled")
	}
	if !strings.Contains(logs.String(), "end other sessions") {
		t.Errorf("failure not logged:\n%s", logs.String())
	}
}

// R5: a redirection to an address that has a query string adds its message
// to it, instead of a second « ? » that left the message in the last value.
func TestRedirectKeepsTheQuery(t *testing.T) {
	for _, c := range []struct{ path, msg, want string }{
		{"/assets", "asset-deleted", "/assets?msg=asset-deleted"},
		{"/assets?project=app+web", "sbom-imported", "/assets?project=app+web&msg=sbom-imported"},
		{"/findings?severity=HIGH", "", "/findings?severity=HIGH"},
	} {
		w := httptest.NewRecorder()
		redirect(w, httptest.NewRequest(http.MethodPost, "/", nil), c.path, c.msg)
		if got := w.Header().Get("Location"); w.Code != http.StatusSeeOther || got != c.want {
			t.Errorf("redirect(%q, %q): %d %q, want %q", c.path, c.msg, w.Code, got, c.want)
		}
	}

	st, base := newServerWith(t, nil)
	seedFindings(t, st)
	c := loginAs(t, base, "analyst", "a-strong-password")
	bom := `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
		{"type":"library","name":"lodash","version":"4.17.15","purl":"pkg:npm/lodash@4.17.15"}]}`
	code, loc := c.upload("/assets/import", "sbom", "bom.json", bom, url.Values{"csrf": {c.csrf()}, "project": {"app web"}})
	if code != http.StatusSeeOther || loc != "/assets?project=app+web&msg=sbom-imported" {
		t.Fatalf("SBOM import: %d %q", code, loc)
	}
	if _, body := c.get(loc); !strings.Contains(body, "SBOM importé") || !strings.Contains(body, "lodash") || strings.Contains(body, "fortios") {
		t.Error("the page after an SBOM import misses its message or its project")
	}
	// A message already in the list's address is not repeated in the next one.
	_, body := c.get("/findings?severity=HIGH&msg=vex-imported")
	if !strings.Contains(body, `name="next" value="/findings?severity=HIGH"`) {
		t.Error("the return address of the bulk form keeps the previous message")
	}
}

// R1: an identifier that is not a number, or that no object bears, is « not
// found » on every route that reads one from its path.
func TestUnknownIdentifiersAreNotFound(t *testing.T) {
	_, base := newServerWith(t, nil)
	admin := loginAs(t, base, "admin", "a-strong-password")
	token := admin.csrf()
	for _, path := range []string{"/assets/abc", "/assets/999", "/findings/999", "/digests/abc", "/digests/999/markdown"} {
		if code, _ := admin.get(path); code != http.StatusNotFound {
			t.Errorf("GET %s: %d", path, code)
		}
	}
	for _, path := range []string{"/assets/999/scan", "/assets/999/dismissals/1/delete", "/findings/abc",
		"/settings/feeds/999", "/settings/feeds/abc/toggle", "/settings/feeds/999/delete",
		"/settings/webhooks/999", "/settings/webhooks/999/test", "/settings/webhooks/abc/delete",
		"/settings/tokens/999/delete", "/settings/users/abc/disable", "/settings/users/999/role"} {
		if code := admin.post(path, url.Values{"csrf": {token}, "role": {"viewer"}}); code != http.StatusNotFound {
			t.Errorf("POST %s: %d", path, code)
		}
	}
}

// R12: every audit call passes key-value pairs (see store.AuditDetail): an
// odd count would write a key without its value.
func TestAuditCallsPassPairs(t *testing.T) {
	for name, f := range webSources(t) {
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "audit" && sel.Sel.Name != "auditAs" || call.Ellipsis != token.NoPos {
				return true
			}
			pairs := len(call.Args) - 2 // r and the action
			if sel.Sel.Name == "auditAs" {
				pairs-- // and the user
			}
			if pairs%2 != 0 {
				t.Errorf("%s: %s called with %d arguments after the action, not pairs", name, sel.Sel.Name, pairs)
			}
			return true
		})
	}
}

// R12: the detail of each action of the UI is written in the one format of
// store.AuditDetail.
func TestAuditDetailOfEachAction(t *testing.T) {
	hook := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer hook.Close()
	st, base := newServerWith(t, func(s *Server) {
		s.Notifier = &notify.Notifier{Store: s.Store, HTTP: hook.Client(), Log: s.Log}
		s.CTI = &cti.Collector{Store: s.Store, HTTP: netsafe.NewClient(time.Second, false), UserAgent: "test", Log: s.Log}
	})
	ctx := context.Background()
	feeds, _ := st.ListFeeds(ctx)
	for _, f := range feeds { // no network in this test
		if err := st.SetFeedEnabled(ctx, f.ID, false); err != nil {
			t.Fatal(err)
		}
	}
	want := func(st *store.Store, action, detail string) {
		t.Helper()
		entries, err := st.ListAudit(ctx, 500)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if e.Action == action {
				if e.Detail != detail {
					t.Errorf("%s: %q, want %q", action, e.Detail, detail)
				}
				return
			}
		}
		t.Errorf("%s not audited", action)
	}
	id := func(loc string) string { // of the object a redirection goes to
		path, _, _ := strings.Cut(loc, "?")
		return path[strings.LastIndex(path, "/")+1:]
	}
	post := func(c *client, path string, form url.Values) string {
		t.Helper()
		form.Set("csrf", c.csrf())
		code, loc := c.postLocation(path, form)
		if code != http.StatusSeeOther {
			t.Fatalf("%s: %d", path, code)
		}
		return loc
	}

	newClient(t, base).post("/login", url.Values{"username": {"admin"}, "password": {"wrong-password"}})
	want(st, "login_failed", "ip=127.0.0.1 user=admin")
	admin := loginAs(t, base, "admin", "a-strong-password")
	want(st, "login", "ip=127.0.0.1")
	analyst := loginAs(t, base, "analyst", "a-strong-password")

	// Inventory and triage.
	asset := id(post(analyst, "/assets", url.Values{"name": {"lodash"}, "version": {"4.17.21"}, "kind": {"package"}, "criticality": {"high"}}))
	want(st, "asset_create", "id="+asset)
	post(analyst, "/assets/"+asset, url.Values{"name": {"lodash"}, "version": {"4.17.21"}, "kind": {"package"}, "criticality": {"low"}})
	want(st, "asset_update", "id="+asset)
	post(analyst, "/assets/"+asset+"/full-history", url.Values{})
	want(st, "asset_update", "id="+asset+" full_history=true")
	post(analyst, "/assets/"+asset+"/scan", url.Values{})
	want(st, "asset_scan", "id="+asset)
	post(analyst, "/assets/"+asset+"/dismissals", url.Values{"text": {"wifi: driver"}})
	want(st, "dismissal_create", "asset="+asset+` text="wifi: driver"`)
	assetID, _ := strconv.ParseInt(asset, 10, 64)
	rules, _ := st.ListDismissalRules(ctx, store.Everything, assetID)
	if len(rules) != 1 {
		t.Fatalf("rules: %+v", rules)
	}
	rule := strconv.FormatInt(rules[0].ID, 10)
	post(analyst, "/assets/"+asset+"/dismissals/"+rule+"/delete", url.Values{})
	want(st, "dismissal_delete", "id="+rule+" asset="+asset)
	post(analyst, "/assets/"+asset+"/delete", url.Values{})
	want(st, "asset_delete", "id="+asset+` asset="lodash 4.17.21"`)

	_, findings := seedFindings(t, st)
	finding := strconv.FormatInt(findings[0], 10)
	post(analyst, "/findings/"+finding, url.Values{"status": {"false_positive"}, "comment": {"test"}})
	want(st, "finding_update", "id="+finding+" status=false_positive")
	post(analyst, "/findings/bulk", url.Values{"status": {"exploitable"}, "next": {"/findings"},
		"id": {strconv.FormatInt(findings[1], 10), strconv.FormatInt(findings[2], 10)}})
	want(st, "finding_bulk", "count=2 status=exploitable")
	post(analyst, "/sync", url.Values{})
	want(st, "sync", "trigger=manual")
	digest := id(post(analyst, "/digests", url.Values{}))
	want(st, "digest_create", "id="+digest)
	post(analyst, "/cti/refresh", url.Values{})
	want(st, "cti_refresh", "trigger=manual")
	post(analyst, "/settings/watch", url.Values{"country": {"FR", "XX"}, "sector": {"health"}})
	want(st, "watch_update", `countries=FR sectors=health regulations=""`)
	bom := `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
		{"type":"library","name":"lodash","version":"4.17.15","purl":"pkg:npm/lodash@4.17.15"}]}`
	if code, _ := analyst.upload("/assets/import", "sbom", "bom.json", bom, url.Values{"csrf": {analyst.csrf()}, "project": {"app"}}); code != http.StatusSeeOther {
		t.Fatalf("SBOM import: %d", code)
	}
	want(st, "sbom_import", "project=app format=CycloneDX added=1 kept=0 removed=0 skipped=0")
	if code, _ := analyst.upload("/assets/import-csv", "csv", "inventaire.csv", "nom;type\nExchange;Produit\n",
		url.Values{"csrf": {analyst.csrf()}}); code != http.StatusSeeOther {
		t.Fatalf("CSV import: %d", code)
	}
	want(st, "csv_import", "added=1 skipped=0")

	// Account.
	post(analyst, "/account/sessions/close-others", url.Values{})
	want(st, "sessions_close", "")
	post(analyst, "/account/password", url.Values{"current": {"a-strong-password"}, "new": {"another-strong-pass"}, "confirm": {"another-strong-pass"}})
	want(st, "password_change", "")
	post(analyst, "/account/totp/start", url.Values{})
	u, _ := st.UserByName(ctx, "analyst")
	_, pending, _, _ := st.UserTOTP(ctx, u.ID)
	step := time.Now().Unix() / 30
	post(analyst, "/account/totp/confirm", url.Values{"password": {"another-strong-pass"}, "code": {totpCodeAt(t, pending, step)}})
	want(st, "totp_enable", "")
	post(analyst, "/account/totp/disable", url.Values{"code": {totpCodeAt(t, pending, step+1)}})
	want(st, "totp_disable", "")

	// Settings.
	post(admin, "/settings/feeds", url.Values{"name": {"CERT FR"}, "url": {"https://example.org/rss?key=SECRET"}})
	feed := ""
	feedList, _ := st.ListFeeds(ctx)
	for _, f := range feedList {
		if f.Name == "CERT FR" {
			feed = strconv.FormatInt(f.ID, 10)
		}
	}
	want(st, "feed_create", "id="+feed+` name="CERT FR" url=https://example.org/…`)
	post(admin, "/settings/feeds/"+feed, url.Values{"country": {"FR"}})
	want(st, "feed_update", "id="+feed+` name="CERT FR" url=https://example.org/…`)
	post(admin, "/settings/feeds/"+feed+"/toggle", url.Values{"enabled": {"0"}})
	want(st, "feed_toggle", "id="+feed+" enabled=false")
	post(admin, "/settings/feeds/"+feed+"/delete", url.Values{})
	want(st, "feed_delete", "id="+feed)
	post(admin, "/settings/news", url.Values{"per_day": {"2"}})
	want(st, "news_frequency", "per_day=2")
	post(admin, "/settings/sla", url.Values{"critical": {"15"}, "high": {"10"}, "medium": {"90"}, "low": {"0"}})
	want(st, "sla_update", "critical=15 high=10 medium=90 low=0")

	post(admin, "/settings/webhooks", url.Values{"name": {"Équipe sécu"}, "kind": {"slack"},
		"url": {"https://hooks.slack.com/services/T/B/SECRET"}, "alerts": {"priority"}})
	hooks, _ := st.ListWebhooks(ctx)
	if len(hooks) != 1 {
		t.Fatalf("channels: %+v", hooks)
	}
	created := strconv.FormatInt(hooks[0].ID, 10)
	want(st, "webhook_create", "id="+created+" target=https://hooks.slack.com/…")
	post(admin, "/settings/webhooks/"+created, url.Values{"alerts": {""}})
	want(st, "webhook_delivery", "id="+created+` digests=false alerts=""`)
	post(admin, "/settings/webhooks/"+created+"/toggle", url.Values{"enabled": {"0"}})
	want(st, "webhook_toggle", "id="+created+" enabled=false")
	post(admin, "/settings/webhooks/"+created+"/delete", url.Values{})
	want(st, "webhook_delete", "id="+created)
	h := store.Webhook{Name: "Test", Kind: "teams", URL: hook.URL + "/SECRET", Enabled: true}
	tested, err := st.CreateWebhook(ctx, h)
	if err != nil {
		t.Fatal(err)
	}
	post(admin, "/settings/webhooks/"+strconv.FormatInt(tested, 10)+"/test", url.Values{})
	want(st, "webhook_test", fmt.Sprintf("id=%d target=%s sent=true", tested, notify.Target(h)))

	post(admin, "/settings/tokens", url.Values{"name": {"ci build"}, "project": {"app"}})
	tokens, _ := st.ListAPITokens(ctx)
	if len(tokens) != 1 {
		t.Fatalf("tokens: %+v", tokens)
	}
	tok := strconv.FormatInt(tokens[0].ID, 10)
	want(st, "api_token_create", "id="+tok+` name="ci build" project=app`)
	post(admin, "/settings/tokens/"+tok+"/delete", url.Values{})
	want(st, "api_token_delete", "id="+tok)
	secret := "vgl_audit-test-secret"
	if _, err := st.CreateAPIToken(ctx, store.APIToken{Name: "ci", Project: "app"}, auth.HashToken(secret), 0); err != nil {
		t.Fatal(err)
	}
	if code := putSBOM(t, base, "app", secret, bom); code != http.StatusOK {
		t.Fatalf("SBOM by the API: %d", code)
	}
	want(st, "sbom_import_api", "project=app token=ci format=CycloneDX added=0 kept=1 removed=0 skipped=0")

	// Users.
	post(admin, "/settings/users", url.Values{"username": {"bob"}, "role": {"analyst"}, "access": {"all"}})
	bob, _ := st.AnyUserByName(ctx, "bob")
	user := strconv.FormatInt(bob.ID, 10)
	want(st, "user_create", "id="+user+" user=bob role=analyst access=all")
	post(admin, "/settings/users/"+user+"/role", url.Values{"role": {"viewer"}})
	want(st, "user_role", "id="+user+" role=viewer")
	post(admin, "/settings/users/"+user+"/password", url.Values{})
	want(st, "password_reset", "id="+user)
	post(admin, "/settings/users/"+user+"/totp-reset", url.Values{})
	want(st, "totp_reset", "id="+user)
	post(admin, "/settings/users/"+user+"/disable", url.Values{})
	want(st, "user_disable", "id="+user)
	post(admin, "/settings/users/"+user+"/enable", url.Values{})
	want(st, "user_enable", "id="+user)
	post(admin, "/settings/users/totp-policy", url.Values{"policy": {store.TOTPOptional}})
	want(st, "totp_policy", `required=""`)

	// First setup, on a database of its own.
	first, fresh := newTestServer(t)
	if code := newClient(t, fresh).post("/setup", url.Values{"username": {"root"}, "password": {"a-strong-password"}}); code != http.StatusSeeOther {
		t.Fatalf("setup: %d", code)
	}
	root, _ := first.AnyUserByName(ctx, "root")
	want(first, "setup", "id="+strconv.FormatInt(root.ID, 10))
}
