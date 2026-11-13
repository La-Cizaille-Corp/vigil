package web

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/auth"
	"github.com/La-Cizaille-Corp/vigil/internal/notify"
	"github.com/La-Cizaille-Corp/vigil/internal/sources/nvd"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
	"github.com/La-Cizaille-Corp/vigil/internal/storetest"
	"github.com/La-Cizaille-Corp/vigil/internal/tracking"
)

func TestBulkTriage(t *testing.T) {
	st, base := newServerWith(t, nil)
	_, ids := seedFindings(t, st)
	c := loginAs(t, base, "analyst", testPassword)
	form := url.Values{"csrf": {c.csrf()}, "status": {"not_affected"}, "justification": {"code_not_reachable"},
		"comment": {"Module désactivé"}, "next": {"/findings?severity=HIGH&severity=CRITICAL"},
		"id": {itoa(ids[0]), itoa(ids[1])}}
	code, loc := c.send(http.MethodPost, "/findings/bulk", form)
	if code != http.StatusSeeOther || loc != "/findings?severity=HIGH&severity=CRITICAL&msg=bulk-updated" {
		t.Fatalf("bulk: %d %s", code, loc)
	}
	list, _ := st.ListFindings(context.Background(), store.Everything, store.FindingFilter{Statuses: []string{"not_affected"}})
	if len(list) != 2 || list[0].Comment != "Module désactivé" {
		t.Errorf("updated: %+v", list)
	}
	// Without a comment, a bulk decision keeps each finding's own comment.
	code, _ = c.send(http.MethodPost, "/findings/bulk", url.Values{"csrf": {c.csrf()}, "status": {"exploitable"},
		"id": {itoa(ids[0])}, "next": {"/findings"}})
	if f, _ := st.Finding(context.Background(), store.Everything, ids[0]); code != http.StatusSeeOther || f.Status != "exploitable" || f.Comment != "Module désactivé" {
		t.Errorf("comment lost by a bulk decision: %d %+v", code, f)
	}
	// SECURITY: the return address cannot leave the findings list.
	form.Set("next", "https://evil.example/")
	if _, loc := c.send(http.MethodPost, "/findings/bulk", form); !strings.HasPrefix(loc, "/findings?msg=") {
		t.Errorf("open redirect: %s", loc)
	}
	form.Set("status", "nope")
	if code := c.post("/findings/bulk", form); code != http.StatusBadRequest {
		t.Errorf("invalid status: %d", code)
	}
	addUser(t, st, "viewer", auth.RoleViewer)
	viewer := loginAs(t, base, "viewer", testPassword)
	if _, body := viewer.get("/findings"); strings.Contains(body, `form="bulk"`) {
		t.Error("a viewer sees the bulk form")
	}
}

func TestCSVExportsAndImport(t *testing.T) {
	st, base := newServerWith(t, nil)
	seedFindings(t, st)
	c := loginAs(t, base, "analyst", testPassword)

	code, body := c.get("/findings.csv?severity=CRITICAL")
	if code != http.StatusOK || !strings.HasPrefix(body, "\xef\xbb\xbfid;vulnerabilite") || strings.Count(body, "\n") != 2 {
		t.Fatalf("findings CSV: %d\n%s", code, body)
	}
	if !strings.Contains(body, `'=cmd|`) {
		t.Errorf("formula not neutralised: %s", body)
	}
	if _, page := c.get("/findings?severity=CRITICAL&q=a+b"); !strings.Contains(page, `href="/findings.csv?q=a&#43;b&amp;severity=CRITICAL"`) {
		t.Errorf("export link does not keep the filters")
	}

	csvFile := "nom;version;type;criticité\nExchange;2019;Produit;Haute\nfortios;7.2.4;os;high\n"
	code, loc := c.upload("/assets/import-csv", "csv", "inventaire.csv", csvFile, url.Values{"csrf": {c.csrf()}})
	if code != http.StatusSeeOther || loc != "/assets?msg=csv-imported" {
		t.Fatalf("CSV import: %d %s", code, loc)
	}
	assets, _ := st.ListAssets(context.Background(), store.Everything)
	if len(assets) != 2 { // fortios 7.2.4 already existed
		t.Errorf("assets after import: %+v", assets)
	}
	// Files up to 2 MB go through (the form limit elsewhere is 64 KiB).
	big := "name;notes\n" + strings.Repeat("svc;"+strings.Repeat("x", 990)+"\n", 120)
	if code, loc := c.upload("/assets/import-csv", "csv", "big.csv", big, url.Values{"csrf": {c.csrf()}}); code != http.StatusSeeOther {
		t.Errorf("120 KB CSV: %d %s", code, loc)
	}
	code, page := c.upload("/assets/import-csv", "csv", "x.csv", "nom;type\nx;librairie\n", url.Values{"csrf": {c.csrf()}})
	if code != http.StatusBadRequest || !strings.Contains(page, "Ligne 2 (x) : type « librairie » inconnu") {
		t.Errorf("invalid CSV: %d", code)
	}
	if code, body := c.get("/assets.csv"); code != http.StatusOK || !strings.Contains(body, "Exchange;2019;product;high") {
		t.Errorf("assets CSV: %d\n%s", code, body)
	}
}

func TestDeadlinesAndAudit(t *testing.T) {
	st, base := newServerWith(t, nil)
	seedFindings(t, st) // the low one was found 40 days ago, the high one 20 days ago
	admin := loginAs(t, base, "admin", testPassword)
	if code := admin.post("/settings/sla", url.Values{"csrf": {admin.csrf()}, "critical": {"15"}, "high": {"10"}, "medium": {"90"}, "low": {"0"}}); code != http.StatusSeeOther {
		t.Fatalf("save SLA: %d", code)
	}
	_, body := admin.get("/findings?overdue=1")
	pageHas(t, "overdue list", body, []string{"CVE-2024-0002", "Hors délai"}, "CVE-2024-0003")
	if code := admin.post("/settings/sla", url.Values{"csrf": {admin.csrf()}, "critical": {"-3"}, "high": {"1"}, "medium": {"1"}, "low": {"1"}}); code != http.StatusBadRequest {
		t.Errorf("negative deadline: %d", code)
	}
	if _, body := admin.get("/"); !strings.Contains(body, "Hors délai") {
		t.Error("dashboard misses the overdue indicator")
	}
	if code, body := admin.get("/settings/audit"); code != http.StatusOK || !strings.Contains(body, "sla_update") {
		t.Errorf("audit page: %d", code)
	}
	analyst := loginAs(t, base, "analyst", testPassword)
	if code, _ := analyst.get("/settings/audit"); code != http.StatusForbidden {
		t.Errorf("analyst reads the audit log: %d", code)
	}
}

func TestNotificationChannels(t *testing.T) {
	var mail *notify.Mailer
	st, base := newServerWith(t, func(s *Server) { s.Notifier = &notify.Notifier{Store: s.Store, Mail: mail} })
	admin := loginAs(t, base, "admin", testPassword)
	form := url.Values{"csrf": {admin.csrf()}, "name": {"RSSI"}, "kind": {"email"}, "url": {"rssi@example.org"}, "alerts": {"priority"}, "digests": {"1"}}
	if code := admin.post("/settings/webhooks", form); code != http.StatusBadRequest {
		t.Errorf("e-mail channel without SMTP: %d", code)
	}
	form.Set("kind", "slack")
	form.Set("url", "https://hooks.slack.com/services/T/B/secret")
	if code := admin.post("/settings/webhooks", form); code != http.StatusSeeOther {
		t.Fatalf("create channel: %d", code)
	}
	hooks, _ := st.ListWebhooks(context.Background())
	if len(hooks) != 1 || hooks[0].Alerts != "priority" || !hooks[0].Digests {
		t.Fatalf("channel: %+v", hooks)
	}
	id := itoa(hooks[0].ID)
	if code := admin.post("/settings/webhooks/"+id, url.Values{"csrf": {admin.csrf()}, "alerts": {"severe"}}); code != http.StatusSeeOther {
		t.Fatalf("update channel: %d", code)
	}
	if hooks, _ = st.ListWebhooks(context.Background()); hooks[0].Alerts != "severe" || hooks[0].Digests {
		t.Errorf("updated channel: %+v", hooks)
	}
	if code := admin.post("/settings/webhooks/"+id, url.Values{"csrf": {admin.csrf()}, "alerts": {"all"}}); code != http.StatusBadRequest {
		t.Errorf("unknown alert level: %d", code)
	}
	_, body := admin.get("/settings/webhooks")
	pageHas(t, "settings page", body, []string{"aucun serveur SMTP"}, "secret")
}

// cpeEntry is a CPE dictionary entry as returned by the NVD.
func cpeEntry(name, title, created string) string {
	return `{"cpe":{"cpeName":"` + name + `","created":"` + created + `","titles":[{"title":"` + title + `","lang":"en"}]}}`
}

// The dictionary returns old vendor names first: the current one must come
// first, the old one be flagged, and the versions follow the search.
func TestCPESearch(t *testing.T) {
	dict := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("cpeMatchString") != "cpe:2.3:*:*:elasticsearch" {
			io.WriteString(w, `{"totalResults":0,"products":[]}`)
			return
		}
		io.WriteString(w, `{"totalResults":4,"products":[`+
			cpeEntry("cpe:2.3:a:elasticsearch:elasticsearch:1.4.0:*:*:*:*:*:*:*", "Elasticsearch 1.4.0", "2014-07-29T18:13:07.643")+`,`+
			cpeEntry("cpe:2.3:a:elastic:elasticsearch:8.15.0:*:*:*:*:*:*:*", "Elastic Elasticsearch 8.15.0", "2024-08-10T10:00:00.000")+`,`+
			cpeEntry("cpe:2.3:a:elastic:elasticsearch:8.15.1:*:*:*:*:*:*:*", "Elastic Elasticsearch 8.15.1", "2024-09-10T10:00:00.000")+`,`+
			cpeEntry("cpe:2.3:a:elastic:elasticsearch:9.1.0:*:*:*:*:*:*:*", "Elastic Elasticsearch 9.1.0", "2026-10-08T10:00:00.000")+`]}`)
	}))
	defer dict.Close()
	_, base := newServerWith(t, func(s *Server) {
		s.Syncer = &tracking.Syncer{Store: s.Store, NVD: &nvd.Client{URL: dict.URL, CPEURL: dict.URL, HTTP: dict.Client()}}
	})
	c := loginAs(t, base, "analyst", testPassword)
	code, body := c.get("/assets/cpe?q=elasticsearch+8.15")
	if code != http.StatusOK {
		t.Fatalf("search: %d\n%s", code, body)
	}
	current, old := strings.Index(body, "<code class=\"small\">elastic</code>"), strings.Index(body, "<code class=\"small\">elasticsearch</code> <span class=\"tag\">ancien nom</span>")
	if current < 0 || old < 0 || current > old {
		t.Errorf("current vendor %d, old vendor %d: the current name must come first, the old one flagged", current, old)
	}
	pageHas(t, "link to track every product of the vendor", body, []string{"Suivre tous les produits Elastic", "cpe%3A2.3%3A%2A%3Aelastic%3A%2A"})
	pageHas(t, "versions offered along the search", body, []string{"Elastic Elasticsearch 8.15.1"}, "Elastic Elasticsearch 9.1.0")
	// "Use" prefills the new asset form.
	_, body = c.get("/assets/new?cpe=cpe%3A2.3%3Ao%3Afortinet%3Afortios%3A7.2.4%3A*%3A*%3A*%3A*%3A*%3A*%3A*&kind=os&name=Fortinet+FortiOS&version=7.2.4")
	for _, want := range []string{`value="Fortinet FortiOS"`, `value="7.2.4"`, `value="cpe:2.3:o:fortinet:fortios:7.2.4:*:*:*:*:*:*:*"`} {
		if !strings.Contains(body, want) {
			t.Errorf("prefilled form misses %s", want)
		}
	}
}

func TestClientIPBehindProxy(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "127.0.0.1:5000"
	r.Header.Add("X-Forwarded-For", "6.6.6.6, 203.0.113.7")
	direct, proxied := &Server{}, &Server{BehindProxy: true}
	if got := direct.clientIP(r); got != "127.0.0.1" {
		t.Errorf("direct: %s", got)
	}
	// The last hop is the one the proxy added; the forged first one is ignored.
	if got := proxied.clientIP(r); got != "203.0.113.7" {
		t.Errorf("behind proxy: %s", got)
	}
	r.Header.Del("X-Forwarded-For")
	if got := proxied.clientIP(r); got != "127.0.0.1" {
		t.Errorf("no header: %s", got)
	}
}

func TestAssetTags(t *testing.T) {
	st, base := newServerWith(t, nil)
	ctx := context.Background()
	c := loginAs(t, base, "analyst", testPassword)
	code, loc := c.send(http.MethodPost, "/assets", url.Values{"csrf": {c.csrf()}, "name": {"nginx"}, "kind": {"technology"},
		"criticality": {"high"}, "tags": {"Prod, Équipe Web; prod"}})
	if code != http.StatusSeeOther {
		t.Fatalf("create: %d %s", code, loc)
	}
	other := storetest.Asset(t, st, store.Asset{Name: "redis", Kind: "technology", Criticality: "low", Source: "manual", Tags: []string{"recette"}})
	assets, err := st.ListAssets(ctx, store.Everything)
	if err != nil {
		t.Fatal(err)
	}
	var nginx store.Asset
	for _, a := range assets {
		if a.Name == "nginx" {
			nginx = a
		}
	}
	if strings.Join(nginx.Tags, "|") != "prod|équipe web" {
		t.Fatalf("tags: %q", nginx.Tags)
	}
	// Inventory filtered by tag, with the tags in use offered.
	_, body := c.get("/assets?tag=prod")
	pageHas(t, "inventory filtered by tag", body, []string{">nginx</a>", "recette (1)"}, ">redis</a>")
	// Vulnerabilities filtered by the tag of their asset.
	storetest.Finding(t, st, nginx.ID, store.Vulnerability{ID: "CVE-1", Severity: "HIGH", EPSS: -1, CVSS: -1}, time.Now())
	storetest.Finding(t, st, other, store.Vulnerability{ID: "CVE-2", Severity: "HIGH", EPSS: -1, CVSS: -1}, time.Now())
	list, err := st.ListFindings(ctx, store.Everything, store.FindingFilter{Tag: "équipe web"})
	if err != nil || len(list) != 1 || list[0].VulnID != "CVE-1" {
		t.Errorf("findings with tag: %+v, %v", list, err)
	}
	_, body = c.get("/findings?tag=recette")
	pageHas(t, "findings filtered by tag", body, []string{"CVE-2"}, "CVE-1")
	// Tags survive a CSV round trip.
	if _, body := c.get("/assets.csv"); !strings.Contains(body, "prod, équipe web") {
		t.Errorf("CSV export misses the tags:\n%s", body)
	}
}

// A channel can be tested without waiting for an alert; the reason of a refusal
// shows in its state, and its URL is never shown.
func TestWebhookTestButton(t *testing.T) {
	status := http.StatusOK
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		if status != http.StatusOK {
			io.WriteString(w, `{"error":{"code":"DirectApiAuthorizationRequired","message":"The request must be authenticated."}}`)
		}
	}))
	defer hook.Close()
	st, base := newServerWith(t, func(s *Server) {
		s.Notifier = &notify.Notifier{Store: s.Store, HTTP: hook.Client(), Log: s.Log}
	})
	id, err := st.CreateWebhook(context.Background(), store.Webhook{Name: "Équipe", Kind: "teams", URL: hook.URL + "/SECRET?sig=SECRET", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	path := "/settings/webhooks/" + itoa(id) + "/test"
	admin := loginAs(t, base, "admin", testPassword)
	if code, loc := admin.send(http.MethodPost, path, url.Values{"csrf": {admin.csrf()}}); code != http.StatusSeeOther || !strings.Contains(loc, "msg=hook-test-sent") {
		t.Errorf("test: %d %s", code, loc)
	}
	status = http.StatusUnauthorized
	if code, loc := admin.send(http.MethodPost, path, url.Values{"csrf": {admin.csrf()}}); code != http.StatusSeeOther || !strings.Contains(loc, "msg=hook-test-failed") {
		t.Errorf("failed test: %d %s", code, loc)
	}
	_, body := admin.get("/settings/webhooks")
	pageHas(t, "state of the channel", body, []string{"DirectApiAuthorizationRequired", "Tout le monde"}, "SECRET")
	if code := admin.post("/settings/webhooks/999/test", url.Values{"csrf": {admin.csrf()}}); code != http.StatusNotFound {
		t.Errorf("unknown channel: %d", code)
	}
	analyst := loginAs(t, base, "analyst", testPassword)
	if code := analyst.post(path, url.Values{"csrf": {analyst.csrf()}}); code != http.StatusForbidden {
		t.Errorf("an analyst tested a channel: %d", code)
	}
}
