package web

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/auth"
	"github.com/La-Cizaille-Corp/vigil/internal/notify"
	"github.com/La-Cizaille-Corp/vigil/internal/sources/nvd"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
	"github.com/La-Cizaille-Corp/vigil/internal/tracking"
)

// newServerWith starts a test server after setup has adjusted it, with an
// admin "admin" and an analyst "analyst" (password "a-strong-password").
func newServerWith(t *testing.T, setup func(*Server)) (*store.Store, string) {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "web.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	srv := &Server{Store: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if setup != nil {
		setup(srv)
	}
	h, err := srv.Handler()
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	hash, _ := auth.HashPassword("a-strong-password")
	st.CreateUser(context.Background(), "admin", hash, auth.RoleAdmin)
	st.CreateUser(context.Background(), "analyst", hash, auth.RoleAnalyst)
	return st, ts.URL
}

func (c *client) upload(path, field, name, content string, form url.Values) (int, string) {
	var b bytes.Buffer
	mw := multipart.NewWriter(&b)
	for k, vs := range form {
		for _, v := range vs {
			mw.WriteField(k, v)
		}
	}
	fw, _ := mw.CreateFormFile(field, name)
	io.WriteString(fw, content)
	mw.Close()
	req, _ := http.NewRequest(http.MethodPost, c.base+path, &b)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := c.http.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if loc := resp.Header.Get("Location"); loc != "" {
		return resp.StatusCode, loc
	}
	return resp.StatusCode, string(body)
}

func seedFindings(t *testing.T, st *store.Store) (assetID int64, ids []int64) {
	t.Helper()
	ctx := context.Background()
	assetID, _ = st.CreateAsset(ctx, store.Asset{Name: "fortios", Version: "7.2.4", Kind: "os", Criticality: "high", Source: "manual"})
	for i, v := range []store.Vulnerability{
		{ID: "CVE-2024-0001", Severity: "CRITICAL", Summary: "=cmd|' /C calc'!A0", EPSS: -1, CVSS: 9.8},
		{ID: "CVE-2024-0002", Severity: "HIGH", EPSS: -1, CVSS: 7.5},
		{ID: "CVE-2024-0003", Severity: "LOW", EPSS: -1, CVSS: 2},
	} {
		st.UpsertVulnerability(ctx, v)
		st.ObserveFinding(ctx, assetID, v.ID, time.Now().Add(-time.Duration(i*20)*24*time.Hour))
	}
	list, _ := st.ListFindings(ctx, store.FindingFilter{})
	for _, f := range list {
		ids = append(ids, f.ID)
	}
	return assetID, ids
}

func TestBulkTriage(t *testing.T) {
	st, base := newServerWith(t, nil)
	_, ids := seedFindings(t, st)
	c := loginAs(t, base, "analyst", "a-strong-password")
	form := url.Values{"csrf": {c.csrf()}, "status": {"not_affected"}, "justification": {"code_not_reachable"},
		"comment": {"Module désactivé"}, "next": {"/findings?severity=HIGH&severity=CRITICAL"},
		"id": {strconv.FormatInt(ids[0], 10), strconv.FormatInt(ids[1], 10)}}
	code, loc := c.postLocation("/findings/bulk", form)
	if code != http.StatusSeeOther || loc != "/findings?severity=HIGH&severity=CRITICAL&msg=bulk-updated" {
		t.Fatalf("bulk: %d %s", code, loc)
	}
	list, _ := st.ListFindings(context.Background(), store.FindingFilter{Statuses: []string{"not_affected"}})
	if len(list) != 2 || list[0].Comment != "Module désactivé" {
		t.Errorf("updated: %+v", list)
	}
	// Without a comment, a bulk decision keeps each finding's own comment.
	code, _ = c.postLocation("/findings/bulk", url.Values{"csrf": {c.csrf()}, "status": {"exploitable"},
		"id": {strconv.FormatInt(ids[0], 10)}, "next": {"/findings"}})
	if f, _ := st.Finding(context.Background(), ids[0]); code != http.StatusSeeOther || f.Status != "exploitable" || f.Comment != "Module désactivé" {
		t.Errorf("comment lost by a bulk decision: %d %+v", code, f)
	}
	// SECURITY: the return address cannot leave the findings list.
	form.Set("next", "https://evil.example/")
	if _, loc := c.postLocation("/findings/bulk", form); !strings.HasPrefix(loc, "/findings?msg=") {
		t.Errorf("open redirect: %s", loc)
	}
	form.Set("status", "nope")
	if code := c.post("/findings/bulk", form); code != http.StatusBadRequest {
		t.Errorf("invalid status: %d", code)
	}
	hash, _ := auth.HashPassword("a-strong-password")
	st.CreateUser(context.Background(), "viewer", hash, auth.RoleViewer)
	viewer := loginAs(t, base, "viewer", "a-strong-password")
	if _, body := viewer.get("/findings"); strings.Contains(body, `form="bulk"`) {
		t.Error("a viewer sees the bulk form")
	}
}

func TestCSVExportsAndImport(t *testing.T) {
	st, base := newServerWith(t, nil)
	seedFindings(t, st)
	c := loginAs(t, base, "analyst", "a-strong-password")

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
	assets, _ := st.ListAssets(context.Background())
	if len(assets) != 2 { // fortios 7.2.4 already existed
		t.Errorf("assets after import: %+v", assets)
	}
	// Files up to 2 MB go through (the form limit elsewhere is 64 KiB).
	big := "name;notes\n" + strings.Repeat("svc;"+strings.Repeat("x", 990)+"\n", 120)
	if code, loc := c.upload("/assets/import-csv", "csv", "big.csv", big, url.Values{"csrf": {c.csrf()}}); code != http.StatusSeeOther {
		t.Errorf("120 KB CSV: %d %s", code, loc)
	}
	code, page := c.upload("/assets/import-csv", "csv", "x.csv", "nom;type\nx;librairie\n", url.Values{"csrf": {c.csrf()}})
	if code != http.StatusBadRequest || !strings.Contains(page, "ligne 2") {
		t.Errorf("invalid CSV: %d", code)
	}
	if code, body := c.get("/assets.csv"); code != http.StatusOK || !strings.Contains(body, "Exchange;2019;product;high") {
		t.Errorf("assets CSV: %d\n%s", code, body)
	}
}

func TestDeadlinesAndAudit(t *testing.T) {
	st, base := newServerWith(t, nil)
	seedFindings(t, st) // the low one was found 40 days ago, the high one 20 days ago
	admin := loginAs(t, base, "admin", "a-strong-password")
	if code := admin.post("/settings/sla", url.Values{"csrf": {admin.csrf()}, "critical": {"15"}, "high": {"10"}, "medium": {"90"}, "low": {"0"}}); code != http.StatusSeeOther {
		t.Fatalf("save SLA: %d", code)
	}
	_, body := admin.get("/findings?overdue=1")
	if !strings.Contains(body, "CVE-2024-0002") || strings.Contains(body, "CVE-2024-0003") || !strings.Contains(body, "Hors délai") {
		t.Errorf("overdue list:\n%s", body)
	}
	if code := admin.post("/settings/sla", url.Values{"csrf": {admin.csrf()}, "critical": {"-3"}, "high": {"1"}, "medium": {"1"}, "low": {"1"}}); code != http.StatusBadRequest {
		t.Errorf("negative deadline: %d", code)
	}
	if _, body := admin.get("/"); !strings.Contains(body, "Hors délai") {
		t.Error("dashboard misses the overdue indicator")
	}
	if code, body := admin.get("/settings/audit"); code != http.StatusOK || !strings.Contains(body, "sla_update") {
		t.Errorf("audit page: %d", code)
	}
	analyst := loginAs(t, base, "analyst", "a-strong-password")
	if code, _ := analyst.get("/settings/audit"); code != http.StatusForbidden {
		t.Errorf("analyst reads the audit log: %d", code)
	}
}

func TestNotificationChannels(t *testing.T) {
	var mail *notify.Mailer
	st, base := newServerWith(t, func(s *Server) { s.Notifier = &notify.Notifier{Store: s.Store, Mail: mail} })
	admin := loginAs(t, base, "admin", "a-strong-password")
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
	id := strconv.FormatInt(hooks[0].ID, 10)
	if code := admin.post("/settings/webhooks/"+id, url.Values{"csrf": {admin.csrf()}, "alerts": {"severe"}}); code != http.StatusSeeOther {
		t.Fatalf("update channel: %d", code)
	}
	if hooks, _ = st.ListWebhooks(context.Background()); hooks[0].Alerts != "severe" || hooks[0].Digests {
		t.Errorf("updated channel: %+v", hooks)
	}
	if code := admin.post("/settings/webhooks/"+id, url.Values{"csrf": {admin.csrf()}, "alerts": {"all"}}); code != http.StatusBadRequest {
		t.Errorf("unknown alert level: %d", code)
	}
	if _, body := admin.get("/settings"); strings.Contains(body, "secret") || !strings.Contains(body, "aucun serveur SMTP") {
		t.Error("settings page: secret shown or SMTP state missing")
	}
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
	c := loginAs(t, base, "analyst", "a-strong-password")
	code, body := c.get("/assets/cpe?q=elasticsearch+8.15")
	if code != http.StatusOK {
		t.Fatalf("search: %d\n%s", code, body)
	}
	current, old := strings.Index(body, "<code class=\"small\">elastic</code>"), strings.Index(body, "<code class=\"small\">elasticsearch</code> <span class=\"tag\">ancien nom</span>")
	if current < 0 || old < 0 || current > old {
		t.Errorf("current vendor %d, old vendor %d: the current name must come first, the old one flagged", current, old)
	}
	if !strings.Contains(body, "Suivre tous les produits Elastic") || !strings.Contains(body, "cpe%3A2.3%3A%2A%3Aelastic%3A%2A") {
		t.Error("no link to track every product of the vendor")
	}
	if !strings.Contains(body, "Elastic Elasticsearch 8.15.1") || strings.Contains(body, "Elastic Elasticsearch 9.1.0") {
		t.Error("versions offered do not follow the search")
	}
	// "Use" prefills the new asset form.
	_, body = c.get("/assets?cpe=cpe%3A2.3%3Ao%3Afortinet%3Afortios%3A7.2.4%3A*%3A*%3A*%3A*%3A*%3A*%3A*&kind=os&name=Fortinet+FortiOS&version=7.2.4")
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

func TestCompareVersions(t *testing.T) {
	ordered := []string{"10.0", "9.5.5", "9.5.3", "8.19.23", "1.4.1", "1.4.0", "1.4.0-rc1", "1.4.0-beta1"}
	for i := 0; i+1 < len(ordered); i++ {
		if compareVersions(ordered[i], ordered[i+1]) <= 0 || compareVersions(ordered[i+1], ordered[i]) >= 0 {
			t.Errorf("%s should rank above %s", ordered[i], ordered[i+1])
		}
	}
	if compareVersions("2019", "2019") != 0 {
		t.Error("equal versions")
	}
}

func TestAssetTags(t *testing.T) {
	st, base := newServerWith(t, nil)
	ctx := context.Background()
	c := loginAs(t, base, "analyst", "a-strong-password")
	code, loc := c.postLocation("/assets", url.Values{"csrf": {c.csrf()}, "name": {"nginx"}, "kind": {"technology"},
		"criticality": {"high"}, "tags": {"Prod, Équipe Web; prod"}})
	if code != http.StatusSeeOther {
		t.Fatalf("create: %d %s", code, loc)
	}
	other, _ := st.CreateAsset(ctx, store.Asset{Name: "redis", Kind: "technology", Criticality: "low", Source: "manual", Tags: []string{"recette"}})
	assets, _ := st.ListAssets(ctx)
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
	if !strings.Contains(body, ">nginx</a>") || strings.Contains(body, ">redis</a>") || !strings.Contains(body, "recette <small>1</small>") {
		t.Errorf("inventory filtered by tag:\n%s", body)
	}
	// Vulnerabilities filtered by the tag of their asset.
	st.UpsertVulnerability(ctx, store.Vulnerability{ID: "CVE-1", Severity: "HIGH", EPSS: -1, CVSS: -1})
	st.UpsertVulnerability(ctx, store.Vulnerability{ID: "CVE-2", Severity: "HIGH", EPSS: -1, CVSS: -1})
	st.ObserveFinding(ctx, nginx.ID, "CVE-1", time.Now())
	st.ObserveFinding(ctx, other, "CVE-2", time.Now())
	list, _ := st.ListFindings(ctx, store.FindingFilter{Tag: "équipe web"})
	if len(list) != 1 || list[0].VulnID != "CVE-1" {
		t.Errorf("findings with tag: %+v", list)
	}
	if _, body := c.get("/findings?tag=recette"); !strings.Contains(body, "CVE-2") || strings.Contains(body, "CVE-1") {
		t.Error("findings page not filtered by tag")
	}
	// Tags survive a CSV round trip.
	if _, body := c.get("/assets.csv"); !strings.Contains(body, "prod, équipe web") {
		t.Errorf("CSV export misses the tags:\n%s", body)
	}
}
