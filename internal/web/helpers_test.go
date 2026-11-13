package web

import (
	"bytes"
	"context"
	"database/sql"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/auth"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
	"github.com/La-Cizaille-Corp/vigil/internal/storetest"

	_ "modernc.org/sqlite" // to break the test database from outside the store
)

// testPassword is the password of the accounts of the tests.
const testPassword = "a-strong-password"

// testHash is the hash of testPassword, computed once for every account of
// the tests: Argon2id takes some 45 ms and 64 MiB each time.
var testHash = sync.OnceValues(func() (string, error) { return auth.HashPassword(testPassword) })

// newBareServer starts a test server on a new database after setup has
// adjusted it (nil for none), without any account: the first-run setup is
// open.
func newBareServer(t *testing.T, setup func(*Server)) (*store.Store, string) {
	t.Helper()
	st := storetest.Open(t)
	return st, serve(t, st, setup)
}

// newServerWith is newBareServer with an administrator "admin" and an
// analyst "analyst", who see everything (password testPassword).
func newServerWith(t *testing.T, setup func(*Server)) (*store.Store, string) {
	t.Helper()
	st, base := newBareServer(t, setup)
	addUser(t, st, "admin", auth.RoleAdmin)
	addUser(t, st, "analyst", auth.RoleAnalyst)
	return st, base
}

// newServerIn is newServerWith on the database file at path, for the tests
// that break the database on purpose (see breakDB).
func newServerIn(t *testing.T, path string, setup func(*Server)) (*store.Store, string) {
	t.Helper()
	st := storetest.OpenAt(t, path)
	base := serve(t, st, setup)
	addUser(t, st, "admin", auth.RoleAdmin)
	addUser(t, st, "analyst", auth.RoleAnalyst)
	return st, base
}

// serve starts a test server on st after setup has adjusted it; the server
// stops at the end of the test, before the database is closed.
func serve(t *testing.T, st *store.Store, setup func(*Server)) string {
	t.Helper()
	srv := &Server{Store: st, Log: slog.New(slog.DiscardHandler)}
	if setup != nil {
		setup(srv)
	}
	h, err := srv.Handler()
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return ts.URL
}

// addUser creates an account who sees everything, with the password
// testPassword.
func addUser(t *testing.T, st *store.Store, name, role string) int64 {
	t.Helper()
	hash, err := testHash()
	if err != nil {
		t.Fatal(err)
	}
	id, err := st.CreateUser(context.Background(), name, hash, role, store.Access{All: true})
	if err != nil {
		t.Fatalf("create account %s: %v", name, err)
	}
	return id
}

// enableTOTP turns the second factor of an account on, its step 0 used, and
// returns its secret.
func enableTOTP(t *testing.T, st *store.Store, id int64) string {
	t.Helper()
	ctx := context.Background()
	secret, err := auth.NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetTOTPPending(ctx, id, secret); err != nil {
		t.Fatal(err)
	}
	if err := st.EnableTOTP(ctx, id, 0); err != nil {
		t.Fatal(err)
	}
	return secret
}

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

// seedFindings creates an asset with three findings, the low one found 40
// days ago, the high one 20 days ago, and returns their identifiers, most
// severe first.
func seedFindings(t *testing.T, st *store.Store) (assetID int64, ids []int64) {
	t.Helper()
	assetID = storetest.Asset(t, st, store.Asset{Name: "fortios", Version: "7.2.4", Kind: "os", Criticality: "high", Source: "manual"})
	for i, v := range []store.Vulnerability{
		{ID: "CVE-2024-0001", Severity: "CRITICAL", Summary: "=cmd|' /C calc'!A0", EPSS: -1, CVSS: 9.8},
		{ID: "CVE-2024-0002", Severity: "HIGH", EPSS: -1, CVSS: 7.5},
		{ID: "CVE-2024-0003", Severity: "LOW", EPSS: -1, CVSS: 2},
	} {
		ids = append(ids, storetest.Finding(t, st, assetID, v, time.Now().Add(-time.Duration(i*20)*24*time.Hour)))
	}
	return assetID, ids
}

// putSBOM sends an SBOM to the CI API with a bearer token (none if empty)
// and extra headers, and returns the status.
func putSBOM(t *testing.T, base, project, token, body string, headers ...string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut, base+"/api/v1/projects/"+project+"/sbom", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// pageHas reports, under what, each text of want missing from the page and
// each unwanted one shown on it.
func pageHas(t *testing.T, what, page string, want []string, unwanted ...string) {
	t.Helper()
	for _, s := range want {
		if !strings.Contains(page, s) {
			t.Errorf("%s: %q missing", what, s)
		}
	}
	for _, s := range unwanted {
		if strings.Contains(page, s) {
			t.Errorf("%s: %q shown", what, s)
		}
	}
}

// client is a browser of the tests: it keeps its cookies and does not follow
// redirects.
type client struct {
	t    *testing.T
	base string
	http *http.Client
}

func newClient(t *testing.T, base string) *client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &client{t: t, base: base, http: &http.Client{
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// loginAs signs in a new client.
func loginAs(t *testing.T, base, username, password string) *client {
	t.Helper()
	c := newClient(t, base)
	if code := c.post("/login", url.Values{"username": {username}, "password": {password}}); code != http.StatusSeeOther {
		t.Fatalf("login %s: %d", username, code)
	}
	return c
}

const formType = "application/x-www-form-urlencoded"

// do sends a request, with extra headers given in pairs, and returns its
// status, the page it redirects to and its body. A request that fails fails
// the test without stopping it, so that goroutines may send requests too.
func (c *client) do(method, path string, body io.Reader, contentType string, headers ...string) (code int, location, page string) {
	c.t.Helper()
	req, err := http.NewRequest(method, c.base+path, body)
	if err != nil {
		c.t.Errorf("%s %s: %v", method, path, err)
		return 0, "", ""
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.t.Errorf("%s %s: %v", method, path, err)
		return 0, "", ""
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		c.t.Errorf("%s %s: %v", method, path, err)
	}
	return resp.StatusCode, resp.Header.Get("Location"), string(b)
}

func (c *client) get(path string) (int, string) {
	c.t.Helper()
	code, _, page := c.do(http.MethodGet, path, nil, "")
	return code, page
}

// post posts a form and returns the status.
func (c *client) post(path string, form url.Values, headers ...string) int {
	c.t.Helper()
	code, _, _ := c.do(http.MethodPost, path, strings.NewReader(form.Encode()), formType, headers...)
	return code
}

// postBody posts a form and returns the status and the page.
func (c *client) postBody(path string, form url.Values, headers ...string) (int, string) {
	c.t.Helper()
	code, _, page := c.do(http.MethodPost, path, strings.NewReader(form.Encode()), formType, headers...)
	return code, page
}

// send makes a form request with any method and returns its status and the
// page it redirects to.
func (c *client) send(method, path string, form url.Values) (int, string) {
	c.t.Helper()
	code, location, _ := c.do(method, path, strings.NewReader(form.Encode()), formType)
	return code, location
}

// upload posts a file in a multipart form and returns the status and the
// page it redirects to, or else the page.
func (c *client) upload(path, field, name, content string, form url.Values) (int, string) {
	c.t.Helper()
	var b bytes.Buffer
	mw := multipart.NewWriter(&b)
	for k, vs := range form {
		for _, v := range vs {
			if err := mw.WriteField(k, v); err != nil {
				c.t.Fatal(err)
			}
		}
	}
	fw, err := mw.CreateFormFile(field, name)
	if err == nil {
		_, err = io.WriteString(fw, content)
	}
	if err == nil {
		err = mw.Close()
	}
	if err != nil {
		c.t.Fatal(err)
	}
	code, location, page := c.do(http.MethodPost, path, &b, mw.FormDataContentType())
	if location != "" {
		return code, location
	}
	return code, page
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

// csrf reads the token of the session: it changes with the session.
func (c *client) csrf() string {
	c.t.Helper()
	_, body := c.get("/assets")
	m := csrfRe.FindStringSubmatch(body)
	if m == nil {
		c.t.Fatal("no CSRF token in page")
	}
	return m[1]
}
