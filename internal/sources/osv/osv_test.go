package osv

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// The latest release is affected by a range that ends affected; ranges of
// other packages named by the same advisory do not count.
func TestUnfixed(t *testing.T) {
	lodash := Package{PURL: "pkg:npm/lodash"}
	cases := []struct {
		name string
		doc  string
		pkg  Package
		want bool
	}{
		{"fixed", `{"affected":[{"package":{"purl":"pkg:npm/lodash"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}`, lodash, false},
		{"no fix yet", `{"affected":[{"package":{"purl":"pkg:npm/lodash"},"ranges":[{"type":"SEMVER","events":[{"introduced":"4.0.0"}]}]}]}`, lodash, true},
		{"reopened", `{"affected":[{"package":{"purl":"pkg:npm/lodash"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.0"},{"introduced":"2.0"}]}]}]}`, lodash, true},
		{"last affected", `{"affected":[{"package":{"purl":"pkg:npm/lodash"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"last_affected":"4.5.1"}]}]}]}`, lodash, true},
		{"other package", `{"affected":[{"package":{"purl":"pkg:npm/lodash"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]},
			{"package":{"purl":"pkg:npm/lodash.template"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"last_affected":"4.5.0"}]}]}]}`, lodash, false},
		{"withdrawn", `{"withdrawn":"2024-01-01T00:00:00Z","affected":[{"package":{"purl":"pkg:npm/lodash"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`, lodash, false},
		{"purl case and version", `{"affected":[{"package":{"purl":"pkg:pypi/django"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}`, Package{PURL: "pkg:pypi/Django@4.2"}, true},
		{"only entry without purl", `{"affected":[{"package":{"name":"lodash","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`, lodash, true},
		{"name and ecosystem", `{"affected":[{"package":{"name":"openssl","ecosystem":"Debian:12"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]},
			{"package":{"name":"openssl","ecosystem":"Alpine:v3.20"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.3.2-r0"}]}]}]}`, Package{Name: "openssl", Ecosystem: "Alpine"}, false},
	}
	for _, c := range cases {
		var v Vuln
		if err := json.Unmarshal([]byte(c.doc), &v); err != nil {
			t.Fatal(c.name, err)
		}
		if got := v.Unfixed(c.pkg); got != c.want {
			t.Errorf("%s: Unfixed = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestWithoutVersion(t *testing.T) {
	for in, want := range map[string]string{
		"pkg:npm/lodash@4.17.15":                   "pkg:npm/lodash",
		"pkg:npm/%40angular/core@17.0.0":           "pkg:npm/%40angular/core",
		"pkg:deb/debian/openssl@3.0.11?distro=x":   "pkg:deb/debian/openssl?distro=x",
		"pkg:npm/lodash":                           "pkg:npm/lodash",
		"pkg:golang/github.com/a/b@v1.2.3#sub/dir": "pkg:golang/github.com/a/b#sub/dir",
		"pkg:npm/@babel/core@7.0.0":                "pkg:npm/@babel/core",
		"pkg:npm/@babel/core":                      "pkg:npm/@babel/core",
		"pkg:deb/debian/libc6?upstream=glibc@2.36": "pkg:deb/debian/libc6?upstream=glibc@2.36",
	} {
		if got := WithoutVersion(in); got != want {
			t.Errorf("WithoutVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPURLVersion(t *testing.T) {
	for in, want := range map[string]string{
		"pkg:npm/lodash@4.17.15":                   "4.17.15",
		"pkg:npm/lodash@4.17.15?repository_url=x":  "4.17.15",
		"pkg:golang/github.com/a/b@v1.2.3#sub/dir": "v1.2.3",
		"pkg:deb/debian/libssl3@1%3A3.0.11-1%7Eb1": "1:3.0.11-1~b1",
		"pkg:npm/%40angular/core@17.0.0":           "17.0.0",
		"pkg:npm/@babel/core@7.0.0":                "7.0.0",
		"pkg:github/a/b@releases/v2":               "releases/v2",
		"pkg:npm/lodash":                           "",
		"pkg:npm/@babel/core":                      "",
		"pkg:deb/debian/libc6?upstream=glibc@2.36": "",
	} {
		if got := PURLVersion(in); got != want {
			t.Errorf("PURLVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

// query collects the advisories of a query.
func query(t *testing.T, c *Client, q Query) []Vuln {
	t.Helper()
	list := c.Advisories(q)
	defer list.Close()
	var out []Vuln
	for list.Next(context.Background()) {
		out = append(out, list.Vuln())
	}
	if err := list.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// Advisories reads every page, without a version.
func TestQueryPages(t *testing.T) {
	var bodies []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/query" {
			http.NotFound(w, r)
			return
		}
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		bodies = append(bodies, body)
		if body["page_token"] == nil {
			w.Write([]byte(`{"vulns":[{"id":"GHSA-1","modified":"2026-01-01T00:00:00Z"}],"next_page_token":"p2"}`))
			return
		}
		w.Write([]byte(`{"vulns":[{"id":"GHSA-2","affected":[{"package":{"purl":"pkg:npm/x"}}]}]}`))
	}))
	defer srv.Close()
	c := &Client{URL: srv.URL, HTTP: http.DefaultClient}
	vulns := query(t, c, Query{Package: Package{PURL: "pkg:npm/x"}})
	if len(vulns) != 2 || vulns[0].ID != "GHSA-1" || vulns[1].ID != "GHSA-2" || len(vulns[1].Affected) != 1 {
		t.Fatalf("vulns = %+v", vulns)
	}
	if len(bodies) != 2 || bodies[0]["version"] != nil || bodies[1]["page_token"] != "p2" {
		t.Errorf("requests = %v", bodies)
	}
	bodies = nil
	query(t, c, Query{Package: Package{Name: "linux", Ecosystem: "Debian"}, Version: "6.1.76-1"})
	if len(bodies) != 2 || bodies[0]["version"] != "6.1.76-1" || bodies[1]["version"] != "6.1.76-1" {
		t.Errorf("requests with a version = %v", bodies)
	}
}

// A batch answer says when a query has more pages: OSV lists from the oldest.
func TestQueryBatchMore(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"results":[{"vulns":[{"id":"DEBIAN-CVE-2004-0230"}],"next_page_token":"p2"},{"vulns":[{"id":"GHSA-1"}]},{}]}`))
	}))
	defer srv.Close()
	c := &Client{URL: srv.URL, HTTP: http.DefaultClient}
	got, err := c.QueryBatch(context.Background(), make([]Query, 3))
	if err != nil {
		t.Fatal(err)
	}
	if !got[0].More || got[1].More || got[2].More || len(got[1].Vulns) != 1 || len(got[2].Vulns) != 0 {
		t.Errorf("results = %+v", got)
	}
}

// The short list of a query follows the pages of the batch answer, one query
// at a time, with its token; a reply that never ends is cut.
func TestRefs(t *testing.T) {
	var asked []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Queries []map[string]any `json:"queries"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		if r.URL.Path != "/v1/querybatch" || len(body.Queries) != 1 {
			t.Errorf("asked %s %v", r.URL.Path, body)
		}
		asked = append(asked, body.Queries[0])
		if body.Queries[0]["version"] == "endless" {
			w.Write([]byte(`{"results":[{"next_page_token":"again"}]}`))
			return
		}
		switch body.Queries[0]["page_token"] {
		case nil:
			w.Write([]byte(`{"results":[{"vulns":[{"id":"A","modified":"2026-01-01T00:00:00.123456Z"},{"id":"B"}],"next_page_token":"p2"}]}`))
		case "p2":
			w.Write([]byte(`{"results":[{"vulns":[{"id":"C"}],"next_page_token":"p3"}]}`))
		default:
			w.Write([]byte(`{"results":[{}]}`))
		}
	}))
	defer srv.Close()
	c := &Client{URL: srv.URL, HTTP: http.DefaultClient}
	q := Query{Package: Package{Name: "linux", Ecosystem: "Ubuntu:22.04:LTS"}, Version: "5.15.0-100.110"}
	refs, err := c.Refs(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 3 || refs[0] != (VulnRef{"A", "2026-01-01T00:00:00.123456Z"}) || refs[2].ID != "C" {
		t.Errorf("refs = %+v", refs)
	}
	if len(asked) != 3 || asked[1]["version"] != "5.15.0-100.110" || asked[2]["page_token"] != "p3" {
		t.Errorf("asked = %v", asked)
	}
	asked = nil
	if _, err := c.Refs(context.Background(), Query{Version: "endless"}); err == nil || len(asked) != maxQueryPages {
		t.Errorf("endless list: %d requests, %v", len(asked), err)
	}
}

// OSV writes the date of modification of an advisory to the microsecond in a
// batch answer, to the nanosecond in the advisory itself.
func TestSameModified(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"2026-11-12T17:20:40.464641Z", "2026-11-12T17:20:40.464641664Z", true},
		{"2026-11-12T17:20:40.464641664Z", "2026-11-12T17:20:40.464641664Z", true},
		{"2025-08-12T21:56:17.174859Z", "2025-08-12T21:56:17.174859Z", true},
		{"2026-01-01T00:00:00Z", "2026-01-01T01:00:00+01:00", true},
		{"2026-11-12T17:20:40.464641Z", "2026-11-12T17:20:40.464642664Z", false},
		{"2026-11-11T09:34:34.479017397Z", "2026-11-12T17:20:40.464641Z", false},
		{"old", "2026-11-12T17:20:40.464641Z", false},
		{"", "", true},
	} {
		if got := SameModified(c.a, c.b); got != c.want {
			t.Errorf("SameModified(%q, %q) = %v", c.a, c.b, got)
		}
	}
}

func TestSourcePURL(t *testing.T) {
	for in, want := range map[string]string{
		"pkg:npm/lodash@4.17.15":                                                                          "pkg:npm/lodash@4.17.15",
		"pkg:npm/lodash@4.17.15?foo=bar#sub":                                                              "pkg:npm/lodash@4.17.15",
		"pkg:npm/linux-image-x@1.0":                                                                       "pkg:npm/linux-image-x@1.0",
		"pkg:deb/debian/linux@6.1.76-1?distro=debian-12":                                                  "pkg:deb/debian/linux@6.1.76-1",
		"pkg:deb/debian/libssl3@3.0.11-1?arch=amd64&upstream=openssl":                                     "pkg:deb/debian/openssl@3.0.11-1",
		"pkg:deb/debian/libfoo1@1.2-3%2Bb1?upstream=foo%401.2-3":                                          "pkg:deb/debian/foo@1.2-3",
		"pkg:deb/debian/linux-image-6.1.0-13-amd64@6.1.55-1":                                              "pkg:deb/debian/linux@6.1.55-1",
		"pkg:deb/ubuntu/linux-image-5.15.0-100-generic@5.15.0-100.110":                                    "pkg:deb/ubuntu/linux@5.15.0-100.110",
		"pkg:deb/debian/linux-base@4.9":                                                                   "pkg:deb/debian/linux-base@4.9",
		"pkg:deb/debian/linux-image-6.1.0-18-amd64@6.1.76-1?upstream=linux-signed-amd64&distro=debian-12": "pkg:deb/debian/linux@6.1.76-1",
		"pkg:apk/alpine/libssl3@3.0.8-r3?arch=x86_64&upstream=openssl&distro=alpine-3.18":                 "pkg:apk/alpine/openssl@3.0.8-r3",
		"pkg:deb/debian/openssl":                                                                          "pkg:deb/debian/openssl",
		"pkg:rpm/redhat/kernel-core@5.14.0-362.el9?arch=x86_64":                                           "pkg:rpm/redhat/kernel@5.14.0-362.el9",
		"pkg:rpm/redhat/openssl-libs@3.0.7-24.el9?upstream=openssl-3.0.7-24.el9.src.rpm":                  "pkg:rpm/redhat/openssl@3.0.7-24.el9",
	} {
		if got := sourcePURL(in); got != want {
			t.Errorf("sourcePURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPURLQuery(t *testing.T) {
	cases := []struct {
		purl, version string
		want          Query
	}{
		{"pkg:npm/lodash@4.17.15", "4.17.15", Query{Package: Package{PURL: "pkg:npm/lodash@4.17.15"}}},
		{"pkg:npm/lodash", "4.17.15", Query{Package: Package{PURL: "pkg:npm/lodash"}, Version: "4.17.15"}},
		{"pkg:deb/debian/openssl@3.0.11", "", Query{Package: Package{PURL: "pkg:deb/debian/openssl@3.0.11"}}},
		{"pkg:deb/debian/libssl3@1%3A3.0.11-1%7Edeb12u2?arch=amd64&upstream=openssl&distro=debian-12", "",
			Query{Package: Package{Name: "openssl", Ecosystem: "Debian:12"}, Version: "1:3.0.11-1~deb12u2"}},
		{"pkg:deb/debian/linux-image-amd64?distro=debian-12.5", "6.1.76-1",
			Query{Package: Package{Name: "linux", Ecosystem: "Debian:12"}, Version: "6.1.76-1"}},
		{"pkg:deb/debian/curl@7.88.1?distro=bookworm", "", Query{Package: Package{Name: "curl", Ecosystem: "Debian:12"}, Version: "7.88.1"}},
		{"pkg:deb/ubuntu/openssl@3.0.2?distro=ubuntu-22.04", "", Query{Package: Package{Name: "openssl", Ecosystem: "Ubuntu:22.04:LTS"}, Version: "3.0.2"}},
		{"pkg:deb/ubuntu/openssl@3.0.2?distro=ubuntu-23.10", "", Query{Package: Package{Name: "openssl", Ecosystem: "Ubuntu:23.10"}, Version: "3.0.2"}},
		{"pkg:deb/ubuntu/openssl@3.0.2?distro=jammy", "", Query{Package: Package{Name: "openssl", Ecosystem: "Ubuntu:22.04:LTS"}, Version: "3.0.2"}},
		{"pkg:apk/alpine/openssl@3.0.8-r3?distro=alpine-3.18.4", "", Query{Package: Package{Name: "openssl", Ecosystem: "Alpine:v3.18"}, Version: "3.0.8-r3"}},
		{"pkg:rpm/rocky/openssl@3.0.7?distro=rocky-9.3", "", Query{Package: Package{Name: "openssl", Ecosystem: "Rocky Linux:9"}, Version: "3.0.7"}},
		{"pkg:rpm/almalinux/kernel-core@5.14.0?distro=almalinux-9", "", Query{Package: Package{Name: "kernel", Ecosystem: "AlmaLinux:9"}, Version: "5.14.0"}},
		{"pkg:rpm/redhat/openssl@3.0.7?distro=rhel-9.3", "", Query{Package: Package{PURL: "pkg:rpm/redhat/openssl@3.0.7"}}},
		{"pkg:deb/debian/openssl@3.0.11?distro=sid", "", Query{Package: Package{PURL: "pkg:deb/debian/openssl@3.0.11"}}},
		// A version that differs from the purl's overrides it, and the version
		// of the source package as well.
		{"pkg:npm/lodash@4.17.15", "4.17.21", Query{Package: Package{PURL: "pkg:npm/lodash"}, Version: "4.17.21"}},
		{"pkg:npm/@babel/core@7.0.0", "7.1.0", Query{Package: Package{PURL: "pkg:npm/@babel/core"}, Version: "7.1.0"}},
		{"pkg:npm/@babel/core", "7.1.0", Query{Package: Package{PURL: "pkg:npm/@babel/core"}, Version: "7.1.0"}},
		{"pkg:deb/debian/openssl@3.0.11-1?distro=debian-12", "3.0.15-1", Query{Package: Package{Name: "openssl", Ecosystem: "Debian:12"}, Version: "3.0.15-1"}},
		{"pkg:deb/debian/libc6@2.36-9?upstream=glibc%402.36-8&distro=debian-12", "2.36-10", Query{Package: Package{Name: "glibc", Ecosystem: "Debian:12"}, Version: "2.36-10"}},
		{"pkg:rpm/rocky/openssl@3.0.7-24.el9?epoch=1&distro=rocky-9.3", "1:3.0.7-24.el9", Query{Package: Package{Name: "openssl", Ecosystem: "Rocky Linux:9"}, Version: "1:3.0.7-24.el9"}},
		// The same version, whichever way it is written, changes nothing: the
		// source package keeps its own.
		{"pkg:deb/debian/libc6@2.36-9?upstream=glibc%402.36-8&distro=debian-12", "2.36-9", Query{Package: Package{Name: "glibc", Ecosystem: "Debian:12"}, Version: "2.36-8"}},
		{"pkg:deb/debian/libssl3@1%3A3.0.11?distro=debian-12", "1:3.0.11", Query{Package: Package{Name: "libssl3", Ecosystem: "Debian:12"}, Version: "1:3.0.11"}},
		{"pkg:deb/debian/libssl3@1%3A3.0.11?distro=debian-12", "1%3A3.0.11", Query{Package: Package{Name: "libssl3", Ecosystem: "Debian:12"}, Version: "1:3.0.11"}},
	}
	for _, c := range cases {
		if got := PURLQuery(c.purl, c.version); got != c.want {
			t.Errorf("PURLQuery(%q, %q) = %+v, want %+v", c.purl, c.version, got, c.want)
		}
	}
}

func TestSourceName(t *testing.T) {
	cases := []struct{ name, ecosystem, want string }{
		{"linux-image-amd64", "Debian", "linux"},
		{"linux-image-amd64", "Debian:12", "linux"},
		{"linux", "Debian", "linux"},
		{"linux-base", "Debian", "linux-base"},
		{"openssl", "Debian", "openssl"},
		{"kernel-core", "Rocky Linux:9", "kernel"},
		{"kernel", "AlmaLinux", "kernel"},
		{"linux-image-amd64", "Red Hat", "linux-image-amd64"},
		{"kernel-core", "npm", "kernel-core"},
		{"Linux Kernel", "Linux", "Kernel"},
	}
	for _, c := range cases {
		if got := SourceName(c.name, c.ecosystem); got != c.want {
			t.Errorf("SourceName(%q, %q) = %q, want %q", c.name, c.ecosystem, got, c.want)
		}
	}
}

func TestOtherIDs(t *testing.T) {
	v := Vuln{Aliases: []string{"CVE-1"}, Upstream: []string{"CVE-1", "CVE-2"}}
	if got := v.OtherIDs(); len(got) != 2 || got[0] != "CVE-1" || got[1] != "CVE-2" {
		t.Errorf("OtherIDs = %v", got)
	}
	if len(v.Aliases) != 1 {
		t.Errorf("aliases changed: %v", v.Aliases)
	}
}

// The kernel's ranges, one per stable branch, as OSV gives them from kernel.org.
func TestAffects(t *testing.T) {
	const doc = `{"affected":[{"ranges":[{"type":"GIT","events":[{"introduced":"abc"},{"fixed":"def"}]}]},
		{"package":{"name":"Kernel","ecosystem":"Linux"},"ranges":[
		{"type":"ECOSYSTEM","events":[{"introduced":"2.6.27"},{"fixed":"5.10.272"}]},
		{"type":"ECOSYSTEM","events":[{"introduced":"5.11.0"},{"fixed":"5.15.223"}]},
		{"type":"ECOSYSTEM","events":[{"introduced":"6.19.0"},{"fixed":"7.2.11"}]}]}]}`
	var v Vuln
	if err := json.Unmarshal([]byte(doc), &v); err != nil {
		t.Fatal(err)
	}
	kernel := Package{Name: "Kernel", Ecosystem: "Linux"}
	for version, want := range map[string]bool{
		"2.6.26": false, "5.10.271": true, "5.10.272": false, "5.15.0": true, "5.15.223": false,
		"6.1.100": false, "7.2.10": true, "7.2.11": false, "7.3": false, "5.15.0-100-generic": true,
	} {
		if got := v.Affects(kernel, version); got != want {
			t.Errorf("Affects(%q) = %v, want %v", version, got, want)
		}
	}
	if v.Affects(Package{Name: "linux", Ecosystem: "Debian"}, "5.15.0") {
		t.Error("the ranges of another package count")
	}
	v.Withdrawn = "2026-01-01T00:00:00Z"
	if v.Affects(kernel, "5.15.0") {
		t.Error("a withdrawn advisory affects nothing")
	}
	var listed Vuln
	json.Unmarshal([]byte(`{"affected":[{"package":{"name":"Kernel","ecosystem":"Linux"},"versions":["6.8.1"]}]}`), &listed)
	if !listed.Affects(kernel, "6.8.1") || listed.Affects(kernel, "6.8.2") {
		t.Error("a version listed by the advisory")
	}
}

func TestIntervals(t *testing.T) {
	r := Range{Type: "SEMVER", Events: []map[string]string{{"introduced": "0"}, {"fixed": "1.0"}, {"introduced": "2.0"}, {"last_affected": "2.5"}, {"introduced": "3.0"}}}
	got := r.Intervals()
	if len(got) != 3 || got[0].Fixed != "1.0" || got[1].LastAffected != "2.5" || got[2].Start != "3.0" || got[2].Fixed != "" {
		t.Errorf("intervals = %+v", got)
	}
	if git := (Range{Type: "GIT", Events: r.Events}); git.Intervals() != nil {
		t.Error("a range of commits has no intervals of versions")
	}
}

// A page is read advisory by advisory, whatever the order of its fields, and
// the reading can stop at any moment.
func TestAdvisoriesStream(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"next_page_token":"","other":[1,{"a":2}],"vulns":[{"id":"A"},{"id":"B"}]}`))
	}))
	defer srv.Close()
	c := &Client{URL: srv.URL, HTTP: http.DefaultClient}
	if got := query(t, c, Query{}); len(got) != 2 || got[1].ID != "B" {
		t.Errorf("advisories = %+v", got)
	}
	list := c.Advisories(Query{})
	if !list.Next(context.Background()) || list.Vuln().ID != "A" {
		t.Errorf("first advisory = %+v, %v", list.Vuln(), list.Err())
	}
	list.Close() // before the end: nothing left open
	list.Close()
	for name, doc := range map[string]string{"truncated": `{"vulns":[{"id":"A"}`, "cut after the list": `{"vulns":[{"id":"A"}]`, "not an object": `[]`, "not a list": `{"vulns":3}`, "empty": ``} {
		bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(doc)) }))
		c.URL = bad.URL
		list := c.Advisories(Query{})
		for list.Next(context.Background()) {
		}
		if list.Err() == nil {
			t.Errorf("%s: no error", name)
		}
		bad.Close()
	}
}

// cutPage sends the start of a page, then loses the connection: the body ends
// before the length announced, as when OSV closes it (HTTP/2 GOAWAY).
func cutPage(w http.ResponseWriter, start string) {
	w.Header().Set("Content-Length", strconv.Itoa(len(start)+1000))
	io.WriteString(w, start)
	w.(http.Flusher).Flush()
	if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
		conn.Close()
	}
}

// A page cut by the network is asked for again and read from its start, what
// was already returned skipped; a cut that lasts ends the reading, with an error
// that says so rather than "unreadable".
func TestAdvisoriesCutPage(t *testing.T) {
	var tokens []any
	cuts := 1
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		tokens = append(tokens, body["page_token"])
		page := `{"vulns":[{"id":"A"},{"id":"B"},{"id":"C"}],"next_page_token":"p2"}`
		if body["page_token"] == "p2" {
			page = `{"vulns":[{"id":"D"}]}`
		} else if cuts > 0 {
			cuts--
			cutPage(w, page[:strings.Index(page, `{"id":"C"}`)]) // A and B sent
			return
		}
		io.WriteString(w, page)
	}))
	defer srv.Close()
	c := &Client{URL: srv.URL, HTTP: http.DefaultClient}
	var ids []string
	for _, v := range query(t, c, Query{Package: Package{Name: "linux", Ecosystem: "Ubuntu:22.04:LTS"}, Version: "5.15.0-100.110"}) {
		ids = append(ids, v.ID)
	}
	if strings.Join(ids, " ") != "A B C D" || len(tokens) != 3 || tokens[0] != nil || tokens[1] != nil || tokens[2] != "p2" {
		t.Errorf("advisories %v, page tokens asked %v", ids, tokens)
	}

	tokens, cuts = nil, 10
	list := c.Advisories(Query{})
	n := 0
	for list.Next(context.Background()) {
		n++
	}
	err := list.Err()
	if err == nil || strings.Contains(err.Error(), "illisible") || !strings.Contains(err.Error(), "lecture interrompue") {
		t.Errorf("lasting cut: %v", err)
	}
	if n != 2 || len(tokens) != 1+len(retryDelays) {
		t.Errorf("lasting cut: %d advisories, %d requests", n, len(tokens))
	}
}

// A reply that never ends is cut.
func TestAdvisoriesPagesBound(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Write([]byte(`{"next_page_token":"more"}`))
	}))
	defer srv.Close()
	c := &Client{URL: srv.URL, HTTP: http.DefaultClient}
	list := c.Advisories(Query{})
	for list.Next(context.Background()) {
	}
	if list.Err() == nil || calls != maxQueryPages {
		t.Errorf("%d calls, %v", calls, list.Err())
	}
}

func TestComparesVersions(t *testing.T) {
	if ComparesVersions("Linux") || !ComparesVersions("Debian:12") || !ComparesVersions("") {
		t.Error("only the Linux ecosystem is compared by Vigil")
	}
}

// A temporary failure is tried again, a few times; a definite refusal is not.
func TestRetries(t *testing.T) {
	calls, codes := 0, []int{http.StatusBadGateway, http.StatusTooManyRequests}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls <= len(codes) {
			w.WriteHeader(codes[calls-1])
			return
		}
		w.Write([]byte(`{"results":[{}]}`))
	}))
	defer srv.Close()
	c := &Client{URL: srv.URL, HTTP: http.DefaultClient}
	if _, err := c.QueryBatch(context.Background(), make([]Query, 1)); err != nil || calls != 3 {
		t.Errorf("temporary failures: %d calls, %v", calls, err)
	}
	calls, codes = 0, []int{503, 503, 503, 503}
	if _, err := c.QueryBatch(context.Background(), make([]Query, 1)); err == nil || calls != 3 {
		t.Errorf("lasting failure: %d calls, %v", calls, err)
	}
	calls, codes = 0, []int{http.StatusBadRequest}
	if _, err := c.QueryBatch(context.Background(), make([]Query, 1)); err == nil || calls != 1 {
		t.Errorf("refusal: %d calls, %v", calls, err)
	}
}

// What is kept of an advisory is what tells the versions fixing it: an
// advisory of a distribution lists hundreds of binaries and versions.
func TestCompact(t *testing.T) {
	const doc = `{"id":"UBUNTU-CVE-1","details":"long text","published":"2026-01-01T00:00:00Z","references":[{"url":"https://a.example"}],
		"affected":[
		{"ranges":[{"type":"GIT","repo":"https://git.example","events":[{"introduced":"abc"},{"fixed":"def"}]}]},
		{"package":{"name":"linux","ecosystem":"Ubuntu:22.04:LTS","purl":"pkg:deb/ubuntu/linux?distro=jammy"},
		 "versions":["5.15.0-1.1","5.15.0-2.2"],"ecosystem_specific":{"binaries":[{"binary_name":"linux-image"}]},"database_specific":{"source":"x"},
		 "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"5.15.0-3.3"}]},{"type":"GIT","events":[{"introduced":"abc"}]}]}]}`
	var v Vuln
	if err := json.Unmarshal([]byte(doc), &v); err != nil {
		t.Fatal(err)
	}
	const want = `{"id":"UBUNTU-CVE-1","affected":[{"package":{"name":"linux","ecosystem":"Ubuntu:22.04:LTS","purl":"pkg:deb/ubuntu/linux?distro=jammy"},` +
		`"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"5.15.0-3.3"}]}]}]}`
	if got := string(v.Compact()); got != want {
		t.Errorf("Compact = %s\nwant      %s", got, want)
	}
	var kept Vuln
	if err := json.Unmarshal(v.Compact(), &kept); err != nil {
		t.Fatal(err)
	}
	pkg := Package{Name: "linux", Ecosystem: "Ubuntu:22.04:LTS"}
	if !kept.Affects(pkg, "5.15.0-2.2") || kept.Affects(pkg, "5.15.0-3.3") {
		t.Errorf("the ranges must survive: %+v", kept)
	}
	if none := (Vuln{ID: "X"}).Compact(); string(none) != `{"id":"X"}` {
		t.Errorf("an advisory without package: %s", none)
	}
}
