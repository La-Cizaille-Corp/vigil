package osv

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
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
	} {
		if got := WithoutVersion(in); got != want {
			t.Errorf("WithoutVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

// query collects what Each visits.
func query(t *testing.T, c *Client, q Query) []Vuln {
	t.Helper()
	var out []Vuln
	if err := c.Each(context.Background(), q, func(v Vuln) error {
		out = append(out, v)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// Each reads every page, without a version, and keeps each record whole.
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
	c := New("test")
	c.BaseURL = srv.URL
	vulns := query(t, c, Query{Package: Package{PURL: "pkg:npm/x"}})
	if len(vulns) != 2 || vulns[0].ID != "GHSA-1" || vulns[1].ID != "GHSA-2" || len(vulns[1].Raw) == 0 || len(vulns[1].Affected) != 1 {
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
	c := New("test")
	c.BaseURL = srv.URL
	got, err := c.QueryBatch(context.Background(), make([]Query, 3))
	if err != nil {
		t.Fatal(err)
	}
	if !got[0].More || got[1].More || got[2].More || len(got[1].Vulns) != 1 || len(got[2].Vulns) != 0 {
		t.Errorf("results = %+v", got)
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
		if got := SourcePURL(in); got != want {
			t.Errorf("SourcePURL(%q) = %q, want %q", in, got, want)
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

// A page is read advisory by advisory, whatever the order of its fields, and a
// visitor can stop the reading.
func TestEachStreams(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"next_page_token":"","other":[1,{"a":2}],"vulns":[{"id":"A"},{"id":"B"}]}`))
	}))
	defer srv.Close()
	c := New("test")
	c.BaseURL = srv.URL
	if got := query(t, c, Query{}); len(got) != 2 || got[1].ID != "B" || string(got[1].Raw) != `{"id":"B"}` {
		t.Errorf("advisories = %+v", got)
	}
	stop := errors.New("stop")
	seen := 0
	if err := c.Each(context.Background(), Query{}, func(Vuln) error {
		seen++
		return stop
	}); !errors.Is(err, stop) || seen != 1 {
		t.Errorf("stopping: %d, %v", seen, err)
	}
	for name, doc := range map[string]string{"truncated": `{"vulns":[{"id":"A"}`, "not an object": `[`} {
		bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(doc)) }))
		c.BaseURL = bad.URL
		if err := c.Each(context.Background(), Query{}, func(Vuln) error { return nil }); err == nil {
			t.Errorf("%s: no error", name)
		}
		bad.Close()
	}
}

func TestComparesVersions(t *testing.T) {
	if ComparesVersions("Linux") || !ComparesVersions("Debian:12") || !ComparesVersions("") {
		t.Error("only the Linux ecosystem is compared by Vigil")
	}
}
