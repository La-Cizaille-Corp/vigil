package osv

import (
	"context"
	"encoding/json"
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

// Query reads every page, without a version, and keeps each record whole.
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
	vulns, err := c.Query(context.Background(), Package{PURL: "pkg:npm/x"})
	if err != nil {
		t.Fatal(err)
	}
	if len(vulns) != 2 || vulns[0].ID != "GHSA-1" || vulns[1].ID != "GHSA-2" || len(vulns[1].Raw) == 0 || len(vulns[1].Affected) != 1 {
		t.Fatalf("vulns = %+v", vulns)
	}
	if len(bodies) != 2 || bodies[0]["version"] != nil || bodies[1]["page_token"] != "p2" {
		t.Errorf("requests = %v", bodies)
	}
}
