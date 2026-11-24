package nvd

import (
	"context"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/La-Cizaille-Corp/vigil/internal/versions"
)

// awaiting builds a record as the NVD relays it before its analysis: no
// configuration, the "affected" list of its CNA. The shapes are those of
// CVE-2026-16545 (GitLab), CVE-2026-132825 (Ruby) and CVE-2026-124002 (XWEB
// EVO), November 2026.
func awaiting(id string, affected ...string) CVE {
	return CVE{ID: id, Description: "A flaw.", Raw: []byte(`{"id":"` + id + `","vulnStatus":"Awaiting Analysis",
		"affected":[{"source":"cna@example.org","affectedData":[` + strings.Join(affected, ",") + `]}]}`)}
}

const (
	gitlabAffected = `{"vendor":"GitLab","product":"GitLab","defaultStatus":"unaffected","versions":[
		{"version":"12.10","lessThan":"19.3.9","versionType":"semver","status":"affected"},
		{"version":"19.4","lessThan":"19.4.8","versionType":"semver","status":"affected"},
		{"version":"19.5","lessThan":"19.5.6","versionType":"semver","status":"affected"}]}`
	rubyAffected = `{"vendor":"ruby-lang","product":"Ruby","defaultStatus":"unaffected","versions":[
		{"version":"0","lessThan":"3.3.14","versionType":"semver","status":"affected"}]}`
	xwebAffected = `{"vendor":"Copeland","product":"XWEB EVO","defaultStatus":"unaffected","versions":[
		{"version":"5.2.3","lessThan":"5.7.0","versionType":"semver","status":"affected"},
		{"version":"5.7.0","versionType":"semver","status":"unaffected"}]}`
	runnerAffected = `{"vendor":"GitLab","product":"GitLab Runner","versions":[
		{"version":"0","lessThan":"18.6.0","versionType":"semver","status":"affected"}]}`
	silentAffected = `{"vendor":"n/a","product":"n/a","versions":[{"version":"n/a","status":"affected"}]}`
	// The kernel's CNA (CVE-2026-99312): commits, then every version from 6.1
	// but the fixed branches.
	kernelAffected = `{"vendor":"Linux","product":"Linux","defaultStatus":"unaffected","versions":[
		{"version":"6425c590d0cc","lessThan":"97be39acdbd7","versionType":"git","status":"affected"}]},
		{"vendor":"Linux","product":"Linux","defaultStatus":"affected","versions":[
		{"version":"6.1","status":"affected"},
		{"version":"0","lessThan":"6.1","versionType":"semver","status":"unaffected"},
		{"version":"6.6.163","lessThanOrEqual":"6.6.*","versionType":"semver","status":"unaffected"}]}`
)

// What a CNA declares becomes the matches of a record the NVD has not
// analysed; what cannot be compared is left out.
func TestDeclared(t *testing.T) {
	declared := func(start, fixed, last string) Match {
		return Match{Version: "*", Range: versions.Range{Start: start, Fixed: fixed, LastAffected: last}, Declared: true}
	}
	gitlab := func(m Match) Match { m.Vendor, m.Product = "GitLab", "GitLab"; return m }
	ivanti := func(m Match) Match { m.Vendor, m.Product = "Ivanti", "Connect Secure"; return m }
	got := Matches(awaiting("CVE-2026-0001", gitlabAffected, silentAffected, kernelAffected,
		`{"vendor":"Ivanti","product":"Connect Secure","versions":[
			{"version":"22.7R2.3","status":"affected"},
			{"version":"unspecified","status":"affected"},
			{"version":"9.0","lessThanOrEqual":"9.1R18","status":"affected"},
			{"version":"n/a","lessThan":"*","status":"affected"},
			{"version":"*","status":"affected"},
			{"version":"22.8","lessThan":"22.8R2","status":"unknown"}]}`).Raw)
	want := []Match{
		gitlab(declared("12.10", "19.3.9", "")), gitlab(declared("19.4", "19.4.8", "")), gitlab(declared("19.5", "19.5.6", "")),
		ivanti(Match{Version: "22.7R2.3", Declared: true}), ivanti(declared("9.0", "", "9.1R18")),
		ivanti(declared("", "", "")), ivanti(declared("", "", "")),
	}
	if !slices.Equal(got, want) {
		t.Errorf("declared:\n got %+v\nwant %+v", got, want)
	}

	// Once analysed, the configurations alone count.
	analysed := `{"id":"CVE-2026-0002","configurations":[{"nodes":[{"cpeMatch":[` + fixedRange + `]}]}],
		"affected":[{"affectedData":[` + gitlabAffected + `]}]}`
	if got := Matches([]byte(analysed)); len(got) != 1 || got[0].Declared || got[0].Product != "connect_secure" {
		t.Errorf("analysed: %+v", got)
	}
	// An "affected" list of another shape is not an answer: nothing is
	// declared, as without one.
	if got := Matches([]byte(`{"id":"CVE-2026-0003","affected":{"vendor":"GitLab"}}`)); got != nil {
		t.Errorf("unreadable list: %+v", got)
	}
}

// A declared product is named in words: it must be the CPE's, vendor and
// product, not merely share a word with it.
func TestOfCPE(t *testing.T) {
	fields := func(cpe string) []string {
		f, ok := SplitCPE(cpe)
		if !ok {
			t.Fatalf("CPE %s", cpe)
		}
		return f
	}
	for _, c := range []struct {
		vendor, product string
		declared        bool
		cpe             string
		want            bool
	}{
		{"ivanti", "connect_secure", false, "cpe:2.3:a:ivanti:connect_secure:22.7:*:*:*:*:*:*:*", true},
		{"ivanti", "connect_secure_x", false, "cpe:2.3:a:ivanti:connect_secure:22.7:*:*:*:*:*:*:*", false},
		{"ivanti", "policy_secure", false, WholeVendor("ivanti"), true},
		{"GitLab", "GitLab", true, "cpe:2.3:a:gitlab:gitlab:19.5.3:*:*:*:enterprise:*:*:*", true},
		{"GitLab", "GitLab Runner", true, "cpe:2.3:a:gitlab:gitlab:19.5.3:*:*:*:enterprise:*:*:*", false},
		{"GitLab", "GitLab Runner", true, WholeVendor("gitlab"), true},
		{"Apache Software Foundation", "Apache HTTP Server", true, "cpe:2.3:a:apache:http_server:2.4.62:*:*:*:*:*:*:*", true},
		{"ruby-lang", "Ruby", true, "cpe:2.3:a:ruby-lang:ruby:3.3.10:*:*:*:*:*:*:*", true},
		{"Ruby", "Ruby", true, "cpe:2.3:a:ruby-lang:ruby:3.3.10:*:*:*:*:*:*:*", false},
		{"Copeland", "XWEB EVO", true, "cpe:2.3:a:gitlab:gitlab:19.5.3:*:*:*:*:*:*:*", false},
	} {
		m := Match{Vendor: c.vendor, Product: c.product, Declared: c.declared}
		if got := m.OfCPE(fields(c.cpe)); got != c.want {
			t.Errorf("%s %s for %s: %v", c.vendor, c.product, c.cpe, got)
		}
	}
}

func TestReaches(t *testing.T) {
	for _, c := range []struct {
		m    Match
		from string
		want bool
	}{
		{Match{Version: "*", Range: versions.Range{Start: "19.5", Fixed: "19.5.6"}}, "19.5.4", true},
		{Match{Version: "*", Range: versions.Range{Start: "19.5", Fixed: "19.5.6"}}, "19.5.6", false},
		{Match{Version: "*", Range: versions.Range{LastAffected: "9.1R18"}}, "9.1R18", true},
		{Match{Version: "*", Range: versions.Range{LastAffected: "9.1R18"}}, "22.7", false},
		{Match{Version: "*"}, "99", true},
		{Match{Version: "22.7R2.3"}, "22.7", true},
		{Match{Version: "9.1"}, "22.7", false},
	} {
		if got := c.m.Reaches(c.from); got != c.want {
			t.Errorf("%+v from %s: %v", c.m, c.from, got)
		}
	}
}

// Searched by its name, an asset keeps a CVE awaiting analysis only when its
// CNA declares nothing that can be compared, or declares the asset, at its
// version: "end of service date" no longer brings XWEB EVO to an asset named
// date.
func TestNameAffectsDeclared(t *testing.T) {
	for _, c := range []struct {
		name       string
		c          CVE
		asset, ver string
		latest     bool
		want       bool
	}{
		{"another product", awaiting("CVE-1", xwebAffected), "date", "3.0.4", false, false},
		{"the product, in range", awaiting("CVE-1", gitlabAffected), "GitLab", "19.5.3", false, true},
		{"the product, fixed", awaiting("CVE-1", gitlabAffected), "GitLab", "19.5.6", false, false},
		{"the product, no version", awaiting("CVE-1", gitlabAffected), "GitLab", "", false, true},
		{"the product, latest", awaiting("CVE-1", gitlabAffected), "GitLab", "latest", true, false},
		{"nothing comparable", awaiting("CVE-1", silentAffected), "date", "3.0.4", false, true},
		{"affected by default", awaiting("CVE-1", kernelAffected), "Linux Kernel", "6.12.3", false, true},
	} {
		if got := NameAffects(c.c, c.asset, c.ver, c.latest); got != c.want {
			t.Errorf("%s: %v", c.name, got)
		}
	}
	if !UnfixedFor(awaiting("CVE-1", `{"vendor":"GitLab","product":"GitLab","versions":[{"version":"19.0","lessThan":"*","status":"affected"}]}`),
		"cpe:2.3:a:gitlab:gitlab:*:*:*:*:*:*:*:*") || UnfixedFor(awaiting("CVE-1", gitlabAffected), "cpe:2.3:a:gitlab:gitlab:*:*:*:*:*:*:*:*") {
		t.Error("latest release of a declared product")
	}
}

// A CPE also gets the CVEs awaiting analysis that the CNA declares for its
// product, at the versions of the query; the others found by the name of the
// product are dropped.
func TestForCPEDeclared(t *testing.T) {
	record := func(c CVE) string { return `{"cve":` + string(c.Raw) + `}` }
	named := []string{
		record(awaiting("CVE-2026-0001", gitlabAffected)), // 19.5 before 19.5.6
		record(awaiting("CVE-2026-0002", `{"vendor":"GitLab","product":"GitLab","versions":[{"version":"19.5","lessThan":"19.5.2","status":"affected"}]}`)),
		record(awaiting("CVE-2026-0003", runnerAffected)),
		record(awaiting("CVE-2026-0004", silentAffected)),
		`{"cve":{"id":"CVE-2026-0005","vulnStatus":"Analyzed","configurations":[{"nodes":[{"cpeMatch":[` +
			`{"vulnerable":true,"criteria":"cpe:2.3:a:gitlab:gitlab:*:*:*:*:*:*:*:*","versionEndExcluding":"19.5.6"}]}]}]}}`,
		record(awaiting("CVE-2026-0006", rubyAffected)),
	}
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		switch {
		case q.Get("keywordSearch") == "gitlab":
			io.WriteString(w, `{"totalResults":6,"vulnerabilities":[`+strings.Join(named, ",")+`]}`)
		case q.Has("cpeName") || q.Has("virtualMatchString"): // the NVD's analysis: CVE-2026-0005 is not the version's
			io.WriteString(w, `{"totalResults":0,"vulnerabilities":[]}`)
		default:
			t.Errorf("unexpected query %s", r.URL.RawQuery)
			w.WriteHeader(http.StatusTeapot)
		}
	})
	cpe := "cpe:2.3:a:gitlab:gitlab:19.5.3:*:*:*:enterprise:*:*:*"
	for _, q := range []struct {
		query Query
		want  []string
	}{
		{Query{CPE: cpe}, []string{"CVE-2026-0001"}},
		{Query{CPE: cpe, Mode: "from", From: "19.5.4"}, []string{"CVE-2026-0001"}},
		{Query{CPE: cpe, Mode: "from", From: "19.6"}, nil},
		{Query{CPE: cpe, Mode: "all"}, []string{"CVE-2026-0001", "CVE-2026-0002"}},
		// Every product of the vendor, searched by the vendor's name.
		{Query{CPE: WholeVendor("gitlab")}, []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"}},
	} {
		cves, err := c.ForCPE(context.Background(), q.query)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, cve := range cves {
			got = append(got, cve.ID)
		}
		if !slices.Equal(got, q.want) {
			t.Errorf("%+v: %v, want %v", q.query, got, q.want)
		}
	}
}
