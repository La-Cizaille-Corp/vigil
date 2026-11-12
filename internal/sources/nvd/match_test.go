package nvd

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// cve builds a record whose configurations list the given cpeMatch entries.
func cve(matches string) CVE {
	return CVE{ID: "CVE-2026-0001", Raw: []byte(`{"id":"CVE-2026-0001","configurations":[{"nodes":[{"cpeMatch":[` + matches + `]}]}]}`)}
}

const (
	fixedRange = `{"vulnerable":true,"criteria":"cpe:2.3:a:ivanti:connect_secure:*:*:*:*:*:*:*:*","versionStartIncluding":"22.0","versionEndExcluding":"22.7"}`
	upTo       = `{"vulnerable":true,"criteria":"cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*","versionStartIncluding":"7.2.0","versionEndIncluding":"7.2.13"}`
	release    = `{"vulnerable":true,"criteria":"cpe:2.3:a:ivanti:connect_secure:22.8:r2:*:*:*:*:*:*"}`
	open       = `{"vulnerable":true,"criteria":"cpe:2.3:a:ivanti:connect_secure:*:*:*:*:*:*:*:*","versionStartIncluding":"22.7"}`
	other      = `{"vulnerable":true,"criteria":"cpe:2.3:a:ivanti:policy_secure:*:*:*:*:*:*:*:*"}`
	platform   = `{"vulnerable":false,"criteria":"cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"}`
)

func TestNamed(t *testing.T) {
	m := Match{Vendor: "microsoft", Product: "exchange_server"}
	for name, want := range map[string]bool{
		"Exchange Server": true, "Microsoft Exchange Server 2019": true, "exchange": true,
		"Exchange Online": false, "": false,
	} {
		if got := m.Named(name); got != want {
			t.Errorf("Named(%q) = %v, want %v", name, got, want)
		}
	}
	if !(Match{Vendor: "f5", Product: "nginx"}).Named("nginx frontal") {
		t.Error("product words in the name")
	}
	if !(Match{Vendor: "nodejs", Product: `node\.js`}).Named("Node.js") {
		t.Error("escaped CPE field")
	}
}

func TestAffects(t *testing.T) {
	r := Match{Version: "22.8", Update: "*"}
	for v, want := range map[string]bool{"22.8": true, "22.8R2": true, "22.8r2.1": true, "22.8.1": false, "22.81": false, "22.7": false} {
		if got := r.Affects(v); got != want {
			t.Errorf("release 22.8 affects %q = %v, want %v", v, got, want)
		}
	}
	base := Match{Version: "22.7", Update: "-"}
	if !base.Affects("22.7") || base.Affects("22.7R2.3") {
		t.Error("release without update")
	}
	u := Match{Version: "22.7", Update: "r2.1"}
	for v, want := range map[string]bool{"22.7R2.1": true, "22.7r2.1": true, "22.7": true, "22.7R2.3": false, "22.7R2": false} {
		if got := u.Affects(v); got != want {
			t.Errorf("release 22.7 r2.1 affects %q = %v, want %v", v, got, want)
		}
	}
}

func TestNameAffects(t *testing.T) {
	cases := []struct {
		name          string
		c             CVE
		asset, ver    string
		latest, wants bool
	}{
		{"awaiting analysis", CVE{Raw: []byte(`{"id":"CVE-1"}`)}, "Connect Secure", "22.7", false, true},
		{"in a range", cve(fixedRange), "Ivanti Connect Secure", "22.6R1", false, true},
		{"after the fix", cve(fixedRange), "Ivanti Connect Secure", "22.7.1", false, false},
		{"release named", cve(fixedRange + "," + release), "Connect Secure", "22.8R2", false, true},
		{"no version", cve(fixedRange), "Connect Secure", "", false, true},
		{"product not named", cve(other + "," + platform), "Connect Secure", "22.6", false, false},
		{"update named", cve(release), "Connect Secure", "22.8R1", false, false},
		{"latest, fixed", cve(fixedRange + "," + release), "Connect Secure", "latest", true, false},
		{"latest, open", cve(fixedRange + "," + open), "Connect Secure", "latest", true, true},
		{"latest, up to a version", cve(upTo), "FortiOS", "latest", true, false},
		{"latest, other product open", cve(fixedRange + "," + other), "Connect Secure", "latest", true, false},
		{"latest, nothing named", cve(other + "," + platform), "Pulse", "latest", true, false},
	}
	for _, c := range cases {
		if got := NameAffects(c.c, c.asset, c.ver, c.latest); got != c.wants {
			t.Errorf("%s: NameAffects = %v, want %v", c.name, got, c.wants)
		}
	}
}

func TestSplitCPE(t *testing.T) {
	f, ok := SplitCPE(`cpe:2.3:a:lemonldap-ng:lemonldap\:\:ng:*:*:*:*:*:*:*:*`)
	if !ok || f[3] != "lemonldap-ng" || f[4] != `lemonldap\:\:ng` || f[5] != "*" {
		t.Errorf("fields = %q", f)
	}
	if !(Match{Vendor: "lemonldap-ng", Product: f[4]}).Named("LemonLDAP::NG") {
		t.Error("escaped product not named")
	}
	// An ordinary CPE, and an escaped backslash before a separator.
	f, ok = SplitCPE("cpe:2.3:o:fortinet:fortios:7.2.4:*:*:*:*:*:*:*")
	if want := "cpe|2.3|o|fortinet|fortios|7.2.4|*|*|*|*|*|*|*"; !ok || strings.Join(f, "|") != want {
		t.Errorf("fields = %q", f)
	}
	if f, ok := SplitCPE(`cpe:2.3:a:v:p\\:1:*:*:*:*:*:*:*`); !ok || f[4] != `p\\` || f[5] != "1" {
		t.Errorf("fields = %q", f)
	}
	for _, bad := range []string{"", "cpe:2.3:bad", "cpe:2.2:a:v:p:1:*:*:*:*:*:*:*",
		"cpe:2.3:a:v:p:1:*:*:*:*:*:*:*:extra", `cpe:2.3:a:v:p\:1:*:*:*:*:*:*:*`} {
		if f, ok := SplitCPE(bad); ok || f != nil {
			t.Errorf("%q accepted: %q", bad, f)
		}
	}
}

func TestUnfixedFor(t *testing.T) {
	product := "cpe:2.3:a:ivanti:connect_secure:*:*:*:*:*:*:*:*"
	if UnfixedFor(cve(fixedRange+","+release), product) || !UnfixedFor(cve(open), product) {
		t.Error("product")
	}
	if UnfixedFor(cve(other), product) || !UnfixedFor(cve(other), WholeVendor("ivanti")) {
		t.Error("vendor")
	}
}

// The name is searched as a phrase over the tracked period; rejected CVEs
// are dropped.
func TestForKeyword(t *testing.T) {
	var got []url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.URL.Query())
		io.WriteString(w, `{"totalResults":2,"vulnerabilities":[
			{"cve":{"id":"CVE-2026-0001","vulnStatus":"Awaiting Analysis","descriptions":[{"lang":"en","value":"A flaw in Ivanti Connect Secure."}]}},
			{"cve":{"id":"CVE-2026-0002","vulnStatus":"Rejected","descriptions":[{"lang":"en","value":"Rejected reason: duplicate."}]}}]}`)
	}))
	defer srv.Close()
	c := &Client{URL: srv.URL, HTTP: srv.Client()}
	cves, err := c.ForKeyword(context.Background(), "Ivanti Connect Secure", time.Now().Add(-30*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(cves) != 1 || cves[0].ID != "CVE-2026-0001" {
		t.Errorf("cves = %+v", cves)
	}
	if len(got) != 2 || got[0].Get("keywordSearch") != "Ivanti Connect Secure" || !got[0].Has("keywordExactMatch") ||
		got[0].Get("pubStartDate") == "" || !got[1].Has("hasKev") || !got[1].Has("keywordExactMatch") {
		t.Errorf("requests = %v", got)
	}
	if _, err := c.ForKeyword(context.Background(), " ", time.Time{}); err == nil {
		t.Error("empty search accepted")
	}
}
