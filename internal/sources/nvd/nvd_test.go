package nvd

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

const sample = `{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2024-21762",
 "published":"2024-02-09T09:15:08.087","lastModified":"2024-02-13T16:00:00.000",
 "descriptions":[{"lang":"en","value":"A out-of-bounds write in Fortinet FortiOS. Details follow."}],
 "metrics":{"cvssMetricV31":[{"cvssData":{"baseSeverity":"CRITICAL"}}]},
 "references":[{"url":"https://fortiguard.com/psirt/FG-IR-24-015"},{"url":"javascript:alert(1)"}]}}]}`

func TestForCPE(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("cpeName"); got != "cpe:2.3:o:fortinet:fortios:7.2.4:*:*:*:*:*:*:*" {
			t.Errorf("cpeName = %q", got)
		}
		io.WriteString(w, sample)
	}))
	defer srv.Close()
	c := &Client{URL: srv.URL, HTTP: srv.Client()}
	cves, err := c.ForCPE(context.Background(), WithVersion("cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", "7.2.4"))
	if err != nil {
		t.Fatal(err)
	}
	if len(cves) != 1 || cves[0].ID != "CVE-2024-21762" || cves[0].Severity != "CRITICAL" || len(cves[0].Refs) != 1 {
		t.Fatalf("unexpected: %+v", cves)
	}
}

func TestWholeProduct(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("virtualMatchString") == "" || q.Get("pubStartDate") == "" {
			t.Errorf("subscription query expected, got %s", r.URL.RawQuery)
		}
		io.WriteString(w, `{"totalResults":0,"vulnerabilities":[]}`)
	}))
	defer srv.Close()
	c := &Client{URL: srv.URL, HTTP: srv.Client()}
	if _, err := c.ForCPE(context.Background(), "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ForCPE(context.Background(), "cpe:2.3:bad"); err == nil {
		t.Fatal("invalid CPE accepted")
	}
}
