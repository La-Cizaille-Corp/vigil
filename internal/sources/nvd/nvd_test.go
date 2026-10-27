package nvd

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const sample = `{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2024-21762",
 "published":"2024-02-09T09:15:08.087","lastModified":"2024-02-13T16:00:00.000",
 "descriptions":[{"lang":"en","value":"A out-of-bounds write in Fortinet FortiOS. Details follow."}],
 "metrics":{"cvssMetricV31":[{"cvssData":{"baseSeverity":"CRITICAL","baseScore":9.8}}]},
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
	cves, err := c.ForCPE(context.Background(), Query{CPE: "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", Version: "7.2.4"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cves) != 1 || cves[0].ID != "CVE-2024-21762" || cves[0].Severity != "CRITICAL" || cves[0].CVSS != 9.8 || len(cves[0].Refs) != 1 {
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
	if _, err := c.ForCPE(context.Background(), Query{CPE: "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ForCPE(context.Background(), Query{CPE: "cpe:2.3:bad"}); err == nil {
		t.Fatal("invalid CPE accepted")
	}
}

func TestModes(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.URL.RawQuery)
		io.WriteString(w, `{"totalResults":0,"vulnerabilities":[]}`)
	}))
	defer srv.Close()
	c := &Client{URL: srv.URL, HTTP: srv.Client()}
	ctx := context.Background()
	// A versioned CPE is widened to the product for product-wide modes.
	cpe := "cpe:2.3:o:fortinet:fortios:7.2.4:*:*:*:*:*:*:*"
	for _, q := range []Query{{CPE: cpe, Mode: "all"}, {CPE: cpe, Mode: "from", From: "7.0.0"}} {
		if _, err := c.ForCPE(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	if !strings.Contains(got[0], "virtualMatchString=cpe%3A2.3%3Ao%3Afortinet%3Afortios%3A%2A") || strings.Contains(got[0], "pubStartDate") {
		t.Errorf("all: %s", got[0])
	}
	if !strings.Contains(got[1], "versionStart=7.0.0") || !strings.Contains(got[1], "versionStartType=including") {
		t.Errorf("from: %s", got[1])
	}
	if _, err := c.ForCPE(ctx, Query{CPE: cpe, Mode: "from"}); err == nil {
		t.Error("from without version accepted")
	}
}
