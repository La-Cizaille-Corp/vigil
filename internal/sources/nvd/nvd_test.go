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

const sample = `{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2024-21762",
 "published":"2024-02-09T09:15:08.087","lastModified":"2024-02-13T16:00:00.000",
 "descriptions":[{"lang":"en","value":"A out-of-bounds write in Fortinet FortiOS. Details follow."}],
 "metrics":{"cvssMetricV31":[{"cvssData":{"baseSeverity":"CRITICAL","baseScore":9.8}}]},
 "references":[{"url":"https://fortiguard.com/psirt/FG-IR-24-015"},{"url":"javascript:alert(1)"}]}}]}`

// The NVD often answers 503 for a moment: the request is sent again, a few
// times, and a definite refusal is not.
func TestRetries(t *testing.T) {
	calls, codes := 0, []int{http.StatusServiceUnavailable, http.StatusForbidden}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls <= len(codes) {
			w.WriteHeader(codes[calls-1])
			return
		}
		io.WriteString(w, sample)
	}))
	defer srv.Close()
	c := &Client{URL: srv.URL, HTTP: srv.Client()}
	q := Query{CPE: "cpe:2.3:o:fortinet:fortios:7.2.4:*:*:*:*:*:*:*"}
	if cves, err := c.ForCPE(context.Background(), q); err != nil || len(cves) != 1 || calls != 3 {
		t.Errorf("temporary failures: %d calls, %v, %v", calls, cves, err)
	}
	calls, codes = 0, []int{503, 503, 503, 503}
	if _, err := c.ForCPE(context.Background(), q); err == nil || calls != 3 {
		t.Errorf("lasting failure: %d calls, %v", calls, err)
	}
	calls, codes = 0, []int{http.StatusBadRequest}
	if _, err := c.ForCPE(context.Background(), q); err == nil || calls != 1 {
		t.Errorf("refusal: %d calls, %v", calls, err)
	}
}

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
	var got []url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.URL.Query())
		io.WriteString(w, sample) // the same CVE in every answer: it must be reported once
	}))
	defer srv.Close()
	c := &Client{URL: srv.URL, HTTP: srv.Client()}
	ctx := context.Background()
	product := "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*"

	// Tracked period of 200 days: two 120-day ranges, then the exploited CVEs.
	cves, err := c.ForCPE(ctx, Query{CPE: product, Since: time.Now().Add(-200 * 24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if len(cves) != 1 {
		t.Errorf("duplicates not merged: %d CVEs", len(cves))
	}
	if len(got) != 3 || got[0].Get("virtualMatchString") != product || got[0].Get("pubStartDate") == "" ||
		got[1].Get("pubEndDate") == "" || !got[2].Has("hasKev") || got[2].Has("pubStartDate") {
		t.Errorf("unexpected requests: %v", got)
	}

	// Without a period, or with one too long for date ranges: one request.
	for _, since := range []time.Time{{}, time.Now().AddDate(-5, 0, 0)} {
		got = nil
		if _, err := c.ForCPE(ctx, Query{CPE: product, Since: since}); err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].Has("pubStartDate") || got[0].Has("hasKev") {
			t.Errorf("since %v: %v", since, got)
		}
	}
	if _, err := c.ForCPE(ctx, Query{CPE: "cpe:2.3:bad"}); err == nil {
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

// A dictionary name with escaped colons (lemonldap\:\:ng) is a valid CPE: its
// version is filled, and it goes to the NVD with its escapes.
func TestForCPEEscapedColons(t *testing.T) {
	var got []url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.URL.Query())
		io.WriteString(w, `{"totalResults":0,"vulnerabilities":[]}`)
	}))
	defer srv.Close()
	c := &Client{URL: srv.URL, HTTP: srv.Client()}
	ctx := context.Background()
	product := `cpe:2.3:a:lemonldap-ng:lemonldap\:\:ng:*:*:*:*:*:*:*:*`
	for _, q := range []Query{{CPE: product, Version: "2.0.16"}, {CPE: product}, {CPE: product, Mode: "from", From: "2.0"}} {
		if _, err := c.ForCPE(ctx, q); err != nil {
			t.Fatalf("%+v: %v", q, err)
		}
	}
	if len(got) != 3 || got[0].Get("cpeName") != `cpe:2.3:a:lemonldap-ng:lemonldap\:\:ng:2.0.16:*:*:*:*:*:*:*` ||
		got[1].Get("virtualMatchString") != product || got[2].Get("virtualMatchString") != product || got[2].Get("versionStart") != "2.0" {
		t.Errorf("unexpected requests: %v", got)
	}
	if w := withVersion(product, "2.0.16"); w != got[0].Get("cpeName") {
		t.Errorf("with version: %s", w)
	}
}

// Every product of a vendor: the vendor CPE goes to the NVD as is, like a
// whole product, even when the asset has a version.
func TestWholeVendor(t *testing.T) {
	var got []url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.URL.Query())
		io.WriteString(w, sample)
	}))
	defer srv.Close()
	c := &Client{URL: srv.URL, HTTP: srv.Client()}
	vendor := WholeVendor("fortinet")
	if _, err := c.ForCPE(context.Background(), Query{CPE: vendor, Version: "7.2.4"}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Get("virtualMatchString") != "cpe:2.3:*:fortinet:*:*:*:*:*:*:*:*:*" || got[0].Has("cpeName") {
		t.Errorf("requests: %v", got)
	}
}

// The NVD answers a refused API key with a 404 and a "message" header, for
// every kind of query (checked against the live API in November 2026, while
// an unknown CPE name gets a 200 without results). That is a failure, said as
// the NVD says it, and not an empty answer.
func TestRefusedKeyIsAnError(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("message", "Invalid apiKey.")
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	c := &Client{URL: srv.URL, CPEURL: srv.URL, HTTP: srv.Client(), APIKey: "wrong"}
	ctx := context.Background()
	if cves, err := c.ForCPE(ctx, Query{CPE: "cpe:2.3:o:fortinet:fortios:7.2.4:*:*:*:*:*:*:*"}); err == nil || !strings.Contains(err.Error(), "Invalid apiKey.") {
		t.Errorf("ForCPE: %v, %v", cves, err)
	}
	if cves, err := c.ForKeyword(ctx, "FortiOS", time.Time{}); err == nil || !strings.Contains(err.Error(), "HTTP 404 (Invalid apiKey.)") {
		t.Errorf("ForKeyword: %v, %v", cves, err)
	}
	if calls != 2 {
		t.Errorf("%d calls: a refusal is not sent again", calls)
	}
	_, err := c.SearchCPE(ctx, "fortios")
	if err == nil || !strings.Contains(err.Error(), "Invalid apiKey.") || strings.Contains(err.Error(), "limite de requêtes") {
		t.Errorf("SearchCPE: %v", err)
	}
}
