// Package sources_test checks the clients of the public vulnerability APIs
// against recorded responses, so that a format change is caught in CI.
package sources_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/La-Cizaille-Corp/vigil/internal/sources/epss"
	"github.com/La-Cizaille-Corp/vigil/internal/sources/kev"
	"github.com/La-Cizaille-Corp/vigil/internal/sources/osv"
)

func serve(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

func TestKEV(t *testing.T) {
	srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"title":"CISA Catalog","catalogVersion":"2026.10.27","count":2,"vulnerabilities":[
			{"cveID":"CVE-2021-44228","vendorProject":"Apache","product":"Log4j2","dueDate":"2021-12-24"},
			{"cveID":"CVE-2024-21762","vendorProject":"Fortinet","product":"FortiOS","dueDate":"2024-02-16"}]}`)
	})
	cat, err := kev.Fetch(context.Background(), srv.Client(), srv.URL, "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(cat) != 2 || cat["CVE-2021-44228"].DueDate != "2021-12-24" {
		t.Fatalf("catalogue = %+v", cat)
	}

	failing := serve(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusBadGateway) })
	if _, err := kev.Fetch(context.Background(), failing.Client(), failing.URL, "test"); err == nil {
		t.Error("HTTP error ignored")
	}
}

func TestEPSSBatches(t *testing.T) {
	requests := 0
	srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		var data []map[string]string
		for _, cve := range strings.Split(r.URL.Query().Get("cve"), ",") {
			data = append(data, map[string]string{"cve": cve, "epss": "0.5", "percentile": "0.9", "date": "2026-10-27"})
		}
		json.NewEncoder(w).Encode(map[string]any{"status": "OK", "total": len(data), "data": data})
	})
	cves := make([]string, 150)
	for i := range cves {
		cves[i] = "CVE-2026-" + strings.Repeat("1", 4) + string(rune('a'+i%26)) + string(rune('a'+i/26))
	}
	scores, err := epss.Scores(context.Background(), srv.Client(), srv.URL, "test", cves)
	if err != nil {
		t.Fatal(err)
	}
	if requests != 2 || len(scores) != 150 || scores[cves[0]] != 0.5 {
		t.Fatalf("requests = %d, scores = %d", requests, len(scores))
	}
}

func TestOSV(t *testing.T) {
	srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			io.WriteString(w, `{"results":[{"vulns":[{"id":"GHSA-jfh8-c2jp-5v3q","modified":"2026-01-01T00:00:00Z"}]},{}]}`)
		case "/v1/vulns/GHSA-jfh8-c2jp-5v3q":
			io.WriteString(w, `{"id":"GHSA-jfh8-c2jp-5v3q","summary":"Remote code injection in Log4j",
				"aliases":["CVE-2021-44228"],"modified":"2026-01-01T00:00:00Z",
				"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],
				"database_specific":{"severity":"CRITICAL"}}`)
		default:
			http.NotFound(w, r)
		}
	})
	c := osv.New("test")
	c.BaseURL, c.HTTP = srv.URL, srv.Client()
	ctx := context.Background()
	res, err := c.QueryBatch(ctx, []osv.Query{
		{Package: osv.Package{PURL: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}},
		{Package: osv.Package{PURL: "pkg:npm/left-pad@1.3.0"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 2 || len(res[0]) != 1 || len(res[1]) != 0 {
		t.Fatalf("results = %+v", res)
	}
	v, err := c.Vuln(ctx, res[0][0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if v.CVSSScore() != 10 || v.SeverityLabel() != "CRITICAL" || v.Aliases[0] != "CVE-2021-44228" {
		t.Fatalf("vuln = %+v score %v", v, v.CVSSScore())
	}
}

func TestOSVSeverityFallbacks(t *testing.T) {
	var moderate, vectorOnly osv.Vuln
	json.Unmarshal([]byte(`{"database_specific":{"severity":"MODERATE"}}`), &moderate)
	json.Unmarshal([]byte(`{"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"}]}`), &vectorOnly)
	if moderate.SeverityLabel() != "MEDIUM" {
		t.Errorf("MODERATE -> %q", moderate.SeverityLabel())
	}
	if vectorOnly.SeverityLabel() != "MEDIUM" || vectorOnly.CVSSScore() != 5.5 {
		t.Errorf("vector only -> %q %v", vectorOnly.SeverityLabel(), vectorOnly.CVSSScore())
	}
}
