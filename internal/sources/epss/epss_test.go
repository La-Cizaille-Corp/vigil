package epss

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// testClient returns a client of a fake EPSS that answers with h, closed at
// the end of the test.
func testClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &Client{URL: srv.URL, HTTP: srv.Client(), UserAgent: "vigil-test"}
}

// Only probabilities are kept: a NaN or out-of-range value would abort the
// enrichment of every vulnerability.
func TestScoresIgnoresInvalid(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"data":[{"cve":"CVE-1","epss":"0.25"},{"cve":"CVE-2","epss":"NaN"},
			{"cve":"CVE-3","epss":"1e9"},{"cve":"CVE-4","epss":"-0.1"}]}`)
	})
	got, err := c.Scores(context.Background(), []string{"CVE-1", "CVE-2", "CVE-3", "CVE-4"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got["CVE-1"] != 0.25 {
		t.Errorf("scores = %v", got)
	}
}

// An answer without its list cannot be read: taken for no score, it would
// clear the score of every vulnerability. An empty list is an answer, for CVEs
// that FIRST does not score yet.
func TestAnswerWithoutList(t *testing.T) {
	doc := ""
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, doc) })
	doc = `{"status":"OK","scores":[{"cve":"CVE-1","epss":"0.25"}]}`
	if got, err := c.Scores(context.Background(), []string{"CVE-1"}); err == nil {
		t.Errorf("list renamed: %v", got)
	}
	doc = `{"status":"OK","data":[]}`
	if got, err := c.Scores(context.Background(), []string{"CVE-1"}); err != nil || len(got) != 0 {
		t.Errorf("empty list: %v, %v", got, err)
	}
}

// A temporary failure is asked again, as for the other sources: one 503 on one
// batch failed the enrichment of every vulnerability.
func TestScoresRetried(t *testing.T) {
	var calls atomic.Int32
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		io.WriteString(w, `{"data":[{"cve":"CVE-1","epss":"0.25"}]}`)
	})
	if got, err := c.Scores(context.Background(), []string{"CVE-1"}); err != nil || got["CVE-1"] != 0.25 || calls.Load() != 2 {
		t.Errorf("%d calls: %v, %v", calls.Load(), got, err)
	}
}

// The CVEs are asked by batches of a hundred.
func TestScoresBatches(t *testing.T) {
	var requests atomic.Int32
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
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
	scores, err := c.Scores(context.Background(), cves)
	if err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 2 || len(scores) != 150 || scores[cves[0]] != 0.5 {
		t.Fatalf("requests = %d, scores = %d", requests.Load(), len(scores))
	}
}
