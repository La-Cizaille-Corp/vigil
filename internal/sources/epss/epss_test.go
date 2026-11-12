package epss

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Only probabilities are kept: a NaN or out-of-range value would abort the
// enrichment of every vulnerability.
func TestScoresIgnoresInvalid(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"data":[{"cve":"CVE-1","epss":"0.25"},{"cve":"CVE-2","epss":"NaN"},
			{"cve":"CVE-3","epss":"1e9"},{"cve":"CVE-4","epss":"-0.1"}]}`)
	}))
	defer srv.Close()
	c := &Client{URL: srv.URL, HTTP: srv.Client()}
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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, doc) }))
	defer srv.Close()
	c := &Client{URL: srv.URL, HTTP: srv.Client()}
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
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls++; calls == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		io.WriteString(w, `{"data":[{"cve":"CVE-1","epss":"0.25"}]}`)
	}))
	defer srv.Close()
	if got, err := (&Client{URL: srv.URL, HTTP: srv.Client()}).Scores(context.Background(), []string{"CVE-1"}); err != nil || got["CVE-1"] != 0.25 || calls != 2 {
		t.Errorf("%d calls: %v, %v", calls, got, err)
	}
}
