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
	got, err := Scores(context.Background(), srv.Client(), srv.URL, "test", []string{"CVE-1", "CVE-2", "CVE-3", "CVE-4"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got["CVE-1"] != 0.25 {
		t.Errorf("scores = %v", got)
	}
}
