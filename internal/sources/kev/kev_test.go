package kev

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// testClient returns a client of a fake KEV catalogue that answers with h,
// closed at the end of the test.
func testClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &Client{URL: srv.URL, HTTP: srv.Client(), UserAgent: "vigil-test"}
}

// A due date is kept only when it is one: the CVE stays in the catalogue.
func TestCatalogueDueDates(t *testing.T) {
	got, err := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"vulnerabilities":[{"cveID":"CVE-2024-0001","dueDate":"2024-02-01"},
			{"cveID":"CVE-2024-0002","dueDate":"<b>demain</b>"}]}`)
	}).Catalogue(context.Background())
	if err != nil || len(got) != 2 || got["CVE-2024-0001"].DueDate != "2024-02-01" || got["CVE-2024-0002"].DueDate != "" {
		t.Errorf("catalogue %v, %v", got, err)
	}
}

// The catalogue is never empty: an empty one, or one whose list was renamed,
// would clear the KEV mark of every vulnerability.
func TestEmptyCatalogueRefused(t *testing.T) {
	for _, doc := range []string{`{"vulnerabilities":[]}`, `{"title":"CISA Catalog","items":[{"cveID":"CVE-2024-0001"}]}`} {
		c := testClient(t, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, doc) })
		if got, err := c.Catalogue(context.Background()); err == nil {
			t.Errorf("%s: %v", doc, got)
		}
	}
}

// A temporary failure is asked again, as for the other sources: one 503 failed
// the enrichment of the whole synchronisation. One that lasts is an error, not
// an empty catalogue.
func TestCatalogueRetried(t *testing.T) {
	for _, c := range []struct {
		name  string
		codes []int // the answers before the catalogue
		calls int32
		fails bool
	}{
		{"temporary failure", []int{http.StatusServiceUnavailable}, 2, false},
		{"lasting failure", []int{502, 502, 502}, 3, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			var calls atomic.Int32
			got, err := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				if n := int(calls.Add(1)); n <= len(c.codes) {
					w.WriteHeader(c.codes[n-1])
					return
				}
				io.WriteString(w, `{"vulnerabilities":[{"cveID":"CVE-2024-0001"}]}`)
			}).Catalogue(context.Background())
			if (err != nil) != c.fails || !c.fails && len(got) != 1 || calls.Load() != c.calls {
				t.Errorf("%d calls: %v, %v", calls.Load(), got, err)
			}
		})
	}
}
