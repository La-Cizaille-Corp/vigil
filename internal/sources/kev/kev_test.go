package kev

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A due date is kept only when it is one: the CVE stays in the catalogue.
func TestCatalogueDueDates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"vulnerabilities":[{"cveID":"CVE-2024-0001","dueDate":"2024-02-01"},
			{"cveID":"CVE-2024-0002","dueDate":"<b>demain</b>"}]}`)
	}))
	defer srv.Close()
	got, err := (&Client{URL: srv.URL, HTTP: srv.Client()}).Catalogue(context.Background())
	if err != nil || len(got) != 2 || got["CVE-2024-0001"].DueDate != "2024-02-01" || got["CVE-2024-0002"].DueDate != "" {
		t.Errorf("catalogue %v, %v", got, err)
	}
}
