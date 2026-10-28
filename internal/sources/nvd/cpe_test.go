package nvd

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

const cpeSample = `{"resultsPerPage":3,"totalResults":3,"products":[
 {"cpe":{"deprecated":false,"cpeName":"cpe:2.3:o:fortinet:fortios:7.2.4:*:*:*:*:*:*:*","titles":[{"title":"Fortinet FortiOS 7.2.4","lang":"en"}]}},
 {"cpe":{"deprecated":true,"cpeName":"cpe:2.3:o:fortinet:fortios:7.2.4:beta:*:*:*:*:*:*","titles":[{"title":"old","lang":"en"}]}},
 {"cpe":{"deprecated":false,"cpeName":"not a cpe","titles":[]}}]}`

func TestSearchCPE(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("keywordSearch") != "fortios 7.2.4" || r.URL.Query().Get("resultsPerPage") != "20" {
			t.Errorf("query: %s", r.URL.RawQuery)
		}
		io.WriteString(w, cpeSample)
	}))
	defer srv.Close()
	c := &Client{URL: srv.URL, CPEURL: srv.URL, HTTP: srv.Client()}
	got, err := c.SearchCPE(context.Background(), "fortios 7.2.4", 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Title != "Fortinet FortiOS 7.2.4" || got[0].Part != "o" || got[0].Version != "7.2.4" {
		t.Fatalf("products: %+v", got)
	}
	if w := got[0].WholeProduct(); w != "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*" {
		t.Errorf("whole product: %s", w)
	}
}
