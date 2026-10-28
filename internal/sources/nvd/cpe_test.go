package nvd

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func entry(name, created string) string {
	return fmt.Sprintf(`{"cpe":{"deprecated":false,"cpeName":%q,"created":%q,"titles":[{"title":"t %s","lang":"en"}]}}`,
		name, created, name)
}

// The dictionary returns entries oldest first: the search must try the exact
// product name, then vendor and product, then the vendor, before keywords.
func TestSearchCPE(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		seen = append(seen, q.Get("cpeMatchString")+q.Get("keywordSearch")+"@"+q.Get("startIndex"))
		switch q.Get("cpeMatchString") {
		case "cpe:2.3:*:fortinet:fortios":
			fmt.Fprintf(w, `{"totalResults":2,"products":[%s,%s,{"cpe":{"deprecated":true,"cpeName":"cpe:2.3:o:fortinet:fortios:1:*:*:*:*:*:*:*"}}]}`,
				entry("cpe:2.3:o:fortinet:fortios:7.2.4:*:*:*:*:*:*:*", "2023-03-01T10:00:00.000"),
				entry("cpe:2.3:o:fortinet:fortios:7.4.3:*:*:*:*:*:*:*", "2024-03-01T10:00:00.000"))
		default:
			io.WriteString(w, `{"totalResults":0,"products":[]}`)
		}
	}))
	defer srv.Close()
	c := &Client{URL: srv.URL, CPEURL: srv.URL, HTTP: srv.Client()}
	got, err := c.SearchCPE(context.Background(), "Fortinet FortiOS 7.2.4")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"cpe:2.3:*:*:fortinet_fortios@", "cpe:2.3:*:fortinet:fortios@"}; !reflect.DeepEqual(seen, want) {
		t.Errorf("requests: %v, want %v", seen, want)
	}
	if len(got) != 2 || got[0].Version != "7.2.4" || got[0].Part != "o" || got[1].Created.Year() != 2024 {
		t.Fatalf("products: %+v", got)
	}
	if w := got[0].WholeProduct(); w != "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*" {
		t.Errorf("whole product: %s", w)
	}
	if w := WholeVendor("fortinet"); w != "cpe:2.3:*:fortinet:*:*:*:*:*:*:*:*:*" {
		t.Errorf("whole vendor: %s", w)
	}

	// One word: product, then vendor; then keywords, newest page only.
	seen = nil
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		seen = append(seen, q.Get("cpeMatchString")+q.Get("keywordSearch")+"@"+q.Get("startIndex"))
		if q.Get("keywordSearch") != "" {
			io.WriteString(w, `{"totalResults":1447,"products":[]}`)
			return
		}
		io.WriteString(w, `{"totalResults":0,"products":[]}`)
	})
	if _, err := c.SearchCPE(context.Background(), "elastic"); err != nil {
		t.Fatal(err)
	}
	if want := []string{"cpe:2.3:*:*:elastic@", "cpe:2.3:*:elastic@", "elastic@", "elastic@1247"}; !reflect.DeepEqual(seen, want) {
		t.Errorf("requests: %v, want %v", seen, want)
	}
}

func TestMatchStrings(t *testing.T) {
	if got := matchStrings([]string{"c++"}); got != nil {
		t.Errorf("characters outside a CPE name: %v", got)
	}
	got := matchStrings([]string{"exchange", "server"})
	var patterns []string
	for _, m := range got {
		patterns = append(patterns, m.pattern)
	}
	if strings.Join(patterns, " ") != "cpe:2.3:*:*:exchange_server cpe:2.3:*:exchange:server cpe:2.3:*:*:server" {
		t.Errorf("patterns: %v", patterns)
	}
	words, versions := SplitQuery("Exchange Server 2019")
	if !reflect.DeepEqual(words, []string{"exchange", "server"}) || !reflect.DeepEqual(versions, []string{"2019"}) {
		t.Errorf("split: %v %v", words, versions)
	}
}
