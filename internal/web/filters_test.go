package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/La-Cizaille-Corp/vigil/internal/inventory"
)

// The tag filters of the inventory and of the vulnerability list read a tag
// as it is stored (see inventory.NormalizeTags) and ignore one longer than
// inventory.MaxTagLen, which no asset can bear: the vulnerability filter took
// up to 100 characters, and the inventory took the tag as typed.
func TestTagFilterReadsTagsAsStored(t *testing.T) {
	longest := strings.Repeat("é", inventory.MaxTagLen)
	for raw, want := range map[string]string{
		longest:                longest,
		longest + "x":          "",
		"  Équipe   Web ":      "équipe web",
		strings.Repeat(" ", 3): "",
	} {
		if got := findingFilterFrom(url.Values{"tag": {raw}}).Tag; got != want {
			t.Errorf("vulnerability filter on %q: %q, want %q", raw, got, want)
		}
	}

	_, base := newServerWith(t, nil)
	c := loginAs(t, base, "analyst", testPassword)
	if code := c.post("/assets", url.Values{"csrf": {c.csrf()}, "name": {"nginx"}, "kind": {"technology"},
		"criticality": {"high"}, "tags": {"Équipe Web"}}); code != http.StatusSeeOther {
		t.Fatalf("create: %d", code)
	}
	if _, body := c.get("/assets?tag=" + url.QueryEscape("  Équipe  WEB ")); !strings.Contains(body, ">nginx</a>") {
		t.Error("inventory filter on a tag typed with capitals and spaces")
	}
}
