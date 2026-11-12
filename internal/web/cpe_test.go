package web

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/sources/nvd"
)

// A vendor or a product whose name the CPE escapes is shown without its
// backslashes (lemonldap\:\:ng reads lemonldap::ng); the CPE offered, and
// stored once chosen, keeps them.
func TestCPEChoicesReadable(t *testing.T) {
	now := time.Now()
	cpe := `cpe:2.3:a:at\&t:lemonldap\:\:ng:2.0.16:*:*:*:*:*:*:*`
	products := cpeProducts([]nvd.Product{{CPE: cpe, Part: "a", Vendor: `at\&t`, Name: `lemonldap\:\:ng`, Version: "2.0.16", Created: now}}, nil, now)
	vendors := cpeVendors(products)
	if len(products) != 1 || len(vendors) != 1 {
		t.Fatalf("products %+v, vendors %+v", products, vendors)
	}
	p, v := products[0], vendors[0]
	if p.Title != "at&t lemonldap::ng" || v.Title != "At&t" || v.Name != `at\&t` || p.Name != `lemonldap\:\:ng` {
		t.Errorf("titles: product %q, vendor %q (%q)", p.Title, v.Title, v.Name)
	}
	use, err := url.Parse(p.Whole.Use)
	if err != nil {
		t.Fatal(err)
	}
	if q := use.Query(); q.Get("name") != "at&t lemonldap::ng" || q.Get("cpe") != `cpe:2.3:a:at\&t:lemonldap\:\:ng:*:*:*:*:*:*:*:*` ||
		!strings.HasPrefix(v.Whole.CPE, `cpe:2.3:*:at\&t:`) {
		t.Errorf("prefilled form: %q, vendor CPE %q", p.Whole.Use, v.Whole.CPE)
	}
}
