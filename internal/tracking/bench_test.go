package tracking_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/La-Cizaille-Corp/vigil/internal/sources/kev"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
	"github.com/La-Cizaille-Corp/vigil/internal/storetest"
	"github.com/La-Cizaille-Corp/vigil/internal/tracking"
)

// benchAdvisories is the size of the package of the benchmark: a few
// thousand advisories, as for a kernel.
const benchAdvisories = 3000

// bigPackage answers like OSV for a package with n unfixed advisories, each
// with a CVE alias, like KEV with a catalogue citing one in ten of them, and
// like EPSS.
func bigPackage(n int) http.HandlerFunc {
	var page strings.Builder
	page.WriteString(`{"vulns":[`)
	for i := range n {
		if i > 0 {
			page.WriteString(",")
		}
		fmt.Fprintf(&page, `{"id":"GHSA-%05d","aliases":["CVE-2026-%05d"],"modified":"2026-10-01T00:00:00Z",
			"published":"2026-10-01T00:00:00Z","summary":"advisory %d","details":"%s",
			"affected":[{"package":{"purl":"pkg:npm/big"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`,
			i, i, i, strings.Repeat("x", 500))
	}
	page.WriteString(`]}`)
	var catalogue struct {
		Vulnerabilities []kev.Entry `json:"vulnerabilities"`
	}
	for i := 0; i < n; i += 10 {
		catalogue.Vulnerabilities = append(catalogue.Vulnerabilities, kev.Entry{CVE: fmt.Sprintf("CVE-2026-%05d", i), DueDate: "2026-12-01"})
	}
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/kev":
			json.NewEncoder(w).Encode(catalogue)
		case "/epss":
			var out struct {
				Data []map[string]string `json:"data"`
			}
			for _, cve := range strings.Split(r.URL.Query().Get("cve"), ",") {
				out.Data = append(out.Data, map[string]string{"cve": cve, "epss": "0.01"})
			}
			json.NewEncoder(w).Encode(out)
		default:
			io.WriteString(w, page.String())
		}
	}
}

// BenchmarkSync times the synchronisation of a package with a few thousand
// advisories: the first one, which stores them all, and the next one, which
// finds them unchanged. Each iteration starts from a new database file.
func BenchmarkSync(b *testing.B) {
	sources, _ := osvSyncer(b, nil, bigPackage(benchAdvisories), true) // asked by a synchroniser of each database
	ctx := context.Background()
	setup := func(b *testing.B) *tracking.Syncer {
		st := storetest.Open(b)
		storetest.Asset(b, st, store.Asset{Name: "big", Kind: "package", PURL: "pkg:npm/big",
			Version: "latest", Criticality: "medium", Source: "manual"})
		return sameSources(sources, st)
	}
	run := func(b *testing.B, s *tracking.Syncer) {
		b.Helper()
		res, err := s.Run(ctx)
		if err != nil || res.Assets != 1 || res.Failed != 0 {
			b.Fatalf("sync: %+v, %v", res, err)
		}
	}
	b.Run("first", func(b *testing.B) {
		for range b.N {
			b.StopTimer()
			s := setup(b)
			b.StartTimer()
			run(b, s)
		}
	})
	b.Run("again", func(b *testing.B) {
		for range b.N {
			b.StopTimer()
			s := setup(b)
			run(b, s)
			b.StartTimer()
			run(b, s)
		}
	})
}
