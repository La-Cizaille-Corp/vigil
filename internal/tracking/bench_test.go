package tracking_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/La-Cizaille-Corp/vigil/internal/sources/epss"
	"github.com/La-Cizaille-Corp/vigil/internal/sources/kev"
	"github.com/La-Cizaille-Corp/vigil/internal/sources/osv"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
	"github.com/La-Cizaille-Corp/vigil/internal/tracking"
)

// benchAdvisories is the size of the package of the benchmark: a few
// thousand advisories, as for a kernel.
const benchAdvisories = 3000

// fakeSources serves a package with n unfixed advisories, each with a CVE
// alias, a KEV catalogue citing one in ten of them, and EPSS scores.
func fakeSources(tb testing.TB, n int) (*osv.Client, *kev.Client, *epss.Client) {
	tb.Helper()
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
	osvSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, page.String())
	}))
	tb.Cleanup(osvSrv.Close)

	var catalogue struct {
		Vulnerabilities []kev.Entry `json:"vulnerabilities"`
	}
	for i := 0; i < n; i += 10 {
		catalogue.Vulnerabilities = append(catalogue.Vulnerabilities, kev.Entry{CVE: fmt.Sprintf("CVE-2026-%05d", i), DueDate: "2026-12-01"})
	}
	kevSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(catalogue)
	}))
	tb.Cleanup(kevSrv.Close)

	epssSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var out struct {
			Data []map[string]string `json:"data"`
		}
		for _, cve := range strings.Split(r.URL.Query().Get("cve"), ",") {
			out.Data = append(out.Data, map[string]string{"cve": cve, "epss": "0.01"})
		}
		json.NewEncoder(w).Encode(out)
	}))
	tb.Cleanup(epssSrv.Close)

	return &osv.Client{URL: osvSrv.URL, HTTP: http.DefaultClient, UserAgent: "vigil-test"},
		&kev.Client{URL: kevSrv.URL, HTTP: http.DefaultClient},
		&epss.Client{URL: epssSrv.URL, HTTP: http.DefaultClient}
}

// BenchmarkSync times the synchronisation of a package with a few thousand
// advisories: the first one, which stores them all, and the next one, which
// finds them unchanged. Each iteration starts from a new database file.
func BenchmarkSync(b *testing.B) {
	osvClient, kevClient, epssClient := fakeSources(b, benchAdvisories)
	ctx := context.Background()
	setup := func(b *testing.B, i int) *tracking.Syncer {
		st, err := store.Open(ctx, filepath.Join(b.TempDir(), fmt.Sprintf("bench-%d.db", i)))
		if err != nil {
			b.Fatal(err)
		}
		b.Cleanup(func() { st.Close() })
		if _, err := st.CreateAsset(ctx, store.Everything, store.Asset{Name: "big", Kind: "package", PURL: "pkg:npm/big",
			Version: "latest", Criticality: "medium", Source: "manual"}); err != nil {
			b.Fatal(err)
		}
		return &tracking.Syncer{Store: st, OSV: osvClient, KEV: kevClient, EPSS: epssClient,
			Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	}
	run := func(b *testing.B, s *tracking.Syncer) {
		res, err := s.Run(ctx)
		if err != nil || res.Assets != 1 || res.Failed != 0 {
			b.Fatalf("sync: %+v, %v", res, err)
		}
	}
	b.Run("first", func(b *testing.B) {
		for i := range b.N {
			b.StopTimer()
			s := setup(b, i)
			b.StartTimer()
			run(b, s)
		}
	})
	b.Run("again", func(b *testing.B) {
		for i := range b.N {
			b.StopTimer()
			s := setup(b, i)
			run(b, s)
			b.StartTimer()
			run(b, s)
		}
	})
}
