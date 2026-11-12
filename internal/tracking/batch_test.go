package tracking_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/La-Cizaille-Corp/vigil/internal/sources/epss"
	"github.com/La-Cizaille-Corp/vigil/internal/sources/kev"
	"github.com/La-Cizaille-Corp/vigil/internal/sources/osv"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
	"github.com/La-Cizaille-Corp/vigil/internal/tracking"
)

// The findings of an asset are recorded together (D4): a failure in the
// middle leaves none of them, the asset is reported as not checked, and the
// other assets are recorded.
func TestFailedRecordingWritesNothingOfTheAsset(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "test.db")
	st, err := store.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	// The database refuses the second finding of the first asset.
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `CREATE TRIGGER refuse BEFORE INSERT ON findings WHEN NEW.vuln_id = 'GHSA-left-2'
		BEGIN SELECT RAISE(ABORT, 'refused by the test'); END`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	advisory := func(id, purl string) string {
		return `{"id":"` + id + `","modified":"2026-10-01T00:00:00Z","published":"2026-10-01T00:00:00Z",
			"affected":[{"package":{"purl":"` + purl + `"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Package osv.Package `json:"package"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		switch body.Package.PURL {
		case "pkg:npm/left":
			io.WriteString(w, `{"vulns":[`+advisory("GHSA-left-1", "pkg:npm/left")+`,`+advisory("GHSA-left-2", "pkg:npm/left")+`]}`)
		default:
			io.WriteString(w, `{"vulns":[`+advisory("GHSA-right-1", "pkg:npm/right")+`]}`)
		}
	}))
	defer srv.Close()
	syncer := &tracking.Syncer{Store: st, OSV: &osv.Client{URL: srv.URL, HTTP: http.DefaultClient, UserAgent: "vigil-test"},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	add := func(name string) int64 {
		id, err := st.CreateAsset(ctx, store.Everything, store.Asset{Name: name, Kind: "package", PURL: "pkg:npm/" + name,
			Version: "latest", Criticality: "medium", Source: "manual"})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	left, right := add("left"), add("right")

	res, err := syncer.Run(ctx)
	if err != nil {
		t.Fatalf("the failure of an asset stopped the sync: %v", err)
	}
	if res.Failed != 1 || res.Created != 1 {
		t.Errorf("result = %+v, want the first asset failed and one finding created", res)
	}
	if got := openIDs(t, st, left); len(got) != 0 {
		t.Errorf("findings of the asset that failed = %v, want none", got)
	}
	if got := openIDs(t, st, right); !slices.Equal(got, []string{"GHSA-right-1"}) {
		t.Errorf("findings of the other asset = %v", got)
	}
	s := syncer.Status()
	if s.Total != 2 || s.Done != 2 || len(s.Failures) != 1 || !strings.HasPrefix(s.Failures[0], "left : enregistrement des vulnérabilités : ") {
		t.Errorf("status = %+v", s)
	}
}

// A synchronisation reads the KEV catalogue once, for the tracked period and
// for the signals, and asks EPSS once for a CVE that several advisories cite.
func TestSignalSourcesAskedOnce(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	var mu sync.Mutex
	kevReads, epssAsked := 0, []string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/kev":
			kevReads++
			io.WriteString(w, `{"vulnerabilities":[{"cveID":"CVE-2026-0001","dueDate":"2026-12-01"}]}`)
		case "/epss":
			epssAsked = append(epssAsked, strings.Split(r.URL.Query().Get("cve"), ",")...)
			io.WriteString(w, `{"data":[{"cve":"CVE-2026-0001","epss":"0.5"}]}`)
		default: // two advisories of the package, both citing the same CVE; the old one is exploited
			io.WriteString(w, `{"vulns":[
				{"id":"GHSA-new","aliases":["CVE-2026-0001"],"modified":"2026-10-01T00:00:00Z","published":"2026-10-01T00:00:00Z",
				 "affected":[{"package":{"purl":"pkg:npm/left"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]},
				{"id":"GHSA-old","aliases":["CVE-2026-0001"],"modified":"2026-10-01T00:00:00Z","published":"2020-01-01T00:00:00Z",
				 "affected":[{"package":{"purl":"pkg:npm/left"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}]}`)
		}
	}))
	defer srv.Close()
	syncer := &tracking.Syncer{Store: st, OSV: &osv.Client{URL: srv.URL, HTTP: http.DefaultClient, UserAgent: "vigil-test"},
		KEV: &kev.Client{URL: srv.URL + "/kev", HTTP: srv.Client()}, EPSS: &epss.Client{URL: srv.URL + "/epss", HTTP: srv.Client()},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	id, err := st.CreateAsset(ctx, store.Everything, store.Asset{Name: "left", Kind: "package", PURL: "pkg:npm/left",
		Version: "latest", TrackSince: "2026-01-01", Criticality: "medium", Source: "manual"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := syncer.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if kevReads != 1 || !slices.Equal(epssAsked, []string{"CVE-2026-0001"}) {
		t.Errorf("KEV read %d times, EPSS asked for %v; want once each", kevReads, epssAsked)
	}
	// One finding for the CVE (A80): the old advisory, exploited, is in the
	// period, so the CVE is.
	if got := openIDs(t, st, id); !slices.Equal(got, []string{"GHSA-new"}) {
		t.Errorf("findings = %v, want one for the CVE", got)
	}
}

// EPSS is asked once for each CVE in a synchronisation: two kernels read whole
// share their CVEs, and the old ones were asked for each kernel to keep those
// likely to be exploited (A31), then again with the stored ones. The check of
// one asset asks for the CVEs of its advisories, not for those of the base.
func TestEPSSAskedOncePerCVE(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	const n = 300
	advisory := func(prefix string, i int, ecosystem string) string {
		published := "2020-01-01T00:00:00Z" // three in four older than the period
		if i%4 == 0 {
			published = "2026-06-01T00:00:00Z"
		}
		return fmt.Sprintf(`{"id":"%s-CVE-2020-%05d","published":"%s","modified":"2026-01-01T00:00:00Z","upstream":["CVE-2020-%05d"],
			"affected":[{"package":{"name":"linux","ecosystem":"%s"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}`,
			prefix, i, published, i, ecosystem)
	}
	ecosystems := map[string]string{"DEBIAN": "Debian:13", "UBUNTU": "Ubuntu:22.04:LTS"}
	var mu sync.Mutex
	asked := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.URL.Path == "/kev":
			io.WriteString(w, `{"vulnerabilities":[{"cveID":"CVE-1999-0001"}]}`)
		case r.URL.Path == "/epss":
			var data []string
			for _, cve := range strings.Split(r.URL.Query().Get("cve"), ",") {
				asked[cve]++
				score := "0.01"
				if strings.HasSuffix(cve, "7") { // likely to be exploited
					score = "0.5"
				}
				data = append(data, `{"cve":"`+cve+`","epss":"`+score+`"}`)
			}
			io.WriteString(w, `{"data":[`+strings.Join(data, ",")+`]}`)
		case r.URL.Path == "/v1/vulns/GHSA-small":
			io.WriteString(w, `{"id":"GHSA-small","aliases":["CVE-2099-0001"],"published":"2026-06-01T00:00:00Z","modified":"2026-06-01T00:00:00Z"}`)
		case strings.HasPrefix(r.URL.Path, "/v1/vulns/"):
			prefix, number, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/v1/vulns/"), "-CVE-2020-")
			i, _ := strconv.Atoi(number)
			io.WriteString(w, advisory(prefix, i, ecosystems[prefix]))
		case r.URL.Path == "/v1/querybatch": // the small package
			io.WriteString(w, `{"results":[{"vulns":[{"id":"GHSA-small","modified":"2026-06-01T00:00:00Z"}]}]}`)
		default: // a kernel read whole, or the advisory of the small package
			var body struct {
				Package osv.Package `json:"package"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			var list []string
			for prefix, ecosystem := range ecosystems {
				if ecosystem == body.Package.Ecosystem {
					for i := range n {
						list = append(list, advisory(prefix, i, ecosystem))
					}
				}
			}
			io.WriteString(w, `{"vulns":[`+strings.Join(list, ",")+`]}`)
		}
	}))
	defer srv.Close()
	for _, ecosystem := range ecosystems {
		if _, err := st.CreateAsset(ctx, store.Everything, store.Asset{Name: "linux", Kind: "os", Ecosystem: ecosystem,
			Version: "latest", TrackSince: "2026-01-01", Criticality: "medium", Source: "manual"}); err != nil {
			t.Fatal(err)
		}
	}
	syncer := &tracking.Syncer{Store: st, OSV: &osv.Client{URL: srv.URL, HTTP: http.DefaultClient},
		KEV: &kev.Client{URL: srv.URL + "/kev", HTTP: srv.Client()}, EPSS: &epss.Client{URL: srv.URL + "/epss", HTTP: srv.Client()},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	askedTwice := func() (distinct int, twice []string) {
		mu.Lock()
		defer mu.Unlock()
		for cve, times := range asked {
			if times > 1 {
				twice = append(twice, cve)
			}
		}
		distinct = len(asked)
		clear(asked)
		return distinct, twice
	}
	if res, err := syncer.Run(ctx); err != nil || res.Created == 0 {
		t.Fatalf("sync: %+v, %v", res, err)
	}
	if distinct, twice := askedTwice(); distinct != n || len(twice) > 0 {
		t.Errorf("synchronisation: %d CVEs asked, %d of them more than once (%v…)", distinct, len(twice), twice[:min(3, len(twice))])
	}

	id, err := st.CreateAsset(ctx, store.Everything, store.Asset{Name: "small", Kind: "package", PURL: "pkg:npm/small@1.0.0",
		TrackSince: "2026-01-01", Criticality: "medium", Source: "manual"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := syncer.RunAsset(ctx, id); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	got := slices.Sorted(maps.Keys(asked))
	mu.Unlock()
	if !slices.Equal(got, []string{"CVE-2099-0001"}) {
		t.Errorf("check of one asset: EPSS asked for %d CVEs (%v…), want those of its advisory", len(got), got[:min(3, len(got))])
	}
}
