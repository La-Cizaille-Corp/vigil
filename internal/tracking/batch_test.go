package tracking_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
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
	if got := openIDs(t, st, id); !slices.Equal(got, []string{"GHSA-new", "GHSA-old"}) {
		t.Errorf("findings = %v, want both, the old one exploited", got)
	}
}
