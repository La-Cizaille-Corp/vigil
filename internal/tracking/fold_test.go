package tracking_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/sources/epss"
	"github.com/La-Cizaille-Corp/vigil/internal/sources/kev"
	"github.com/La-Cizaille-Corp/vigil/internal/sources/osv"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
	"github.com/La-Cizaille-Corp/vigil/internal/tracking"
)

// ubuntuKernel answers like OSV for an Ubuntu kernel, a package too large for
// a batch answer: an advisory per CVE, an old one, and grouped advisories (USN)
// citing the advisories of their CVEs; epss gives the EPSS scores.
func ubuntuKernel(t *testing.T, epssScores *string) (*httptest.Server, *sync.Mutex) {
	t.Helper()
	var mu sync.Mutex
	const range5 = `"affected":[{"package":{"name":"linux","ecosystem":"Ubuntu:22.04:LTS"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"5.15.0-200.1"}]}]}]`
	advisories := map[string]string{
		"UBUNTU-CVE-2026-1": `{"id":"UBUNTU-CVE-2026-1","published":"2026-09-01T00:00:00Z","modified":"2026-09-01T00:00:00Z","upstream":["CVE-2026-1"],"severity":[{"type":"Ubuntu","score":"medium"}],` + range5 + `}`,
		"UBUNTU-CVE-2026-2": `{"id":"UBUNTU-CVE-2026-2","published":"2026-09-02T00:00:00Z","modified":"2026-09-02T00:00:00Z","upstream":["CVE-2026-2"],` + range5 + `}`,
		// Older than the tracked period, not exploited.
		"UBUNTU-CVE-2022-9": `{"id":"UBUNTU-CVE-2022-9","published":"2022-01-01T00:00:00Z","modified":"2026-09-01T00:00:00Z","upstream":["CVE-2022-9"],` + range5 + `}`,
		"UBUNTU-CVE-2026-7": `{"id":"UBUNTU-CVE-2026-7","published":"2026-06-25T00:00:00Z","modified":"2026-09-01T00:00:00Z","upstream":["CVE-2026-7"],` + range5 + `}`,
		// A grouped advisory of the period, citing the advisories of its CVEs.
		"USN-9000-1": `{"id":"USN-9000-1","published":"2026-10-01T00:00:00Z","modified":"2026-10-01T00:00:00Z","summary":"linux vulnerabilities",
			"upstream":["CVE-2026-1","CVE-2026-2","CVE-2022-9","UBUNTU-CVE-2026-1","UBUNTU-CVE-2026-2","UBUNTU-CVE-2022-9"],` + range5 + `}`,
		// A notice of one CVE, published after it: the CVE keeps its own date.
		"USN-9100-1": `{"id":"USN-9100-1","published":"2026-09-07T00:00:00Z","modified":"2026-09-07T00:00:00Z","upstream":["CVE-2026-7","UBUNTU-CVE-2026-7"],` + range5 + `}`,
	}
	order := []string{"UBUNTU-CVE-2022-9", "UBUNTU-CVE-2026-1", "UBUNTU-CVE-2026-2", "UBUNTU-CVE-2026-7", "USN-9000-1", "USN-9100-1"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.URL.Path == "/v1/querybatch": // three advisories a page, by id
			var body struct {
				Queries []struct {
					PageToken string `json:"page_token"`
				} `json:"queries"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			page, next := order[:3], `"p2"`
			if body.Queries[0].PageToken == "p2" {
				page, next = order[3:], `""`
			}
			var refs []string
			for _, id := range page {
				var v osv.Vuln
				json.Unmarshal([]byte(advisories[id]), &v)
				refs = append(refs, `{"id":"`+id+`","modified":"`+v.Modified+`"}`)
			}
			io.WriteString(w, `{"results":[{"vulns":[`+strings.Join(refs, ",")+`],"next_page_token":`+next+`}]}`)
		case r.URL.Path == "/v1/query":
			var list []string
			for _, id := range order {
				list = append(list, advisories[id])
			}
			io.WriteString(w, `{"vulns":[`+strings.Join(list, ",")+`]}`)
		case strings.HasPrefix(r.URL.Path, "/v1/vulns/"):
			io.WriteString(w, advisories[strings.TrimPrefix(r.URL.Path, "/v1/vulns/")])
		case r.URL.Path == "/kev":
			io.WriteString(w, `{"vulnerabilities":[{"cveID":"CVE-1999-0001"}]}`) // never empty
		case r.URL.Path == "/epss":
			io.WriteString(w, *epssScores)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &mu
}

func syncerFor(st *store.Store, srv *httptest.Server) *tracking.Syncer {
	return &tracking.Syncer{Store: st, OSV: &osv.Client{URL: srv.URL, HTTP: http.DefaultClient, UserAgent: "vigil-test"},
		KEV: &kev.Client{URL: srv.URL + "/kev", HTTP: srv.Client()}, EPSS: &epss.Client{URL: srv.URL + "/epss", HTTP: srv.Client()},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

// findingOf returns the finding of an asset for an advisory, folded or not.
func findingOf(t *testing.T, st *store.Store, assetID int64, vulnID string) store.Finding {
	t.Helper()
	triage, err := st.ListFindingTriage(context.Background(), assetID)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range triage {
		if f.VulnID == vulnID {
			found, err := st.Finding(context.Background(), store.Everything, f.ID)
			if err != nil {
				t.Fatal(err)
			}
			return found
		}
	}
	t.Fatalf("no finding of %s", vulnID)
	return store.Finding{}
}

// One finding per CVE (A80): a grouped advisory that cites the advisories of
// its CVEs is not a finding, and does not bring back a CVE older than the
// tracked period; the finding it was before 0.5.0 is folded, its decision
// kept on it and left out of every list.
func TestGroupedAdvisoryFolded(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	scores := `{"data":[]}`
	srv, _ := ubuntuKernel(t, &scores)
	id, err := st.CreateAsset(ctx, store.Everything, store.Asset{Name: "linux", Kind: "os", Ecosystem: "Ubuntu:22.04:LTS",
		Version: "5.15.0-100.110", TrackSince: "2026-07-08", Criticality: "high", Source: "manual"})
	if err != nil {
		t.Fatal(err)
	}
	// A finding of the grouped advisory, made by an earlier version and triaged.
	user, err := st.CreateUser(ctx, "alice", "hash", "analyst", store.Access{All: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertVulnerability(ctx, store.Vulnerability{ID: "USN-9000-1", Published: "2026-10-01T00:00:00Z", Modified: "2026-01-01T00:00:00Z",
		Aliases: []string{"CVE-2026-1", "CVE-2026-2", "CVE-2022-9", "UBUNTU-CVE-2026-1", "UBUNTU-CVE-2026-2", "UBUNTU-CVE-2022-9"}, EPSS: -1, CVSS: -1}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ObserveFinding(ctx, id, "USN-9000-1", "", time.Now()); err != nil {
		t.Fatal(err)
	}
	usn := findingOf(t, st, id, "USN-9000-1")
	if err := st.SetFindingStatus(ctx, store.Everything, usn.ID, user, "not_affected", "code_not_present", "pas de wifi"); err != nil {
		t.Fatal(err)
	}

	syncer := syncerFor(st, srv)
	res, err := syncer.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := openIDs(t, st, id); !slices.Equal(got, []string{"UBUNTU-CVE-2026-1", "UBUNTU-CVE-2026-2"}) {
		t.Errorf("findings = %v, want one per CVE of the period", got)
	}
	usn = findingOf(t, st, id, "USN-9000-1")
	if usn.FoldedInto != store.FoldedNotice || usn.Status != "not_affected" || usn.Comment != "pas de wifi" || res.Folded != 1 {
		t.Errorf("grouped advisory: folded %d, status %s, comment %q; result %+v", usn.FoldedInto, usn.Status, usn.Comment, res)
	}
	events, _ := st.ListFindingEvents(ctx, store.Everything, usn.ID)
	if len(events) != 2 || !strings.Contains(events[1].Comment, "avis groupé") {
		t.Errorf("history of the grouped advisory: %+v", events)
	}
	// The CVE of the notice of one CVE keeps its own date, before the period;
	// the old one, not exploited, stays out too.
	asset, _ := st.Asset(ctx, store.Everything, id)
	if asset.OlderVulns != 2 {
		t.Errorf("older vulnerabilities = %d, want 2 (CVE-2026-7, CVE-2022-9)", asset.OlderVulns)
	}
	// Folded: in no count, no alert.
	counts, _ := st.CountFindingsByStatus(ctx, store.Everything)
	if counts["not_affected"] != 0 || counts["in_triage"] != 2 {
		t.Errorf("counts = %v", counts)
	}
	alerts, _ := st.PendingAlerts(ctx, store.Everything)
	for _, a := range alerts {
		if a.VulnID == "USN-9000-1" {
			t.Error("the grouped advisory is alerted")
		}
	}
	// The finding of a CVE shows the grouped advisory, with the fix it names
	// for the asset, and the decision taken on it.
	cve := findingOf(t, st, id, "UBUNTU-CVE-2026-1")
	if cve.FixedIn != "5.15.0-200.1" {
		t.Errorf("fixed in %q", cve.FixedIn)
	}
	notices, err := st.ListNotices(ctx, store.Everything, id, tracking.CVEs(cve.VulnID, cve.Aliases))
	if err != nil {
		t.Fatal(err)
	}
	refs := tracking.GroupedNotices(notices, asset)
	if len(refs) != 1 || refs[0].ID != "USN-9000-1" || refs[0].FindingID != usn.ID || refs[0].DecidedBy != "alice" || refs[0].FixedIn != "5.15.0-200.1" {
		t.Errorf("grouped advisories of the CVE = %+v", refs)
	}

	// Once likely to be exploited, the old CVE passes the tracked period, as
	// an exploited one does (A31).
	scores = `{"data":[{"cve":"CVE-2022-9","epss":"0.42"}]}`
	if _, err := syncer.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := openIDs(t, st, id); !slices.Equal(got, []string{"UBUNTU-CVE-2022-9", "UBUNTU-CVE-2026-1", "UBUNTU-CVE-2026-2"}) {
		t.Errorf("findings with a likely old CVE = %v", got)
	}
}

// Two advisories of the same CVE (GHSA and GO) make one finding: the later
// decision of a user stands, the other is noted; the finding kept takes the
// earliest detection and stays open while one of them is reported.
func TestSameCVEFolded(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	var mu sync.Mutex
	reported := []string{"GHSA-aaaa", "GO-2026-1"}
	advisories := map[string]string{
		"GHSA-aaaa": `{"id":"GHSA-aaaa","aliases":["CVE-2026-5","GO-2026-1"],"published":"2026-09-01T00:00:00Z","modified":"2026-09-01T00:00:00Z",
			"database_specific":{"severity":"HIGH"},"affected":[{"package":{"purl":"pkg:golang/golang.org/x/net"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"0.60.0"}]}]}]}`,
		"GO-2026-1": `{"id":"GO-2026-1","aliases":["CVE-2026-5","GHSA-aaaa"],"published":"2026-09-02T00:00:00Z","modified":"2026-09-02T00:00:00Z",
			"affected":[{"package":{"purl":"pkg:golang/golang.org/x/net"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"0.61.0"}]}]}]}`,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.URL.Path == "/v1/querybatch":
			var refs []string
			for _, id := range reported {
				refs = append(refs, `{"id":"`+id+`","modified":"2026-09-01T00:00:00Z"}`)
			}
			io.WriteString(w, `{"results":[{"vulns":[`+strings.Join(refs, ",")+`]}]}`)
		case strings.HasPrefix(r.URL.Path, "/v1/vulns/"):
			io.WriteString(w, advisories[strings.TrimPrefix(r.URL.Path, "/v1/vulns/")])
		case r.URL.Path == "/kev":
			io.WriteString(w, `{"vulnerabilities":[{"cveID":"CVE-1999-0001"}]}`) // never empty
		case r.URL.Path == "/epss":
			io.WriteString(w, `{"data":[]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	id, err := st.CreateAsset(ctx, store.Everything, store.Asset{Name: "x/net", Kind: "package", PURL: "pkg:golang/golang.org/x/net@v0.47.0",
		Version: "v0.47.0", Criticality: "medium", Source: "manual"})
	if err != nil {
		t.Fatal(err)
	}
	// Two findings of another CVE, no longer reported: one stays, closed by
	// the synchronisation, the other is folded into it.
	for _, vuln := range []string{"GHSA-bbbb", "GO-2025-9"} {
		st.UpsertVulnerability(ctx, store.Vulnerability{ID: vuln, Aliases: []string{"CVE-2025-9"}, Modified: "old", EPSS: -1, CVSS: -1})
		st.ObserveFinding(ctx, id, vuln, "", time.Now())
	}
	// Both advisories had a finding before 0.5.0, decided differently.
	alice, _ := st.CreateUser(ctx, "alice", "hash", "analyst", store.Access{All: true})
	bob, _ := st.CreateUser(ctx, "bob", "hash", "analyst", store.Access{All: true})
	early := time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC)
	for i, vuln := range []string{"GHSA-aaaa", "GO-2026-1"} {
		st.UpsertVulnerability(ctx, store.Vulnerability{ID: vuln, Aliases: []string{"CVE-2026-5"}, Modified: "old", EPSS: -1, CVSS: -1})
		if _, err := st.ObserveFinding(ctx, id, vuln, "", early.AddDate(0, 0, i)); err != nil {
			t.Fatal(err)
		}
	}
	ghsa, gov := findingOf(t, st, id, "GHSA-aaaa"), findingOf(t, st, id, "GO-2026-1")
	st.SetFindingStatus(ctx, store.Everything, ghsa.ID, alice, "not_affected", "code_not_reachable", "non atteint")
	st.SetFindingStatus(ctx, store.Everything, gov.ID, bob, "exploitable", "", "à corriger") // the later one

	syncer := syncerFor(st, srv)
	if _, err := syncer.Run(ctx); err != nil {
		t.Fatal(err)
	}
	list, _ := st.ListFindings(ctx, store.Everything, store.FindingFilter{AssetID: id, CVEs: []string{"CVE-2026-5"}})
	if len(list) != 1 || list[0].VulnID != "GO-2026-1" || list[0].Status != "exploitable" {
		t.Fatalf("findings = %+v, want GO-2026-1 alone, as bob decided", list)
	}
	kept := list[0]
	if !kept.FirstSeen.Equal(early) || kept.FixedIn != "0.60.0, 0.61.0" {
		t.Errorf("kept: first seen %v, fixed in %q", kept.FirstSeen, kept.FixedIn)
	}
	if ghsa = findingOf(t, st, id, "GHSA-aaaa"); ghsa.FoldedInto != kept.ID || ghsa.Status != "not_affected" {
		t.Errorf("folded: %+v", ghsa)
	}
	events, _ := st.ListFindingEvents(ctx, store.Everything, kept.ID)
	if last := events[len(events)-1]; !strings.Contains(last.Comment, "décision divergente sur GHSA-aaaa") || !strings.Contains(last.Comment, "alice") {
		t.Errorf("note on the finding kept: %+v", last)
	}
	folded, _ := st.ListFoldedInto(ctx, store.Everything, kept.ID)
	if len(folded) != 1 || folded[0].VulnID != "GHSA-aaaa" {
		t.Errorf("folded into the finding kept: %+v", folded)
	}
	oldKept, oldFolded := findingOf(t, st, id, "GHSA-bbbb"), findingOf(t, st, id, "GO-2025-9")
	if oldKept.Status != "resolved" || oldKept.FoldedInto != 0 || oldFolded.FoldedInto != oldKept.ID {
		t.Errorf("older pair, no longer reported: kept %+v, folded %+v", oldKept, oldFolded)
	}

	// GO-2026-1 is no longer reported, GHSA-aaaa still is: the CVE is, so its
	// finding stays open.
	mu.Lock()
	reported = []string{"GHSA-aaaa"}
	mu.Unlock()
	if res, err := syncer.Run(ctx); err != nil || res.Resolved != 0 {
		t.Fatalf("result %+v, %v", res, err)
	}
	if kept = findingOf(t, st, id, "GO-2026-1"); kept.Status != "exploitable" || kept.FoldedInto != 0 {
		t.Errorf("finding of the CVE: %+v", kept)
	}
}
