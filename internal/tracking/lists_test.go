package tracking_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/store"
	"github.com/La-Cizaille-Corp/vigil/internal/storetest"
	"github.com/La-Cizaille-Corp/vigil/internal/tracking"
)

// kernelOSV answers like OSV for an Ubuntu kernel, a package too large for a
// batch answer (two advisories a page here, three for /v1/query). It writes
// the dates of modification as OSV does: to the nanosecond in an advisory, to
// the microsecond in a batch answer. A test changes what it answers within
// locked, and counts what it is asked with counts.
type kernelOSV struct {
	*fakeSources

	advisories map[string]kernelAdvisory
	kev        []string          // exploited CVEs
	epss       map[string]string // CVE → score
	failRefs   bool              // the short list fails after its first page
	emptyRefs  bool              // the short list, asked after the batch answer, is empty
	failVulns  bool              // advisories cannot be read alone
	batches    int               // batch requests answered since counts
}

type kernelAdvisory struct {
	published, modified, fixed string
	others                     []string
}

func (k kernelAdvisory) record(id string) string {
	others, _ := json.Marshal(k.others)
	return fmt.Sprintf(`{"id":%q,"published":%q,"modified":%q,"upstream":%s,"details":"%s",`+
		`"affected":[{"package":{"name":"linux","ecosystem":"Ubuntu:22.04:LTS"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":%q}]}],`+
		`"ecosystem_specific":{"binaries":"%s"}}]}`, id, k.published, k.modified, others, "Some text.", k.fixed, strings.Repeat("b", 2000))
}

const kernelQuery = `{"package":{"name":"linux","ecosystem":"Ubuntu:22.04:LTS"},"version":"5.15.0-100.110"}`

// newKernelOSV serves 34 advisories: 30 in the tracked period, three older
// ones and a grouped one (USN) citing the advisories of three of its CVEs. It
// returns them with a synchroniser of st that asks them.
func newKernelOSV(t *testing.T, st *store.Store) (*kernelOSV, *tracking.Syncer) {
	t.Helper()
	k := &kernelOSV{advisories: map[string]kernelAdvisory{}, epss: map[string]string{}}
	for i := 1; i <= 30; i++ {
		k.advisories[fmt.Sprintf("UBUNTU-CVE-2026-%02d", i)] = kernelAdvisory{published: fmt.Sprintf("2026-08-%02dT00:00:00Z", i),
			modified: "2026-10-01T10:00:00.123456789Z", fixed: "5.15.0-200.1", others: []string{fmt.Sprintf("CVE-2026-%02d", i)}}
	}
	for _, year := range []int{2022, 2023, 2024} {
		k.advisories[fmt.Sprintf("UBUNTU-CVE-%d-9", year)] = kernelAdvisory{published: fmt.Sprintf("%d-01-01T00:00:00Z", year),
			modified: "2026-10-01T10:00:00.123456789Z", fixed: "5.15.0-200.1", others: []string{fmt.Sprintf("CVE-%d-9", year)}}
	}
	k.advisories["USN-9000-1"] = kernelAdvisory{published: "2026-10-01T00:00:00Z", modified: "2026-10-01T10:00:00.123456789Z", fixed: "5.15.0-200.1",
		others: []string{"CVE-2026-01", "CVE-2026-02", "CVE-2022-9", "UBUNTU-CVE-2026-01", "UBUNTU-CVE-2026-02", "UBUNTU-CVE-2022-9"}}
	syncer, f := osvSyncer(t, st, k.serve, true)
	k.fakeSources = f
	return k, syncer
}

func (k *kernelOSV) serve(w http.ResponseWriter, r *http.Request) {
	ids := slices.Sorted(maps.Keys(k.advisories))
	switch {
	case r.URL.Path == "/v1/querybatch":
		var req struct {
			Queries []struct {
				PageToken string `json:"page_token"`
			} `json:"queries"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		var results []string
		for _, q := range req.Queries {
			if q.PageToken != "" && k.failRefs {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			if k.emptyRefs && k.batches > 0 { // not the batch answer of the synchronisation
				results = append(results, `{"vulns":[],"next_page_token":""}`)
				continue
			}
			start, _ := strconv.Atoi(q.PageToken)
			end := min(start+2, len(ids))
			var refs []string
			for _, id := range ids[start:end] {
				modified, _ := time.Parse(time.RFC3339Nano, k.advisories[id].modified)
				refs = append(refs, fmt.Sprintf(`{"id":%q,"modified":%q}`, id, modified.UTC().Format("2006-01-02T15:04:05.000000Z")))
			}
			next := ""
			if end < len(ids) {
				next = strconv.Itoa(end)
			}
			results = append(results, `{"vulns":[`+strings.Join(refs, ",")+`],"next_page_token":"`+next+`"}`)
		}
		k.batches++
		io.WriteString(w, `{"results":[`+strings.Join(results, ",")+`]}`)
	case r.URL.Path == "/v1/query":
		var req struct {
			PageToken string `json:"page_token"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		start, _ := strconv.Atoi(req.PageToken)
		end := min(start+3, len(ids))
		var records []string
		for _, id := range ids[start:end] {
			records = append(records, k.advisories[id].record(id))
		}
		next := ""
		if end < len(ids) {
			next = strconv.Itoa(end)
		}
		io.WriteString(w, `{"vulns":[`+strings.Join(records, ",")+`],"next_page_token":"`+next+`"}`)
	case strings.HasPrefix(r.URL.Path, "/v1/vulns/"):
		id := strings.TrimPrefix(r.URL.Path, "/v1/vulns/")
		a, ok := k.advisories[id]
		if !ok || k.failVulns {
			http.NotFound(w, r)
			return
		}
		io.WriteString(w, a.record(id))
	case r.URL.Path == "/kev":
		entries := []string{`{"cveID":"CVE-1999-0001"}`} // a real catalogue is never empty
		for _, cve := range k.kev {
			entries = append(entries, `{"cveID":"`+cve+`","dueDate":"2026-12-01"}`)
		}
		io.WriteString(w, `{"vulnerabilities":[`+strings.Join(entries, ",")+`]}`)
	case r.URL.Path == "/epss":
		var data []string
		for _, cve := range strings.Split(r.URL.Query().Get("cve"), ",") {
			if score, ok := k.epss[cve]; ok {
				data = append(data, `{"cve":"`+cve+`","epss":"`+score+`"}`)
			}
		}
		io.WriteString(w, `{"data":[`+strings.Join(data, ",")+`]}`)
	default:
		http.NotFound(w, r)
	}
}

// counts returns the requests answered and the bytes sent since the last
// call (fakeSources.counts), from when the batch requests are counted again.
func (k *kernelOSV) counts() (map[string]int, map[string]int) {
	k.locked(func() { k.batches = 0 })
	return k.fakeSources.counts()
}

func addKernel(t *testing.T, st *store.Store, name string) int64 {
	t.Helper()
	id, err := st.CreateAsset(context.Background(), store.Everything, store.Asset{Name: name, Kind: "os", Ecosystem: "Ubuntu:22.04:LTS",
		Version: "5.15.0-100.110", TrackSince: "2026-07-08", Criticality: "high", Source: "manual"})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// found describes what a synchronisation leaves for an asset: its findings,
// folded or not, with their status and fix, how many vulnerabilities are older
// than its period, and the advisories stored, as they are.
func found(t *testing.T, st *store.Store, assetID int64, ids []string) string {
	t.Helper()
	ctx := context.Background()
	triage, err := st.ListFindingTriage(ctx, assetID)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, f := range triage {
		full, err := st.Finding(ctx, store.Everything, f.ID)
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, fmt.Sprintf("finding %s %s folded=%v fixed=%s", f.VulnID, f.Status, f.FoldedInto != 0, full.FixedIn))
	}
	a, _ := st.Asset(ctx, store.Everything, assetID)
	lines = append(lines, fmt.Sprintf("older %d", a.OlderVulns))
	for _, id := range ids {
		v, err := st.Vulnerability(ctx, id)
		if err != nil {
			lines = append(lines, "absent "+id)
			continue
		}
		lines = append(lines, fmt.Sprintf("stored %s %s %s %v %v %.2f %s", v.ID, v.Published, v.Modified, v.Aliases, v.KEV, v.EPSS, v.Raw))
	}
	slices.Sort(lines)
	return strings.Join(lines, "\n")
}

// A large package is read in full once, then only what changed (A90): nothing
// for a list unchanged, an advisory alone when it is new or modified, or when
// the asset can now report it; in full again beyond a tenth of the list, after
// a week, or without the short list. Each time, what it finds is what a full
// read finds, on a database that always reads in full.
func TestLargePackageReadAgain(t *testing.T) {
	ctx := context.Background()
	st, whole := storetest.Open(t), storetest.Open(t)
	k, syncer := newKernelOSV(t, st)
	wholeSyncer := sameSources(syncer, whole)
	id, wholeID := addKernel(t, st, "linux"), addKernel(t, whole, "linux")
	advisoryIDs := func() (ids []string) {
		k.locked(func() { ids = slices.Sorted(maps.Keys(k.advisories)) })
		return ids
	}
	allIDs := append(advisoryIDs(), "UBUNTU-CVE-2026-31")

	// step syncs both databases and returns the requests of the incremental
	// one, after checking that it finds what the full read finds.
	step := func(name string) (map[string]int, map[string]int, tracking.Result) {
		t.Helper()
		k.counts()
		res, err := syncer.Run(ctx)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		requests, bytes := k.counts()
		if _, err := whole.PurgeOSVLists(ctx, time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		if _, err := wholeSyncer.Run(ctx); err != nil {
			t.Fatalf("%s, full read: %v", name, err)
		}
		k.counts()
		if got, want := found(t, st, id, allIDs), found(t, whole, wholeID, allIDs); got != want {
			t.Errorf("%s: read again\n%s\nread in full\n%s", name, got, want)
		}
		return requests, bytes, res
	}
	pages := func() int { return (len(advisoryIDs()) + 2) / 3 }

	requests, _, res := step("first sync")
	if requests["query"] != pages() || requests["querybatch"] != 1 || requests["vulns"] != 0 {
		t.Errorf("first sync, read in full: %v", requests)
	}
	if res.Created != 30 || res.Skipped != 3 {
		t.Errorf("first sync: %+v", res)
	}

	requests, bytes, _ := step("nothing changed")
	if requests["query"] != 0 || requests["vulns"] != 0 || bytes["query"]+bytes["vulns"] != 0 || requests["querybatch"] != 1+17 {
		t.Errorf("nothing changed: %v, %v bytes", requests, bytes)
	}

	k.locked(func() {
		a := k.advisories["UBUNTU-CVE-2026-03"]
		a.modified, a.fixed = "2026-11-01T08:00:00.987654321Z", "5.15.0-210.1"
		k.advisories["UBUNTU-CVE-2026-03"] = a
	})
	if requests, _, _ := step("one advisory modified"); requests["query"] != 0 || requests["vulns"] != 1 {
		t.Errorf("one advisory modified: %v", requests)
	}
	if f := findingOf(t, st, id, "UBUNTU-CVE-2026-03"); f.FixedIn != "5.15.0-210.1" {
		t.Errorf("the fix of the advisory modified: %q", f.FixedIn)
	}

	k.locked(func() {
		k.advisories["UBUNTU-CVE-2026-31"] = kernelAdvisory{published: "2026-11-02T00:00:00Z", modified: "2026-11-02T00:00:00.5Z",
			fixed: "5.15.0-210.1", others: []string{"CVE-2026-31"}}
	})
	if requests, _, res := step("a new advisory"); requests["query"] != 0 || requests["vulns"] != 1 || res.Created != 1 {
		t.Errorf("a new advisory: %v, %+v", requests, res)
	}

	// The guard of the tracked period (A31): an old CVE that becomes exploited,
	// unchanged at OSV, is read alone and reported; one likely to be too.
	k.locked(func() { k.kev = []string{"CVE-2023-9"} })
	if requests, _, res := step("an old CVE exploited"); requests["vulns"] != 1 || res.Created != 1 {
		t.Errorf("an old CVE exploited: %v, %+v", requests, res)
	}
	k.locked(func() { k.epss["CVE-2024-9"] = "0.5" })
	if requests, _, res := step("an old CVE likely exploited"); requests["vulns"] != 1 || res.Created != 1 {
		t.Errorf("an old CVE likely exploited: %v, %+v", requests, res)
	}
	if requests, _, _ := step("stored as it is"); requests["vulns"] != 0 || requests["query"] != 0 {
		t.Errorf("an old advisory stored as it is is not read again: %v", requests)
	}

	k.locked(func() { delete(k.advisories, "UBUNTU-CVE-2026-02") })
	if requests, _, res := step("an advisory no longer reported"); requests["vulns"] != 0 || res.Resolved != 1 {
		t.Errorf("an advisory no longer reported: %v, %+v", requests, res)
	}

	// A release of the kernel modifies every advisory: read in full.
	k.locked(func() {
		for id, a := range k.advisories {
			a.modified = "2026-11-05T00:00:00.000000001Z"
			k.advisories[id] = a
		}
	})
	if requests, _, _ := step("every advisory modified"); requests["query"] != pages() || requests["vulns"] != 1 {
		t.Errorf("every advisory modified: %v (in full, and the likely one alone)", requests)
	}

	// Without the short list, as before it: in full.
	k.locked(func() { k.failRefs = true })
	if requests, _, res := step("short list failed"); requests["query"] != pages() || res.Failed != 0 {
		t.Errorf("short list failed: %v, %+v", requests, res)
	}
	k.locked(func() { k.failRefs = false })

	// A short list that holds fewer advisories than the first page of the
	// batch answer is not the whole list: as without it, in full. Taken as it
	// is, it would mark every finding of the kernel fixed.
	k.locked(func() { k.emptyRefs = true })
	if requests, _, res := step("short list empty"); requests["query"] != pages() || res.Resolved != 0 {
		t.Errorf("short list empty: %v, %+v", requests, res)
	}
	k.locked(func() { k.emptyRefs = false })

	// An advisory that cannot be read: the asset is not checked, keeps its
	// findings, and its list is not changed.
	k.locked(func() {
		a := k.advisories["UBUNTU-CVE-2026-04"]
		a.modified, a.fixed = "2026-11-06T00:00:00Z", "5.15.0-220.1"
		k.advisories["UBUNTU-CVE-2026-04"] = a
		k.failVulns = true
	})
	before := found(t, st, id, allIDs)
	k.counts()
	if res, err := syncer.Run(ctx); err != nil || res.Failed != 1 {
		t.Errorf("advisory unreadable: %+v, %v", res, err)
	}
	if after := found(t, st, id, allIDs); after != before {
		t.Errorf("an asset not checked changed:\n%s\nbefore\n%s", after, before)
	}
	k.locked(func() { k.failVulns = false })
	if requests, _, _ := step("advisory readable again"); requests["vulns"] != 1 || requests["query"] != 0 {
		t.Errorf("advisory readable again: %v", requests)
	}

	// The tracked period moved back: the old advisory left out is read alone.
	a, _ := st.Asset(ctx, store.Everything, id)
	a.TrackSince = ""
	wa, _ := whole.Asset(ctx, store.Everything, wholeID)
	wa.TrackSince = ""
	if err := st.UpdateAsset(ctx, store.Everything, a); err != nil {
		t.Fatal(err)
	}
	if err := whole.UpdateAsset(ctx, store.Everything, wa); err != nil {
		t.Fatal(err)
	}
	if requests, _, _ := step("period moved back"); requests["vulns"] != 1 || requests["query"] != 0 {
		t.Errorf("period moved back: %v", requests)
	}

	// A week after its full read, the list goes: read in full.
	key := kernelQuery
	l, err := st.OSVList(ctx, key)
	if err != nil {
		t.Fatalf("list of %s: %v", key, err)
	}
	l.ReadAt = time.Now().Add(-8 * 24 * time.Hour)
	if err := st.SaveOSVList(ctx, l); err != nil {
		t.Fatal(err)
	}
	if requests, _, _ := step("a week later"); requests["query"] != pages() {
		t.Errorf("a week later: %v", requests)
	}
	if l, err := st.OSVList(ctx, key); err != nil || time.Since(l.ReadAt) > time.Hour {
		t.Errorf("list after a full read: %v, %v", l.ReadAt, err)
	}
}

// Two assets that ask the same share the list: the second one reads nothing.
func TestLargePackageSharedList(t *testing.T) {
	ctx := context.Background()
	st := storetest.Open(t)
	k, syncer := newKernelOSV(t, st)
	first, second := addKernel(t, st, "linux"), addKernel(t, st, "linux") // two servers
	if res, err := syncer.Run(ctx); err != nil || res.Failed != 0 {
		t.Fatalf("%+v, %v", res, err)
	}
	if requests, _ := k.counts(); requests["query"] != 12 || requests["vulns"] != 0 {
		t.Errorf("two assets of one version: %v", requests)
	}
	if a, b := openIDs(t, st, first), openIDs(t, st, second); len(a) != 30 || !slices.Equal(a, b) {
		t.Errorf("findings %v and %v", a, b)
	}
}

// OSV writes the date of modification of an advisory to the microsecond in a
// batch answer, to the nanosecond in the advisory: an advisory unchanged was
// downloaded again at each synchronisation.
func TestModifiedPrecision(t *testing.T) {
	ctx := context.Background()
	st := storetest.Open(t)
	syncer, srv := osvSyncer(t, st, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			io.WriteString(w, `{"results":[{"vulns":[{"id":"GHSA-35jh-r3h4-6jhm","modified":"2026-10-17T02:55:38.085813Z"}]}]}`)
		case "/v1/vulns/GHSA-35jh-r3h4-6jhm":
			io.WriteString(w, `{"id":"GHSA-35jh-r3h4-6jhm","modified":"2026-10-17T02:55:38.085813876Z","published":"2021-05-06T16:05:51Z"}`)
		default:
			http.NotFound(w, r)
		}
	}, false)
	if _, err := st.CreateAsset(ctx, store.Everything, store.Asset{Name: "lodash", Kind: "package", PURL: "pkg:npm/lodash@4.17.15",
		Criticality: "low", Source: "manual"}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if res, err := syncer.Run(ctx); err != nil || res.Failed != 0 {
			t.Fatalf("%+v, %v", res, err)
		}
	}
	if requests, _ := srv.counts(); requests["vulns"] != 1 {
		t.Errorf("the advisory was downloaded %d times", requests["vulns"])
	}
}
