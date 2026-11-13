package tracking_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/sources/osv"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
	"github.com/La-Cizaille-Corp/vigil/internal/storetest"
	"github.com/La-Cizaille-Corp/vigil/internal/tracking"
)

// A kernel has thousands of advisories, listed from the oldest: reading only
// the first page of the batch answer would find nothing in the tracked period.
// The whole list is read, and only what the asset can report is stored.
func TestLargePackage(t *testing.T) {
	ctx := context.Background()
	st := storetest.Open(t)
	var batches []osv.Query
	syncer, srv := osvSyncer(t, st, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			var body struct {
				Queries []osv.Query `json:"queries"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			batches = append(batches, body.Queries...)
			io.WriteString(w, `{"results":[{"vulns":[{"id":"DEBIAN-CVE-2004-0230","modified":"2026-01-01T00:00:00Z"}],"next_page_token":"p2"}]}`)
		case "/v1/query":
			var body struct {
				Package   osv.Package `json:"package"`
				Version   string      `json:"version"`
				PageToken string      `json:"page_token"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			if body.Package.Name != "linux" || body.Package.Ecosystem != "Debian:12" || body.Version != "6.1.76-1" {
				t.Errorf("query = %+v", body)
			}
			if body.PageToken == "" {
				io.WriteString(w, `{"vulns":[
					{"id":"DEBIAN-CVE-2004-0230","published":"2004-05-01T00:00:00Z","modified":"2026-01-01T00:00:00Z","upstream":["CVE-2004-0230"]},
					{"id":"DEBIAN-CVE-2021-0001","published":"2021-05-01T00:00:00Z","modified":"2026-01-01T00:00:00Z","upstream":["CVE-2021-22555"],
					 "details":"In the Linux kernel, the following vulnerability has been resolved:  wifi: mt76: add a check  Since mt76 does this."}
				],"next_page_token":"p2"}`)
				return
			}
			io.WriteString(w, `{"vulns":[{"id":"DEBIAN-CVE-2026-0001","published":"2026-10-01T00:00:00Z","modified":"2026-10-01T00:00:00Z","upstream":["CVE-2026-0001"],
				"details":"In the Linux kernel, the following vulnerability has been resolved:\n\nipv4: validate checksum_start\n\nIf a packet with bad metadata gets in."}]}`)
		case "/kev":
			io.WriteString(w, `{"vulnerabilities":[{"cveID":"CVE-2021-22555","dueDate":"2025-11-01"}]}`)
		case "/epss":
			io.WriteString(w, `{"data":[]}`)
		default:
			http.NotFound(w, r)
		}
	}, true)

	id, err := st.CreateAsset(ctx, store.Everything, store.Asset{Name: "linux", Kind: "os", Ecosystem: "Debian:12", Version: "6.1.76-1",
		Criticality: "high", Source: "manual", TrackSince: "2026-06-01"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := syncer.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Created != 2 || res.Skipped != 1 || res.Failed != 0 {
		t.Errorf("result = %+v", res)
	}
	if got := openIDs(t, st, id); !slices.Equal(got, []string{"DEBIAN-CVE-2021-0001", "DEBIAN-CVE-2026-0001"}) {
		t.Errorf("findings = %v (the recent one, and the old one known to be exploited)", got)
	}
	if _, err := st.Vulnerability(ctx, "DEBIAN-CVE-2004-0230"); err == nil {
		t.Error("an old advisory that cannot be reported was stored")
	}
	if v, err := st.Vulnerability(ctx, "DEBIAN-CVE-2026-0001"); err != nil || !slices.Contains(v.Aliases, "CVE-2026-0001") {
		t.Errorf("the upstream CVE must be an alias: %+v, %v", v, err)
	} else if v.Summary != "ipv4: validate checksum_start" {
		t.Errorf("summary of a record without one: %q", v.Summary)
	}
	if v, _ := st.Vulnerability(ctx, "DEBIAN-CVE-2021-0001"); !v.KEV {
		t.Error("the upstream CVE must bring the KEV flag")
	} else if v.Summary != "wifi: mt76: add a check" {
		t.Errorf("summary of a Debian record: %q", v.Summary)
	}
	if a, _ := st.Asset(ctx, store.Everything, id); a.OlderVulns != 1 {
		t.Errorf("older vulnerabilities = %d, want 1", a.OlderVulns)
	}
	if requests, _ := srv.counts(); requests["query"] != 2 || requests["vulns"] != 0 {
		t.Errorf("%d queries and %d single reads: the advisories come in full from the query", requests["query"], requests["vulns"])
	}
	if len(batches) != 1 || batches[0].Package.Name != "linux" {
		t.Errorf("batch = %+v", batches)
	}
}

// OSV finds nothing for the purl of a Debian SBOM with its qualifiers, nor for
// a binary package: what it is asked is the source package, in its release.
func TestPURLQualifiers(t *testing.T) {
	ctx := context.Background()
	st := storetest.Open(t)
	var asked []osv.Query
	syncer, _ := osvSyncer(t, st, func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Queries []osv.Query `json:"queries"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		var results []string
		for _, q := range body.Queries {
			asked = append(asked, q)
			results = append(results, `{}`)
		}
		io.WriteString(w, `{"results":[`+strings.Join(results, ",")+`]}`)
	}, false)
	for _, purl := range []string{
		"pkg:deb/debian/libssl3@3.0.11-1?arch=amd64&upstream=openssl&distro=debian-12",
		"pkg:deb/debian/linux-image-6.1.0-13-amd64@6.1.55-1?arch=amd64&distro=debian-12",
		"pkg:npm/lodash@4.17.15?foo=bar",
	} {
		if _, err := st.CreateAsset(ctx, store.Everything, store.Asset{Name: purl, Kind: "package", PURL: purl, Criticality: "low", Source: "sbom", Project: "app"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := syncer.Run(ctx); err != nil {
		t.Fatal(err)
	}
	want := []osv.Query{
		{Package: osv.Package{Name: "linux", Ecosystem: "Debian:12"}, Version: "6.1.55-1"},
		{Package: osv.Package{Name: "openssl", Ecosystem: "Debian:12"}, Version: "3.0.11-1"},
		{Package: osv.Package{PURL: "pkg:npm/lodash@4.17.15"}},
	}
	for _, q := range want {
		if !slices.Contains(asked, q) {
			t.Errorf("asked %+v, want %+v among them", asked, q)
		}
	}
}

// An asset a source could not check is reported, keeps its findings and does
// not stop the others; the progress reaches the end.
func TestFailedAssetAndProgress(t *testing.T) {
	ctx := context.Background()
	st := storetest.Open(t)
	syncer, _ := nvdSyncer(t, st, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("keywordSearch") == "panne" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		io.WriteString(w, `{"totalResults":1,"vulnerabilities":[`+cveAwaiting+`]}`)
	})
	var seen []tracking.Status
	syncer.Alert = func(context.Context) error {
		seen = append(seen, syncer.Status())
		return nil
	}
	add := func(name string) int64 {
		return storetest.Asset(t, st, store.Asset{Name: name, Kind: "product", Criticality: "low", Source: "manual"})
	}
	down, up := add("panne"), add("marche")
	storetest.Finding(t, st, down, store.Vulnerability{ID: "CVE-1", EPSS: -1, CVSS: -1}, time.Now())

	res, err := syncer.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Failed != 1 || res.Created != 1 || res.Resolved != 0 {
		t.Errorf("result = %+v", res)
	}
	if got := openIDs(t, st, down); !slices.Equal(got, []string{"CVE-1"}) {
		t.Errorf("findings of the unchecked asset = %v", got)
	}
	if got := openIDs(t, st, up); !slices.Equal(got, []string{"CVE-2026-1001"}) {
		t.Errorf("findings of the other asset = %v", got)
	}
	if len(seen) != 1 || seen[0].Total != 2 || seen[0].Done != 2 || !seen[0].Running {
		t.Errorf("progress at the end of the run: %+v", seen)
	}
	s := syncer.Status()
	if s.Running || s.Current != "" || len(s.Failures) != 1 || !strings.Contains(s.Failures[0], "panne") {
		t.Errorf("status = %+v", s)
	}
}

const (
	kernelFixed = `{"id":"CVE-2026-2001","published":"2026-10-01T00:00:00Z","modified":"2026-10-02T00:00:00Z","affected":[{"package":{"name":"Kernel","ecosystem":"Linux"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"6.7.0"},{"fixed":"6.12.5"}]}]}]}`
	kernelOther = `{"id":"CVE-2026-2002","published":"2026-10-01T00:00:00Z","modified":"2026-10-02T00:00:00Z","affected":[{"package":{"name":"Kernel","ecosystem":"Linux"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"5.11.0"},{"fixed":"5.15.100"}]}]}]}`
	kernelOpen  = `{"id":"CVE-2026-2003","published":"2026-10-01T00:00:00Z","modified":"2026-10-02T00:00:00Z","affected":[{"package":{"name":"Kernel","ecosystem":"Linux"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"6.0.0"}]}]}]}`
	kernelOld   = `{"id":"CVE-2022-2004","published":"2022-01-01T00:00:00Z","modified":"2026-10-02T00:00:00Z","affected":[{"package":{"name":"Kernel","ecosystem":"Linux"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"6.0.0"},{"fixed":"6.12.5"}]}]}]}`
)

// In an ecosystem where OSV does not compare versions, the advisories of the
// package are read once for all its assets, and their ranges compared here.
func TestVersionsComparedHere(t *testing.T) {
	ctx := context.Background()
	st := storetest.Open(t)
	syncer, srv := osvSyncer(t, st, func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Package osv.Package `json:"package"`
			Version string      `json:"version"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		if r.URL.Path != "/v1/query" || body.Package.Name != "Kernel" || body.Package.Ecosystem != "Linux" || body.Version != "" {
			t.Errorf("OSV asked %s %+v", r.URL.Path, body)
		}
		io.WriteString(w, `{"vulns":[`+kernelFixed+`,`+kernelOther+`,`+kernelOpen+`,`+kernelOld+`]}`)
	}, false)

	add := func(version string) int64 {
		id, err := st.CreateAsset(ctx, store.Everything, store.Asset{Name: "Linux Kernel", Ecosystem: "Linux", Version: version, Kind: "os",
			Criticality: "high", Source: "manual", TrackSince: "2026-06-01"})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	recent, older, latest := add("6.8.1"), add("5.15.0-100-generic"), add("latest")

	res, err := syncer.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Assets != 3 || res.Failed != 0 {
		t.Errorf("result = %+v", res)
	}
	if requests, _ := srv.counts(); requests["query"] != 1 {
		t.Errorf("the advisories were read %d times", requests["query"])
	}
	if got := openIDs(t, st, recent); !slices.Equal(got, []string{"CVE-2026-2001", "CVE-2026-2003"}) {
		t.Errorf("version 6.8.1: %v", got)
	}
	if got := openIDs(t, st, older); !slices.Equal(got, []string{"CVE-2026-2002"}) {
		t.Errorf("version of a distribution: %v", got)
	}
	if got := openIDs(t, st, latest); !slices.Equal(got, []string{"CVE-2026-2003"}) {
		t.Errorf("latest: %v", got)
	}
	if _, err := st.Vulnerability(ctx, "CVE-2022-2004"); err == nil {
		t.Error("an advisory older than the tracked period was stored")
	}
	if a, _ := st.Asset(ctx, store.Everything, recent); a.OlderVulns != 1 {
		t.Errorf("older vulnerabilities = %d, want 1", a.OlderVulns)
	}
}

// A dismissal rule applies to the findings of a sync, and before the alerts.
func TestDismissalRuleAtSync(t *testing.T) {
	ctx := context.Background()
	st := storetest.Open(t)
	syncer, _ := osvSyncer(t, st, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"vulns":[
			{"id":"CVE-2026-1","summary":"wifi: fix","published":"2026-10-01T00:00:00Z","modified":"2026-10-02T00:00:00Z","affected":[{"package":{"name":"Kernel","ecosystem":"Linux"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"6.0.0"}]}]}]},
			{"id":"CVE-2026-2","summary":"ipv4: fix","published":"2026-10-01T00:00:00Z","modified":"2026-10-02T00:00:00Z","affected":[{"package":{"name":"Kernel","ecosystem":"Linux"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"6.0.0"}]}]}]}]}`)
	}, false)
	var atAlert []store.Finding
	syncer.Alert = func(ctx context.Context) error {
		atAlert, _ = st.ListFindings(ctx, store.Everything, store.FindingFilter{Status: "in_triage"})
		return nil
	}
	id, err := st.CreateAsset(ctx, store.Everything, store.Asset{Name: "Kernel", Ecosystem: "Linux", Version: "6.8.1", Kind: "os", Criticality: "high", Source: "manual"})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateDismissalRule(ctx, store.Everything, id, "wifi:"); err != nil {
		t.Fatal(err)
	}
	res, err := syncer.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Created != 2 || res.Dismissed != 1 {
		t.Errorf("result = %+v", res)
	}
	findings, _ := st.ListFindings(ctx, store.Everything, store.FindingFilter{AssetID: id})
	for _, f := range findings {
		if want := map[string]string{"CVE-2026-1": "not_affected", "CVE-2026-2": "in_triage"}[f.VulnID]; f.Status != want {
			t.Errorf("%s: %s, want %s", f.VulnID, f.Status, want)
		}
	}
	if len(atAlert) != 1 || atAlert[0].VulnID != "CVE-2026-2" {
		t.Errorf("to analyse when the alerts are sent: %+v", atAlert)
	}
}
