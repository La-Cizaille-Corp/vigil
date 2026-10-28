package tracking_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/La-Cizaille-Corp/vigil/internal/digest"
	"github.com/La-Cizaille-Corp/vigil/internal/sources/osv"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
	"github.com/La-Cizaille-Corp/vigil/internal/tracking"
)

// fakeOSV reports GHSA-test for lodash 4.17.15 only.
func fakeOSV(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/querybatch":
			var req struct{ Queries []osv.Query }
			json.NewDecoder(r.Body).Decode(&req)
			var results []map[string]any
			for _, q := range req.Queries {
				var vulns []osv.VulnRef
				if strings.HasSuffix(q.Package.PURL, "@4.17.15") {
					vulns = append(vulns, osv.VulnRef{ID: "GHSA-test", Modified: "2026-01-01T00:00:00Z"})
				}
				if strings.HasSuffix(q.Package.PURL, "@1.0.0") {
					vulns = append(vulns, osv.VulnRef{ID: "GHSA-old", Modified: "2019-01-01T00:00:00Z"},
						osv.VulnRef{ID: "GHSA-oldkev", Modified: "2019-01-01T00:00:00Z"},
						osv.VulnRef{ID: "GHSA-new", Modified: "2026-01-01T00:00:00Z"})
				}
				results = append(results, map[string]any{"vulns": vulns})
			}
			json.NewEncoder(w).Encode(map[string]any{"results": results})
		case r.URL.Path == "/v1/vulns/GHSA-test":
			io.WriteString(w, `{"id":"GHSA-test","summary":"Prototype pollution","aliases":["CVE-2020-8203"],
				"modified":"2026-01-01T00:00:00Z","database_specific":{"severity":"HIGH"},
				"references":[{"type":"WEB","url":"https://example.org/advisory"}]}`)
		case r.URL.Path == "/v1/vulns/GHSA-old":
			io.WriteString(w, `{"id":"GHSA-old","aliases":["CVE-2019-0001"],"published":"2019-01-01T00:00:00Z","modified":"2019-01-01T00:00:00Z"}`)
		case r.URL.Path == "/v1/vulns/GHSA-oldkev":
			io.WriteString(w, `{"id":"GHSA-oldkev","aliases":["CVE-2020-8203"],"published":"2019-01-01T00:00:00Z","modified":"2019-01-01T00:00:00Z"}`)
		case r.URL.Path == "/v1/vulns/GHSA-new":
			io.WriteString(w, `{"id":"GHSA-new","published":"2026-09-01T00:00:00Z","modified":"2026-01-01T00:00:00Z"}`)
		case r.URL.Path == "/kev":
			io.WriteString(w, `{"vulnerabilities":[{"cveID":"CVE-2020-8203","dueDate":"2026-12-01"}]}`)
		case r.URL.Path == "/epss":
			if !strings.Contains(r.URL.Query().Get("cve"), "CVE-2020-8203") {
				t.Errorf("unexpected EPSS query %q", r.URL.RawQuery)
			}
			io.WriteString(w, `{"data":[{"cve":"CVE-2020-8203","epss":"0.42"}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestSyncLifecycle(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	srv := fakeOSV(t)
	defer srv.Close()
	client := osv.New("vigil-test")
	client.BaseURL = srv.URL
	syncer := &tracking.Syncer{Store: st, OSV: client, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		HTTP: srv.Client(), KEVURL: srv.URL + "/kev", EPSSURL: srv.URL + "/epss"}

	asset := store.Asset{Name: "lodash", Kind: "package", PURL: "pkg:npm/lodash@4.17.15",
		Criticality: "high", Source: "manual"}
	id, err := st.CreateAsset(ctx, asset)
	if err != nil {
		t.Fatal(err)
	}

	// 1. First sync creates the finding.
	res, err := syncer.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Created != 1 {
		t.Fatalf("created = %d, want 1", res.Created)
	}
	findings, _ := st.ListFindings(ctx, store.FindingFilter{})
	if len(findings) != 1 || findings[0].Severity != "HIGH" || findings[0].Status != "in_triage" {
		t.Fatalf("unexpected findings: %+v", findings)
	}
	if !findings[0].KEV || findings[0].EPSS != 0.42 {
		t.Fatalf("KEV/EPSS enrichment missing: %+v", findings[0])
	}

	// 2. Second sync is idempotent.
	if res, _ = syncer.Run(ctx); res.Created != 0 {
		t.Fatalf("second sync created %d findings", res.Created)
	}

	// 3. A user triages it.
	if err := st.SetFindingStatus(ctx, findings[0].ID, 0, "exploitable", "", "à patcher"); err != nil {
		t.Fatal(err)
	}

	// 4. Upgrading the asset makes the source stop reporting it: auto-resolved.
	asset.ID, asset.PURL = id, "pkg:npm/lodash@4.17.21"
	if err := st.UpdateAsset(ctx, asset); err != nil {
		t.Fatal(err)
	}
	if res, _ = syncer.Run(ctx); res.Resolved != 1 {
		t.Fatalf("resolved = %d, want 1", res.Resolved)
	}

	// 5. Downgrading again reopens it.
	asset.PURL = "pkg:npm/lodash@4.17.15"
	st.UpdateAsset(ctx, asset)
	if res, _ = syncer.Run(ctx); res.Reopened != 1 {
		t.Fatalf("reopened = %d, want 1", res.Reopened)
	}
	events, _ := st.FindingEvents(ctx, findings[0].ID)
	if len(events) != 3 {
		t.Fatalf("events = %d, want 3", len(events))
	}

	// 6. The digest lists the vulnerability.
	d, err := digest.Generate(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(d.Markdown, "GHSA-test") || !strings.Contains(d.HTML, "CVE-2020-8203") {
		t.Fatalf("digest misses the vulnerability:\n%s", d.Markdown)
	}
}

// TestTrackedPeriod checks that an asset only reports vulnerabilities
// published since the start of its tracked period, or exploited.
func TestTrackedPeriod(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	srv := fakeOSV(t)
	defer srv.Close()
	client := osv.New("vigil-test")
	client.BaseURL = srv.URL
	syncer := &tracking.Syncer{Store: st, OSV: client, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		HTTP: srv.Client(), KEVURL: srv.URL + "/kev", EPSSURL: srv.URL + "/epss"}

	id, err := st.CreateAsset(ctx, store.Asset{Name: "lib", Kind: "package", PURL: "pkg:npm/lib@1.0.0",
		Criticality: "medium", Source: "manual", TrackSince: "2026-06-01"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := syncer.RunAsset(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if res.Created != 2 || res.Skipped != 1 {
		t.Fatalf("created %d, skipped %d; want 2 and 1", res.Created, res.Skipped)
	}
	findings, _ := st.ListFindings(ctx, store.FindingFilter{AssetID: id})
	for _, f := range findings {
		if f.VulnID == "GHSA-old" {
			t.Errorf("old vulnerability reported")
		}
	}
	if s := syncer.Status(); s.Running || s.Asset != "lib" || s.Result.Created != 2 || s.Finished.IsZero() {
		t.Errorf("status: %+v", s)
	}
	// The asset page tells that older known flaws exist.
	if a, _ := st.Asset(ctx, id); a.OlderVulns != 1 {
		t.Errorf("older vulnerabilities = %d, want 1", a.OlderVulns)
	}

	// Whole history: the old one is reported too.
	a, _ := st.Asset(ctx, id)
	a.TrackSince = ""
	st.UpdateAsset(ctx, a)
	if res, _ = syncer.RunAsset(ctx, id); res.Created != 1 {
		t.Fatalf("created %d, want 1", res.Created)
	}
	if a, _ := st.Asset(ctx, id); a.OlderVulns != 0 {
		t.Errorf("older vulnerabilities after tracking the whole history = %d", a.OlderVulns)
	}
}

func TestValidateStatus(t *testing.T) {
	if err := tracking.ValidateStatus("not_affected", "", ""); err == nil {
		t.Error("not_affected without justification accepted")
	}
	if err := tracking.ValidateStatus("bogus", "", ""); err == nil {
		t.Error("unknown status accepted")
	}
	if err := tracking.ValidateStatus("not_affected", "code_not_reachable", "ok"); err != nil {
		t.Error(err)
	}
}
