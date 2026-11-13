package tracking_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/La-Cizaille-Corp/vigil/internal/sources/nvd"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
	"github.com/La-Cizaille-Corp/vigil/internal/tracking"
)

// A refused NVD key (404) leaves the asset unchecked: its open findings are
// not taken as fixed.
func TestNVDRefusalKeepsFindingsOpen(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	var refuse atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if refuse.Load() {
			w.Header().Set("message", "Invalid apiKey.")
			w.WriteHeader(http.StatusNotFound)
			return
		}
		io.WriteString(w, `{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2024-21762","published":"2024-02-09T09:15:00.000",
			"descriptions":[{"lang":"en","value":"out-of-bounds write"}],
			"metrics":{"cvssMetricV31":[{"cvssData":{"baseSeverity":"CRITICAL","baseScore":9.8}}]}}}]}`)
	}))
	defer srv.Close()
	id, err := st.CreateAsset(ctx, store.Everything, store.Asset{Name: "FortiGate", Kind: "product", Criticality: "high",
		CPE: "cpe:2.3:o:fortinet:fortios:7.2.4:*:*:*:*:*:*:*", Source: "manual"})
	if err != nil {
		t.Fatal(err)
	}
	s := &tracking.Syncer{Store: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		NVD: &nvd.Client{URL: srv.URL, HTTP: srv.Client(), APIKey: "key"}}
	if res, err := s.Run(ctx); err != nil || res.Created != 1 {
		t.Fatalf("first sync: %+v, %v", res, err)
	}
	refuse.Store(true)
	res, err := s.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Resolved != 0 || res.Failed != 1 {
		t.Errorf("sync with a refused key: %+v", res)
	}
	if open := openIDs(t, st, id); len(open) != 1 {
		t.Errorf("open findings after the refusal: %v", open)
	}
}

// A CVE of the NVD stored as it is, by its date of modification, is not
// written again: every synchronisation rewrote it. Modified, it is.
func TestNVDRecordWrittenOnceModified(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	var description, modified atomic.Value
	description.Store("first text")
	modified.Store("2024-02-13T16:00:00.000")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2024-21762","published":"2024-02-09T09:15:00.000",
			"lastModified":"`+modified.Load().(string)+`","descriptions":[{"lang":"en","value":"`+description.Load().(string)+`"}]}}]}`)
	}))
	defer srv.Close()
	if _, err := st.CreateAsset(ctx, store.Everything, store.Asset{Name: "FortiGate", Kind: "product", Criticality: "high",
		CPE: "cpe:2.3:o:fortinet:fortios:7.2.4:*:*:*:*:*:*:*", Source: "manual"}); err != nil {
		t.Fatal(err)
	}
	s := &tracking.Syncer{Store: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		NVD: &nvd.Client{URL: srv.URL, HTTP: srv.Client()}}
	details := func() string {
		t.Helper()
		if _, err := s.Run(ctx); err != nil {
			t.Fatal(err)
		}
		v, err := st.Vulnerability(ctx, "CVE-2024-21762")
		if err != nil {
			t.Fatal(err)
		}
		return v.Details
	}
	if got := details(); got != "first text" {
		t.Fatalf("first sync: %q", got)
	}
	description.Store("second text") // as the NVD would not send it without a new date
	if got := details(); got != "first text" {
		t.Errorf("record unchanged at the NVD written again: %q", got)
	}
	modified.Store("2024-03-01T10:00:00.000")
	if got := details(); got != "second text" {
		t.Errorf("record modified at the NVD: %q", got)
	}
}
