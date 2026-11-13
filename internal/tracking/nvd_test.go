package tracking_test

import (
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/La-Cizaille-Corp/vigil/internal/store"
)

// A refused NVD key (404) leaves the asset unchecked: its open findings are
// not taken as fixed.
func TestNVDRefusalKeepsFindingsOpen(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	refuse := false
	s, srv := nvdSyncer(t, st, func(w http.ResponseWriter, r *http.Request) {
		if refuse {
			w.Header().Set("message", "Invalid apiKey.")
			w.WriteHeader(http.StatusNotFound)
			return
		}
		io.WriteString(w, `{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2024-21762","published":"2024-02-09T09:15:00.000",
			"descriptions":[{"lang":"en","value":"out-of-bounds write"}],
			"metrics":{"cvssMetricV31":[{"cvssData":{"baseSeverity":"CRITICAL","baseScore":9.8}}]}}}]}`)
	})
	s.NVD.APIKey = "key"
	id, err := st.CreateAsset(ctx, store.Everything, store.Asset{Name: "FortiGate", Kind: "product", Criticality: "high",
		CPE: "cpe:2.3:o:fortinet:fortios:7.2.4:*:*:*:*:*:*:*", Source: "manual"})
	if err != nil {
		t.Fatal(err)
	}
	if res, err := s.Run(ctx); err != nil || res.Created != 1 {
		t.Fatalf("first sync: %+v, %v", res, err)
	}
	srv.locked(func() { refuse = true })
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
	description, modified := "first text", "2024-02-13T16:00:00.000"
	s, srv := nvdSyncer(t, st, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2024-21762","published":"2024-02-09T09:15:00.000",
			"lastModified":"`+modified+`","descriptions":[{"lang":"en","value":"`+description+`"}]}}]}`)
	})
	if _, err := st.CreateAsset(ctx, store.Everything, store.Asset{Name: "FortiGate", Kind: "product", Criticality: "high",
		CPE: "cpe:2.3:o:fortinet:fortios:7.2.4:*:*:*:*:*:*:*", Source: "manual"}); err != nil {
		t.Fatal(err)
	}
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
	srv.locked(func() { description = "second text" }) // as the NVD would not send it without a new date
	if got := details(); got != "first text" {
		t.Errorf("record unchanged at the NVD written again: %q", got)
	}
	srv.locked(func() { modified = "2024-03-01T10:00:00.000" })
	if got := details(); got != "second text" {
		t.Errorf("record modified at the NVD: %q", got)
	}
}
