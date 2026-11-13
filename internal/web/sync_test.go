package web

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/store"
	"github.com/La-Cizaille-Corp/vigil/internal/tracking"
)

// A run asked while another one goes waits for it instead of being lost
// (A32): here the run of an import, which a sync in progress would miss, as
// the schedule of serve, which goes through Sync too. Two requests to check
// the same asset meanwhile make one run, not two: it reads the asset when it
// starts.
func TestSyncsWaitForTheRunInProgress(t *testing.T) {
	retry := syncRetry
	syncRetry = 10 * time.Millisecond
	t.Cleanup(func() { syncRetry = retry })
	runs := make(chan string, 10) // the asset of each run, "" for the whole inventory
	release := make(chan struct{})
	var syncer *tracking.Syncer
	st, base := newServerWith(t, func(s *Server) {
		// No source: a run checks nothing, then holds the Syncer in Alert
		// until the test releases it.
		syncer = &tracking.Syncer{Store: s.Store, Log: s.Log, Alert: func(context.Context) error {
			runs <- syncer.Status().Asset
			<-release
			return nil
		}}
		s.Syncer = syncer
	})
	id, err := st.CreateAsset(context.Background(), store.Everything, store.Asset{Name: "nginx", Kind: "package", Criticality: "high", Source: "manual"})
	if err != nil {
		t.Fatal(err)
	}
	c := loginAs(t, base, "analyst", testPassword)
	if code, _ := c.send(http.MethodPost, "/sync", url.Values{"csrf": {c.csrf()}}); code != http.StatusSeeOther {
		t.Fatalf("sync: %d", code)
	}
	if first := <-runs; first != "" {
		t.Fatalf("first run: %q", first)
	}
	for range 2 {
		if code, _ := c.send(http.MethodPost, "/assets/"+itoa(id)+"/scan", url.Values{"csrf": {c.csrf()}}); code != http.StatusSeeOther {
			t.Fatalf("scan: %d", code)
		}
	}
	if code, _ := c.upload("/assets/import-csv", "csv", "a.csv", "name\napache\n", url.Values{"csrf": {c.csrf()}}); code != http.StatusSeeOther {
		t.Fatalf("CSV import: %d", code)
	}
	close(release)
	var got []string
	timeout := time.After(30 * time.Second)
	for len(got) < 2 {
		select {
		case asset := <-runs:
			got = append(got, asset)
		case <-timeout:
			t.Fatalf("runs after the first: %q", got)
		}
	}
	select {
	case asset := <-runs:
		got = append(got, asset)
	case <-time.After(50 * syncRetry):
	}
	slices.Sort(got)
	if !slices.Equal(got, []string{"", "nginx"}) {
		t.Errorf("runs after the first: %q, want the whole inventory once (the import) and nginx once", got)
	}
}
