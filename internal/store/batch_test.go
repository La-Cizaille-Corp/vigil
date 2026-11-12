package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

// The calls made with the context of InTx join its transaction, those that
// open their own (ObserveFinding) included: an error undoes them all.
func TestInTxAllOrNothing(t *testing.T) {
	st := openTest(t)
	// A call outside the transaction would wait for its connection: fail
	// rather than hang.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := st.UpsertVulnerability(ctx, Vulnerability{ID: "CVE-1", EPSS: -1, CVSS: -1}); err != nil {
		t.Fatal(err)
	}
	refused := errors.New("refused")
	write := func(fail bool) error {
		return st.InTx(ctx, func(ctx context.Context) error {
			id, err := st.CreateAsset(ctx, Everything, Asset{Name: "nginx", Kind: "technology", Criticality: "low", Source: "manual"})
			if err != nil {
				return err
			}
			if _, err := st.ObserveFinding(ctx, id, "CVE-1", "", time.Now()); err != nil {
				return err
			}
			if fail {
				return refused
			}
			return nil
		})
	}
	if err := write(true); !errors.Is(err, refused) {
		t.Fatalf("failed batch: %v", err)
	}
	if assets, _ := st.ListAssets(ctx, Everything); len(assets) != 0 {
		t.Errorf("failed batch left %d assets", len(assets))
	}
	if err := write(false); err != nil {
		t.Fatal(err)
	}
	if findings, _ := st.ListFindings(ctx, Everything, FindingFilter{}); len(findings) != 1 {
		t.Errorf("batch: %d findings, want 1", len(findings))
	}
}

// The exploitation signals of every vulnerability are given at each
// synchronisation: only those that changed are written.
func TestExploitSignalsWrittenOnlyWhenChanged(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	for _, id := range []string{"CVE-1", "CVE-2"} {
		if err := st.UpsertVulnerability(ctx, Vulnerability{ID: id, EPSS: -1, CVSS: -1}); err != nil {
			t.Fatal(err)
		}
	}
	signals := []ExploitSignal{{ID: "CVE-1", KEV: true, KEVDue: "2026-12-01", EPSS: 0.5}, {ID: "CVE-2", EPSS: -1}, {ID: "CVE-unknown", EPSS: 0.1}}
	for _, want := range []int{1, 0} {
		if n, err := st.SetExploitSignals(ctx, signals...); err != nil || n != want {
			t.Errorf("changed = %d, %v; want %d", n, err, want)
		}
	}
	if v, _ := st.Vulnerability(ctx, "CVE-1"); !v.KEV || v.KEVDue != "2026-12-01" || v.EPSS != 0.5 {
		t.Errorf("signals = %+v", v)
	}
	signals[0].EPSS = 0.6
	if n, err := st.SetExploitSignals(ctx, signals...); err != nil || n != 1 {
		t.Errorf("after a new score: changed = %d, %v", n, err)
	}
}
