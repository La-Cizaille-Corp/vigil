package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

// The list kept of a query replaces the one before, and goes once its full
// read is old enough.
func TestOSVLists(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	if _, err := st.OSVList(ctx, "q1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("no list yet: %v", err)
	}
	week := time.Now().Add(-7 * 24 * time.Hour)
	old := OSVList{Query: "q1", ReadAt: week.Add(-time.Hour), Advisories: `[{"id":"A"}]`}
	recent := OSVList{Query: "q2", ReadAt: time.Now(), Advisories: `[]`}
	for _, l := range []OSVList{old, recent} {
		if err := st.SaveOSVList(ctx, l); err != nil {
			t.Fatal(err)
		}
	}
	old.Advisories = `[{"id":"B"}]`
	if err := st.SaveOSVList(ctx, old); err != nil {
		t.Fatal(err)
	}
	got, err := st.OSVList(ctx, "q1")
	if err != nil || got.Advisories != `[{"id":"B"}]` || !got.ReadAt.Equal(old.ReadAt.Truncate(time.Second)) {
		t.Errorf("list = %+v, %v", got, err)
	}
	if n, err := st.PurgeOSVLists(ctx, week); err != nil || n != 1 {
		t.Errorf("purge: %d, %v", n, err)
	}
	if _, err := st.OSVList(ctx, "q1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("an old list stays: %v", err)
	}
	if _, err := st.OSVList(ctx, "q2"); err != nil {
		t.Errorf("a recent list went: %v", err)
	}
}
