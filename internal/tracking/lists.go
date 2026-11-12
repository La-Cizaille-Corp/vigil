package tracking

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/sources/osv"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
)

// A package too large for a batch answer of OSV is read in full, a kernel in
// 25 minutes and 4.5 GB for an Ubuntu release. What the synchronisation needs
// of each advisory reported is kept, by query: then a list unchanged at OSV is
// not read again, and a few advisories new or modified are read alone (A90).

// listed is what is kept of an advisory reported for a query: enough to tell,
// without reading it again, whether an asset reports it in its tracked period
// (reportable) and what it names (describe).
type listed struct {
	ID        string   `json:"id"`
	Modified  string   `json:"modified"`
	Published string   `json:"published,omitempty"`
	Others    []string `json:"others,omitempty"` // osv.Vuln.OtherIDs
}

// short returns what is kept of an advisory read in full, checked as what is
// stored of it (listed.checked).
func short(v osv.Vuln) (listed, error) {
	return listed{ID: v.ID, Modified: v.Modified, Published: v.Published, Others: v.OtherIDs()}.checked()
}

func (l listed) ref() osv.VulnRef { return osv.VulnRef{ID: l.ID, Modified: l.Modified} }

// listKey is the key of the list of a query: the assets that ask the same
// share it.
func listKey(q osv.Query) string {
	key, _ := json.Marshal(q) // strings only: cannot fail
	return string(key)
}

const (
	// listMaxAge is how long a list serves after the full read that made it:
	// then the package is read in full again. Should OSV change an advisory
	// without its date of modification, or a list drift, it would last a week
	// at most, for one full read a week instead of four a day.
	listMaxAge = 7 * 24 * time.Hour
	// changedShare: beyond a tenth of the advisories to read again, the package
	// is read in full. Below, one request each costs at most a tenth of the
	// bytes of a full read; an Ubuntu advisory is read alone in 0.65 s, against
	// 0.2 to 0.4 s in a full read, a Debian one in 0.2 s against 6 ms. A release
	// of a kernel modifies nearly all the advisories of its distribution.
	changedShare = 10
)

// packageRead is what the advisories of a large package give for an asset:
// those reported, what they name, those older than its tracked period, and
// the list to keep.
type packageRead struct {
	reported []string
	known    map[string]described
	older    likelyOlder
	list     []listed
}

func newPackageRead() *packageRead {
	return &packageRead{known: map[string]described{}, older: likelyOlder{}}
}

// take notes an advisory reported for the asset; true when the asset can
// report it, and it must then be stored.
func (r *packageRead) take(a store.Asset, l listed, exploited func() map[string]bool) bool {
	r.reported = append(r.reported, l.ID)
	r.known[l.ID] = describe(l.ID, l.Others)
	r.list = append(r.list, l)
	if reportable(a, l, exploited) {
		return true
	}
	r.older.candidate(l.ref(), r.known[l.ID])
	return false
}

// encode returns the list to keep, as stored.
func (r *packageRead) encode() string {
	data, _ := json.Marshal(r.list) // strings only: cannot fail
	return string(data)
}

// readChanged reads, of the advisories reported for a large package, those
// new or modified since its list was kept, and takes the others from it, with
// the time of the full read that made it. It returns nil, for a full read,
// without a list kept, without the short list of OSV, or when more than a
// tenth of the advisories would be read again: those changed, and those the
// asset can report that are not stored as they are (its period moved back, a
// CVE became exploited).
func (s *Syncer) readChanged(ctx context.Context, pending *advisories, a store.Asset, q osv.Query, key string, exploited func() map[string]bool) (*packageRead, time.Time, error) {
	kept, err := s.Store.OSVList(ctx, key)
	if errors.Is(err, store.ErrNotFound) {
		return nil, time.Time{}, nil
	}
	if err != nil {
		return nil, time.Time{}, err
	}
	var entries []listed
	if err := json.Unmarshal([]byte(kept.Advisories), &entries); err != nil {
		s.Log.Warn("osv list unreadable: the package is read in full", "asset", a.Name, "err", err)
		return nil, time.Time{}, nil
	}
	refs, err := s.OSV.Refs(ctx, q)
	if err != nil {
		s.Log.Warn("osv short list failed: the package is read in full", "asset", a.Name, "err", err)
		return nil, time.Time{}, nil
	}
	byID := make(map[string]listed, len(entries))
	for _, l := range entries {
		byID[l.ID] = l
	}
	again := map[string]bool{}
	for _, ref := range refs {
		l, ok := byID[ref.ID]
		switch {
		case !ok || !osv.SameModified(l.Modified, ref.Modified):
			again[ref.ID] = true
		case reportable(a, l, exploited):
			stale, err := s.stale(ctx, ref)
			if err != nil {
				return nil, time.Time{}, err
			}
			again[ref.ID] = stale
		}
	}
	n := 0
	for _, read := range again {
		if read {
			n++
		}
	}
	s.Log.Info("osv large package", "asset", a.Name, "advisories", len(refs), "changed", n, "whole", n*changedShare > len(refs))
	if n*changedShare > len(refs) {
		return nil, time.Time{}, nil
	}
	r := newPackageRead()
	for _, ref := range refs {
		if !again[ref.ID] { // as kept, and stored as it is when reportable
			r.take(a, byID[ref.ID], exploited)
			continue
		}
		v, err := s.OSV.Vuln(ctx, ref.ID)
		if err != nil {
			return nil, time.Time{}, err
		}
		l, err := short(v)
		if err != nil {
			return nil, time.Time{}, err
		}
		if r.take(a, l, exploited) {
			if err := s.storeOSV(ctx, pending, v, false); err != nil {
				return nil, time.Time{}, err
			}
		}
	}
	return r, kept.ReadAt, nil
}
