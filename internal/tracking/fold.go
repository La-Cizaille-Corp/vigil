package tracking

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/La-Cizaille-Corp/vigil/internal/choice"
	"github.com/La-Cizaille-Corp/vigil/internal/fr"
	"github.com/La-Cizaille-Corp/vigil/internal/sources/osv"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
)

// One finding per CVE (A80). A source reports a vulnerability of an asset
// under its own advisory (UBUNTU-CVE-…, DEBIAN-CVE-…, GHSA-…) and, at times,
// under others: a grouped advisory listing it among hundreds (USN-…, DSA-…), or
// a second database (GO-… beside GHSA-…). The synchronisation keeps one finding
// per CVE: the rules read the identifiers the advisories give, never a list of
// prefixes.

// described is what an advisory names: the CVEs it is about (one for the
// advisory of a CVE, several for a grouped one) and the other advisories it
// cites (a USN cites the UBUNTU-CVE of each of its CVEs).
type described struct {
	cves  []string
	named []string
}

// describe reads an advisory from its id and its other ids: osv.Vuln.OtherIDs
// as read, or the aliases stored.
func describe(id string, others []string) described {
	var d described
	for _, x := range append([]string{id}, others...) {
		switch {
		case strings.HasPrefix(x, "CVE-"):
			d.cves = append(d.cves, x)
		case x != id:
			d.named = append(d.named, x)
		}
	}
	slices.Sort(d.cves)
	d.cves = slices.Compact(d.cves)
	return d
}

// CVEs returns the CVEs a vulnerability names, from its id and aliases.
func CVEs(id string, aliases []string) []string { return describe(id, aliases).cves }

// findingPlan is what record writes for an asset: the findings to fold, those
// observed, the advisories whose findings stay open, and how many
// vulnerabilities are older than the tracked period.
type findingPlan struct {
	folds   []store.Fold
	observe []observed
	still   []string
	older   int
}

// reportedAdvisory is an advisory reported for the asset being recorded, or
// behind one of its findings.
type reportedAdvisory struct {
	described
	stored   *store.Vulnerability // nil when not stored: older than the tracked period
	inPeriod bool                 // see store.InTrackedPeriod
}

// The events of a folded finding.
const (
	foldedNotice = "avis groupé : chacune de ses CVE a son propre avis pour cet actif"
	foldedSame   = "même CVE que %s, qui la suit pour cet actif"
)

// plan reads what record needs and decides, by the rules of A80:
//   - a grouped advisory that cites advisories of its CVEs, one of which is
//     reported for the asset or has a finding on it, is not a finding: the
//     source describes its CVEs one by one, and it is shown on their findings;
//   - the advisories describing the same CVE alone make one finding: the one
//     already shown stays, reported or not, as long as one of them is; among
//     several, the one a user decided on last, then an open one, then one with
//     a severity, then the oldest;
//   - a CVE is in the tracked period when all of its advisories are, or when
//     it already has a finding: its own date counts, not that of a later
//     advisory;
//   - any other advisory is a finding of its own, as before;
//   - the findings made before, no longer reported, are folded alike.
func (s *Syncer) plan(ctx context.Context, o observation) (findingPlan, error) {
	var p findingPlan
	a := o.asset
	triage, err := s.Store.ListFindingTriage(ctx, a.ID)
	if err != nil {
		return p, err
	}
	ids := slices.Clone(o.reported)
	slices.Sort(ids)
	ids = slices.Compact(ids)
	// What each advisory names, reported or behind a finding of the asset.
	advs := make(map[string]*reportedAdvisory, len(ids)+len(triage))
	read := func(id string) (*reportedAdvisory, error) {
		if ad := advs[id]; ad != nil {
			return ad, nil
		}
		ad := &reportedAdvisory{}
		d, known := o.known[id]
		v, err := s.Store.Vulnerability(ctx, id)
		switch {
		case errors.Is(err, store.ErrNotFound):
		case err != nil:
			return nil, err
		default:
			ad.stored = &v
			if !known {
				d = describe(v.ID, v.Aliases)
			}
		}
		ad.described = d
		advs[id] = ad
		return ad, nil
	}
	alone := map[string]bool{}     // advisories of one CVE, reported or behind a finding
	byCVE := map[string][]string{} // their CVE → its advisories
	for _, id := range ids {
		ad, err := read(id)
		if err != nil {
			return p, err
		}
		if ad.inPeriod, err = s.Store.InTrackedPeriod(ctx, a.ID, id, a.TrackSince); err != nil {
			return p, err
		}
		if len(ad.cves) == 1 {
			alone[id] = true
			byCVE[ad.cves[0]] = append(byCVE[ad.cves[0]], id)
		}
	}
	rows := make(map[string]store.FindingTriage, len(triage))
	rowsByCVE := map[string][]store.FindingTriage{} // findings of one CVE
	for _, t := range triage {
		rows[t.VulnID] = t
		ad, err := read(t.VulnID)
		if err != nil {
			return p, err
		}
		if len(ad.cves) == 1 {
			alone[t.VulnID] = true // the source described it for the asset
			rowsByCVE[ad.cves[0]] = append(rowsByCVE[ad.cves[0]], t)
		}
	}
	// A grouped advisory, reported or behind a finding made before A80, that
	// cites advisories of its CVEs the source reports for the asset.
	grouped := func(id string) bool {
		ad := advs[id]
		return len(ad.cves) > 1 && slices.ContainsFunc(ad.named, func(n string) bool { return alone[n] })
	}
	foldGrouped := func(id string) {
		if r, ok := rows[id]; ok && r.FoldedInto == 0 {
			p.folds = append(p.folds, store.Fold{ID: r.ID, Into: store.FoldedNotice, Why: foldedNotice})
		}
	}
	p.still = slices.Clone(ids)
	for _, id := range ids {
		ad := advs[id]
		switch {
		case len(ad.cves) == 1: // below, with the other advisories of its CVE
		case grouped(id):
			foldGrouped(id)
		case ad.inPeriod:
			p.observe = append(p.observe, observed{id, fixedIn(a, ad)})
		default:
			p.older++
		}
	}
	cves := make([]string, 0, len(byCVE))
	for cve := range byCVE {
		cves = append(cves, cve)
	}
	slices.Sort(cves)
	for _, cve := range cves {
		list, found := byCVE[cve], rowsByCVE[cve]
		inPeriod := !slices.ContainsFunc(list, func(id string) bool { return !advs[id].inPeriod })
		if len(found) == 0 && !inPeriod {
			p.older++
			continue
		}
		kept := keptAdvisory(list, advs)
		shown := slices.DeleteFunc(slices.Clone(found), func(r store.FindingTriage) bool { return r.FoldedInto != 0 })
		if len(shown) > 0 {
			slices.SortStableFunc(shown, func(x, y store.FindingTriage) int { return compareKept(x, y, advs) })
			kept = shown[0].VulnID
			for _, r := range shown[1:] {
				p.folds = append(p.folds, store.Fold{ID: r.ID, Into: shown[0].ID,
					Why: fmt.Sprintf(foldedSame, kept), Note: divergence(shown[0], r)})
			}
		}
		var raws []string
		for _, id := range list {
			if ad := advs[id]; ad.stored != nil {
				raws = append(raws, ad.stored.Raw)
			}
		}
		p.observe = append(p.observe, observed{kept, fixedInAny(a, raws...)})
		if !slices.Contains(ids, kept) { // its advisory no longer reported, another one is
			p.still = append(p.still, kept)
		}
	}
	// The findings no longer reported, made before A80 and closed since, are
	// folded the same way: the closed ones count once per CVE too.
	for _, t := range triage {
		if _, reported := slices.BinarySearch(ids, t.VulnID); !reported && grouped(t.VulnID) {
			foldGrouped(t.VulnID)
		}
	}
	cves = cves[:0]
	for cve := range rowsByCVE {
		if _, reported := byCVE[cve]; !reported {
			cves = append(cves, cve)
		}
	}
	slices.Sort(cves)
	for _, cve := range cves {
		shown := slices.DeleteFunc(slices.Clone(rowsByCVE[cve]), func(r store.FindingTriage) bool { return r.FoldedInto != 0 })
		slices.SortStableFunc(shown, func(x, y store.FindingTriage) int { return compareKept(x, y, advs) })
		for i := 1; i < len(shown); i++ {
			p.folds = append(p.folds, store.Fold{ID: shown[i].ID, Into: shown[0].ID,
				Why: fmt.Sprintf(foldedSame, shown[0].VulnID), Note: divergence(shown[0], shown[i])})
		}
	}
	return p, nil
}

// fixedIn reads in the stored advisory the versions fixing it for the asset.
// They are kept with the finding: reading them again for each row of a list
// would take about a second for the thousands of a kernel.
func fixedIn(a store.Asset, ad *reportedAdvisory) string {
	if ad.stored == nil {
		return ""
	}
	return fixedInAny(a, ad.stored.Raw)
}

// keptAdvisory is the advisory that makes the finding of a CVE that has none
// yet: one with a severity, then the first by identifier.
func keptAdvisory(list []string, advs map[string]*reportedAdvisory) string {
	best := ""
	for _, id := range list {
		if ad := advs[id]; ad.stored != nil && (best == "" || rated(ad) && !rated(advs[best])) {
			best = id
		}
	}
	return cmp.Or(best, list[0])
}

func rated(ad *reportedAdvisory) bool { return ad.stored != nil && ad.stored.Severity != "" }

// compareKept orders the findings of one CVE, the one to keep first: the one a
// user decided on last, then an open one, then one rated, then the oldest.
func compareKept(x, y store.FindingTriage, advs map[string]*reportedAdvisory) int {
	ratedRow := func(f store.FindingTriage) bool { ad := advs[f.VulnID]; return ad != nil && rated(ad) }
	first := func(b bool) int { // true first
		if b {
			return -1
		}
		return 1
	}
	switch {
	case x.Decision != y.Decision:
		return first(x.Decision > y.Decision)
	case x.Open() != y.Open():
		return first(x.Open())
	case ratedRow(x) != ratedRow(y):
		return first(ratedRow(x))
	}
	return cmp.Compare(x.ID, y.ID)
}

// divergence is the note left on the finding kept when the one folded into it
// carries another decision of a user: the later decision stands (that of the
// finding kept), the other remains in its history.
func divergence(kept, folded store.FindingTriage) string {
	if !folded.Decided() || !kept.Decided() || folded.DecidedStatus == kept.DecidedStatus {
		return ""
	}
	return fmt.Sprintf("décision divergente sur %s : « %s », par %s le %s ; la plus récente, celle-ci, est gardée",
		folded.VulnID, choice.Label(Statuses, folded.DecidedStatus), folded.DecidedBy, fr.Date(folded.DecidedAt))
}

// NoticeRef is a grouped advisory shown on the finding of one of its CVEs.
type NoticeRef struct {
	store.Notice
	FixedIn string // the versions it names as fixing it for the asset
	Link    string // its page at OSV
}

// GroupedNotices keeps, of the advisories that name a CVE of a finding, the
// grouped ones (several CVEs) with a range for the asset's package: those the
// source reports for it, and that a list of the asset no longer shows.
func GroupedNotices(list []store.Notice, a store.Asset) []NoticeRef {
	var out []NoticeRef
	for _, n := range list {
		if len(describe(n.ID, n.Aliases).cves) < 2 || len(Fixes(n.Raw, a)) == 0 {
			continue
		}
		out = append(out, NoticeRef{Notice: n, FixedIn: fixedInAny(a, n.Raw),
			Link: "https://osv.dev/vulnerability/" + url.PathEscape(n.ID)})
	}
	return out
}

// likelyOlder are the advisories of one CVE an asset reports but that were
// not stored for being older than its tracked period, with their CVE: those
// likely to be exploited are read again (see storeLikely).
type likelyOlder map[osv.VulnRef]string // advisory → its CVE

// candidate notes an advisory left out of the tracked period.
func (l likelyOlder) candidate(ref osv.VulnRef, d described) {
	if len(d.cves) == 1 {
		l[ref] = d.cves[0]
	}
}

// storeLikely stores, among the advisories left out of the tracked period,
// those whose CVE is likely to be exploited (EPSS >= store.LikelyEPSS): the
// period lets through what is exploited or likely to be, as the dismissal
// rules and the levels do (A31). The exploited ones (KEV) were kept already.
// Without EPSS, nothing more is kept: the failure is logged.
func (s *Syncer) storeLikely(ctx context.Context, pending *advisories, older likelyOlder) error {
	if s.EPSS == nil || len(older) == 0 {
		return nil
	}
	cves := make([]string, 0, len(older))
	for _, cve := range older {
		cves = append(cves, cve)
	}
	slices.Sort(cves)
	scores, err := s.EPSS.Scores(ctx, slices.Compact(cves))
	if err != nil {
		s.Log.Warn("epss of older vulnerabilities failed", "err", err)
		return nil
	}
	refs := make([]osv.VulnRef, 0, len(older))
	for ref, cve := range older {
		if scores[cve] >= store.LikelyEPSS {
			refs = append(refs, ref)
		}
	}
	slices.SortFunc(refs, func(x, y osv.VulnRef) int { return cmp.Compare(x.ID, y.ID) })
	for _, ref := range refs { // read again unless stored as it is
		if err := s.refreshVuln(ctx, pending, ref); err != nil {
			return err
		}
	}
	return nil
}
