// Package tracking synchronises vulnerabilities for the inventory and
// defines the triage statuses of findings.
package tracking

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/choice"
	"github.com/La-Cizaille-Corp/vigil/internal/clip"
	"github.com/La-Cizaille-Corp/vigil/internal/cvss"
	"github.com/La-Cizaille-Corp/vigil/internal/inventory"
	"github.com/La-Cizaille-Corp/vigil/internal/netsafe"
	"github.com/La-Cizaille-Corp/vigil/internal/sources/epss"
	"github.com/La-Cizaille-Corp/vigil/internal/sources/kev"
	"github.com/La-Cizaille-Corp/vigil/internal/sources/nvd"
	"github.com/La-Cizaille-Corp/vigil/internal/sources/osv"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
)

// Statuses are the CycloneDX / VEX analysis states, labelled in French.
var Statuses = []choice.Option{
	{Value: store.StatusInTriage, Label: "À analyser"},
	{Value: store.StatusExploitable, Label: "Exploitable – à traiter"},
	{Value: store.StatusResolved, Label: "Corrigé"},
	{Value: store.StatusNotAffected, Label: "Non affecté"},
	{Value: store.StatusFalsePositive, Label: "Faux positif"},
}

// Severities are the severity levels of vulnerabilities, labelled in French,
// most severe first: the order of Band, of the digest tables and of the charts.
var Severities = []choice.Option{
	{Value: "CRITICAL", Label: "Critique"}, {Value: "HIGH", Label: "Haute"},
	{Value: "MEDIUM", Label: "Moyenne"}, {Value: "LOW", Label: "Basse"}, {Value: "UNKNOWN", Label: "Inconnue"},
}

// SeverityLabel returns the French label of a severity, "Inconnue" when empty.
func SeverityLabel(v string) string {
	if v == "" {
		v = "UNKNOWN"
	}
	return choice.Label(Severities, v)
}

// TemplateFuncs returns the template functions that name findings in French,
// shared by the web pages and the digest with fr.Funcs (A79).
func TemplateFuncs() map[string]any {
	return map[string]any{
		"band":        Band,
		"sevLabel":    SeverityLabel,
		"statusLabel": func(v string) string { return choice.Label(Statuses, v) },
		"level":       Level,
		"levelName":   levelName,
		"reason":      Reason,
		"explain":     explain,
		"aliases":     aliasList,
	}
}

// maxAliases bounds the aliases named in a list row or a digest line: an
// Ubuntu notice can have nearly two thousand.
const maxAliases = 3

// aliasList names the first aliases of a vulnerability, then how many more.
func aliasList(aliases []string) string {
	if len(aliases) <= maxAliases {
		return strings.Join(aliases, ", ")
	}
	more, word := len(aliases)-maxAliases, "autres"
	if more == 1 {
		word = "autre"
	}
	return strings.Join(aliases[:maxAliases], ", ") + " et " + strconv.Itoa(more) + " " + word
}

// Justifications explain a "not_affected" status (CycloneDX vocabulary).
var Justifications = []choice.Option{
	{Value: "code_not_present", Label: "Code vulnérable absent"},
	{Value: "code_not_reachable", Label: "Code vulnérable non atteignable"},
	{Value: "requires_configuration", Label: "Nécessite une configuration absente"},
	{Value: "requires_dependency", Label: "Nécessite une dépendance absente"},
	{Value: "requires_environment", Label: "Nécessite un environnement absent"},
	{Value: "protected_by_compiler", Label: "Protégé par le compilateur"},
	{Value: "protected_at_runtime", Label: "Protégé à l'exécution"},
	{Value: "protected_at_perimeter", Label: "Protégé en périphérie"},
	{Value: "protected_by_mitigating_control", Label: "Protégé par une mesure compensatoire"},
}

// MaxComment is the longest comment of a status change, in characters.
const MaxComment = 4000

// StatusError is a status change refused by ValidateStatus, with the field
// at fault, as the triage forms name it: "status", "justification" or
// "comment"; a form shows the message beside it (A85).
type StatusError struct {
	Field, Msg string
}

func (e *StatusError) Error() string { return e.Msg }

// ValidateStatus checks a status change submitted by a user; the error is a
// *StatusError.
func ValidateStatus(status, justification, comment string) error {
	if !choice.Has(Statuses, status) {
		return &StatusError{"status", "statut invalide"}
	}
	if justification != "" && !choice.Has(Justifications, justification) {
		return &StatusError{"justification", "justification invalide"}
	}
	if status == store.StatusNotAffected && justification == "" {
		return &StatusError{"justification", "une justification est requise pour « Non affecté »"}
	}
	if !clip.Fits(comment, MaxComment) {
		return &StatusError{"comment", "commentaire trop long"}
	}
	return nil
}

// ErrRunning is returned when a sync is already in progress.
var ErrRunning = errors.New("une synchronisation est déjà en cours")

// Result summarises a sync run.
type Result struct {
	Assets   int // assets queried
	Created  int // new findings
	Reopened int
	Resolved int // auto-resolved findings
	Skipped  int // vulnerabilities published before the tracked period of their asset
	Failed   int // assets a source could not check: left as they were
	// Dismissed counts the findings set aside by a dismissal rule.
	Dismissed int
	// Folded counts the findings folded into others: one per CVE (A80).
	Folded int
}

// Status describes the running or last synchronisation, for the UI.
type Status struct {
	Running  bool
	Asset    string // name of the asset for a single-asset scan, "" for the inventory
	Started  time.Time
	Finished time.Time
	Result   Result
	Err      string
	// Progress of the run: assets to check, assets done, and what it is doing.
	Total   int
	Done    int
	Current string
	// Failures tells why assets could not be checked, the first few of them.
	Failures []string
}

// maxFailures bounds the failures kept for the UI; the logs have them all.
const maxFailures = 10

// Syncer queries sources for the inventory. It is safe for concurrent use;
// only one run happens at a time.
type Syncer struct {
	Store *store.Store
	OSV   *osv.Client
	Log   *slog.Logger
	// NVD matches assets that only have a CPE, or only a name; nil disables it.
	NVD *nvd.Client

	// KEV and EPSS give the exploitation signals, refreshed only with both;
	// without KEV, the tracked period does not let exploited CVEs through.
	KEV  *kev.Client
	EPSS *epss.Client

	// Alert, if set, is called after each successful run to notify the
	// findings that became urgent (see notify.Notifier.SendAlerts).
	Alert func(context.Context) error

	mu       sync.Mutex // held during a run
	statusMu sync.Mutex
	status   Status
}

// Run synchronises the whole inventory.
func (s *Syncer) Run(ctx context.Context) (Result, error) { return s.run(ctx, 0) }

// RunAsset synchronises a single asset, e.g. right after it was added.
func (s *Syncer) RunAsset(ctx context.Context, id int64) (Result, error) { return s.run(ctx, id) }

// Status returns the state of the running or last synchronisation.
func (s *Syncer) Status() Status {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	return s.status
}

func (s *Syncer) setStatus(update func(*Status)) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	update(&s.status)
}

func (s *Syncer) run(ctx context.Context, assetID int64) (res Result, err error) {
	if !s.mu.TryLock() {
		return Result{}, ErrRunning
	}
	defer s.mu.Unlock()

	var assets []store.Asset
	name := ""
	if assetID == 0 {
		assets, err = s.Store.ListAssets(ctx, store.Everything)
	} else {
		var a store.Asset
		a, err = s.Store.Asset(ctx, store.Everything, assetID)
		assets, name = []store.Asset{a}, a.Name
		if !a.Retired.IsZero() { // dropped from its SBOM: checking it would reopen its findings
			assets = nil
		}
	}
	if err != nil {
		return res, err
	}
	s.setStatus(func(st *Status) {
		*st = Status{Running: true, Asset: name, Started: time.Now()}
	})
	defer func() {
		s.setStatus(func(st *Status) {
			st.Running, st.Finished, st.Result, st.Current = false, time.Now(), res, ""
			if err != nil {
				st.Err = err.Error()
			}
		})
	}()
	res, err = s.scan(ctx, assets)
	if err != nil {
		return res, err
	}
	s.Log.Info("sync done", "assets", res.Assets, "created", res.Created,
		"reopened", res.Reopened, "resolved", res.Resolved, "skipped", res.Skipped, "folded", res.Folded)
	if s.Alert != nil {
		// A failed notification is logged: the findings are recorded anyway
		// and the next digest lists them.
		if alertErr := s.Alert(ctx); alertErr != nil {
			s.Log.Warn("immediate alerts failed", "err", alertErr)
		}
	}
	return res, nil
}

// observation is what the sources report for one asset: the advisories, and
// what those read whole name (the others are read from the database).
type observation struct {
	asset    store.Asset
	reported []string
	known    map[string]described
}

func (s *Syncer) scan(ctx context.Context, assets []store.Asset) (Result, error) {
	var res Result
	start := time.Now().UTC().Truncate(time.Second)

	var targets, cpeTargets, nameTargets []store.Asset
	var queries []osv.Query
	var packages []osv.Package // read whole, once each, for the assets in byPackage
	byPackage := map[osv.Package][]store.Asset{}
	for _, a := range assets {
		switch {
		case inventory.Queryable(a) && (inventory.IsLatest(a) || !osv.ComparesVersions(a.Ecosystem)):
			pkg := inventory.Package(a)
			if byPackage[pkg] == nil {
				packages = append(packages, pkg)
			}
			byPackage[pkg] = append(byPackage[pkg], a)
		case inventory.Queryable(a):
			targets = append(targets, a)
			queries = append(queries, toQuery(a))
		case a.CPE != "" && s.NVD != nil:
			cpeTargets = append(cpeTargets, a)
		case inventory.ByName(a) && s.NVD != nil:
			nameTargets = append(nameTargets, a)
		}
	}
	res.Assets = len(targets) + len(cpeTargets) + len(nameTargets)
	for _, list := range byPackage {
		res.Assets += len(list)
	}
	if res.Assets == 0 {
		return res, nil
	}
	s.setStatus(func(st *Status) { st.Total = res.Assets })

	// 1. Ask the sources and store the advisories. An asset that cannot be
	// checked must not block the others: it is reported, its findings kept.
	var seen []observation
	// The KEV catalogue is read once: for the tracked period here, for the
	// exploitation signals below.
	catalogue := sync.OnceValues(func() (map[string]kev.Entry, error) {
		if s.KEV == nil {
			return nil, nil
		}
		return s.KEV.Catalogue(ctx)
	})
	exploited := sync.OnceValue(func() map[string]bool { return s.exploitedCVEs(catalogue) })
	pending := &advisories{store: s.Store}
	// finish stores the advisories read for assets, or drops them if the
	// sources failed: what is kept of an asset is all it reported, or nothing.
	finish := func(err error, assets ...store.Asset) bool {
		if err == nil {
			err = pending.flush(ctx)
		}
		pending.drop()
		for _, a := range assets {
			if err != nil {
				s.failed(&res, a, err)
			} else {
				s.checked()
			}
		}
		return err == nil
	}
	if len(targets) > 0 {
		s.working("interrogation d'OSV")
		results, err := s.OSV.QueryBatch(ctx, queries)
		if err != nil {
			return res, err
		}
		for i, a := range targets {
			s.working(a.Name)
			reported, known, err := s.readAdvisories(ctx, pending, a, queries[i], results[i], exploited)
			if finish(err, a) {
				seen = append(seen, observation{a, reported, known})
			}
		}
	}
	for _, pkg := range packages {
		list := byPackage[pkg]
		s.working(list[0].Name)
		reported, known, err := s.readPackage(ctx, pending, pkg, list, exploited)
		if finish(err, list...) {
			for _, a := range list {
				seen = append(seen, observation{a, reported[a.ID], known})
			}
		}
	}
	for _, a := range cpeTargets {
		s.working(a.Name)
		reported, err := s.readCPE(ctx, pending, a)
		if finish(err, a) {
			seen = append(seen, observation{asset: a, reported: reported})
		}
	}
	for _, a := range nameTargets {
		s.working(a.Name)
		cves, err := s.NVD.ForKeyword(ctx, a.Name, inventory.SinceTime(a))
		var o observation
		if err == nil {
			o, err = s.storeNVD(ctx, pending, a, cves, func(c nvd.CVE) bool {
				return nvd.NameAffects(c, a.Name, a.Version, inventory.IsLatest(a))
			})
		}
		if finish(err, a) {
			seen = append(seen, o)
		}
	}

	// 2. Exploitation signals before the findings: an old vulnerability is
	// kept outside the tracked period unless it is known to be exploited.
	if s.KEV != nil && s.EPSS != nil {
		s.working("scores d'exploitation (KEV, EPSS)")
		// Enrichment failures are logged but do not fail the sync.
		if err := s.enrich(ctx, catalogue); err != nil {
			s.Log.Warn("kev/epss enrichment failed", "err", err)
		}
	}

	// 3. Findings, one transaction per asset: an asset whose findings cannot
	// be recorded keeps them as they were, and the others go on.
	s.working("enregistrement des vulnérabilités")
	for _, o := range seen {
		if err := s.record(ctx, &res, o, start); err != nil {
			if ctx.Err() != nil {
				return res, ctx.Err()
			}
			s.unrecorded(&res, o.asset, err)
		}
	}
	// Before the alerts: what is set aside must not be notified.
	var err error
	res.Dismissed, err = s.Store.ApplyDismissalRules(ctx)
	return res, err
}

// advisories holds the advisories read for an asset, stored together in a
// transaction (see finish in scan). A long list is stored by chunks, so that
// memory stays bounded: one advisory at a time is read from the network
// (A62), a chunk at most is held. The network is never read during a
// transaction, which holds the only connection to the database.
type advisories struct {
	store *store.Store
	list  []store.Vulnerability
	size  int // characters of their texts
}

// Bounds of a chunk of advisories: a few seconds of writing one by one, a
// few megabytes.
const (
	chunkAdvisories = 500
	chunkSize       = 8 << 20
)

// add keeps an advisory to store, and stores the chunk once it is full.
func (p *advisories) add(ctx context.Context, v store.Vulnerability) error {
	p.list = append(p.list, v)
	p.size += len(v.Summary) + len(v.Details) + len(v.Raw)
	if len(p.list) < chunkAdvisories && p.size < chunkSize {
		return nil
	}
	return p.flush(ctx)
}

// flush stores the advisories held, in one transaction.
func (p *advisories) flush(ctx context.Context) error {
	if len(p.list) == 0 {
		return nil
	}
	err := p.store.InTx(ctx, func(ctx context.Context) error {
		for _, v := range p.list {
			if err := p.store.UpsertVulnerability(ctx, v); err != nil {
				return err
			}
		}
		return nil
	})
	p.drop()
	if err != nil {
		return fmt.Errorf("enregistrement des avis : %w", err)
	}
	return nil
}

// drop forgets the advisories held, of an asset the sources failed to check.
func (p *advisories) drop() {
	p.list, p.size = p.list[:0], 0
}

// working tells what the run is doing, for the UI.
func (s *Syncer) working(current string) {
	s.setStatus(func(st *Status) { st.Current = current })
}

// checked counts an asset as done, for the UI.
func (s *Syncer) checked() {
	s.setStatus(func(st *Status) { st.Done++ })
}

// failed reports an asset the sources could not check: its findings stay as
// they were, as the next run may check it.
func (s *Syncer) failed(res *Result, a store.Asset, err error) {
	s.report(res, a, err)
	s.setStatus(func(st *Status) { st.Done++ })
}

// unrecorded reports an asset checked, and counted as done, whose findings
// could not be recorded: they stay as they were.
func (s *Syncer) unrecorded(res *Result, a store.Asset, err error) {
	s.report(res, a, fmt.Errorf("enregistrement des vulnérabilités : %w", err))
}

// report counts an asset not checked, with the reason, for the UI and the log.
func (s *Syncer) report(res *Result, a store.Asset, err error) {
	s.Log.Warn("asset not checked", "asset", a.Name, "err", err)
	res.Failed++
	s.setStatus(func(st *Status) {
		if len(st.Failures) < maxFailures {
			st.Failures = append(st.Failures, a.Name+" : "+err.Error())
		}
	})
}

// observed is a vulnerability reported for an asset in its tracked period,
// with the versions fixing it.
type observed struct {
	id, fixedIn string
}

// record creates or reopens the findings of an asset, one per CVE (A80), folds
// the others, and auto-resolves the ones its source no longer reports.
// Vulnerabilities published before the tracked period of the asset are
// skipped, unless they are exploited or likely to be, or already have a
// finding. What it reads comes first (see plan); then its writes are made in
// one transaction, all or none of them, and only then counted in res.
func (s *Syncer) record(ctx context.Context, res *Result, o observation, seen time.Time) error {
	a := o.asset
	p, err := s.plan(ctx, o)
	if err != nil {
		return err
	}
	var done Result
	err = s.Store.InTx(ctx, func(ctx context.Context) error {
		if err := s.Store.FoldFindings(ctx, p.folds...); err != nil {
			return err
		}
		for _, o := range p.observe {
			touch, err := s.Store.ObserveFinding(ctx, a.ID, o.id, o.fixedIn, seen)
			if err != nil {
				return err
			}
			switch touch {
			case store.TouchCreated:
				done.Created++
			case store.TouchReopened:
				done.Reopened++
			}
		}
		n, err := s.Store.AutoResolveStale(ctx, a.ID, p.still, a.TrackSince)
		if err != nil {
			return err
		}
		done.Resolved = n
		if p.older != a.OlderVulns {
			return s.Store.SetOlderVulns(ctx, a.ID, p.older)
		}
		return nil
	})
	if err != nil {
		return err
	}
	res.Created += done.Created
	res.Reopened += done.Reopened
	res.Resolved += done.Resolved
	res.Skipped += p.older
	res.Folded += len(p.folds)
	return nil
}

// storeNVD stores the CVEs kept for an asset and returns them as observed.
func (s *Syncer) storeNVD(ctx context.Context, pending *advisories, a store.Asset, cves []nvd.CVE, keep func(nvd.CVE) bool) (observation, error) {
	o := observation{asset: a}
	for _, c := range cves {
		if !keep(c) {
			continue
		}
		o.reported = append(o.reported, c.ID)
		if err := pending.add(ctx, nvdVuln(c)); err != nil {
			return o, err
		}
	}
	return o, nil
}

// kernelPreamble opens the description of every CVE of the Linux kernel.
const kernelPreamble = "In the Linux kernel, the following vulnerability has been resolved:"

// brief returns the start of a description, for lists: its title for a kernel
// CVE, otherwise its first sentence.
func brief(description string) string {
	text, kernel := strings.CutPrefix(strings.TrimSpace(description), kernelPreamble)
	text = strings.TrimSpace(text)
	if kernel { // its title ends with the line, or with two spaces in the records of Debian
		if i := strings.IndexAny(text, "\r\n"); i > 0 {
			text = text[:i]
		}
		if i := strings.Index(text, "  "); i > 0 {
			text = text[:i]
		}
	}
	if i := strings.Index(text, ". "); i > 0 && i < 300 {
		return text[:i+1]
	}
	return clip.Text(text, 300)
}

func nvdVuln(c nvd.CVE) store.Vulnerability {
	return sanitize(store.Vulnerability{
		ID: c.ID, Summary: brief(c.Description), Details: c.Description, Severity: c.Severity, CVSS: c.CVSS,
		Published: c.Published, Modified: c.Modified, Refs: c.Refs, Raw: string(c.Raw),
	})
}

// Bounds of what is stored of an advisory, set well above real ones so that
// they only stop a faulty or hostile answer: an NVD description holds at most
// 4 096 characters (CVE JSON 5 schema), an OSV summary is meant to be one
// line, and the long lists (the CVE of a kernel advisory, the references of
// an old CVE) count in hundreds.
const (
	maxSummary = 1000      // characters
	maxDetails = 64 * 1024 // characters
	maxID      = 100       // characters of an alias
	maxList    = 2000      // aliases, references
)

// sanitize returns an advisory as it may be stored. SECURITY: the sources
// are fixed HTTPS hosts, but what they send is counted, filtered and shown:
// a severity still outside Severities (osv.Vuln.SeverityLabel has translated
// the scales of the databases) becomes unknown (""), like a missing one, a
// CVSS score outside 0..10 becomes absent, texts and lists are bounded. A
// longer alias is not an identifier: it is dropped.
func sanitize(v store.Vulnerability) store.Vulnerability {
	if v.Severity == "UNKNOWN" || !choice.Has(Severities, v.Severity) {
		v.Severity = ""
	}
	if !(v.CVSS >= 0 && v.CVSS <= 10) { // NaN included
		v.CVSS = cvss.Unknown
	}
	v.Summary = clip.Text(v.Summary, maxSummary)
	v.Details = clip.Text(v.Details, maxDetails)
	v.Aliases = slices.DeleteFunc(slices.Clone(v.Aliases), func(id string) bool { return !clip.Fits(id, maxID) })
	v.Aliases = v.Aliases[:min(len(v.Aliases), maxList)]
	v.Refs = v.Refs[:min(len(v.Refs), maxList)]
	return v
}

// readCPE stores the CVEs of an asset found by its CPE and returns their ids.
func (s *Syncer) readCPE(ctx context.Context, pending *advisories, a store.Asset) ([]string, error) {
	q := nvd.Query{CPE: a.CPE, Version: a.Version, Mode: a.CPEMode, From: a.CPEFrom, Since: inventory.SinceTime(a)}
	keep := func(nvd.CVE) bool { return true }
	if a.CPEMode == "" && inventory.IsLatest(a) {
		q.Version, q.Mode = "", "all"
		keep = func(c nvd.CVE) bool { return nvd.UnfixedFor(c, a.CPE) }
	}
	cves, err := s.NVD.ForCPE(ctx, q)
	if err != nil {
		return nil, err
	}
	o, err := s.storeNVD(ctx, pending, a, cves, keep)
	return o.reported, err
}

// readPackage reads the advisories of a whole package, once for all the assets
// that designate it, and returns their ids by asset. The ranges of each one are
// compared here: at its latest release an asset is affected by those without a
// fixed version, and OSV does not compare versions in every ecosystem.
func (s *Syncer) readPackage(ctx context.Context, pending *advisories, pkg osv.Package, assets []store.Asset, exploited func() map[string]bool) (map[int64][]string, map[string]described, error) {
	reported := make(map[int64][]string, len(assets))
	known, older := map[string]described{}, likelyOlder{}
	list := s.OSV.Advisories(osv.Query{Package: pkg})
	defer list.Close()
	for list.Next(ctx) {
		v := list.Vuln()
		keep, affects := false, false
		for _, a := range assets {
			affected := v.Affects(pkg, a.Version)
			if inventory.IsLatest(a) {
				affected = v.Unfixed(pkg)
			}
			if affected {
				reported[a.ID] = append(reported[a.ID], v.ID)
				keep = keep || reportable(a, v, exploited)
				affects = true
			}
		}
		if !affects {
			continue
		}
		known[v.ID] = describe(v.ID, v.OtherIDs())
		if !keep {
			older.candidate(v.ID, known[v.ID])
			continue
		}
		if err := s.storeOSV(ctx, pending, v, false); err != nil {
			return nil, nil, err
		}
	}
	if err := list.Err(); err != nil {
		return nil, nil, err
	}
	return reported, known, s.storeLikely(ctx, pending, older)
}

// reportable reports whether an asset can report an advisory: published in
// its tracked period, or known to be exploited (KEV); those likely to be are
// read again afterwards (see storeLikely).
func reportable(a store.Asset, v osv.Vuln, exploited func() map[string]bool) bool {
	if a.TrackSince == "" || v.Published == "" || v.Published[:min(len(v.Published), 10)] >= a.TrackSince {
		return true
	}
	known := exploited()
	return known[v.ID] || slices.ContainsFunc(v.OtherIDs(), func(id string) bool { return known[id] })
}

// readAdvisories stores the advisories found for an asset and returns their
// ids, and what those read whole name: each one is stored here, unless it
// comes from a package too large for a batch answer.
func (s *Syncer) readAdvisories(ctx context.Context, pending *advisories, a store.Asset, q osv.Query, found osv.BatchResult, exploited func() map[string]bool) ([]string, map[string]described, error) {
	if found.More {
		return s.readLargePackage(ctx, pending, a, q, exploited)
	}
	reported := make([]string, 0, len(found.Vulns))
	for _, ref := range found.Vulns {
		reported = append(reported, ref.ID)
		if err := s.refreshVuln(ctx, pending, ref); err != nil {
			return nil, nil, err
		}
	}
	return reported, nil, nil
}

// readLargePackage reads a package whose advisories do not fit in a batch
// answer. A kernel has thousands, listed from the oldest: without the last
// pages, none would be in the tracked period. They come in full from the query,
// not one request each, and only those the asset can report are stored; the
// others are still reported, to count them as older.
func (s *Syncer) readLargePackage(ctx context.Context, pending *advisories, a store.Asset, q osv.Query, exploited func() map[string]bool) ([]string, map[string]described, error) {
	var reported []string
	known, older := map[string]described{}, likelyOlder{}
	list := s.OSV.Advisories(q)
	defer list.Close()
	for list.Next(ctx) {
		v := list.Vuln()
		reported = append(reported, v.ID)
		known[v.ID] = describe(v.ID, v.OtherIDs())
		if !reportable(a, v, exploited) {
			older.candidate(v.ID, known[v.ID])
			continue
		}
		if err := s.storeOSV(ctx, pending, v, false); err != nil {
			return nil, nil, err
		}
	}
	if err := list.Err(); err != nil {
		return nil, nil, err
	}
	return reported, known, s.storeLikely(ctx, pending, older)
}

// exploitedCVEs returns the CVEs of the KEV catalogue. Without it, only the
// exploited vulnerabilities older than the tracked period would be missed: the
// failure is logged and the sync goes on.
func (s *Syncer) exploitedCVEs(catalogue func() (map[string]kev.Entry, error)) map[string]bool {
	entries, err := catalogue()
	if err != nil {
		s.Log.Warn("kev catalog failed", "err", err)
		return nil
	}
	out := make(map[string]bool, len(entries))
	for cve := range entries {
		out[cve] = true
	}
	return out
}

// refreshVuln downloads the advisory if unknown or modified since last fetch.
func (s *Syncer) refreshVuln(ctx context.Context, pending *advisories, ref osv.VulnRef) error {
	modified, known, err := s.Store.VulnModified(ctx, ref.ID)
	if err != nil {
		return err
	}
	if known && modified == ref.Modified {
		return nil
	}
	v, err := s.OSV.Vuln(ctx, ref.ID)
	if err != nil {
		return err
	}
	return s.storeOSV(ctx, pending, v, true)
}

// storeOSV stores an advisory, unless the stored copy has the same
// modification date; changed: it was fetched because it differs.
func (s *Syncer) storeOSV(ctx context.Context, pending *advisories, v osv.Vuln, changed bool) error {
	if !changed {
		modified, known, err := s.Store.VulnModified(ctx, v.ID)
		if err != nil || known && modified == v.Modified {
			return err
		}
	}
	var refs []string
	for _, r := range v.References {
		if u, ok := netsafe.WebURL(r.URL); ok {
			refs = append(refs, u)
		}
	}
	return pending.add(ctx, sanitize(store.Vulnerability{
		ID:        v.ID,
		Aliases:   v.OtherIDs(),
		Summary:   cmp.Or(v.Summary, brief(v.Details)), // a DEBIAN-CVE record has no summary
		Details:   v.Details,
		Severity:  v.SeverityLabel(),
		CVSS:      v.CVSSScore(),
		Published: v.Published,
		Modified:  v.Modified,
		Refs:      refs,
		Raw:       string(v.Compact()),
	}))
}

// enrich refreshes the KEV flag and EPSS score of every stored vulnerability:
// each CVE is asked once to EPSS, and only the changes are written.
func (s *Syncer) enrich(ctx context.Context, catalogue func() (map[string]kev.Entry, error)) error {
	byVuln, err := s.Store.ListVulnCVEs(ctx)
	if err != nil || len(byVuln) == 0 {
		return err
	}
	entries, err := catalogue()
	if err != nil {
		return err
	}
	var cves []string
	for _, list := range byVuln {
		cves = append(cves, list...)
	}
	slices.Sort(cves) // a CVE can be the alias of several advisories
	scores, err := s.EPSS.Scores(ctx, slices.Compact(cves))
	if err != nil {
		return err
	}
	signals := make([]store.ExploitSignal, 0, len(byVuln))
	for id, list := range byVuln {
		sg := store.ExploitSignal{ID: id, EPSS: -1}
		for _, cve := range list {
			if e, ok := entries[cve]; ok {
				sg.KEV, sg.KEVDue = true, e.DueDate
			}
			if p, ok := scores[cve]; ok && p > sg.EPSS {
				sg.EPSS = p
			}
		}
		signals = append(signals, sg)
	}
	_, err = s.Store.SetExploitSignals(ctx, signals...)
	return err
}

func toQuery(a store.Asset) osv.Query {
	if a.PURL != "" {
		return osv.PURLQuery(a.PURL, a.Version)
	}
	return osv.Query{Package: inventory.Package(a), Version: a.Version}
}
