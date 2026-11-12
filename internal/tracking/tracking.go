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
	"strings"
	"sync"
	"time"

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
var Statuses = []inventory.Option{
	{Value: "in_triage", Label: "À analyser"},
	{Value: "exploitable", Label: "Exploitable – à traiter"},
	{Value: "resolved", Label: "Corrigé"},
	{Value: "not_affected", Label: "Non affecté"},
	{Value: "false_positive", Label: "Faux positif"},
}

// Severities are the severity levels of vulnerabilities, labelled in French,
// most severe first: the order of Band, of the digest tables and of the charts.
var Severities = []inventory.Option{
	{Value: "CRITICAL", Label: "Critique"}, {Value: "HIGH", Label: "Haute"},
	{Value: "MEDIUM", Label: "Moyenne"}, {Value: "LOW", Label: "Basse"}, {Value: "UNKNOWN", Label: "Inconnue"},
}

// SeverityLabel returns the French label of a severity, "Inconnue" when empty.
func SeverityLabel(v string) string {
	if v == "" {
		v = "UNKNOWN"
	}
	return inventory.Label(Severities, v)
}

// TemplateFuncs returns the template functions that name findings in French,
// shared by the web pages and the digest with fr.Funcs (A79).
func TemplateFuncs() map[string]any {
	return map[string]any{
		"band":        Band,
		"sevLabel":    SeverityLabel,
		"statusLabel": func(v string) string { return inventory.Label(Statuses, v) },
	}
}

// Justifications explain a "not_affected" status (CycloneDX vocabulary).
var Justifications = []inventory.Option{
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

// ValidateStatus checks a status change submitted by a user.
func ValidateStatus(status, justification, comment string) error {
	if inventory.Label(Statuses, status) == status {
		return errors.New("statut invalide")
	}
	if justification != "" && inventory.Label(Justifications, justification) == justification {
		return errors.New("justification invalide")
	}
	if status == "not_affected" && justification == "" {
		return errors.New("une justification est requise pour « Non affecté »")
	}
	if !clip.Fits(comment, MaxComment) {
		return errors.New("commentaire trop long")
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
		"reopened", res.Reopened, "resolved", res.Resolved, "skipped", res.Skipped)
	if s.Alert != nil {
		// A failed notification is logged: the findings are recorded anyway
		// and the next digest lists them.
		if alertErr := s.Alert(ctx); alertErr != nil {
			s.Log.Warn("immediate alerts failed", "err", alertErr)
		}
	}
	return res, nil
}

// observation is what the sources report for one asset.
type observation struct {
	asset    store.Asset
	reported []string
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
	exploited := sync.OnceValue(func() map[string]bool { return s.exploitedCVEs(ctx) })
	if len(targets) > 0 {
		s.working("interrogation d'OSV")
		results, err := s.OSV.QueryBatch(ctx, queries)
		if err != nil {
			return res, err
		}
		for i, a := range targets {
			s.working(a.Name)
			reported, err := s.readAdvisories(ctx, a, queries[i], results[i], exploited)
			if err != nil {
				s.failed(&res, a, err)
				continue
			}
			seen = append(seen, observation{a, reported})
			s.checked()
		}
	}
	for _, pkg := range packages {
		list := byPackage[pkg]
		s.working(list[0].Name)
		reported, err := s.readPackage(ctx, pkg, list, exploited)
		for _, a := range list {
			if err != nil {
				s.failed(&res, a, err)
				continue
			}
			seen = append(seen, observation{a, reported[a.ID]})
			s.checked()
		}
	}
	for _, a := range cpeTargets {
		s.working(a.Name)
		reported, err := s.readCPE(ctx, a)
		if err != nil {
			s.failed(&res, a, err)
			continue
		}
		seen = append(seen, observation{a, reported})
		s.checked()
	}
	for _, a := range nameTargets {
		s.working(a.Name)
		cves, err := s.NVD.ForKeyword(ctx, a.Name, inventory.SinceTime(a))
		if err != nil {
			s.failed(&res, a, err)
			continue
		}
		o, err := s.storeNVD(ctx, a, cves, func(c nvd.CVE) bool {
			return nvd.NameAffects(c, a.Name, a.Version, inventory.IsLatest(a))
		})
		if err != nil {
			return res, err
		}
		seen = append(seen, o)
		s.checked()
	}

	// 2. Exploitation signals before the findings: an old vulnerability is
	// kept outside the tracked period unless it is known to be exploited.
	if s.KEV != nil && s.EPSS != nil {
		s.working("scores d'exploitation (KEV, EPSS)")
		// Enrichment failures are logged but do not fail the sync.
		if err := s.enrich(ctx); err != nil {
			s.Log.Warn("kev/epss enrichment failed", "err", err)
		}
	}

	// 3. Findings.
	s.working("enregistrement des vulnérabilités")
	for _, o := range seen {
		if err := s.record(ctx, &res, o.asset, o.reported, start); err != nil {
			return res, err
		}
	}
	// Before the alerts: what is set aside must not be notified.
	var err error
	res.Dismissed, err = s.Store.ApplyDismissalRules(ctx)
	return res, err
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
	s.Log.Warn("asset not checked", "asset", a.Name, "err", err)
	res.Failed++
	s.setStatus(func(st *Status) {
		st.Done++
		if len(st.Failures) < maxFailures {
			st.Failures = append(st.Failures, a.Name+" : "+err.Error())
		}
	})
}

// record creates or reopens the findings of an asset and auto-resolves the
// ones its source no longer reports. Vulnerabilities published before the
// tracked period of the asset are skipped, unless they are listed in KEV or
// already have a finding.
func (s *Syncer) record(ctx context.Context, res *Result, a store.Asset, reported []string, seen time.Time) error {
	older := 0
	for _, id := range reported {
		in, err := s.Store.InTrackedPeriod(ctx, a.ID, id, a.TrackSince)
		if err != nil {
			return err
		}
		if !in {
			res.Skipped++
			older++
			continue
		}
		fixed, err := s.fixedIn(ctx, a, id)
		if err != nil {
			return err
		}
		touch, err := s.Store.ObserveFinding(ctx, a.ID, id, fixed, seen)
		if err != nil {
			return err
		}
		switch touch {
		case store.TouchCreated:
			res.Created++
		case store.TouchReopened:
			res.Reopened++
		}
	}
	n, err := s.Store.AutoResolveStale(ctx, a.ID, reported, a.TrackSince)
	if err != nil {
		return fmt.Errorf("auto-resolve asset %d: %w", a.ID, err)
	}
	res.Resolved += n
	if older != a.OlderVulns {
		return s.Store.SetOlderVulns(ctx, a.ID, older)
	}
	return nil
}

// fixedIn reads in the stored advisory the versions fixing it for the asset.
// They are kept with the finding: reading them again for each row of a list
// would take about a second for the thousands of a kernel.
func (s *Syncer) fixedIn(ctx context.Context, a store.Asset, id string) (string, error) {
	v, err := s.Store.Vulnerability(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return FixedIn(v.Raw, a), nil
}

// storeNVD stores the CVEs kept for an asset and returns them as observed.
func (s *Syncer) storeNVD(ctx context.Context, a store.Asset, cves []nvd.CVE, keep func(nvd.CVE) bool) (observation, error) {
	o := observation{asset: a}
	for _, c := range cves {
		if !keep(c) {
			continue
		}
		o.reported = append(o.reported, c.ID)
		if err := s.Store.UpsertVulnerability(ctx, nvdVuln(c)); err != nil {
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
	if v.Severity == "UNKNOWN" || inventory.Label(Severities, v.Severity) == v.Severity {
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
func (s *Syncer) readCPE(ctx context.Context, a store.Asset) ([]string, error) {
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
	o, err := s.storeNVD(ctx, a, cves, keep)
	return o.reported, err
}

// readPackage reads the advisories of a whole package, once for all the assets
// that designate it, and returns their ids by asset. The ranges of each one are
// compared here: at its latest release an asset is affected by those without a
// fixed version, and OSV does not compare versions in every ecosystem.
func (s *Syncer) readPackage(ctx context.Context, pkg osv.Package, assets []store.Asset, exploited func() map[string]bool) (map[int64][]string, error) {
	reported := make(map[int64][]string, len(assets))
	list := s.OSV.Advisories(osv.Query{Package: pkg})
	defer list.Close()
	for list.Next(ctx) {
		v := list.Vuln()
		keep := false
		for _, a := range assets {
			affected := v.Affects(pkg, a.Version)
			if inventory.IsLatest(a) {
				affected = v.Unfixed(pkg)
			}
			if affected {
				reported[a.ID] = append(reported[a.ID], v.ID)
				keep = keep || reportable(a, v, exploited)
			}
		}
		if keep {
			if err := s.storeOSV(ctx, v, false); err != nil {
				return nil, err
			}
		}
	}
	return reported, list.Err()
}

// reportable reports whether an asset can report an advisory: published in
// its tracked period, or known to be exploited.
func reportable(a store.Asset, v osv.Vuln, exploited func() map[string]bool) bool {
	if a.TrackSince == "" || v.Published == "" || v.Published[:min(len(v.Published), 10)] >= a.TrackSince {
		return true
	}
	known := exploited()
	return known[v.ID] || slices.ContainsFunc(v.OtherIDs(), func(id string) bool { return known[id] })
}

// readAdvisories stores the advisories found for an asset and returns their ids.
func (s *Syncer) readAdvisories(ctx context.Context, a store.Asset, q osv.Query, found osv.BatchResult, exploited func() map[string]bool) ([]string, error) {
	if found.More {
		return s.readLargePackage(ctx, a, q, exploited)
	}
	reported := make([]string, 0, len(found.Vulns))
	for _, ref := range found.Vulns {
		reported = append(reported, ref.ID)
		if err := s.refreshVuln(ctx, ref); err != nil {
			return nil, err
		}
	}
	return reported, nil
}

// readLargePackage reads a package whose advisories do not fit in a batch
// answer. A kernel has thousands, listed from the oldest: without the last
// pages, none would be in the tracked period. They come in full from the query,
// not one request each, and only those the asset can report are stored; the
// others are still reported, to count them as older.
func (s *Syncer) readLargePackage(ctx context.Context, a store.Asset, q osv.Query, exploited func() map[string]bool) ([]string, error) {
	var reported []string
	list := s.OSV.Advisories(q)
	defer list.Close()
	for list.Next(ctx) {
		v := list.Vuln()
		reported = append(reported, v.ID)
		if reportable(a, v, exploited) {
			if err := s.storeOSV(ctx, v, false); err != nil {
				return nil, err
			}
		}
	}
	return reported, list.Err()
}

// exploitedCVEs returns the CVEs of the KEV catalogue. Without it, only the
// exploited vulnerabilities older than the tracked period would be missed: the
// failure is logged and the sync goes on.
func (s *Syncer) exploitedCVEs(ctx context.Context) map[string]bool {
	if s.KEV == nil {
		return nil
	}
	catalogue, err := s.KEV.Catalogue(ctx)
	if err != nil {
		s.Log.Warn("kev catalog failed", "err", err)
		return nil
	}
	out := make(map[string]bool, len(catalogue))
	for cve := range catalogue {
		out[cve] = true
	}
	return out
}

// refreshVuln downloads the advisory if unknown or modified since last fetch.
func (s *Syncer) refreshVuln(ctx context.Context, ref osv.VulnRef) error {
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
	return s.storeOSV(ctx, v, true)
}

// storeOSV stores an advisory, unless the stored copy has the same
// modification date; changed: it was fetched because it differs.
func (s *Syncer) storeOSV(ctx context.Context, v osv.Vuln, changed bool) error {
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
	return s.Store.UpsertVulnerability(ctx, sanitize(store.Vulnerability{
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

// enrich refreshes the KEV flag and EPSS score of every stored vulnerability.
func (s *Syncer) enrich(ctx context.Context) error {
	byVuln, err := s.Store.ListVulnCVEs(ctx)
	if err != nil || len(byVuln) == 0 {
		return err
	}
	catalogue, err := s.KEV.Catalogue(ctx)
	if err != nil {
		return err
	}
	var cves []string
	for _, list := range byVuln {
		cves = append(cves, list...)
	}
	scores, err := s.EPSS.Scores(ctx, cves)
	if err != nil {
		return err
	}
	for id, list := range byVuln {
		inKEV, due, score := false, "", -1.0
		for _, cve := range list {
			if e, ok := catalogue[cve]; ok {
				inKEV, due = true, e.DueDate
			}
			if p, ok := scores[cve]; ok && p > score {
				score = p
			}
		}
		if err := s.Store.SetExploitSignals(ctx, id, inKEV, due, score); err != nil {
			return err
		}
	}
	return nil
}

func toQuery(a store.Asset) osv.Query {
	if a.PURL != "" {
		return osv.PURLQuery(a.PURL, a.Version)
	}
	return osv.Query{Package: inventory.Package(a), Version: a.Version}
}
