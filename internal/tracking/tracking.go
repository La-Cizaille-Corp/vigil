// Package tracking synchronises vulnerabilities for the inventory and
// defines the triage statuses of findings.
package tracking

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/inventory"
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

// Severities are the severity levels of vulnerabilities, labelled in French.
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
	if len(comment) > 4000 {
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
}

// Status describes the running or last synchronisation, for the UI.
type Status struct {
	Running  bool
	Asset    string // name of the asset for a single-asset scan, "" for the inventory
	Started  time.Time
	Finished time.Time
	Result   Result
	Err      string
}

// Syncer queries sources for the inventory. It is safe for concurrent use;
// only one run happens at a time.
type Syncer struct {
	Store *store.Store
	OSV   *osv.Client
	Log   *slog.Logger
	// NVD matches assets that only have a CPE; nil disables it.
	NVD *nvd.Client

	// HTTP is used for KEV and EPSS; nil disables enrichment.
	HTTP      *http.Client
	UserAgent string
	KEVURL    string // defaults to kev.DefaultURL
	EPSSURL   string // defaults to epss.DefaultURL

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
		assets, err = s.Store.ListAssets(ctx)
	} else {
		var a store.Asset
		a, err = s.Store.Asset(ctx, assetID)
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
			st.Running, st.Finished, st.Result = false, time.Now(), res
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
			s.Log.Warn("alertes immédiates", "err", alertErr)
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

	var targets, cpeTargets []store.Asset
	var queries []osv.Query
	for _, a := range assets {
		switch {
		case inventory.Queryable(a):
			targets = append(targets, a)
			queries = append(queries, toQuery(a))
		case a.CPE != "" && s.NVD != nil:
			cpeTargets = append(cpeTargets, a)
		}
	}
	res.Assets = len(targets) + len(cpeTargets)
	if res.Assets == 0 {
		return res, nil
	}

	// 1. Ask the sources and store the advisories.
	var seen []observation
	if len(targets) > 0 {
		results, err := s.OSV.QueryBatch(ctx, queries)
		if err != nil {
			return res, err
		}
		for i, a := range targets {
			var reported []string
			for _, ref := range results[i] {
				reported = append(reported, ref.ID)
				if err := s.refreshVuln(ctx, ref); err != nil {
					return res, err
				}
			}
			seen = append(seen, observation{a, reported})
		}
	}
	for _, a := range cpeTargets {
		q := nvd.Query{CPE: a.CPE, Version: a.Version, Mode: a.CPEMode, From: a.CPEFrom, Since: inventory.SinceTime(a)}
		cves, err := s.NVD.ForCPE(ctx, q)
		if err != nil {
			// One unreachable or invalid CPE must not block the others.
			s.Log.Warn("NVD", "asset", a.Name, "err", err)
			continue
		}
		var reported []string
		for _, c := range cves {
			reported = append(reported, c.ID)
			if err := s.Store.UpsertVulnerability(ctx, nvdVuln(c)); err != nil {
				return res, err
			}
		}
		seen = append(seen, observation{a, reported})
	}

	// 2. Exploitation signals before the findings: an old vulnerability is
	// kept outside the tracked period unless it is known to be exploited.
	if s.HTTP != nil {
		// Enrichment failures are logged but do not fail the sync.
		if err := s.enrich(ctx); err != nil {
			s.Log.Warn("enrichissement KEV/EPSS", "err", err)
		}
	}

	// 3. Findings.
	for _, o := range seen {
		if err := s.record(ctx, &res, o.asset, o.reported, start); err != nil {
			return res, err
		}
	}
	return res, nil
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
		touch, err := s.Store.ObserveFinding(ctx, a.ID, id, seen)
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

func nvdVuln(c nvd.CVE) store.Vulnerability {
	summary := c.Description
	if i := strings.Index(summary, ". "); i > 0 && i < 300 {
		summary = summary[:i+1]
	} else if len(summary) > 300 {
		summary = summary[:300] + "…"
	}
	return store.Vulnerability{
		ID: c.ID, Summary: summary, Details: c.Description, Severity: c.Severity, CVSS: c.CVSS,
		Published: c.Published, Modified: c.Modified, Refs: c.Refs, Raw: string(c.Raw),
	}
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
	var refs []string
	for _, r := range v.References {
		if strings.HasPrefix(r.URL, "https://") || strings.HasPrefix(r.URL, "http://") {
			refs = append(refs, r.URL)
		}
	}
	return s.Store.UpsertVulnerability(ctx, store.Vulnerability{
		ID:        v.ID,
		Aliases:   v.Aliases,
		Summary:   v.Summary,
		Details:   v.Details,
		Severity:  v.SeverityLabel(),
		CVSS:      v.CVSSScore(),
		Published: v.Published,
		Modified:  v.Modified,
		Refs:      refs,
		Raw:       string(v.Raw),
	})
}

// enrich refreshes the KEV flag and EPSS score of every stored vulnerability.
func (s *Syncer) enrich(ctx context.Context) error {
	byVuln, err := s.Store.VulnCVEs(ctx)
	if err != nil || len(byVuln) == 0 {
		return err
	}
	catalogue, err := kev.Fetch(ctx, s.HTTP, cmp.Or(s.KEVURL, kev.DefaultURL), s.UserAgent)
	if err != nil {
		return err
	}
	var cves []string
	for _, list := range byVuln {
		cves = append(cves, list...)
	}
	scores, err := epss.Scores(ctx, s.HTTP, cmp.Or(s.EPSSURL, epss.DefaultURL), s.UserAgent, cves)
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
		// A purl that already carries a version must not be sent with "version".
		if strings.Contains(a.PURL, "@") || a.Version == "" {
			return osv.Query{Package: osv.Package{PURL: a.PURL}}
		}
		return osv.Query{Package: osv.Package{PURL: a.PURL}, Version: a.Version}
	}
	return osv.Query{Package: osv.Package{Name: a.Name, Ecosystem: a.Ecosystem}, Version: a.Version}
}
