// Package tracking synchronises vulnerabilities for the inventory and
// defines the triage statuses of findings.
package tracking

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/inventory"
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
}

// Syncer queries sources for the whole inventory. It is safe for concurrent
// use; only one run happens at a time.
type Syncer struct {
	Store *store.Store
	OSV   *osv.Client
	Log   *slog.Logger

	mu sync.Mutex
}

// Run performs one synchronisation.
func (s *Syncer) Run(ctx context.Context) (Result, error) {
	if !s.mu.TryLock() {
		return Result{}, ErrRunning
	}
	defer s.mu.Unlock()

	var res Result
	start := time.Now().UTC().Truncate(time.Second)

	assets, err := s.Store.ListAssets(ctx)
	if err != nil {
		return res, err
	}
	var targets []store.Asset
	var queries []osv.Query
	for _, a := range assets {
		if inventory.Queryable(a) {
			targets = append(targets, a)
			queries = append(queries, toQuery(a))
		}
	}
	res.Assets = len(targets)
	if len(targets) == 0 {
		return res, nil
	}

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
			touch, err := s.Store.ObserveFinding(ctx, a.ID, ref.ID, start)
			if err != nil {
				return res, err
			}
			switch touch {
			case store.TouchCreated:
				res.Created++
			case store.TouchReopened:
				res.Reopened++
			}
		}
		n, err := s.Store.AutoResolveStale(ctx, a.ID, reported)
		if err != nil {
			return res, fmt.Errorf("auto-resolve asset %d: %w", a.ID, err)
		}
		res.Resolved += n
	}
	s.Log.Info("sync done", "assets", res.Assets, "created", res.Created,
		"reopened", res.Reopened, "resolved", res.Resolved)
	return res, nil
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
		Published: v.Published,
		Modified:  v.Modified,
		Refs:      refs,
		Raw:       string(v.Raw),
	})
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
