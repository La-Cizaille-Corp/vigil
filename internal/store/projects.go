package store

import (
	"context"
	"database/sql"
	"fmt"
)

// ImportResult summarises an SBOM import.
type ImportResult struct {
	Added   int
	Kept    int // including retired components listed again
	Removed int // retired, see ReplaceProjectAssets
}

// ReplaceProjectAssets makes the SBOM-sourced assets of project match assets,
// keyed by purl: unknown purls are added, existing ones kept. A missing one is
// retired rather than deleted, so that its triage history survives: its open
// findings are resolved with a history event (the component is gone, often
// replaced by a fixed version), its decisions are kept, and it comes back as
// it was if a later SBOM lists it again. Manually created assets are never
// touched. The components must land inside the scope (ErrOutsideGroups).
func (s *Store) ReplaceProjectAssets(ctx context.Context, sc Scope, project string, assets []Asset) (ImportResult, error) {
	var res ImportResult
	if err := sc.writable(); err != nil {
		return res, err
	}
	ts := now()
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		type known struct {
			id      int64
			purl    string
			retired bool
		}
		list, err := collect(ctx, tx, "project components", func(row scanner) (known, error) {
			var k known
			err := row.Scan(&k.id, &k.purl, &k.retired)
			return k, err
		}, `SELECT id, purl, retired_at <> '' FROM assets WHERE project = ? AND source = 'sbom'`, project)
		if err != nil {
			return err
		}
		existing := make(map[string]known, len(list))
		for _, k := range list {
			existing[k.purl] = k
		}

		seen := map[string]bool{}
		for _, a := range assets {
			if seen[a.PURL] {
				continue
			}
			seen[a.PURL] = true
			if k, ok := existing[a.PURL]; ok {
				if k.retired {
					if _, err := tx.ExecContext(ctx, `UPDATE assets SET retired_at = '', updated_at = ? WHERE id = ?`, ts, k.id); err != nil {
						return err
					}
				}
				res.Kept++
				continue
			}
			// Only what an SBOM tells: the rest takes the values of a new component.
			if _, err := insertAsset(ctx, tx, Asset{Name: a.Name, Kind: a.Kind, Version: a.Version, PURL: a.PURL, CPE: a.CPE,
				TrackSince: a.TrackSince, Criticality: "medium", Source: "sbom", Project: project}, ts); err != nil {
				return err
			}
			res.Added++
		}
		for purl, k := range existing {
			if seen[purl] || k.retired {
				continue
			}
			if err := retireAsset(ctx, tx, k.id, project, ts); err != nil {
				return err
			}
			res.Removed++
		}
		return nil
	})
	if err != nil {
		return res, fmt.Errorf("import project %q: %w", project, err)
	}
	return res, nil
}

// retireAsset marks an asset retired and resolves its open findings, with an
// event in their history.
func retireAsset(ctx context.Context, tx querier, id int64, project, ts string) error {
	if _, err := tx.ExecContext(ctx, `UPDATE assets SET retired_at = ?, updated_at = ? WHERE id = ?`, ts, ts, id); err != nil {
		return err
	}
	list, err := collect(ctx, tx, "open findings", scanFindingState,
		`SELECT f.id, f.status, f.vuln_id FROM findings f WHERE f.asset_id = ? AND f.status IN `+openStatuses+` AND `+shownExpr, id)
	if err != nil {
		return err
	}
	reason := fmt.Sprintf("composant absent du dernier SBOM du projet %s", project)
	for _, o := range list {
		if err := autoResolve(ctx, tx, o, reason, ts); err != nil {
			return err
		}
	}
	return nil
}

// ListProjects returns the distinct non-empty projects of the active assets
// of the scope.
func (s *Store) ListProjects(ctx context.Context, sc Scope) ([]string, error) {
	cond, args := sc.cond("a")
	// #nosec G202 -- cond is a fixed expression of Scope.cond; the values are parameters.
	return collect(ctx, s.q(ctx), "list projects", value[string], `SELECT DISTINCT a.project FROM assets a
		WHERE a.project <> '' AND a.retired_at = '' AND `+cond+` ORDER BY a.project COLLATE NOCASE`, args...)
}
