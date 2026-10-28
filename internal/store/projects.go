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
// touched.
func (s *Store) ReplaceProjectAssets(ctx context.Context, project string, assets []Asset) (ImportResult, error) {
	var res ImportResult
	ts := now()
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		type known struct {
			id      int64
			retired bool
		}
		existing := map[string]known{}
		rows, err := tx.QueryContext(ctx,
			`SELECT id, purl, retired_at <> '' FROM assets WHERE project = ? AND source = 'sbom'`, project)
		if err != nil {
			return err
		}
		for rows.Next() {
			var k known
			var purl string
			if err := rows.Scan(&k.id, &purl, &k.retired); err != nil {
				_ = rows.Close() // already failing, or fully read
				return err
			}
			existing[purl] = k
		}
		_ = rows.Close() // already failing, or fully read
		if err := rows.Err(); err != nil {
			return err
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
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO assets (name, kind, ecosystem, version, purl, cpe, track_since, criticality, owner, notes, source, project, created_at, updated_at)
				VALUES (?, ?, '', ?, ?, ?, ?, 'medium', '', '', 'sbom', ?, ?, ?)`,
				a.Name, a.Kind, a.Version, a.PURL, a.CPE, a.TrackSince, project, ts, ts); err != nil {
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
func retireAsset(ctx context.Context, tx *sql.Tx, id int64, project, ts string) error {
	if _, err := tx.ExecContext(ctx, `UPDATE assets SET retired_at = ?, updated_at = ? WHERE id = ?`, ts, ts, id); err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx,
		`SELECT id, status FROM findings WHERE asset_id = ? AND status IN ('in_triage', 'exploitable')`, id)
	if err != nil {
		return err
	}
	type open struct {
		id     int64
		status string
	}
	var list []open
	for rows.Next() {
		var o open
		if err := rows.Scan(&o.id, &o.status); err != nil {
			_ = rows.Close() // already failing
			return err
		}
		list = append(list, o)
	}
	_ = rows.Close() // fully read
	if err := rows.Err(); err != nil {
		return err
	}
	for _, o := range list {
		if _, err := tx.ExecContext(ctx,
			`UPDATE findings SET status = 'resolved', auto_resolved = 1, updated_at = ? WHERE id = ?`, ts, o.id); err != nil {
			return err
		}
		if err := insertEvent(ctx, tx, o.id, 0, o.status, "resolved",
			fmt.Sprintf("composant absent du dernier SBOM du projet %s", project), ts); err != nil {
			return err
		}
	}
	return nil
}

// ListProjects returns the distinct non-empty projects of the active assets.
func (s *Store) ListProjects(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT DISTINCT project FROM assets WHERE project <> '' AND retired_at = '' ORDER BY project COLLATE NOCASE`)
	if err != nil {
		return nil, fmt.Errorf("list projects: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
