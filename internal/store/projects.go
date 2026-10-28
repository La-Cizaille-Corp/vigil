package store

import (
	"context"
	"database/sql"
	"fmt"
)

// ImportResult summarises an SBOM import.
type ImportResult struct {
	Added   int
	Kept    int
	Removed int
}

// ReplaceProjectAssets makes the SBOM-sourced assets of project match assets,
// keyed by purl: unknown purls are added, missing ones removed (with their
// findings), existing ones kept so that their triage history survives.
// Manually created assets are never touched.
func (s *Store) ReplaceProjectAssets(ctx context.Context, project string, assets []Asset) (ImportResult, error) {
	var res ImportResult
	ts := now()
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		existing := map[string]int64{}
		rows, err := tx.QueryContext(ctx,
			`SELECT id, purl FROM assets WHERE project = ? AND source = 'sbom'`, project)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id int64
			var purl string
			if err := rows.Scan(&id, &purl); err != nil {
				_ = rows.Close() // already failing, or fully read
				return err
			}
			existing[purl] = id
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
			if _, ok := existing[a.PURL]; ok {
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
		for purl, id := range existing {
			if seen[purl] {
				continue
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM assets WHERE id = ?`, id); err != nil {
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

// ListProjects returns the distinct non-empty projects.
func (s *Store) ListProjects(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT DISTINCT project FROM assets WHERE project <> '' ORDER BY project COLLATE NOCASE`)
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
