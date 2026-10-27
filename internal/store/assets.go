package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Asset is something tracked for vulnerabilities: a package, a technology,
// a product or an operating system.
type Asset struct {
	ID          int64
	Name        string
	Kind        string
	Ecosystem   string
	Version     string
	PURL        string
	CPE         string
	Criticality string
	Owner       string
	Notes       string
	Source      string
	Project     string // set for assets imported from an SBOM
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

const assetColumns = `id, name, kind, ecosystem, version, purl, cpe, criticality, owner, notes, source, project, created_at, updated_at`

func scanAsset(row interface{ Scan(...any) error }) (Asset, error) {
	var a Asset
	var created, updated string
	err := row.Scan(&a.ID, &a.Name, &a.Kind, &a.Ecosystem, &a.Version, &a.PURL, &a.CPE,
		&a.Criticality, &a.Owner, &a.Notes, &a.Source, &a.Project, &created, &updated)
	a.CreatedAt, a.UpdatedAt = parseTime(created), parseTime(updated)
	return a, err
}

// CreateAsset inserts an asset and returns its id.
func (s *Store) CreateAsset(ctx context.Context, a Asset) (int64, error) {
	ts := now()
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO assets (name, kind, ecosystem, version, purl, cpe, criticality, owner, notes, source, project, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.Name, a.Kind, a.Ecosystem, a.Version, a.PURL, a.CPE, a.Criticality, a.Owner, a.Notes, a.Source, a.Project, ts, ts)
	if err != nil {
		return 0, fmt.Errorf("create asset: %w", err)
	}
	return res.LastInsertId()
}

// UpdateAsset replaces the editable fields of an asset.
func (s *Store) UpdateAsset(ctx context.Context, a Asset) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE assets SET name = ?, kind = ?, ecosystem = ?, version = ?, purl = ?, cpe = ?,
		       criticality = ?, owner = ?, notes = ?, project = ?, updated_at = ?
		WHERE id = ?`,
		a.Name, a.Kind, a.Ecosystem, a.Version, a.PURL, a.CPE, a.Criticality, a.Owner, a.Notes, a.Project, now(), a.ID)
	if err != nil {
		return fmt.Errorf("update asset: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Asset returns one asset.
func (s *Store) Asset(ctx context.Context, id int64) (Asset, error) {
	a, err := scanAsset(s.db.QueryRowContext(ctx, `SELECT `+assetColumns+` FROM assets WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return a, ErrNotFound
	}
	return a, err
}

// ListAssets returns every asset ordered by name.
func (s *Store) ListAssets(ctx context.Context) ([]Asset, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+assetColumns+` FROM assets ORDER BY project COLLATE NOCASE, name COLLATE NOCASE, version`)
	if err != nil {
		return nil, fmt.Errorf("list assets: %w", err)
	}
	defer rows.Close()
	var out []Asset
	for rows.Next() {
		a, err := scanAsset(rows)
		if err != nil {
			return nil, fmt.Errorf("scan asset: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// DeleteAsset removes an asset and, by cascade, its findings.
func (s *Store) DeleteAsset(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM assets WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete asset: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
