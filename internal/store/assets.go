package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
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
	CPEMode     string // NVD tracking mode, see nvd.Modes
	CPEFrom     string // first tracked version when CPEMode is "from"
	TrackSince  string // "YYYY-MM-DD": vulnerabilities published before are not reported; "" = whole history
	Criticality string
	Owner       string
	Notes       string
	Source      string
	Project     string   // set for assets imported from an SBOM
	Tags        []string // free tags chosen by the users (see inventory.NormalizeTags)
	CreatedAt   time.Time
	UpdatedAt   time.Time
	Retired     time.Time // dropped from its project's SBOM; zero while active
	OlderVulns  int       // known vulnerabilities published before TrackSince, at the last check
}

const assetColumns = `id, name, kind, ecosystem, version, purl, cpe, cpe_mode, cpe_from, track_since, criticality, owner, notes, source, project, tags, created_at, updated_at, retired_at, older_vulns`

func scanAsset(row interface{ Scan(...any) error }) (Asset, error) {
	var a Asset
	var tags, created, updated, retired string
	err := row.Scan(&a.ID, &a.Name, &a.Kind, &a.Ecosystem, &a.Version, &a.PURL, &a.CPE, &a.CPEMode, &a.CPEFrom, &a.TrackSince,
		&a.Criticality, &a.Owner, &a.Notes, &a.Source, &a.Project, &tags, &created, &updated, &retired, &a.OlderVulns)
	a.Tags = splitTags(tags)
	a.CreatedAt, a.UpdatedAt = parseTime(created), parseTime(updated)
	if retired != "" {
		a.Retired = parseTime(retired)
	}
	return a, err
}

// CreateAsset inserts an asset and returns its id.
func (s *Store) CreateAsset(ctx context.Context, a Asset) (int64, error) {
	ts := now()
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO assets (name, kind, ecosystem, version, purl, cpe, cpe_mode, cpe_from, track_since, criticality, owner, notes, source, project, tags, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.Name, a.Kind, a.Ecosystem, a.Version, a.PURL, a.CPE, a.CPEMode, a.CPEFrom, a.TrackSince, a.Criticality, a.Owner, a.Notes, a.Source, a.Project,
		joinTags(a.Tags), ts, ts)
	if err != nil {
		return 0, fmt.Errorf("create asset: %w", err)
	}
	return res.LastInsertId()
}

// UpdateAsset replaces the editable fields of an asset.
func (s *Store) UpdateAsset(ctx context.Context, a Asset) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE assets SET name = ?, kind = ?, ecosystem = ?, version = ?, purl = ?, cpe = ?, cpe_mode = ?, cpe_from = ?, track_since = ?,
		       criticality = ?, owner = ?, notes = ?, project = ?, tags = ?, updated_at = ?
		WHERE id = ?`,
		a.Name, a.Kind, a.Ecosystem, a.Version, a.PURL, a.CPE, a.CPEMode, a.CPEFrom, a.TrackSince, a.Criticality, a.Owner, a.Notes, a.Project,
		joinTags(a.Tags), now(), a.ID)
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

// ListAssets returns the active assets ordered by name: retired ones (see
// ReplaceProjectAssets) are neither listed nor checked.
func (s *Store) ListAssets(ctx context.Context) ([]Asset, error) {
	return s.listAssets(ctx, false)
}

// ListRetiredAssets returns the components dropped from their project's SBOM.
func (s *Store) ListRetiredAssets(ctx context.Context) ([]Asset, error) {
	return s.listAssets(ctx, true)
}

func (s *Store) listAssets(ctx context.Context, retired bool) ([]Asset, error) {
	cond := "retired_at = ''"
	if retired {
		cond = "retired_at <> ''"
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+assetColumns+` FROM assets WHERE `+cond+`
		ORDER BY project COLLATE NOCASE, name COLLATE NOCASE, version`)
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

// AssetTags returns every tag in use, with the number of assets carrying it,
// in alphabetical order.
func (s *Store) AssetTags(ctx context.Context) ([]TagCount, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT tags FROM assets WHERE tags <> '' AND retired_at = ''`)
	if err != nil {
		return nil, fmt.Errorf("asset tags: %w", err)
	}
	defer rows.Close()
	counts := map[string]int{}
	for rows.Next() {
		var tags string
		if err := rows.Scan(&tags); err != nil {
			return nil, err
		}
		for _, t := range splitTags(tags) {
			counts[t]++
		}
	}
	out := make([]TagCount, 0, len(counts))
	for t, n := range counts {
		out = append(out, TagCount{Tag: t, N: n})
	}
	slices.SortFunc(out, func(a, b TagCount) int { return strings.Compare(a.Tag, b.Tag) })
	return out, rows.Err()
}

// TagCount is a tag and the number of assets carrying it.
type TagCount struct {
	Tag string
	N   int
}

// SetOlderVulns records how many known vulnerabilities of an asset were
// published before its tracked period.
func (s *Store) SetOlderVulns(ctx context.Context, id int64, n int) error {
	_, err := s.db.ExecContext(ctx, `UPDATE assets SET older_vulns = ? WHERE id = ?`, n, id)
	return err
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
