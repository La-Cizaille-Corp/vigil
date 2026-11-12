package store

import (
	"context"
	"database/sql"
	"errors"
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
	Retired     time.Time // dropped from its project's SBOM; zero while active
	OlderVulns  int       // known vulnerabilities published before TrackSince, at the last check
}

const assetColumns = `id, name, kind, ecosystem, version, purl, cpe, cpe_mode, cpe_from, track_since, criticality, owner, notes, source, project, tags, created_at, retired_at, older_vulns`

func scanAsset(row scanner) (Asset, error) {
	var a Asset
	var tags, created, retired string
	err := row.Scan(&a.ID, &a.Name, &a.Kind, &a.Ecosystem, &a.Version, &a.PURL, &a.CPE, &a.CPEMode, &a.CPEFrom, &a.TrackSince,
		&a.Criticality, &a.Owner, &a.Notes, &a.Source, &a.Project, &tags, &created, &retired, &a.OlderVulns)
	a.Tags = splitTags(tags)
	a.CreatedAt = parseTime(created)
	if retired != "" {
		a.Retired = parseTime(retired)
	}
	return a, err
}

// CreateAsset inserts an asset and returns its id; the asset must land inside
// the scope (ErrOutsideGroups).
func (s *Store) CreateAsset(ctx context.Context, sc Scope, a Asset) (int64, error) {
	ids, err := s.CreateAssets(ctx, sc, []Asset{a})
	if err != nil {
		return 0, err
	}
	return ids[0], nil
}

// CreateAssets inserts assets in one transaction, all or none, and returns
// their ids in order; they must land inside the scope (ErrOutsideGroups).
func (s *Store) CreateAssets(ctx context.Context, sc Scope, assets []Asset) ([]int64, error) {
	if err := sc.writable(); err != nil {
		return nil, err
	}
	ts := now()
	ids := make([]int64, 0, len(assets))
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		for _, a := range assets {
			id, err := insertAsset(ctx, tx, a, ts)
			if err != nil {
				return err
			}
			ids = append(ids, id)
		}
		return nil
	})
	if err != nil {
		return nil, wrap("create asset", err)
	}
	return ids, nil
}

// insertAsset inserts an asset created at ts and returns its id.
func insertAsset(ctx context.Context, q querier, a Asset, ts string) (int64, error) {
	res, err := q.ExecContext(ctx, `
		INSERT INTO assets (name, kind, ecosystem, version, purl, cpe, cpe_mode, cpe_from, track_since, criticality, owner, notes, source, project, tags, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.Name, a.Kind, a.Ecosystem, a.Version, a.PURL, a.CPE, a.CPEMode, a.CPEFrom, a.TrackSince, a.Criticality, a.Owner, a.Notes, a.Source, a.Project,
		joinTags(a.Tags), ts, ts)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpdateAsset replaces the editable fields of an asset of the scope.
func (s *Store) UpdateAsset(ctx context.Context, sc Scope, a Asset) error {
	cond, args := sc.cond("a")
	// #nosec G202 -- cond is a fixed expression of Scope.cond; the values are parameters.
	return wrap("update asset", expectRow(s.q(ctx).ExecContext(ctx, `
		UPDATE assets AS a SET name = ?, kind = ?, ecosystem = ?, version = ?, purl = ?, cpe = ?, cpe_mode = ?, cpe_from = ?, track_since = ?,
		       criticality = ?, owner = ?, notes = ?, project = ?, tags = ?, updated_at = ?
		WHERE a.id = ? AND `+cond,
		append([]any{a.Name, a.Kind, a.Ecosystem, a.Version, a.PURL, a.CPE, a.CPEMode, a.CPEFrom, a.TrackSince, a.Criticality, a.Owner, a.Notes, a.Project,
			joinTags(a.Tags), now(), a.ID}, args...)...)))
}

// Asset returns one asset of the scope: ErrNotFound outside of it, as for an
// asset that does not exist, so that a guessed id tells nothing.
func (s *Store) Asset(ctx context.Context, sc Scope, id int64) (Asset, error) {
	cond, args := sc.cond("a")
	a, err := scanAsset(s.q(ctx).QueryRowContext(ctx, `SELECT `+assetColumns+` FROM assets a WHERE a.id = ? AND `+cond,
		append([]any{id}, args...)...))
	if errors.Is(err, sql.ErrNoRows) {
		return a, ErrNotFound
	}
	return a, wrap("asset", err)
}

// ListAssets returns the active assets of the scope ordered by name: retired
// ones (see ReplaceProjectAssets) are neither listed nor checked.
func (s *Store) ListAssets(ctx context.Context, sc Scope) ([]Asset, error) {
	return s.listAssets(ctx, sc, false)
}

// ListRetiredAssets returns the components of the scope dropped from their
// project's SBOM.
func (s *Store) ListRetiredAssets(ctx context.Context, sc Scope) ([]Asset, error) {
	return s.listAssets(ctx, sc, true)
}

func (s *Store) listAssets(ctx context.Context, sc Scope, retired bool) ([]Asset, error) {
	state := "a.retired_at = ''"
	if retired {
		state = "a.retired_at <> ''"
	}
	cond, args := sc.cond("a")
	// #nosec G202 -- cond is a fixed expression of Scope.cond; the values are parameters.
	return collect(ctx, s.q(ctx), "list assets", scanAsset, `SELECT `+assetColumns+` FROM assets a WHERE `+state+` AND `+cond+`
		ORDER BY a.project COLLATE NOCASE, a.name COLLATE NOCASE, a.version`, args...)
}

// ListAssetTags returns every tag in use in the scope, with the number of assets
// carrying it, in alphabetical order.
func (s *Store) ListAssetTags(ctx context.Context, sc Scope) ([]TagCount, error) {
	cond, args := sc.cond("a")
	// #nosec G202 -- cond is a fixed expression of Scope.cond; the values are parameters.
	lists, err := collect(ctx, s.q(ctx), "asset tags", value[string], `SELECT a.tags FROM assets a WHERE a.tags <> '' AND a.retired_at = '' AND `+cond, args...)
	if err != nil {
		return nil, err
	}
	counts := map[string]int{}
	for _, tags := range lists {
		for _, t := range splitTags(tags) {
			counts[t]++
		}
	}
	out := make([]TagCount, 0, len(counts))
	for t, n := range counts {
		out = append(out, TagCount{Tag: t, N: n})
	}
	slices.SortFunc(out, func(a, b TagCount) int { return strings.Compare(a.Tag, b.Tag) })
	return out, nil
}

// TagCount is a tag and the number of assets carrying it.
type TagCount struct {
	Tag string
	N   int
}

// SetOlderVulns records how many known vulnerabilities of an asset were
// published before its tracked period.
func (s *Store) SetOlderVulns(ctx context.Context, id int64, n int) error {
	_, err := s.q(ctx).ExecContext(ctx, `UPDATE assets SET older_vulns = ? WHERE id = ?`, n, id)
	return wrap("set older vulnerabilities", err)
}

// DeleteAsset removes an asset of the scope and, by cascade, its findings.
func (s *Store) DeleteAsset(ctx context.Context, sc Scope, id int64) error {
	cond, args := sc.cond("a")
	// #nosec G202 -- cond is a fixed expression of Scope.cond; the values are parameters.
	return wrap("delete asset", expectRow(s.q(ctx).ExecContext(ctx, `DELETE FROM assets AS a WHERE a.id = ? AND `+cond, append([]any{id}, args...)...)))
}
