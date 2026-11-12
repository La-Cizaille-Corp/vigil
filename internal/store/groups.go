package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Group is a named part of the inventory (A68): the assets carrying one of its
// tags or belonging to one of its projects. Nothing is stored per asset: an
// asset may be in several groups, and the components of an SBOM enter the
// group of their project as soon as they are imported, by the API too.
type Group struct {
	ID        int64
	Name      string
	CreatedAt time.Time
	Tags      []string // tags it takes in
	Projects  []string // projects it takes in
	Assets    int      // active assets it covers
	Users     int      // accounts restricted to it, among others
}

// groupSelect reads a group with its counts (see scanGroup), on the table
// asset_groups aliased g.
var groupSelect = `SELECT g.id, g.name, g.created_at,
	(SELECT COUNT(*) FROM assets ga WHERE ga.retired_at = '' AND EXISTS (
		SELECT 1 FROM group_rules gr WHERE gr.group_id = g.id AND ` + ruleMatch("ga") + `)),
	(SELECT COUNT(*) FROM user_groups ug WHERE ug.group_id = g.id)
	FROM asset_groups g`

func scanGroup(row scanner) (Group, error) {
	var g Group
	var created string
	err := row.Scan(&g.ID, &g.Name, &created, &g.Assets, &g.Users)
	g.CreatedAt = parseTime(created)
	return g, err
}

// ListGroups returns the groups of the scope, by name, with their rules and
// counts: every group for Everything, those of a restricted account
// otherwise, whose assets it sees.
func (s *Store) ListGroups(ctx context.Context, sc Scope) ([]Group, error) {
	return s.groups(ctx, sc, 0)
}

// Group returns one group of the scope: ErrNotFound outside of it.
func (s *Store) Group(ctx context.Context, sc Scope, id int64) (Group, error) {
	list, err := s.groups(ctx, sc, id)
	if err != nil {
		return Group{}, err
	}
	if len(list) == 0 {
		return Group{}, ErrNotFound
	}
	return list[0], nil
}

// groups reads the groups of the scope, or the one bearing id if not 0.
func (s *Store) groups(ctx context.Context, sc Scope, id int64) ([]Group, error) {
	where, args := sc.groupCond("g")
	if id != 0 {
		where += " AND g.id = ?"
		args = append(args, id)
	}
	// #nosec G202 -- where is made of fixed expressions; the values are parameters.
	list, err := collect(ctx, s.q(ctx), "list groups", scanGroup, groupSelect+` WHERE `+where+` ORDER BY g.name`, args...)
	if err != nil || len(list) == 0 {
		return list, err
	}
	type rule struct {
		group       int64
		kind, value string
	}
	// #nosec G202 -- where is made of fixed expressions; the values are parameters.
	rules, err := collect(ctx, s.q(ctx), "group rules", func(row scanner) (rule, error) {
		var r rule
		err := row.Scan(&r.group, &r.kind, &r.value)
		return r, err
	}, `SELECT gr.group_id, gr.kind, gr.value FROM group_rules gr JOIN asset_groups g ON g.id = gr.group_id
		WHERE `+where+` ORDER BY gr.value`, args...)
	if err != nil {
		return nil, err
	}
	index := make(map[int64]*Group, len(list))
	for i := range list {
		index[list[i].ID] = &list[i]
	}
	for _, r := range rules {
		g := index[r.group]
		if r.kind == "tag" {
			g.Tags = append(g.Tags, r.value)
		} else {
			g.Projects = append(g.Projects, r.value)
		}
	}
	return list, nil
}

// ListAssetGroups returns the groups of the scope an asset belongs to, by
// name, without their rules and counts: what its page shows, as changing a
// tag may change who sees it.
func (s *Store) ListAssetGroups(ctx context.Context, sc Scope, assetID int64) ([]Group, error) {
	cond, args := sc.groupCond("g")
	// #nosec G202 -- cond is a fixed expression of Scope.groupCond; the values are parameters.
	return collect(ctx, s.q(ctx), "asset groups", func(row scanner) (Group, error) {
		var g Group
		err := row.Scan(&g.ID, &g.Name)
		return g, err
	}, `SELECT g.id, g.name FROM asset_groups g JOIN assets ga ON ga.id = ?
		WHERE `+cond+` AND EXISTS (SELECT 1 FROM group_rules gr WHERE gr.group_id = g.id AND `+ruleMatch("ga")+`)
		ORDER BY g.name`, append([]any{assetID}, args...)...)
}

// UngroupedAssets counts the active assets of the scope in no group: only the
// accounts that see everything see them.
func (s *Store) UngroupedAssets(ctx context.Context, sc Scope) (int, error) {
	cond, args := sc.cond("a")
	var n int
	// #nosec G202 -- cond is a fixed expression of Scope.cond; the values are parameters.
	err := s.q(ctx).QueryRowContext(ctx, `SELECT COUNT(*) FROM assets a WHERE a.retired_at = '' AND `+cond+`
		AND NOT EXISTS (SELECT 1 FROM group_rules gr WHERE `+ruleMatch("a")+`)`, args...).Scan(&n)
	return n, wrap("ungrouped assets", err)
}

// CreateGroup adds a group without rules and returns its id; ErrExists when
// another group bears the name, at the case of its letters (see nameTaken).
func (s *Store) CreateGroup(ctx context.Context, name string) (int64, error) {
	var id int64
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		if err := nameTaken(ctx, tx, name, `SELECT name FROM asset_groups`); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO asset_groups (name, created_at) VALUES (?, ?)`, name, now())
		if err != nil {
			return mapUnique(err)
		}
		id, err = res.LastInsertId()
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("create group: %w", err)
	}
	return id, nil
}

// RenameGroup renames a group; ErrExists when another one bears the name.
func (s *Store) RenameGroup(ctx context.Context, id int64, name string) error {
	return wrap("rename group", s.inTx(ctx, func(tx *sql.Tx) error {
		if err := nameTaken(ctx, tx, name, `SELECT name FROM asset_groups WHERE id <> ?`, id); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `UPDATE asset_groups SET name = ? WHERE id = ?`, name, id)
		return expectRow(res, mapUnique(err))
	}))
}

// SetGroupRules replaces the rules of a group: the tags and the projects it
// takes in. A value no asset bears yet is kept, to prepare a group.
func (s *Store) SetGroupRules(ctx context.Context, id int64, tags, projects []string) error {
	return wrap("set group rules", s.inTx(ctx, func(tx *sql.Tx) error {
		var one int
		err := tx.QueryRowContext(ctx, `SELECT 1 FROM asset_groups WHERE id = ?`, id).Scan(&one)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM group_rules WHERE group_id = ?`, id); err != nil {
			return err
		}
		for kind, values := range map[string][]string{"tag": tags, "project": projects} {
			for _, v := range values {
				if _, err := tx.ExecContext(ctx,
					`INSERT OR IGNORE INTO group_rules (group_id, kind, value) VALUES (?, ?, ?)`, id, kind, v); err != nil {
					return err
				}
			}
		}
		return nil
	}))
}

// DeleteGroup removes a group, its rules and its place in the access of the
// accounts restricted to it, which then see less, never more.
func (s *Store) DeleteGroup(ctx context.Context, id int64) error {
	return wrap("delete group", expectRow(s.q(ctx).ExecContext(ctx, `DELETE FROM asset_groups WHERE id = ?`, id)))
}
