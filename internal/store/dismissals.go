package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// DismissalRule sets aside the vulnerabilities of an asset whose identifier or
// summary holds a text: components it does not have, such as "wifi:" on a
// server. It also applies to the next ones. A vulnerability exploited or likely
// to be stays out of it, and so does any finding a user has decided on.
type DismissalRule struct {
	ID        int64
	AssetID   int64
	Text      string
	CreatedAt time.Time
	Findings  int // findings it currently sets aside
}

// Whether the finding f of the vulnerability v holds a text, any case: the text
// of the rule r, or the one given to preview a rule. They must look at the same
// columns, as what is listed before setting aside is what gets set aside.
const (
	ruleMatchExpr = `(instr(lower(f.vuln_id), lower(r.text)) > 0 OR instr(lower(v.aliases), lower(r.text)) > 0
		OR instr(lower(v.summary), lower(r.text)) > 0)`
	previewMatchExpr = `(instr(lower(f.vuln_id), lower(?)) > 0 OR instr(lower(v.aliases), lower(?)) > 0
		OR instr(lower(v.summary), lower(?)) > 0)`
)

func dismissalComment(text string) string { return "Écartée par la règle « " + text + " »" }

// CreateDismissalRule adds a rule to an asset of the scope and applies it; a
// rule that already exists is left as it is.
func (s *Store) CreateDismissalRule(ctx context.Context, sc Scope, assetID int64, text string) error {
	if err := assetInScope(ctx, s.q(ctx), sc, assetID); err != nil {
		return wrap("create dismissal rule", err)
	}
	if _, err := s.q(ctx).ExecContext(ctx, `
		INSERT INTO dismissal_rules (asset_id, text, created_at) VALUES (?, ?, ?)
		ON CONFLICT (asset_id, text) DO NOTHING`, assetID, text, now()); err != nil {
		return fmt.Errorf("create dismissal rule: %w", err)
	}
	_, err := s.ApplyDismissalRules(ctx)
	return err
}

// ListDismissalRules returns the rules of an asset of the scope, with the findings
// each sets aside.
func (s *Store) ListDismissalRules(ctx context.Context, sc Scope, assetID int64) ([]DismissalRule, error) {
	query, args := dismissalRulesQuery(sc, assetID)
	return collect(ctx, s.q(ctx), "dismissal rules", func(row scanner) (DismissalRule, error) {
		var r DismissalRule
		var created string
		err := row.Scan(&r.ID, &r.AssetID, &r.Text, &created, &r.Findings)
		r.CreatedAt = parseTime(created)
		return r, err
	}, query, args...)
}

// dismissalRulesQuery reads the rules of an asset of the scope, counting the
// findings of each through the index findings_dismissed_by
// (TestHistoryQueriesUseIndexes).
func dismissalRulesQuery(sc Scope, assetID int64) (string, []any) {
	cond, args := sc.cond("a")
	// #nosec G202 -- cond is a fixed expression of Scope.cond; the values are parameters.
	return `
		SELECT r.id, r.asset_id, r.text, r.created_at,
		       (SELECT count(*) FROM findings f WHERE f.dismissed_by = r.id AND ` + shownExpr + `)
		FROM dismissal_rules r JOIN assets a ON a.id = r.asset_id
		WHERE r.asset_id = ? AND ` + cond + ` ORDER BY r.text COLLATE NOCASE`, append([]any{assetID}, args...)
}

// DeleteDismissalRule removes a rule of an asset of the scope: the findings it
// set aside are to analyse again.
func (s *Store) DeleteDismissalRule(ctx context.Context, sc Scope, assetID, id int64) error {
	cond, args := sc.cond("a")
	return wrap("delete dismissal rule", s.inTx(ctx, func(tx *sql.Tx) error {
		var text string
		err := tx.QueryRowContext(ctx, `SELECT r.text FROM dismissal_rules r JOIN assets a ON a.id = r.asset_id
			WHERE r.id = ? AND r.asset_id = ? AND `+cond, append([]any{id, assetID}, args...)...).Scan(&text)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		list, err := collect(ctx, tx, "set aside findings", value[int64], `SELECT id FROM findings WHERE dismissed_by = ?`, id)
		if err != nil {
			return err
		}
		if err := restoreFindings(ctx, tx, list, dismissalComment(text), "règle d'écart supprimée"); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM dismissal_rules WHERE id = ?`, id)
		return err
	}))
}

// ApplyDismissalRules sets aside the findings to analyse that match a rule of
// their asset, and gives back those that became exploited or likely to be. It
// returns how many were set aside.
func (s *Store) ApplyDismissalRules(ctx context.Context) (int, error) {
	done := 0
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		// A match is a finding and the rule setting it aside, or that would.
		type match struct {
			finding, rule int64
			text          string
		}
		scanMatch := func(row scanner) (match, error) {
			var m match
			err := row.Scan(&m.finding, &m.rule, &m.text)
			return m, err
		}
		exploited, err := collect(ctx, tx, "exploited findings set aside", scanMatch, `
			SELECT f.id, r.id, r.text FROM findings f
			JOIN dismissal_rules r ON r.id = f.dismissed_by
			JOIN vulnerabilities v ON v.id = f.vuln_id
			WHERE `+shownExpr+` AND `+exploitedExpr)
		if err != nil {
			return err
		}
		given := map[string][]int64{}
		for _, m := range exploited {
			given[m.text] = append(given[m.text], m.finding)
		}
		for text, list := range given {
			if err := restoreFindings(ctx, tx, list, dismissalComment(text), "exploitée ou probable : sortie de la règle d'écart"); err != nil {
				return err
			}
		}

		matches, err := collect(ctx, tx, "findings to set aside", scanMatch, `
			SELECT f.id, r.id, r.text FROM dismissal_rules r
			JOIN findings f ON f.asset_id = r.asset_id
			JOIN vulnerabilities v ON v.id = f.vuln_id
			WHERE f.status = 'in_triage' AND `+shownExpr+` AND NOT `+exploitedExpr+` AND `+ruleMatchExpr+`
			  AND NOT EXISTS (SELECT 1 FROM finding_events e WHERE e.finding_id = f.id AND e.user_id IS NOT NULL)`)
		if err != nil {
			return err
		}
		ts := now()
		for _, m := range matches {
			// Two rules can match: the first one has set it aside.
			err := expectRow(tx.ExecContext(ctx, `
				UPDATE findings SET status = 'not_affected', justification = 'code_not_present', dismissed_by = ?, updated_at = ?,
				       comment = CASE WHEN comment = '' THEN ? ELSE comment END
				WHERE id = ? AND status = 'in_triage'`, m.rule, ts, dismissalComment(m.text), m.finding))
			if errors.Is(err, ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			if err := insertEvent(ctx, tx, m.finding, 0, StatusInTriage, StatusNotAffected, dismissalComment(m.text), ts); err != nil {
				return err
			}
			done++
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("apply dismissal rules: %w", err)
	}
	return done, nil
}

// restoreFindings puts findings set aside by a rule back to analyse, with the
// reason in their history. Their comment goes if it is the rule's.
func restoreFindings(ctx context.Context, tx querier, ids []int64, ruleComment, reason string) error {
	ts := now()
	for _, id := range ids {
		if _, err := tx.ExecContext(ctx, `
			UPDATE findings SET status = 'in_triage', justification = '', dismissed_by = 0, updated_at = ?,
			       comment = CASE WHEN comment = ? THEN '' ELSE comment END
			WHERE id = ?`, ts, ruleComment, id); err != nil {
			return err
		}
		if err := insertEvent(ctx, tx, id, 0, StatusNotAffected, StatusInTriage, reason, ts); err != nil {
			return err
		}
	}
	return nil
}
