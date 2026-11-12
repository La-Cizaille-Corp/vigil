package store

import (
	"context"
	"database/sql"
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

// exploitedExpr tells whether the vulnerability v is exploited or likely to be.
const exploitedExpr = `(v.kev = 1 OR v.epss >= 0.1)`

func dismissalComment(text string) string { return "Écartée par la règle « " + text + " »" }

// CreateDismissalRule adds a rule to an asset of the scope and applies it; a
// rule that already exists is left as it is.
func (s *Store) CreateDismissalRule(ctx context.Context, sc Scope, assetID int64, text string) error {
	if err := assetInScope(ctx, s.db, sc, assetID); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO dismissal_rules (asset_id, text, created_at) VALUES (?, ?, ?)
		ON CONFLICT (asset_id, text) DO NOTHING`, assetID, text, now()); err != nil {
		return fmt.Errorf("create dismissal rule: %w", err)
	}
	_, err := s.ApplyDismissalRules(ctx)
	return err
}

// DismissalRules returns the rules of an asset of the scope, with the findings
// each sets aside.
func (s *Store) DismissalRules(ctx context.Context, sc Scope, assetID int64) ([]DismissalRule, error) {
	cond, args := sc.cond("a")
	// #nosec G202 -- cond is a fixed expression of Scope.cond; the values are parameters.
	rows, err := s.db.QueryContext(ctx, `
		SELECT r.id, r.asset_id, r.text, r.created_at,
		       (SELECT count(*) FROM findings f WHERE f.dismissed_by = r.id)
		FROM dismissal_rules r JOIN assets a ON a.id = r.asset_id
		WHERE r.asset_id = ? AND `+cond+` ORDER BY r.text COLLATE NOCASE`, append([]any{assetID}, args...)...)
	if err != nil {
		return nil, fmt.Errorf("dismissal rules: %w", err)
	}
	defer rows.Close()
	var out []DismissalRule
	for rows.Next() {
		var r DismissalRule
		var created string
		if err := rows.Scan(&r.ID, &r.AssetID, &r.Text, &created, &r.Findings); err != nil {
			return nil, fmt.Errorf("dismissal rules: %w", err)
		}
		r.CreatedAt = parseTime(created)
		out = append(out, r)
	}
	return out, rows.Err()
}

// DeleteDismissalRule removes a rule of an asset of the scope: the findings it
// set aside are to analyse again.
func (s *Store) DeleteDismissalRule(ctx context.Context, sc Scope, assetID, id int64) error {
	var text string
	cond, args := sc.cond("a")
	err := s.db.QueryRowContext(ctx, `SELECT r.text FROM dismissal_rules r JOIN assets a ON a.id = r.asset_id
		WHERE r.id = ? AND r.asset_id = ? AND `+cond, append([]any{id, assetID}, args...)...).Scan(&text)
	if err != nil {
		if err == sql.ErrNoRows {
			return ErrNotFound
		}
		return err
	}
	return s.inTx(ctx, func(tx *sql.Tx) error {
		list, err := idsOf(ctx, tx, `SELECT id FROM findings WHERE dismissed_by = ?`, id)
		if err != nil {
			return err
		}
		if err := restoreFindings(ctx, tx, list, dismissalComment(text), "règle d'écart supprimée"); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM dismissal_rules WHERE id = ?`, id)
		return err
	})
}

// ApplyDismissalRules sets aside the findings to analyse that match a rule of
// their asset, and gives back those that became exploited or likely to be. It
// returns how many were set aside.
func (s *Store) ApplyDismissalRules(ctx context.Context) (int, error) {
	done := 0
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		exploited, err := tx.QueryContext(ctx, `
			SELECT f.id, r.text FROM findings f
			JOIN dismissal_rules r ON r.id = f.dismissed_by
			JOIN vulnerabilities v ON v.id = f.vuln_id
			WHERE `+exploitedExpr)
		if err != nil {
			return err
		}
		given := map[string][]int64{}
		for exploited.Next() {
			var id int64
			var text string
			if err := exploited.Scan(&id, &text); err != nil {
				_ = exploited.Close() // already failing
				return err
			}
			given[text] = append(given[text], id)
		}
		_ = exploited.Close() // fully read
		if err := exploited.Err(); err != nil {
			return err
		}
		for text, list := range given {
			if err := restoreFindings(ctx, tx, list, dismissalComment(text), "exploitée ou probable : sortie de la règle d'écart"); err != nil {
				return err
			}
		}

		rows, err := tx.QueryContext(ctx, `
			SELECT f.id, r.id, r.text FROM dismissal_rules r
			JOIN findings f ON f.asset_id = r.asset_id
			JOIN vulnerabilities v ON v.id = f.vuln_id
			WHERE f.status = 'in_triage' AND NOT `+exploitedExpr+` AND `+ruleMatchExpr+`
			  AND NOT EXISTS (SELECT 1 FROM finding_events e WHERE e.finding_id = f.id AND e.user_id IS NOT NULL)`)
		if err != nil {
			return err
		}
		type match struct {
			finding, rule int64
			text          string
		}
		var matches []match
		for rows.Next() {
			var m match
			if err := rows.Scan(&m.finding, &m.rule, &m.text); err != nil {
				_ = rows.Close() // already failing
				return err
			}
			matches = append(matches, m)
		}
		_ = rows.Close() // fully read
		if err := rows.Err(); err != nil {
			return err
		}
		ts := now()
		for _, m := range matches {
			// Two rules can match: the first one has set it aside.
			res, err := tx.ExecContext(ctx, `
				UPDATE findings SET status = 'not_affected', justification = 'code_not_present', dismissed_by = ?, updated_at = ?,
				       comment = CASE WHEN comment = '' THEN ? ELSE comment END
				WHERE id = ? AND status = 'in_triage'`, m.rule, ts, dismissalComment(m.text), m.finding)
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n == 0 {
				continue
			}
			if err := insertEvent(ctx, tx, m.finding, 0, "in_triage", "not_affected", dismissalComment(m.text), ts); err != nil {
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

// idsOf returns the ids selected by a query.
func idsOf(ctx context.Context, tx *sql.Tx, query string, args ...any) ([]int64, error) {
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// restoreFindings puts findings set aside by a rule back to analyse, with the
// reason in their history. Their comment goes if it is the rule's.
func restoreFindings(ctx context.Context, tx *sql.Tx, ids []int64, ruleComment, reason string) error {
	ts := now()
	for _, id := range ids {
		if _, err := tx.ExecContext(ctx, `
			UPDATE findings SET status = 'in_triage', justification = '', dismissed_by = 0, updated_at = ?,
			       comment = CASE WHEN comment = ? THEN '' ELSE comment END
			WHERE id = ?`, ts, ruleComment, id); err != nil {
			return err
		}
		if err := insertEvent(ctx, tx, id, 0, "not_affected", "in_triage", reason, ts); err != nil {
			return err
		}
	}
	return nil
}
