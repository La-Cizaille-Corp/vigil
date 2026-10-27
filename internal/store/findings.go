package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Vulnerability is an advisory as fetched from a source.
type Vulnerability struct {
	ID        string
	Aliases   []string
	Summary   string
	Details   string
	Severity  string
	Published string
	Modified  string
	Refs      []string
	Raw       string
	KEV       bool    // listed in CISA Known Exploited Vulnerabilities
	KEVDue    string  // CISA remediation due date
	EPSS      float64 // exploitation probability, -1 when unknown
}

// Finding links an asset to a vulnerability affecting it, with its triage state.
type Finding struct {
	ID            int64
	AssetID       int64
	AssetName     string
	AssetVersion  string
	VulnID        string
	Aliases       []string
	Summary       string
	Severity      string
	KEV           bool
	EPSS          float64
	Status        string
	Justification string
	Comment       string
	FirstSeen     time.Time
	UpdatedAt     time.Time
}

// FindingEvent is one entry of a finding's status history.
type FindingEvent struct {
	Username  string // empty for system changes
	OldStatus string
	NewStatus string
	Comment   string
	CreatedAt time.Time
}

// FindingFilter narrows ListFindings. Zero values mean "any".
type FindingFilter struct {
	Status  string
	AssetID int64
	Since   time.Time // first_seen >= Since
	KEV     bool      // only known exploited vulnerabilities
}

// VulnModified returns the stored "modified" date of a vulnerability.
func (s *Store) VulnModified(ctx context.Context, id string) (string, bool, error) {
	var m string
	err := s.db.QueryRowContext(ctx, `SELECT modified FROM vulnerabilities WHERE id = ?`, id).Scan(&m)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return m, err == nil, err
}

// UpsertVulnerability inserts or refreshes an advisory.
func (s *Store) UpsertVulnerability(ctx context.Context, v Vulnerability) error {
	aliases, _ := json.Marshal(nonNil(v.Aliases))
	refs, _ := json.Marshal(nonNil(v.Refs))
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO vulnerabilities (id, aliases, summary, details, severity, published, modified, refs, raw, fetched_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET
			aliases = excluded.aliases, summary = excluded.summary, details = excluded.details,
			severity = excluded.severity, published = excluded.published, modified = excluded.modified,
			refs = excluded.refs, raw = excluded.raw, fetched_at = excluded.fetched_at`,
		v.ID, string(aliases), v.Summary, v.Details, v.Severity, v.Published, v.Modified, string(refs), v.Raw, now())
	if err != nil {
		return fmt.Errorf("upsert vulnerability %s: %w", v.ID, err)
	}
	return nil
}

// Vulnerability returns one advisory.
func (s *Store) Vulnerability(ctx context.Context, id string) (Vulnerability, error) {
	var v Vulnerability
	var aliases, refs string
	err := s.db.QueryRowContext(ctx, `
		SELECT id, aliases, summary, details, severity, published, modified, refs, kev, kev_due, epss
		FROM vulnerabilities WHERE id = ?`, id).
		Scan(&v.ID, &aliases, &v.Summary, &v.Details, &v.Severity, &v.Published, &v.Modified, &refs,
			&v.KEV, &v.KEVDue, &v.EPSS)
	if errors.Is(err, sql.ErrNoRows) {
		return v, ErrNotFound
	}
	if err != nil {
		return v, err
	}
	if err := json.Unmarshal([]byte(aliases), &v.Aliases); err != nil {
		return v, fmt.Errorf("decode aliases of %s: %w", id, err)
	}
	if err := json.Unmarshal([]byte(refs), &v.Refs); err != nil {
		return v, fmt.Errorf("decode references of %s: %w", id, err)
	}
	return v, nil
}

// TouchResult tells what ObserveFinding did.
type TouchResult int

const (
	TouchExisting TouchResult = iota // already known and open
	TouchCreated                     // new finding
	TouchReopened                    // was auto-resolved, reported again
)

// ObserveFinding records that a source reports vulnID for assetID at time seen.
func (s *Store) ObserveFinding(ctx context.Context, assetID int64, vulnID string, seen time.Time) (TouchResult, error) {
	ts := formatTime(seen)
	result := TouchExisting
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		var id int64
		var status string
		var auto int
		err := tx.QueryRowContext(ctx,
			`SELECT id, status, auto_resolved FROM findings WHERE asset_id = ? AND vuln_id = ?`,
			assetID, vulnID).Scan(&id, &status, &auto)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			_, err = tx.ExecContext(ctx, `
				INSERT INTO findings (asset_id, vuln_id, first_seen, last_seen, updated_at)
				VALUES (?, ?, ?, ?, ?)`, assetID, vulnID, ts, ts, ts)
			result = TouchCreated
			return err
		case err != nil:
			return err
		}
		if auto == 1 && status == "resolved" {
			result = TouchReopened
			if _, err := tx.ExecContext(ctx, `
				UPDATE findings SET status = 'in_triage', auto_resolved = 0, last_seen = ?, updated_at = ?
				WHERE id = ?`, ts, ts, id); err != nil {
				return err
			}
			return insertEvent(ctx, tx, id, 0, status, "in_triage", "signalée à nouveau par la source", ts)
		}
		_, err = tx.ExecContext(ctx, `UPDATE findings SET last_seen = ? WHERE id = ?`, ts, id)
		return err
	})
	if err != nil {
		return result, fmt.Errorf("observe finding %d/%s: %w", assetID, vulnID, err)
	}
	return result, nil
}

// AutoResolveStale closes open findings of assetID whose vulnerability is not
// in reported, i.e. the source no longer lists it. It returns how many were closed.
func (s *Store) AutoResolveStale(ctx context.Context, assetID int64, reported []string) (int, error) {
	still := make(map[string]bool, len(reported))
	for _, id := range reported {
		still[id] = true
	}
	ts := now()
	closed := 0
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT id, vuln_id, status FROM findings
			WHERE asset_id = ? AND status IN ('in_triage', 'exploitable')`, assetID)
		if err != nil {
			return err
		}
		type stale struct {
			id     int64
			status string
		}
		var list []stale
		for rows.Next() {
			var st stale
			var vulnID string
			if err := rows.Scan(&st.id, &vulnID, &st.status); err != nil {
				_ = rows.Close() // already failing, or fully read
				return err
			}
			if !still[vulnID] {
				list = append(list, st)
			}
		}
		_ = rows.Close() // already failing, or fully read
		if err := rows.Err(); err != nil {
			return err
		}
		for _, st := range list {
			if _, err := tx.ExecContext(ctx, `
				UPDATE findings SET status = 'resolved', auto_resolved = 1, updated_at = ? WHERE id = ?`,
				ts, st.id); err != nil {
				return err
			}
			if err := insertEvent(ctx, tx, st.id, 0, st.status, "resolved", "plus signalée par la source (version corrigée ?)", ts); err != nil {
				return err
			}
			closed++
		}
		return nil
	})
	return closed, err
}

// ListFindings returns findings with their asset and vulnerability, most recent first.
func (s *Store) ListFindings(ctx context.Context, f FindingFilter) ([]Finding, error) {
	var where []string
	var args []any
	if f.Status != "" {
		where = append(where, "f.status = ?")
		args = append(args, f.Status)
	}
	if f.AssetID != 0 {
		where = append(where, "f.asset_id = ?")
		args = append(args, f.AssetID)
	}
	if f.KEV {
		where = append(where, "v.kev = 1")
	}
	if !f.Since.IsZero() {
		where = append(where, "f.first_seen >= ?")
		args = append(args, formatTime(f.Since))
	}
	q := findingSelect
	if len(where) > 0 {
		// Only fixed column expressions are joined here; values stay parameterised.
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY f.first_seen DESC, f.id DESC"

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list findings: %w", err)
	}
	defer rows.Close()
	var out []Finding
	for rows.Next() {
		fd, err := scanFinding(rows)
		if err != nil {
			return nil, fmt.Errorf("scan finding: %w", err)
		}
		out = append(out, fd)
	}
	return out, rows.Err()
}

// Finding returns one finding.
func (s *Store) Finding(ctx context.Context, id int64) (Finding, error) {
	fd, err := scanFinding(s.db.QueryRowContext(ctx, findingSelect+" WHERE f.id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return fd, ErrNotFound
	}
	return fd, err
}

const findingSelect = `
	SELECT f.id, f.asset_id, a.name, a.version, f.vuln_id, v.aliases, v.summary, v.severity,
	       v.kev, v.epss, f.status, f.justification, f.comment, f.first_seen, f.updated_at
	FROM findings f
	JOIN assets a ON a.id = f.asset_id
	JOIN vulnerabilities v ON v.id = f.vuln_id`

func scanFinding(row interface{ Scan(...any) error }) (Finding, error) {
	var fd Finding
	var aliases, first, updated string
	err := row.Scan(&fd.ID, &fd.AssetID, &fd.AssetName, &fd.AssetVersion, &fd.VulnID, &aliases,
		&fd.Summary, &fd.Severity, &fd.KEV, &fd.EPSS, &fd.Status, &fd.Justification, &fd.Comment, &first, &updated)
	if err != nil {
		return fd, err
	}
	if err := json.Unmarshal([]byte(aliases), &fd.Aliases); err != nil {
		return fd, fmt.Errorf("decode aliases of %s: %w", fd.VulnID, err)
	}
	fd.FirstSeen, fd.UpdatedAt = parseTime(first), parseTime(updated)
	return fd, nil
}

// SetFindingStatus changes the triage state and records it in the history.
func (s *Store) SetFindingStatus(ctx context.Context, id, userID int64, status, justification, comment string) error {
	ts := now()
	return s.inTx(ctx, func(tx *sql.Tx) error {
		var old string
		err := tx.QueryRowContext(ctx, `SELECT status FROM findings WHERE id = ?`, id).Scan(&old)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE findings SET status = ?, justification = ?, comment = ?, auto_resolved = 0, updated_at = ?
			WHERE id = ?`, status, justification, comment, ts, id); err != nil {
			return err
		}
		return insertEvent(ctx, tx, id, userID, old, status, comment, ts)
	})
}

// FindingEvents returns the history of a finding, oldest first.
func (s *Store) FindingEvents(ctx context.Context, findingID int64) ([]FindingEvent, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT COALESCE(u.username, ''), e.old_status, e.new_status, e.comment, e.created_at
		FROM finding_events e LEFT JOIN users u ON u.id = e.user_id
		WHERE e.finding_id = ? ORDER BY e.id`, findingID)
	if err != nil {
		return nil, fmt.Errorf("list finding events: %w", err)
	}
	defer rows.Close()
	var out []FindingEvent
	for rows.Next() {
		var e FindingEvent
		var created string
		if err := rows.Scan(&e.Username, &e.OldStatus, &e.NewStatus, &e.Comment, &created); err != nil {
			return nil, err
		}
		e.CreatedAt = parseTime(created)
		out = append(out, e)
	}
	return out, rows.Err()
}

// CountFindingsByStatus returns the number of findings per status.
func (s *Store) CountFindingsByStatus(ctx context.Context) (map[string]int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT status, COUNT(*) FROM findings GROUP BY status`)
	if err != nil {
		return nil, fmt.Errorf("count findings: %w", err)
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var st string
		var n int
		if err := rows.Scan(&st, &n); err != nil {
			return nil, err
		}
		out[st] = n
	}
	return out, rows.Err()
}

func insertEvent(ctx context.Context, tx *sql.Tx, findingID, userID int64, old, status, comment, ts string) error {
	var uid any
	if userID != 0 {
		uid = userID
	}
	_, err := tx.ExecContext(ctx, `
		INSERT INTO finding_events (finding_id, user_id, old_status, new_status, comment, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`, findingID, uid, old, status, comment, ts)
	return err
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// VulnCVEs returns, for every stored vulnerability, its CVE identifiers
// (its own id when it is a CVE, plus its CVE aliases).
func (s *Store) VulnCVEs(ctx context.Context) (map[string][]string, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, id FROM vulnerabilities WHERE id LIKE 'CVE-%'
		UNION
		SELECT v.id, j.value FROM vulnerabilities v, json_each(v.aliases) j WHERE j.value LIKE 'CVE-%'`)
	if err != nil {
		return nil, fmt.Errorf("list vulnerability CVEs: %w", err)
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var id, cve string
		if err := rows.Scan(&id, &cve); err != nil {
			return nil, err
		}
		out[id] = append(out[id], cve)
	}
	return out, rows.Err()
}

// SetExploitSignals stores KEV and EPSS data for a vulnerability.
func (s *Store) SetExploitSignals(ctx context.Context, id string, kev bool, kevDue string, epss float64) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE vulnerabilities SET kev = ?, kev_due = ?, epss = ? WHERE id = ?`, kev, kevDue, epss, id)
	return err
}
