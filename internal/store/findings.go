package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
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
	CVSS      float64 // CVSS base score, -1 when unknown
}

// Finding links an asset to a vulnerability affecting it, with its triage state.
type Finding struct {
	ID            int64
	AssetID       int64
	AssetName     string
	AssetVersion  string
	AssetPURL     string
	AssetCPE      string
	AssetProject  string
	VulnID        string
	Aliases       []string
	Summary       string
	Severity      string
	CVSS          float64
	KEV           bool
	EPSS          float64
	Status        string
	Justification string
	Comment       string
	FixedIn       string // versions fixing it for the asset, "" when unknown (see tracking.FixedIn)
	FirstSeen     time.Time
	Due           time.Time // remediation deadline (see SLA), zero without one
	Late          bool      // open and past its deadline
	// Class is the alert class (AlertNone, AlertSevere, AlertPriority): the
	// alerts and the levels of tracking.Level go by it.
	Class int
	// FoldedInto tells a finding folded into others (A80): -1 for a grouped
	// advisory shown through its CVEs, otherwise the finding kept for its
	// CVE; 0 for a finding shown.
	FoldedInto int64
}

// Triage statuses of a finding: the CycloneDX / VEX analysis states
// (labelled in tracking.Statuses).
const (
	StatusInTriage      = "in_triage"
	StatusExploitable   = "exploitable"
	StatusResolved      = "resolved"
	StatusNotAffected   = "not_affected"
	StatusFalsePositive = "false_positive"
)

// Open reports whether a finding is still to triage or to fix; openStatuses
// says the same in SQL.
func (f Finding) Open() bool { return f.Status == StatusInTriage || f.Status == StatusExploitable }

// openStatuses are the statuses of findings still to triage or to fix (see
// Finding.Open).
const openStatuses = `('in_triage', 'exploitable')`

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
	Project string
	Tag     string // the asset carries this tag

	Statuses   []string // any of these statuses
	Severities []string // any of these ratings; "UNKNOWN" matches findings without one
	Kinds      []string // any of these asset kinds
	MinCVSS    float64  // 0 = any
	MinEPSS    float64  // 0 = any
	Overdue    bool     // open and past the remediation deadline
	Search     string   // substring of the vulnerability id, aliases, summary or asset name
	Matching   string   // text a dismissal rule would look for (see previewMatchExpr)
	CVEs       []string // any of these CVEs, as the vulnerability id or an alias

	// Now is the time Overdue and Late are judged at, so that a page agrees
	// with the figures computed at the same time; zero is the current time.
	Now time.Time
}

// VulnModified returns the stored "modified" date of a vulnerability.
func (s *Store) VulnModified(ctx context.Context, id string) (string, bool, error) {
	var m string
	err := s.q(ctx).QueryRowContext(ctx, `SELECT modified FROM vulnerabilities WHERE id = ?`, id).Scan(&m)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return m, err == nil, wrap("vulnerability modified "+id, err)
}

// UpsertVulnerability inserts or refreshes an advisory.
func (s *Store) UpsertVulnerability(ctx context.Context, v Vulnerability) error {
	aliases, _ := json.Marshal(nonNil(v.Aliases))
	refs, _ := json.Marshal(nonNil(v.Refs))
	_, err := s.q(ctx).ExecContext(ctx, `
		INSERT INTO vulnerabilities (id, aliases, summary, details, severity, cvss, published, modified, refs, raw, fetched_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET
			aliases = excluded.aliases, summary = excluded.summary, details = excluded.details,
			severity = excluded.severity, cvss = excluded.cvss, published = excluded.published, modified = excluded.modified,
			refs = excluded.refs, raw = excluded.raw, fetched_at = excluded.fetched_at`,
		v.ID, string(aliases), v.Summary, v.Details, v.Severity, v.CVSS, v.Published, v.Modified, string(refs), v.Raw, now())
	if err != nil {
		return fmt.Errorf("upsert vulnerability %s: %w", v.ID, err)
	}
	return nil
}

// Vulnerability returns one advisory.
func (s *Store) Vulnerability(ctx context.Context, id string) (Vulnerability, error) {
	var v Vulnerability
	var aliases, refs string
	err := s.q(ctx).QueryRowContext(ctx, `
		SELECT id, aliases, summary, details, severity, cvss, published, modified, refs, kev, kev_due, epss, raw
		FROM vulnerabilities WHERE id = ?`, id).
		Scan(&v.ID, &aliases, &v.Summary, &v.Details, &v.Severity, &v.CVSS, &v.Published, &v.Modified, &refs,
			&v.KEV, &v.KEVDue, &v.EPSS, &v.Raw)
	if errors.Is(err, sql.ErrNoRows) {
		return v, ErrNotFound
	}
	if err != nil {
		return v, fmt.Errorf("vulnerability %s: %w", id, err)
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

// ObserveFinding records that a source reports vulnID for assetID at time
// seen, fixed in the versions given ("" when unknown).
func (s *Store) ObserveFinding(ctx context.Context, assetID int64, vulnID, fixedIn string, seen time.Time) (TouchResult, error) {
	ts := formatTime(seen)
	result := TouchExisting
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		var id, folded int64
		var status string
		var auto int
		err := tx.QueryRowContext(ctx,
			`SELECT id, status, auto_resolved, folded_into FROM findings WHERE asset_id = ? AND vuln_id = ?`,
			assetID, vulnID).Scan(&id, &status, &auto, &folded)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			_, err = tx.ExecContext(ctx, `
				INSERT INTO findings (asset_id, vuln_id, fixed_in, first_seen, last_seen, updated_at)
				VALUES (?, ?, ?, ?, ?, ?)`, assetID, vulnID, fixedIn, ts, ts, ts)
			result = TouchCreated
			return err
		case err != nil:
			return err
		}
		if folded != 0 { // its CVEs no longer have advisories of their own (A80)
			if _, err := tx.ExecContext(ctx, `UPDATE findings SET folded_into = 0, updated_at = ? WHERE id = ?`, ts, id); err != nil {
				return err
			}
			if err := insertEvent(ctx, tx, id, 0, status, status, "de nouveau affichée : la source ne la décrit plus par d'autres avis", ts); err != nil {
				return err
			}
		}
		if auto == 1 && status == StatusResolved {
			result = TouchReopened
			if _, err := tx.ExecContext(ctx, `
				UPDATE findings SET status = 'in_triage', auto_resolved = 0, fixed_in = ?, last_seen = ?, updated_at = ?
				WHERE id = ?`, fixedIn, ts, ts, id); err != nil {
				return err
			}
			return insertEvent(ctx, tx, id, 0, status, StatusInTriage, "signalée à nouveau par la source", ts)
		}
		_, err = tx.ExecContext(ctx, `UPDATE findings SET fixed_in = ?, last_seen = ? WHERE id = ?`, fixedIn, ts, id)
		return err
	})
	if err != nil {
		return result, fmt.Errorf("observe finding %d/%s: %w", assetID, vulnID, err)
	}
	return result, nil
}

// inPeriod is the SQL condition, on vulnerabilities aliased v, for a
// vulnerability inside a tracked period starting at the date given as two
// parameters ("" = no limit). Vulnerabilities exploited or likely to be (KEV,
// EPSS >= LikelyEPSS, A31) and undated ones are always inside.
var inPeriod = `(? = '' OR ` + exploitedExpr + ` OR v.published = '' OR substr(v.published, 1, 10) >= ?)`

// InTrackedPeriod reports whether vulnID should be tracked for assetID given
// the asset's period start (see Asset.TrackSince): the vulnerability is in the
// period, or the asset already has a finding for it.
func (s *Store) InTrackedPeriod(ctx context.Context, assetID int64, vulnID, since string) (bool, error) {
	var in bool
	err := s.q(ctx).QueryRowContext(ctx, `
		SELECT EXISTS (SELECT 1 FROM findings WHERE asset_id = ? AND vuln_id = ?)
		    OR EXISTS (SELECT 1 FROM vulnerabilities v WHERE v.id = ? AND `+inPeriod+`)`,
		assetID, vulnID, vulnID, since, since).Scan(&in)
	if err != nil {
		return false, fmt.Errorf("tracked period %d/%s: %w", assetID, vulnID, err)
	}
	return in, nil
}

// AutoResolveStale closes open findings of assetID whose vulnerability is not
// in reported, i.e. the source no longer lists it. Findings of vulnerabilities
// published before since are left alone: sources may not be asked about that
// period. It returns how many were closed.
func (s *Store) AutoResolveStale(ctx context.Context, assetID int64, reported []string, since string) (int, error) {
	still := make(map[string]bool, len(reported))
	for _, id := range reported {
		still[id] = true
	}
	ts := now()
	closed := 0
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		open, err := collect(ctx, tx, "open findings", scanFindingState, `
			SELECT f.id, f.status, f.vuln_id FROM findings f JOIN vulnerabilities v ON v.id = f.vuln_id
			WHERE f.asset_id = ? AND f.status IN `+openStatuses+` AND `+shownExpr+` AND `+inPeriod,
			assetID, since, since)
		if err != nil {
			return err
		}
		for _, st := range open {
			if still[st.vulnID] {
				continue
			}
			if err := autoResolve(ctx, tx, st, "plus signalée par la source (version corrigée ?)", ts); err != nil {
				return err
			}
			closed++
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("auto-resolve findings of asset %d: %w", assetID, err)
	}
	return closed, nil
}

// findingState is a finding about to change status: its id, its status, and
// the vulnerability or the rule it refers to.
type findingState struct {
	id     int64
	status string
	vulnID string
}

// autoResolve closes an open finding the sources no longer report, or whose
// component is gone, with the reason in its history: a later report reopens
// it (see ObserveFinding).
func autoResolve(ctx context.Context, q querier, st findingState, reason, ts string) error {
	if _, err := q.ExecContext(ctx,
		`UPDATE findings SET status = 'resolved', auto_resolved = 1, updated_at = ? WHERE id = ?`, ts, st.id); err != nil {
		return err
	}
	return insertEvent(ctx, q, st.id, 0, st.status, StatusResolved, reason, ts)
}

// scanFindingState reads id, status and, if selected, the vulnerability.
func scanFindingState(row scanner) (findingState, error) {
	var st findingState
	err := row.Scan(&st.id, &st.status, &st.vulnID)
	return st, err
}

// ListFindings returns the findings of the scope with their asset and
// vulnerability, most recent first.
func (s *Store) ListFindings(ctx context.Context, sc Scope, f FindingFilter) ([]Finding, error) {
	sla, err := s.SLA(ctx)
	if err != nil {
		return nil, err
	}
	at := f.Now
	if at.IsZero() {
		at = time.Now()
	}
	today := day(at)
	cond, condArgs := sc.cond("a")
	where := []string{cond, shownExpr}
	args := append(sla.args(), condArgs...) // the deadline column of findingSelect comes first
	if f.Status != "" {
		where = append(where, "f.status = ?")
		args = append(args, f.Status)
	}
	if f.AssetID != 0 {
		where = append(where, "f.asset_id = ?")
		args = append(args, f.AssetID)
	}
	if f.Project != "" {
		where = append(where, "a.project = ?")
		args = append(args, f.Project)
	}
	if f.Tag != "" {
		cond, arg := hasTag("a.tags", f.Tag)
		where = append(where, cond)
		args = append(args, arg)
	}
	if f.KEV {
		where = append(where, "v.kev = 1")
	}
	if !f.Since.IsZero() {
		where = append(where, "f.first_seen >= ?")
		args = append(args, formatTime(f.Since))
	}
	where, args = inClause(where, args, "f.status", f.Statuses)
	where, args = inClause(where, args, "a.kind", f.Kinds)
	severities := f.Severities
	if slices.Contains(severities, "UNKNOWN") {
		severities = append(slices.Clone(severities), "")
	}
	where, args = inClause(where, args, "UPPER(v.severity)", severities)
	if f.MinCVSS > 0 {
		where = append(where, "v.cvss >= ?")
		args = append(args, f.MinCVSS)
	}
	if f.MinEPSS > 0 {
		where = append(where, "v.epss >= ?")
		args = append(args, f.MinEPSS)
	}
	if f.Overdue {
		where = append(where, "f.status IN "+openStatuses+" AND "+dueExpr+" < ?")
		args = append(append(args, sla.args()...), today)
	}
	if f.Search != "" {
		where = append(where, `(f.vuln_id LIKE ? ESCAPE '\' OR v.aliases LIKE ? ESCAPE '\'
			OR v.summary LIKE ? ESCAPE '\' OR a.name LIKE ? ESCAPE '\')`)
		term := "%" + likeEscaper.Replace(f.Search) + "%"
		args = append(args, term, term, term, term)
	}
	if f.Matching != "" {
		where = append(where, previewMatchExpr)
		args = append(args, f.Matching, f.Matching, f.Matching)
	}
	if len(f.CVEs) > 0 {
		var ids, aliases []string
		ids, args = inClause(nil, args, "f.vuln_id", f.CVEs)
		aliases, args = inClause(nil, args, "j.value", f.CVEs)
		where = append(where, "("+ids[0]+" OR EXISTS (SELECT 1 FROM json_each(v.aliases) j WHERE "+aliases[0]+"))")
	}
	// #nosec G202 -- only fixed expressions, the scope's included, are joined; the values are parameters.
	q := findingSelect + " WHERE " + strings.Join(where, " AND ") + " ORDER BY f.first_seen DESC, f.id DESC"
	return collect(ctx, s.q(ctx), "list findings", func(row scanner) (Finding, error) {
		return scanFinding(row, today)
	}, q, args...)
}

// Finding returns one finding of the scope: ErrNotFound outside of it.
func (s *Store) Finding(ctx context.Context, sc Scope, id int64) (Finding, error) {
	sla, err := s.SLA(ctx)
	if err != nil {
		return Finding{}, err
	}
	cond, condArgs := sc.cond("a")
	args := append(append(sla.args(), id), condArgs...)
	fd, err := scanFinding(s.q(ctx).QueryRowContext(ctx, findingSelect+" WHERE f.id = ? AND "+cond, args...), day(time.Now()))
	if errors.Is(err, sql.ErrNoRows) {
		return fd, ErrNotFound
	}
	return fd, wrap("finding", err)
}

// shownExpr keeps the findings aliased f that are not folded into others
// (A80): every list, count, alert and statistic goes by it; the page of a
// folded finding remains (Finding), for the links already sent.
const shownExpr = `f.folded_into = 0`

// findingColumns and findingFrom select findings with their asset and
// vulnerability; the deadline column takes the SLA arguments first.
var (
	findingColumns = `f.id, f.asset_id, a.name, a.version, a.purl, a.cpe, a.project, f.vuln_id, v.aliases, v.summary, v.severity,
	       v.cvss, v.kev, v.epss, f.status, f.justification, f.comment, f.fixed_in, f.first_seen, ` + dueExpr + `,
	       ` + alertClassExpr + ` AS alert_class, f.folded_into`
	findingSelect = "SELECT " + findingColumns + findingFrom
)

const findingFrom = `
	FROM findings f
	JOIN assets a ON a.id = f.asset_id
	JOIN vulnerabilities v ON v.id = f.vuln_id`

// scanFinding reads the columns of findingSelect, then extra ones if given; a
// finding is late when its deadline is before today (see day).
func scanFinding(row scanner, today string, extra ...any) (Finding, error) {
	var fd Finding
	var aliases, first string
	var due sql.NullString
	dest := append([]any{&fd.ID, &fd.AssetID, &fd.AssetName, &fd.AssetVersion,
		&fd.AssetPURL, &fd.AssetCPE, &fd.AssetProject, &fd.VulnID, &aliases,
		&fd.Summary, &fd.Severity, &fd.CVSS, &fd.KEV, &fd.EPSS, &fd.Status, &fd.Justification, &fd.Comment, &fd.FixedIn, &first,
		&due, &fd.Class, &fd.FoldedInto}, extra...)
	if err := row.Scan(dest...); err != nil {
		return fd, err
	}
	if err := json.Unmarshal([]byte(aliases), &fd.Aliases); err != nil {
		return fd, fmt.Errorf("decode aliases of %s: %w", fd.VulnID, err)
	}
	fd.FirstSeen = parseTime(first)
	if due.Valid {
		fd.Due, _ = time.Parse(time.DateOnly, due.String) // written by SQLite's date()
		fd.Late = fd.Open() && due.String < today
	}
	return fd, nil
}

// SetFindingStatus changes the triage state of a finding of the scope and
// records it in the history.
func (s *Store) SetFindingStatus(ctx context.Context, sc Scope, id, userID int64, status, justification, comment string) error {
	c := StatusChange{ID: id, Status: status, Justification: justification, Comment: comment}
	return wrap("set finding status", s.inTx(ctx, func(tx *sql.Tx) error {
		return setStatus(ctx, tx, sc, userID, c, false, now())
	}))
}

// setStatus applies a triage decision to a finding of the scope, with an
// event in its history; ErrNotFound when it does not exist or is outside the
// scope. With keepComment, an empty comment keeps the finding's own instead
// of erasing it.
func setStatus(ctx context.Context, q querier, sc Scope, userID int64, c StatusChange, keepComment bool, ts string) error {
	old, err := findingStatus(ctx, q, sc, c.ID)
	if err != nil {
		return err
	}
	if _, err := q.ExecContext(ctx, `
		UPDATE findings SET status = ?, justification = ?, auto_resolved = 0, dismissed_by = 0, updated_at = ?,
		       comment = CASE WHEN ? AND ? = '' THEN comment ELSE ? END
		WHERE id = ?`, c.Status, c.Justification, ts, keepComment, c.Comment, c.Comment, c.ID); err != nil {
		return err
	}
	return insertEvent(ctx, q, c.ID, userID, old, c.Status, c.Comment, ts)
}

// StatusChange is a triage decision for one finding.
type StatusChange struct {
	ID                             int64
	Status, Justification, Comment string
}

// SetFindingStatuses applies triage decisions to several findings of the
// scope, in order, in a single transaction, with an event in the history of
// each: the same decision for a selection of findings, or one per finding for
// a VEX import. An empty comment keeps the finding's own comment instead of
// erasing it. Unknown ids, and those outside the scope, are skipped: they come
// from a form or a file. It returns how many findings were updated.
func (s *Store) SetFindingStatuses(ctx context.Context, sc Scope, userID int64, changes []StatusChange) (int, error) {
	ts := now()
	done := 0
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		for _, c := range changes {
			err := setStatus(ctx, tx, sc, userID, c, true, ts)
			if errors.Is(err, ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			done++
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("set finding statuses: %w", err)
	}
	return done, nil
}

// ListFindingEvents returns the history of a finding of the scope, oldest first.
func (s *Store) ListFindingEvents(ctx context.Context, sc Scope, findingID int64) ([]FindingEvent, error) {
	query, args := findingEventsQuery(sc, findingID)
	return collect(ctx, s.q(ctx), "list finding events", func(row scanner) (FindingEvent, error) {
		var e FindingEvent
		var created string
		err := row.Scan(&e.Username, &e.OldStatus, &e.NewStatus, &e.Comment, &created)
		e.CreatedAt = parseTime(created)
		return e, err
	}, query, args...)
}

// findingEventsQuery reads the history of a finding of the scope, through
// the index finding_events_finding (TestHistoryQueriesUseIndexes).
func findingEventsQuery(sc Scope, findingID int64) (string, []any) {
	cond, args := sc.cond("a")
	// #nosec G202 -- cond is a fixed expression of Scope.cond; the values are parameters.
	return `
		SELECT COALESCE(u.username, ''), e.old_status, e.new_status, e.comment, e.created_at
		FROM finding_events e JOIN findings f ON f.id = e.finding_id JOIN assets a ON a.id = f.asset_id
		LEFT JOIN users u ON u.id = e.user_id
		WHERE e.finding_id = ? AND ` + cond + ` ORDER BY e.id`, append([]any{findingID}, args...)
}

// CountFindingsByStatus returns the number of findings of the scope per status.
func (s *Store) CountFindingsByStatus(ctx context.Context, sc Scope) (map[string]int, error) {
	cond, args := sc.cond("a")
	// #nosec G202 -- cond is a fixed expression of Scope.cond; the values are parameters.
	counts, err := collect(ctx, s.q(ctx), "count findings", scanCount, `SELECT f.status, COUNT(*) FROM findings f JOIN assets a ON a.id = f.asset_id
		WHERE `+shownExpr+` AND `+cond+` GROUP BY f.status`, args...)
	if err != nil {
		return nil, err
	}
	out := make(map[string]int, len(counts))
	for _, c := range counts {
		out[c.key] = c.n
	}
	return out, nil
}

// findingStatus returns the status of a finding of the scope, ErrNotFound when
// it does not exist or is outside the scope.
func findingStatus(ctx context.Context, q querier, sc Scope, id int64) (string, error) {
	cond, args := sc.cond("a")
	var status string
	err := q.QueryRowContext(ctx, `SELECT f.status FROM findings f JOIN assets a ON a.id = f.asset_id
		WHERE f.id = ? AND `+cond, append([]any{id}, args...)...).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return status, err
}

// insertEvent records a change of status in the history of a finding.
func insertEvent(ctx context.Context, q querier, findingID, userID int64, old, status, comment, ts string) error {
	_, err := q.ExecContext(ctx, `
		INSERT INTO finding_events (finding_id, user_id, old_status, new_status, comment, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`, findingID, nullID(userID), old, status, comment, ts)
	return err
}

// ListVulnCVEs returns, for every stored vulnerability, its CVE identifiers
// (its own id when it is a CVE, plus its CVE aliases).
func (s *Store) ListVulnCVEs(ctx context.Context) (map[string][]string, error) {
	pairs, err := collect(ctx, s.q(ctx), "list vulnerability CVEs", func(row scanner) ([2]string, error) {
		var p [2]string
		err := row.Scan(&p[0], &p[1])
		return p, err
	}, `
		SELECT id, id FROM vulnerabilities WHERE id LIKE 'CVE-%'
		UNION
		SELECT v.id, j.value FROM vulnerabilities v, json_each(v.aliases) j WHERE j.value LIKE 'CVE-%'`)
	if err != nil {
		return nil, err
	}
	out := map[string][]string{}
	for _, p := range pairs {
		out[p[0]] = append(out[p[0]], p[1])
	}
	return out, nil
}

// ExploitSignal is what CISA KEV and EPSS tell of a vulnerability.
type ExploitSignal struct {
	ID     string
	KEV    bool    // listed in CISA Known Exploited Vulnerabilities
	KEVDue string  // CISA remediation due date
	EPSS   float64 // exploitation probability, -1 when unknown
}

// SetExploitSignals stores the KEV and EPSS data of vulnerabilities in one
// transaction, and writes only those that changed: a synchronisation gives
// them for every stored vulnerability. It returns how many changed.
func (s *Store) SetExploitSignals(ctx context.Context, signals ...ExploitSignal) (int, error) {
	changed := 0
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		stmt, err := tx.PrepareContext(ctx, `UPDATE vulnerabilities SET kev = ?, kev_due = ?, epss = ?
			WHERE id = ? AND (kev <> ? OR kev_due <> ? OR epss <> ?)`)
		if err != nil {
			return err
		}
		defer stmt.Close()
		for _, sg := range signals {
			err := expectRow(stmt.ExecContext(ctx, sg.KEV, sg.KEVDue, sg.EPSS, sg.ID, sg.KEV, sg.KEVDue, sg.EPSS))
			if errors.Is(err, ErrNotFound) {
				continue // unchanged, or unknown
			}
			if err != nil {
				return fmt.Errorf("%s: %w", sg.ID, err)
			}
			changed++
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("set exploit signals: %w", err)
	}
	return changed, nil
}
