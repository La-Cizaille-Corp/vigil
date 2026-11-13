package tracking_test

import (
	"cmp"
	"context"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/digest"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
	"github.com/La-Cizaille-Corp/vigil/internal/tracking"
)

// urgencyCase is an edge case of the ranking of findings (A78).
type urgencyCase struct {
	id       string
	severity string
	cvss     float64
	kev      bool
	epss     float64
	status   string
	level    string
}

// urgencyCases are the edge cases, most urgent first.
var urgencyCases = []urgencyCase{
	// Judged exploitable: the same rank as a KEV entry, ahead of it here by its CVSS score.
	{id: "CVE-2026-0001", severity: "LOW", cvss: 3.1, epss: -1, status: "exploitable", level: tracking.LevelUrgent},
	{id: "CVE-2026-0002", severity: "LOW", cvss: 3, kev: true, epss: -1, level: tracking.LevelUrgent},
	// KEV without severity nor score: urgent all the same, last of its rank.
	{id: "CVE-2026-0003", cvss: -1, kev: true, epss: -1, level: tracking.LevelUrgent},
	// EPSS at the threshold: likely to be exploited, ahead of every severity.
	{id: "CVE-2026-0004", severity: "MEDIUM", cvss: 5, epss: store.LikelyEPSS, level: tracking.LevelUrgent},
	// Just below the threshold: ranked by its severity.
	{id: "CVE-2026-0005", severity: "CRITICAL", cvss: 9, epss: 0.0999, level: tracking.LevelPlan},
	// A CVSS score only: rated critical by it, ahead of a high one.
	{id: "CVE-2026-0006", cvss: 9.8, epss: -1, level: tracking.LevelPlan},
	{id: "CVE-2026-0007", severity: "HIGH", cvss: 8.8, epss: -1, level: tracking.LevelPlan},
	// A medium advisory scored 7.5: to plan, in the medium band.
	{id: "CVE-2026-0008", severity: "MEDIUM", cvss: 7.5, epss: -1, level: tracking.LevelPlan},
	{id: "CVE-2026-0009", severity: "MEDIUM", cvss: 5, epss: -1, level: tracking.LevelWatch},
	// A score of 0 rates nothing: unknown, ahead of no score at all.
	{id: "CVE-2026-0010", cvss: 0, epss: -1, level: tracking.LevelWatch},
	{id: "CVE-2026-0011", cvss: -1, epss: -1, level: tracking.LevelWatch},
}

func (c urgencyCase) finding() store.Finding {
	return store.Finding{VulnID: c.id, Severity: c.severity, CVSS: c.cvss, KEV: c.kev, EPSS: c.epss,
		Status: cmp.Or(c.status, "in_triage")}
}

func caseIDs() []string {
	var ids []string
	for _, c := range urgencyCases {
		ids = append(ids, c.id)
	}
	return ids
}

func vulnIDs(fs []store.Finding) []string {
	var ids []string
	for _, f := range fs {
		ids = append(ids, f.VulnID)
	}
	return ids
}

func TestComparePriority(t *testing.T) {
	var fs []store.Finding
	for _, c := range slices.Backward(urgencyCases) {
		fs = append(fs, c.finding())
	}
	tracking.SortByPriority(fs)
	if got := vulnIDs(fs); !slices.Equal(got, caseIDs()) {
		t.Errorf("order = %v\nwant    %v", got, caseIDs())
	}
	for i, a := range fs {
		for j, b := range fs {
			if got := tracking.ComparePriority(a, b); (i < j && got <= 0) || (i > j && got >= 0) || (i == j && got != 0) {
				t.Errorf("ComparePriority(%s, %s) = %d", a.VulnID, b.VulnID, got)
			}
		}
	}
	// Ties go to the most recent detection.
	old, recent := urgencyCases[6].finding(), urgencyCases[6].finding()
	old.FirstSeen, recent.FirstSeen = time.Now().Add(-time.Hour), time.Now()
	if tracking.ComparePriority(recent, old) <= 0 {
		t.Error("the most recent is not first on a tie")
	}
}

func TestBand(t *testing.T) {
	for _, c := range []struct {
		f    store.Finding
		want string
	}{
		{store.Finding{Severity: "HIGH", CVSS: 9.8}, "HIGH"}, // the advisory comes first
		{store.Finding{Severity: "high"}, "HIGH"},
		{store.Finding{CVSS: 9}, "CRITICAL"},
		{store.Finding{CVSS: 6.9}, "MEDIUM"},
		{store.Finding{CVSS: 0}, "UNKNOWN"},
		{store.Finding{CVSS: -1}, "UNKNOWN"},
		{store.Finding{Severity: "MODERATE", CVSS: 5}, "UNKNOWN"}, // translated by the sources, never stored
	} {
		if got := tracking.Band(c.f); got != c.want {
			t.Errorf("Band(%+v) = %s, want %s", c.f, got, c.want)
		}
	}
}

func TestTemplateFuncs(t *testing.T) {
	f := tracking.TemplateFuncs()
	if got := f["statusLabel"].(func(string) string)("exploitable"); got != "Exploitable – à traiter" {
		t.Errorf("statusLabel = %s", got)
	}
	if got := f["sevLabel"].(func(string) string)(""); got != "Inconnue" {
		t.Errorf("sevLabel = %s", got)
	}
	if got := f["band"].(func(store.Finding) string)(store.Finding{CVSS: 9.8}); got != "CRITICAL" {
		t.Errorf("band = %s", got)
	}
}

// The levels, the lists, the dashboard, the alerts and the digest rank the
// edge cases alike.
func TestUrgencyEverywhere(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	assetID, err := st.CreateAsset(ctx, store.Everything, store.Asset{Name: "appliance", Kind: "product", Criticality: "high", Source: "manual"})
	if err != nil {
		t.Fatal(err)
	}
	observe := func(id, severity string, cvss float64, kev bool, epss float64) {
		t.Helper()
		if err := st.UpsertVulnerability(ctx, store.Vulnerability{ID: id, Severity: severity, CVSS: cvss}); err != nil {
			t.Fatal(err)
		}
		if _, err := st.SetExploitSignals(ctx, store.ExploitSignal{ID: id, KEV: kev, EPSS: epss}); err != nil {
			t.Fatal(err)
		}
		if _, err := st.ObserveFinding(ctx, assetID, id, "", time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	status := map[string]string{}
	for _, c := range urgencyCases {
		observe(c.id, c.severity, c.cvss, c.kev, c.epss)
		status[c.id] = c.status
	}
	// Decided on: aside, or fixed, whatever their signals.
	decided := map[string]struct{ status, level string }{
		"CVE-2026-0097": {"false_positive", tracking.LevelAside},
		"CVE-2026-0098": {"not_affected", tracking.LevelAside},
		"CVE-2026-0099": {"resolved", ""},
	}
	for id, d := range decided {
		observe(id, "CRITICAL", 9.8, true, 0.9)
		status[id] = d.status
	}
	list, err := st.ListFindings(ctx, store.Everything, store.FindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range list {
		if s := status[f.VulnID]; s != "" {
			if err := st.SetFindingStatus(ctx, store.Everything, f.ID, 0, s, "", ""); err != nil {
				t.Fatal(err)
			}
		}
	}

	open, err := st.ListFindings(ctx, store.Everything, store.FindingFilter{Statuses: []string{"in_triage", "exploitable"}})
	if err != nil {
		t.Fatal(err)
	}
	tracking.SortByPriority(open)
	if got := vulnIDs(open); !slices.Equal(got, caseIDs()) {
		t.Errorf("open findings: %v\nwant           %v", got, caseIDs())
	}
	level := map[string]string{}
	var urgent []string
	for _, c := range urgencyCases {
		level[c.id] = c.level
		if c.level == tracking.LevelUrgent {
			urgent = append(urgent, c.id)
		}
	}
	for id, d := range decided {
		level[id] = d.level
	}
	all, err := st.ListFindings(ctx, store.Everything, store.FindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range all {
		if got := tracking.Level(f); got != level[f.VulnID] {
			t.Errorf("Level(%s, %s) = %q, want %q", f.VulnID, f.Status, got, level[f.VulnID])
		}
	}

	// Why each has its level, by the rule of the ranking: in a list row or an
	// alert, beside the band, and on its page (A84).
	explain := tracking.TemplateFuncs()["explain"].(func(store.Finding) string)
	notLikely := "elle n'est ni exploitée, ni probable, ni critique ou haute"
	why := map[string][2]string{
		"CVE-2026-0001": {"jugée exploitable", "l'équipe l'a jugée exploitable"},
		"CVE-2026-0002": {"exploitée (CISA KEV)", "elle est exploitée activement (CISA KEV)"},
		"CVE-2026-0003": {"exploitée (CISA KEV)", "elle est exploitée activement (CISA KEV)"},
		"CVE-2026-0004": {"EPSS 10,0\u00a0%", "la probabilité d'exploitation EPSS est de 10,0\u00a0% (seuil 10,0\u00a0%)"},
		"CVE-2026-0005": {"", "sa sévérité est critique"},
		"CVE-2026-0006": {"", "sa sévérité est critique"}, // rated by its score: the band says it
		"CVE-2026-0007": {"", "sa sévérité est haute"},
		"CVE-2026-0008": {"CVSS 7,5", "son score CVSS est de 7,5 (seuil 7)"},
		"CVE-2026-0009": {"", notLikely},
		"CVE-2026-0010": {"", notLikely},
		"CVE-2026-0011": {"", notLikely},
		// Set aside or fixed: the exploitation stays a fact, the level is the decision.
		"CVE-2026-0097": {"exploitée (CISA KEV)", "elle est marquée « Faux positif »"},
		"CVE-2026-0098": {"exploitée (CISA KEV)", "elle est marquée « Non affecté »"},
		"CVE-2026-0099": {"exploitée (CISA KEV)", ""},
	}
	for _, f := range all {
		if got := [2]string{tracking.Reason(f), explain(f)}; got != why[f.VulnID] {
			t.Errorf("%s: reason %q, explanation %q\nwant %q", f.VulnID, got[0], got[1], why[f.VulnID])
		}
	}

	// The level Urgentes of the list and the card of the dashboard.
	var urgentOpen []store.Finding
	for _, f := range open {
		if tracking.Level(f) == tracking.LevelUrgent {
			urgentOpen = append(urgentOpen, f)
		}
	}
	if got := vulnIDs(urgentOpen); !slices.Equal(got, urgent) {
		t.Errorf("level Urgentes: %v, want %v", got, urgent)
	}
	stats, err := st.DashboardStats(ctx, store.Everything, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if stats.Priority != len(urgent) {
		t.Errorf("dashboard: %d to treat first, want %d", stats.Priority, len(urgent))
	}
	// The alerts: the urgent ones at the priority class, the ones to plan
	// at the severe class.
	alerts, err := st.PendingAlerts(ctx, store.Everything)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range alerts {
		want := map[string]int{tracking.LevelUrgent: store.AlertPriority, tracking.LevelPlan: store.AlertSevere}[tracking.Level(a.Finding)]
		if a.Class != want || want == store.AlertNone {
			t.Errorf("alert %s at class %d, want %d", a.VulnID, a.Class, want)
		}
	}
	if want := len(urgent) + 4; len(alerts) != want { // 0005 to 0008 are to plan
		t.Errorf("%d alerts, want %d", len(alerts), want)
	}

	// The digest lists them in the same order: the urgent ones at its head,
	// then the other new ones (A87).
	d, err := digest.Generate(ctx, st, store.Everything, store.Group{})
	if err != nil {
		t.Fatal(err)
	}
	sectionOf := func(title string) string {
		s := d.Markdown[strings.Index(d.Markdown, title):]
		return s[:strings.Index(s, "\n## ")]
	}
	section := sectionOf("## Urgentes") + sectionOf("## Nouvelles vulnérabilités")
	var listed []string
	for _, m := range regexp.MustCompile(`CVE-2026-00(?:0\d|1\d)`).FindAllString(section, -1) {
		if !slices.Contains(listed, m) {
			listed = append(listed, m)
		}
	}
	if !slices.Equal(listed, caseIDs()) {
		t.Errorf("digest: %v\nwant    %v", listed, caseIDs())
	}
}
