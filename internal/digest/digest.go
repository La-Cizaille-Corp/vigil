// Package digest builds the periodic summary of new and open vulnerabilities.
package digest

import (
	"bytes"
	"context"
	_ "embed"
	htmltemplate "html/template"
	"sort"
	"strings"
	texttemplate "text/template"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/inventory"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
	"github.com/La-Cizaille-Corp/vigil/internal/tracking"
)

//go:embed digest.md.tmpl
var mdSource string

//go:embed digest.html.tmpl
var htmlSource string

var funcs = map[string]any{
	"date":   func(t time.Time) string { return t.Local().Format("02/01/2006 15:04") },
	"status": func(s string) string { return inventory.Label(tracking.Statuses, s) },
	"join":   strings.Join,
	// cell makes a value safe inside a Markdown table cell.
	"cell": func(s string) string {
		return strings.NewReplacer("|", `\|`, "\r", " ", "\n", " ").Replace(s)
	},
}

var (
	mdTmpl   = texttemplate.Must(texttemplate.New("md").Funcs(funcs).Parse(mdSource))
	htmlTmpl = htmltemplate.Must(htmltemplate.New("html").Funcs(funcs).Parse(htmlSource))
)

// DefaultWindow is used for the first digest, when no previous one exists.
const DefaultWindow = 7 * 24 * time.Hour

// Data is what the templates render.
type Data struct {
	Since       time.Time
	GeneratedAt time.Time
	New         []store.Finding
	Open        []store.Finding // still in triage or exploitable, all dates
	Counts      []Count
}

// Count is a number of findings for one status.
type Count struct {
	Status string
	N      int
}

// Generate builds and stores a digest covering findings first seen since the
// previous digest (or DefaultWindow for the first one).
func Generate(ctx context.Context, st *store.Store) (store.Digest, error) {
	last, err := st.LastDigestTime(ctx)
	if err != nil {
		return store.Digest{}, err
	}
	now := time.Now().UTC()
	since := last
	if since.IsZero() {
		since = now.Add(-DefaultWindow)
	}

	d := Data{Since: since, GeneratedAt: now}
	if d.New, err = st.ListFindings(ctx, store.FindingFilter{Since: since}); err != nil {
		return store.Digest{}, err
	}
	for _, status := range []string{"exploitable", "in_triage"} {
		open, err := st.ListFindings(ctx, store.FindingFilter{Status: status})
		if err != nil {
			return store.Digest{}, err
		}
		d.Open = append(d.Open, open...)
	}
	counts, err := st.CountFindingsByStatus(ctx)
	if err != nil {
		return store.Digest{}, err
	}
	for _, s := range tracking.Statuses {
		d.Counts = append(d.Counts, Count{Status: s.Value, N: counts[s.Value]})
	}
	SortBySeverity(d.New)
	SortBySeverity(d.Open)

	var md, html bytes.Buffer
	if err := mdTmpl.Execute(&md, d); err != nil {
		return store.Digest{}, err
	}
	if err := htmlTmpl.Execute(&html, d); err != nil {
		return store.Digest{}, err
	}
	dg := store.Digest{Since: since, CreatedAt: now, Markdown: md.String(), HTML: html.String()}
	if dg.ID, err = st.CreateDigest(ctx, dg); err != nil {
		return store.Digest{}, err
	}
	return dg, nil
}

// SortBySeverity orders findings from most to least severe, newest first on ties.
func SortBySeverity(fs []store.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		ri, rj := severityRank(fs[i].Severity), severityRank(fs[j].Severity)
		if ri != rj {
			return ri > rj
		}
		return fs[i].FirstSeen.After(fs[j].FirstSeen)
	})
}

func severityRank(s string) int {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM", "MODERATE":
		return 2
	case "LOW":
		return 1
	}
	return 0
}
