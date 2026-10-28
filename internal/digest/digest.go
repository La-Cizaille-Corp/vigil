// Package digest builds the periodic summary of new and open vulnerabilities.
package digest

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	htmltemplate "html/template"
	"sort"
	"strings"
	texttemplate "text/template"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/cti"
	"github.com/La-Cizaille-Corp/vigil/internal/inventory"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
	"github.com/La-Cizaille-Corp/vigil/internal/tracking"
)

//go:embed digest.md.tmpl
var mdSource string

//go:embed digest.html.tmpl
var htmlSource string

var funcs = map[string]any{
	"date":      func(t time.Time) string { return t.Local().Format("02/01/2006 15:04") },
	"status":    func(s string) string { return inventory.Label(tracking.Statuses, s) },
	"sev":       tracking.SeverityLabel,
	"join":      strings.Join,
	"epss":      FormatEPSS,
	"countries": func(v []string) string { return labels(cti.Countries, v) },
	"sectors":   func(v []string) string { return labels(cti.Sectors, v) },
	"regs":      func(v []string) string { return labels(cti.Regulations, v) },
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
	CTI         []store.CTIItem // threat news matching the watched countries/sectors
	CTIScope    string          // human description of that filter
	Regulatory  []store.CTIItem // regulation and standards news
	RegScope    string
}

// maxCTIItems bounds the CTI section of a digest.
const maxCTIItems = 30

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
	SortByPriority(d.New)
	SortByPriority(d.Open)

	filter, err := cti.WatchedFilter(ctx, st)
	if err != nil {
		return store.Digest{}, err
	}
	filter.Since, filter.Limit = since, maxCTIItems
	if d.CTI, err = st.ListCTIItems(ctx, filter); err != nil {
		return store.Digest{}, err
	}
	d.CTIScope = describeScope(filter)

	regs, err := cti.WatchedRegulations(ctx, st)
	if err != nil {
		return store.Digest{}, err
	}
	regs.Since, regs.Limit = since, maxCTIItems
	if d.Regulatory, err = st.ListCTIItems(ctx, regs); err != nil {
		return store.Digest{}, err
	}
	d.RegScope = "toutes les réglementations et normes"
	if len(regs.Regulations) > 0 {
		d.RegScope = labels(cti.Regulations, regs.Regulations)
	}

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

// SortByPriority orders findings by exploitation risk: known exploited (KEV)
// first, then likely exploited (EPSS >= 10 %), then severity, then EPSS score,
// newest first on ties.
func SortByPriority(fs []store.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.KEV != b.KEV {
			return a.KEV
		}
		if la, lb := a.EPSS >= likelyEPSS, b.EPSS >= likelyEPSS; la != lb {
			return la
		}
		if ra, rb := severityRank(a.Severity), severityRank(b.Severity); ra != rb {
			return ra > rb
		}
		if a.EPSS != b.EPSS {
			return a.EPSS > b.EPSS
		}
		return a.FirstSeen.After(b.FirstSeen)
	})
}

// likelyEPSS is the probability above which exploitation is considered likely.
const likelyEPSS = 0.1

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

// FormatEPSS renders an EPSS probability as a percentage, or "" when unknown.
func FormatEPSS(p float64) string {
	if p < 0 {
		return ""
	}
	return fmt.Sprintf("%.1f %%", p*100)
}

func labels(tags []cti.Tag, values []string) string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = cti.Label(tags, v)
	}
	return strings.Join(out, ", ")
}

func describeScope(f store.CTIFilter) string {
	var parts []string
	if len(f.Countries) > 0 {
		parts = append(parts, "pays : "+labels(cti.Countries, f.Countries))
	}
	if len(f.Sectors) > 0 {
		parts = append(parts, "secteurs : "+labels(cti.Sectors, f.Sectors))
	}
	if len(parts) == 0 {
		return "tous pays et secteurs"
	}
	return strings.Join(parts, " ; ")
}
