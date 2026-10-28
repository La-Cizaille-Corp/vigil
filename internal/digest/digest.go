// Package digest builds the periodic summary of new and open vulnerabilities.
package digest

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	htmltemplate "html/template"
	"slices"
	"sort"
	"strconv"
	"strings"
	texttemplate "text/template"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/chattext"
	"github.com/La-Cizaille-Corp/vigil/internal/cti"
	"github.com/La-Cizaille-Corp/vigil/internal/cvss"
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
	"sev":    tracking.SeverityLabel,
	"band":   Band,
	"score": func(v float64) string {
		if v <= 0 {
			return ""
		}
		return strconv.FormatFloat(v, 'f', 1, 64)
	},
	"join":      strings.Join,
	"epss":      FormatEPSS,
	"countries": func(v []string) string { return labels(cti.Countries, v) },
	"sectors":   func(v []string) string { return labels(cti.Sectors, v) },
	"regs":      func(v []string) string { return labels(cti.Regulations, v) },
	// Untrusted text (sources, feeds, SBOMs) in the Markdown digest goes
	// through chattext, so that it cannot ping a channel or disguise a link.
	"md":   chattext.Text,
	"cell": chattext.Cell,
	"link": func(title, link string) string {
		if link == "" {
			return chattext.Text(title)
		}
		return "[" + strings.NewReplacer("[", "(", "]", ")").Replace(chattext.Text(title)) + "](" + chattext.URL(link) + ")"
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
	New         Breakdown // first seen in the period
	Open        Breakdown // still in triage or exploitable, all dates
	Counts      []Count
	CTI         []store.CTIItem // threat news matching the watched countries/sectors
	CTIScope    string          // human description of that filter
	Regulatory  []store.CTIItem // regulation and standards news
	RegScope    string
	Overdue     []store.Finding // open and past their remediation deadline
	Concerning  []store.CTIItem // news of the period citing an open finding's vulnerability
}

// maxCTIItems bounds the CTI section of a digest.
const maxCTIItems = 30

// Count is a number of findings for one status.
type Count struct {
	Status string
	N      int
}

// Bands are the severity ranges findings are counted in, most severe first;
// CRITICAL means a CVSS score of 9 or more, HIGH 7 to 8.9, MEDIUM 4 to 6.9
// and LOW below 4.
var Bands = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}

// Band returns the severity range of a finding: its advisory severity, or
// the rating of its CVSS score when the advisory gives none.
func Band(f store.Finding) string {
	s := strings.ToUpper(f.Severity)
	if s == "MODERATE" {
		s = "MEDIUM"
	}
	if s == "" {
		s = cvss.Severity(f.CVSS)
	}
	if severityRank(s) == 0 {
		return "UNKNOWN"
	}
	return s
}

// Breakdown is a set of findings by vendor, the most exposed vendor first.
type Breakdown struct {
	Total  Group // every finding, most severe first
	Groups []Group
}

// Group is the findings of one vendor, most severe first.
type Group struct {
	Vendor   string
	Bands    []int // number of findings in each of Bands
	KEV      int   // known exploited
	Findings []store.Finding
}

// Summary describes the bands of a group: "2 critiques, 1 haute".
func (g Group) Summary() string {
	var parts []string
	for i, n := range g.Bands {
		if n == 0 {
			continue
		}
		label := strings.ToLower(tracking.SeverityLabel(Bands[i]))
		if Bands[i] == "UNKNOWN" {
			label = "de sévérité " + label
		} else if n > 1 {
			label += "s"
		}
		parts = append(parts, strconv.Itoa(n)+" "+label)
	}
	switch {
	case g.KEV == 1:
		parts = append(parts, "dont 1 exploitée")
	case g.KEV > 1:
		parts = append(parts, fmt.Sprintf("dont %d exploitées", g.KEV))
	}
	return strings.Join(parts, ", ")
}

// unknownVendor files the findings of assets without CPE nor purl.
const unknownVendor = "Éditeur non renseigné"

// ByVendor groups findings by the vendor of their asset (see
// inventory.VendorName) and counts them by severity band.
func ByVendor(fs []store.Finding) Breakdown {
	b := Breakdown{Total: newGroup("Total")}
	index := map[string]int{}
	for _, f := range fs {
		vendor := inventory.VendorName(store.Asset{CPE: f.AssetCPE, PURL: f.AssetPURL})
		if vendor == "" {
			vendor = unknownVendor
		}
		i, ok := index[vendor]
		if !ok {
			i = len(b.Groups)
			index[vendor] = i
			b.Groups = append(b.Groups, newGroup(vendor))
		}
		b.Groups[i].add(f)
		b.Total.add(f)
	}
	SortBySeverity(b.Total.Findings)
	for _, g := range b.Groups {
		SortBySeverity(g.Findings)
	}
	sort.SliceStable(b.Groups, func(i, j int) bool {
		a, c := b.Groups[i], b.Groups[j]
		for k := range a.Bands {
			if a.Bands[k] != c.Bands[k] {
				return a.Bands[k] > c.Bands[k]
			}
		}
		return strings.ToLower(a.Vendor) < strings.ToLower(c.Vendor)
	})
	return b
}

// maxListed bounds the findings listed per vendor among open ones: a vendor
// subscription can hold thousands, the counts above them stay complete.
const maxListed = 25

// Listed returns the most severe findings of the group, at most maxListed.
func (g Group) Listed() []store.Finding { return g.Findings[:min(len(g.Findings), maxListed)] }

// Unlisted is the number of findings Listed leaves out.
func (g Group) Unlisted() int { return len(g.Findings) - len(g.Listed()) }

func newGroup(vendor string) Group { return Group{Vendor: vendor, Bands: make([]int, len(Bands))} }

func (g *Group) add(f store.Finding) {
	g.Findings = append(g.Findings, f)
	g.Bands[slices.Index(Bands, Band(f))]++
	if f.KEV {
		g.KEV++
	}
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
	news, err := st.ListFindings(ctx, store.FindingFilter{Since: since})
	if err != nil {
		return store.Digest{}, err
	}
	d.New = ByVendor(news)
	var open []store.Finding
	for _, status := range []string{"exploitable", "in_triage"} {
		fs, err := st.ListFindings(ctx, store.FindingFilter{Status: status})
		if err != nil {
			return store.Digest{}, err
		}
		open = append(open, fs...)
	}
	d.Open = ByVendor(open)
	counts, err := st.CountFindingsByStatus(ctx)
	if err != nil {
		return store.Digest{}, err
	}
	for _, s := range tracking.Statuses {
		d.Counts = append(d.Counts, Count{Status: s.Value, N: counts[s.Value]})
	}
	if d.Overdue, err = st.ListFindings(ctx, store.FindingFilter{Overdue: true}); err != nil {
		return store.Digest{}, err
	}
	SortBySeverity(d.Overdue)
	if d.Concerning, err = st.ListCTIItems(ctx, store.CTIFilter{Concerning: true, Since: since, Limit: maxCTIItems}); err != nil {
		return store.Digest{}, err
	}

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

// SortBySeverity orders findings by severity band, then known exploited
// (KEV) first, then CVSS and EPSS scores, newest first on ties.
func SortBySeverity(fs []store.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if ra, rb := severityRank(Band(a)), severityRank(Band(b)); ra != rb {
			return ra > rb
		}
		if a.KEV != b.KEV {
			return a.KEV
		}
		if a.CVSS != b.CVSS {
			return a.CVSS > b.CVSS
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
