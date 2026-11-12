// Package digest builds the periodic summary of new and open vulnerabilities.
package digest

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	htmltemplate "html/template"
	"maps"
	"slices"
	"sort"
	"strconv"
	"strings"
	texttemplate "text/template"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/chattext"
	"github.com/La-Cizaille-Corp/vigil/internal/cti"
	"github.com/La-Cizaille-Corp/vigil/internal/fr"
	"github.com/La-Cizaille-Corp/vigil/internal/inventory"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
	"github.com/La-Cizaille-Corp/vigil/internal/tracking"
)

//go:embed digest.md.tmpl
var mdSource string

//go:embed digest.html.tmpl
var htmlSource string

// funcs are the template functions shared with the web pages (fr.Funcs,
// tracking.TemplateFuncs), and those of the digest.
var funcs = func() map[string]any {
	f := fr.Funcs()
	maps.Copy(f, tracking.TemplateFuncs())
	maps.Copy(f, map[string]any{
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
	})
	return f
}()

var (
	mdTmpl   = texttemplate.Must(texttemplate.New("md").Funcs(funcs).Parse(mdSource))
	htmlTmpl = htmltemplate.Must(htmltemplate.New("html").Funcs(funcs).Parse(htmlSource))
)

// defaultWindow is used for the first digest, when no previous one exists.
const defaultWindow = 7 * 24 * time.Hour

// data is what the templates render.
type data struct {
	Since       time.Time
	GeneratedAt time.Time
	New         breakdown // first seen in the period
	Open        breakdown // still in triage or exploitable, all dates
	Counts      []statusCount
	CTI         []store.CTIItem // threat news matching the watched countries/sectors
	CTIScope    string          // human description of that filter
	Regulatory  []store.CTIItem // regulation and standards news
	RegScope    string
	Overdue     []store.Finding // open and past their remediation deadline
	Concerning  []store.CTIItem // news of the period citing an open finding's vulnerability
}

// maxCTIItems bounds the CTI section of a digest.
const maxCTIItems = 30

// statusCount is a number of findings for one status.
type statusCount struct {
	Status string
	N      int
}

// breakdown is a set of findings by vendor, the most exposed vendor first.
type breakdown struct {
	Total  vendorGroup // every finding, most urgent first
	Groups []vendorGroup
}

// vendorGroup is the findings of one vendor, most urgent first (see
// tracking.ComparePriority).
type vendorGroup struct {
	Vendor   string
	Bands    []int // number of findings in each severity band of tracking.Severities
	KEV      int   // known exploited
	Findings []store.Finding
}

// Summary describes the bands of a group: "2 critiques, 1 haute".
func (g vendorGroup) Summary() string {
	var parts []string
	for i, n := range g.Bands {
		if n == 0 {
			continue
		}
		band := tracking.Severities[i]
		label := strings.ToLower(band.Label)
		if band.Value == "UNKNOWN" {
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

// byVendor groups findings by the vendor of their asset (see
// inventory.VendorName) and counts them by severity band.
func byVendor(fs []store.Finding) breakdown {
	b := breakdown{Total: newGroup("Total")}
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
	tracking.SortByPriority(b.Total.Findings)
	for _, g := range b.Groups {
		tracking.SortByPriority(g.Findings)
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

// Listed returns the most urgent findings of the group, at most maxListed.
func (g vendorGroup) Listed() []store.Finding { return g.Findings[:min(len(g.Findings), maxListed)] }

// Unlisted is the number of findings Listed leaves out.
func (g vendorGroup) Unlisted() int { return len(g.Findings) - len(g.Listed()) }

func newGroup(vendor string) vendorGroup {
	return vendorGroup{Vendor: vendor, Bands: make([]int, len(tracking.Severities))}
}

func (g *vendorGroup) add(f store.Finding) {
	g.Findings = append(g.Findings, f)
	band := tracking.Band(f)
	g.Bands[slices.IndexFunc(tracking.Severities, func(o inventory.Option) bool { return o.Value == band })]++
	if f.KEV {
		g.KEV++
	}
}

// Generate builds and stores a digest covering findings first seen since the
// previous digest (or defaultWindow for the first one).
func Generate(ctx context.Context, st *store.Store) (store.Digest, error) {
	last, err := st.LastDigestTime(ctx)
	if err != nil {
		return store.Digest{}, err
	}
	now := time.Now().UTC()
	since := last
	if since.IsZero() {
		since = now.Add(-defaultWindow)
	}

	d := data{Since: since, GeneratedAt: now}
	news, err := st.ListFindings(ctx, store.Everything, store.FindingFilter{Since: since})
	if err != nil {
		return store.Digest{}, err
	}
	d.New = byVendor(news)
	var open []store.Finding
	for _, status := range []string{"exploitable", "in_triage"} {
		fs, err := st.ListFindings(ctx, store.Everything, store.FindingFilter{Status: status})
		if err != nil {
			return store.Digest{}, err
		}
		open = append(open, fs...)
	}
	d.Open = byVendor(open)
	counts, err := st.CountFindingsByStatus(ctx, store.Everything)
	if err != nil {
		return store.Digest{}, err
	}
	for _, s := range tracking.Statuses {
		d.Counts = append(d.Counts, statusCount{Status: s.Value, N: counts[s.Value]})
	}
	if d.Overdue, err = st.ListFindings(ctx, store.Everything, store.FindingFilter{Overdue: true}); err != nil {
		return store.Digest{}, err
	}
	tracking.SortByPriority(d.Overdue)
	if d.Concerning, err = st.ListCTIItems(ctx, store.Everything, store.CTIFilter{Concerning: true, Since: since, Limit: maxCTIItems}); err != nil {
		return store.Digest{}, err
	}

	filter, err := cti.WatchedFilter(ctx, st)
	if err != nil {
		return store.Digest{}, err
	}
	filter.Since, filter.Limit = since, maxCTIItems
	if d.CTI, err = st.ListCTIItems(ctx, store.Everything, filter); err != nil {
		return store.Digest{}, err
	}
	d.CTIScope = describeScope(filter)

	regs, err := cti.WatchedRegulations(ctx, st)
	if err != nil {
		return store.Digest{}, err
	}
	regs.Since, regs.Limit = since, maxCTIItems
	if d.Regulatory, err = st.ListCTIItems(ctx, store.Everything, regs); err != nil {
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
