// Package digest builds the periodic summary of new and open vulnerabilities.
package digest

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	htmltemplate "html/template"
	"maps"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	texttemplate "text/template"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/chattext"
	"github.com/La-Cizaille-Corp/vigil/internal/choice"
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

// data is what the templates render: the levels first, as the lists of the
// interface (A87), each list cut to maxListed lines.
type data struct {
	Group       string // the group covered, "" for the whole inventory
	GroupID     int64
	Since       time.Time
	GeneratedAt time.Time
	SinceDays   string          // the period in whole days, rounded up: the ?since= of its lists
	Urgent      listed          // open and urgent, all dates, most urgent first
	Levels      []levelRow      // the levels, then the fixed ones
	New         breakdown       // open, first seen in the period
	NewListed   listed          // the most urgent of New
	Open        breakdown       // open, all dates
	Overdue     listed          // open and past their remediation deadline
	CTI         []store.CTIItem // threat news matching the watched countries/sectors
	CTIScope    string          // human description of that filter
	Regulatory  []store.CTIItem // regulation and standards news
	RegScope    string
	Concerning  []store.CTIItem // news of the period citing an open finding's vulnerability
}

// maxCTIItems bounds the CTI section of a digest.
const maxCTIItems = 30

// maxListed bounds each list of findings of a digest, so that it stays a
// summary on a kernel of thousands of vulnerabilities; its counts stay
// complete, and the lines left out are counted with a link to their list.
const maxListed = 50

// listed is a list of findings cut to maxListed lines, most urgent first.
type listed struct {
	Lines []line
	Total int    // findings of the list, Lines included
	More  int    // findings left out of Lines
	Link  string // the whole list in the interface (data.List)
	Name  string // what that list is, "la liste des urgentes"
	Empty string // what to say of an empty list, "" for nothing
}

// with names the whole list of l: its link, what it is, and what to say when
// it is empty.
func (l listed) with(link, name, empty string) listed {
	l.Link, l.Name, l.Empty = link, name, empty
	return l
}

// line is a finding listed in a digest.
type line struct {
	store.Finding
	New     bool // first seen in the period
	ShowDue bool // its remediation deadline is what the list is about
}

// bound sorts findings by priority and cuts them to maxListed lines.
func bound(fs []store.Finding, since time.Time, showDue bool) listed {
	tracking.SortByPriority(fs)
	l := listed{Total: len(fs), More: max(0, len(fs)-maxListed)}
	for _, f := range fs[:min(len(fs), maxListed)] {
		l.Lines = append(l.Lines, line{Finding: f, New: !f.FirstSeen.Before(since), ShowDue: showDue})
	}
	return l
}

// levelRow is a level of the digest: how many findings reached it in the
// period, and how many are at it now.
type levelRow struct {
	Level, Label string
	New, Now     int
}

// fixedLevel is the value of the fixed findings in the list of the interface
// (?level=fixed), which have no level of their own.
const fixedLevel = "fixed"

// newLevels returns the rows of the levels, then of the fixed findings, from
// the findings of the period, the open ones and the counts by status.
func newLevels(news, open []store.Finding, statuses map[string]int) []levelRow {
	added, now := tracking.CountLevels(news), tracking.CountLevels(open)
	now[tracking.LevelAside] = statuses[store.StatusNotAffected] + statuses[store.StatusFalsePositive]
	now[""] = statuses[store.StatusResolved]
	var rows []levelRow
	for _, l := range tracking.Levels {
		rows = append(rows, levelRow{Level: l.Value, Label: l.Label, New: added[l.Value], Now: now[l.Value]})
	}
	return append(rows, levelRow{Level: fixedLevel, Label: "Corrigées", New: added[""], Now: now[""]})
}

// List is the address of the vulnerability list of what the digest covers,
// with the parameters given as key, value…: where its counts and the lines it
// leaves out lead, in the interface (A87).
func (d data) List(params ...string) string {
	q := url.Values{}
	for i := 0; i+1 < len(params); i += 2 {
		q.Set(params[i], params[i+1])
	}
	if d.GroupID != 0 {
		q.Set("group", strconv.FormatInt(d.GroupID, 10))
	}
	if len(q) == 0 {
		return "/findings"
	}
	return "/findings?" + q.Encode()
}

// breakdown counts findings by vendor, the most exposed vendor first.
type breakdown struct {
	Total  vendorGroup // every finding
	Groups []vendorGroup
}

// vendorGroup counts the findings of one vendor.
type vendorGroup struct {
	Vendor string
	N      int
	Urgent int   // at the level Urgentes
	Bands  []int // in each severity band of tracking.Severities
}

// unknownVendor files the findings of assets without CPE nor purl.
const unknownVendor = "Éditeur non renseigné"

// byVendor groups findings by the vendor of their asset (see
// inventory.VendorName) and counts them by severity band; the vendor with the
// most urgent ones comes first, then by bands.
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
	sort.SliceStable(b.Groups, func(i, j int) bool {
		a, c := b.Groups[i], b.Groups[j]
		if a.Urgent != c.Urgent {
			return a.Urgent > c.Urgent
		}
		for k := range a.Bands {
			if a.Bands[k] != c.Bands[k] {
				return a.Bands[k] > c.Bands[k]
			}
		}
		return strings.ToLower(a.Vendor) < strings.ToLower(c.Vendor)
	})
	return b
}

func newGroup(vendor string) vendorGroup {
	return vendorGroup{Vendor: vendor, Bands: make([]int, len(tracking.Severities))}
}

func (g *vendorGroup) add(f store.Finding) {
	g.N++
	g.Bands[choice.Rank(tracking.Severities, tracking.Band(f))]++
	if tracking.Level(f) == tracking.LevelUrgent {
		g.Urgent++
	}
}

// Generate builds and stores the digest of a group, or of the whole inventory
// for the zero Group (A68), covering findings first seen since its previous
// digest (or defaultWindow for the first one). The news of the watch are the
// same for every digest; the rest is that of the group, as sc sees it.
// SECURITY: sc is the scope of the caller (store.Everything for the system,
// that of the account for a page), narrowed to the group: a digest never
// covers more than its caller sees, whatever group it names (W6 of the 0.5.0
// review: the zero Group used to read store.Everything for anyone).
func Generate(ctx context.Context, st *store.Store, sc store.Scope, group store.Group) (store.Digest, error) {
	if group.ID != 0 {
		sc = sc.Only(group.ID)
	}
	last, err := st.LastDigestTime(ctx, group.ID)
	if err != nil {
		return store.Digest{}, err
	}
	now := time.Now().UTC()
	since := last
	if since.IsZero() {
		since = now.Add(-defaultWindow)
	}

	d := data{Since: since, GeneratedAt: now, Group: group.Name, GroupID: group.ID,
		SinceDays: strconv.Itoa(max(1, int((now.Sub(since)+24*time.Hour-1)/(24*time.Hour))))}
	news, err := st.ListFindings(ctx, sc, store.FindingFilter{Since: since, Now: now})
	if err != nil {
		return store.Digest{}, err
	}
	open, err := st.ListFindings(ctx, sc, store.FindingFilter{Statuses: []string{store.StatusExploitable, store.StatusInTriage}, Now: now})
	if err != nil {
		return store.Digest{}, err
	}
	statuses, err := st.CountFindingsByStatus(ctx, sc)
	if err != nil {
		return store.Digest{}, err
	}
	d.Levels = newLevels(news, open, statuses)
	newOpen := slices.DeleteFunc(slices.Clone(news), func(f store.Finding) bool { return !f.Open() })
	d.New, d.Open = byVendor(newOpen), byVendor(open)
	urgent := func(f store.Finding) bool { return tracking.Level(f) == tracking.LevelUrgent }
	d.Urgent = bound(slices.DeleteFunc(slices.Clone(open), func(f store.Finding) bool { return !urgent(f) }), since, false).
		with(d.List("level", tracking.LevelUrgent), "la liste des urgentes", "Aucune vulnérabilité urgente.")
	// The new ones beside the urgent ones, listed first.
	d.NewListed = bound(slices.DeleteFunc(slices.Clone(newOpen), urgent), since, false).
		with(d.List("since", d.SinceDays), "la liste des nouvelles", "")
	overdue, err := st.ListFindings(ctx, sc, store.FindingFilter{Overdue: true, Now: now})
	if err != nil {
		return store.Digest{}, err
	}
	d.Overdue = bound(overdue, since, true).with(d.List("overdue", "1"), "la liste des vulnérabilités hors délai", "")
	if d.Concerning, err = st.ListCTIItems(ctx, sc, store.CTIFilter{Concerning: true, Since: since, Limit: maxCTIItems}); err != nil {
		return store.Digest{}, err
	}

	filter, err := cti.WatchedFilter(ctx, st)
	if err != nil {
		return store.Digest{}, err
	}
	filter.Since, filter.Limit = since, maxCTIItems
	if d.CTI, err = st.ListCTIItems(ctx, sc, filter); err != nil {
		return store.Digest{}, err
	}
	d.CTIScope = describeScope(filter)

	regs, err := cti.WatchedRegulations(ctx, st)
	if err != nil {
		return store.Digest{}, err
	}
	regs.Since, regs.Limit = since, maxCTIItems
	if d.Regulatory, err = st.ListCTIItems(ctx, sc, regs); err != nil {
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
	dg := store.Digest{Since: since, CreatedAt: now, Markdown: md.String(), HTML: html.String(), Group: group.ID, GroupName: group.Name}
	if dg.ID, err = st.CreateDigest(ctx, dg); err != nil {
		return store.Digest{}, err
	}
	return dg, nil
}

// Run generates the periodic digests and hands each one to send: the digest
// of the whole inventory, then one for each group with an enabled channel
// receiving digests (A68), each covering the period since its own previous
// one. A failure to send does not stop the next digests; it is returned with
// the others.
func Run(ctx context.Context, st *store.Store, send func(store.Digest) error) ([]store.Digest, error) {
	hooks, err := st.ListWebhooks(ctx)
	if err != nil {
		return nil, err
	}
	targets := []store.Group{{}}
	for _, h := range hooks {
		if h.Group != 0 && h.ReceivesDigest(h.Group) &&
			!slices.ContainsFunc(targets, func(g store.Group) bool { return g.ID == h.Group }) {
			targets = append(targets, store.Group{ID: h.Group, Name: h.GroupName})
		}
	}
	var made []store.Digest
	var errs []error
	for _, g := range targets {
		d, err := Generate(ctx, st, store.Everything, g)
		if err != nil {
			return made, errors.Join(append(errs, err)...)
		}
		made = append(made, d)
		errs = append(errs, send(d))
	}
	return made, errors.Join(errs...)
}

func labels(tags []choice.Option, values []string) string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = choice.Label(tags, v)
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
