package web

import (
	"cmp"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/La-Cizaille-Corp/vigil/internal/choice"
	"github.com/La-Cizaille-Corp/vigil/internal/inventory"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
	"github.com/La-Cizaille-Corp/vigil/internal/tracking"
	"github.com/La-Cizaille-Corp/vigil/internal/versions"
)

// column is a column of a list, sorted from its header unless compare is nil.
type column[T any] struct {
	key, label string
	compare    func(a, b T) int // ascending
	empty      func(T) bool     // rows without a value stay last, in both directions
	desc       bool             // sorted in descending order first: scores, dates
	num        bool             // a number, aligned to the right (class num)
}

// sortHeader is the title of a column in a template.
type sortHeader struct {
	Label string
	Href  string // sorts by this column, or the other way if it already does; "" when it cannot
	Order string // aria-sort value when the list is sorted by this column
	Class string // "no-sort" without Href, "num" over numbers
}

// headerClass is the class of the title of c, a link that sorts or not.
func headerClass[T any](c column[T], sorts bool) string {
	var classes []string
	if !sorts {
		classes = append(classes, "no-sort")
	}
	if c.num {
		classes = append(classes, "num")
	}
	return strings.Join(classes, " ")
}

// listOrder is the order of a list: key "" leaves it as it is.
type listOrder struct {
	key  string
	desc bool
}

// orderFrom reads the order asked for in a query string, fallback if it names
// no column of the list.
func orderFrom[T any](q url.Values, cols []column[T], fallback string) listOrder {
	c, ok := columnOf(cols, q.Get("sort"))
	if !ok {
		if c, ok = columnOf(cols, fallback); !ok {
			return listOrder{}
		}
	}
	desc := c.desc
	switch q.Get("dir") {
	case "asc":
		desc = false
	case "desc":
		desc = true
	}
	return listOrder{c.key, desc}
}

func columnOf[T any](cols []column[T], key string) (column[T], bool) {
	for _, c := range cols {
		if c.key != "" && c.key == key {
			return c, true
		}
	}
	return column[T]{}, false
}

// sortRows orders rows; rows that compare equal keep their order.
func sortRows[T any](rows []T, cols []column[T], o listOrder) {
	c, ok := columnOf(cols, o.key)
	if !ok {
		return
	}
	slices.SortStableFunc(rows, func(a, b T) int {
		if c.empty != nil {
			switch ea, eb := c.empty(a), c.empty(b); {
			case ea && eb:
				return 0
			case ea:
				return 1
			case eb:
				return -1
			}
		}
		if o.desc {
			return c.compare(b, a)
		}
		return c.compare(a, b)
	})
}

// sortHeaders returns the titles of the columns; each link keeps the filters
// of the query string.
func sortHeaders[T any](cols []column[T], path string, q url.Values, o listOrder) []sortHeader {
	out := make([]sortHeader, 0, len(cols))
	for _, c := range cols {
		h := sortHeader{Label: c.label, Class: headerClass(c, c.compare != nil)}
		if c.compare != nil {
			desc := c.desc
			if c.key == o.key {
				desc = !o.desc
				h.Order = "ascending"
				if o.desc {
					h.Order = "descending"
				}
			}
			link := without(q, "msg", "page") // a new order starts at its first page
			link.Set("sort", c.key)
			link.Set("dir", "asc")
			if desc {
				link.Set("dir", "desc")
			}
			h.Href = path + "?" + link.Encode()
		}
		out = append(out, h)
	}
	return out
}

// plainHeaders returns the titles of the columns of a list that is not sorted
// by its reader.
func plainHeaders[T any](cols []column[T]) []sortHeader {
	out := make([]sortHeader, 0, len(cols))
	for _, c := range cols {
		out = append(out, sortHeader{Label: c.label, Class: headerClass(c, false)})
	}
	return out
}

// textColumn sorts by a text, ignoring case.
func textColumn[T any](key, label string, get func(T) string) column[T] {
	return column[T]{key: key, label: label, empty: func(x T) bool { return get(x) == "" },
		compare: func(a, b T) int { return compareText(get(a), get(b)) }}
}

func compareText(a, b string) int {
	return strings.Compare(strings.ToLower(a), strings.ToLower(b))
}

// assetIdentifier is what the inventory shows in its Identifier column.
func assetIdentifier(a store.Asset) string {
	return cmp.Or(a.PURL, a.CPE, a.Ecosystem)
}

// assetRow is an asset of the inventory with its open findings, and how many
// of them are urgent (A86).
type assetRow struct {
	store.Asset
	Urgent, Open int
}

// assetColumnList are the columns of the inventory, as in assets.html.
var assetColumnList = []column[assetRow]{
	{key: "name", label: "Nom", compare: func(a, b assetRow) int {
		return cmp.Or(compareText(a.Name, b.Name), versions.Compare(a.Version, b.Version))
	}},
	textColumn("vendor", "Éditeur", func(a assetRow) string { return inventory.VendorName(a.Asset) }),
	{key: "version", label: "Version", empty: func(a assetRow) bool { return a.Version == "" },
		compare: func(a, b assetRow) int { return versions.Compare(a.Version, b.Version) }},
	{key: "urgent", label: "Urgentes", desc: true, num: true, compare: func(a, b assetRow) int { return cmp.Compare(a.Urgent, b.Urgent) }},
	{key: "open", label: "Ouvertes", desc: true, num: true, compare: func(a, b assetRow) int { return cmp.Compare(a.Open, b.Open) }},
	textColumn("kind", "Type", func(a assetRow) string { return choice.Label(inventory.Kinds, a.Kind) }),
	// "Identifiant" alone: the two counts above take the width its "(purl, CPE ou écosystème)" took at 1 280 px.
	textColumn("id", "Identifiant", func(a assetRow) string { return assetIdentifier(a.Asset) }),
	textColumn("project", "Projet", func(a assetRow) string { return a.Project }),
	{key: "criticality", label: "Criticité", desc: true, compare: func(a, b assetRow) int {
		return cmp.Compare(choice.Rank(inventory.Criticalities, a.Criticality), choice.Rank(inventory.Criticalities, b.Criticality))
	}},
	textColumn("owner", "Responsable", func(a assetRow) string { return a.Owner }),
	textColumn("tracking", "Détection", func(a assetRow) string { return trackingSource(a.Asset) }),
}

// findingColumnList are the columns of a vulnerability list, as in the
// findingTable template. The default order is the priority, most urgent first.
var findingColumnList = []column[store.Finding]{
	{key: "priority", label: "Priorité", desc: true, compare: tracking.ComparePriority},
	{key: "cvss", label: "CVSS", desc: true, num: true, empty: func(f store.Finding) bool { return f.CVSS < 0 },
		compare: func(a, b store.Finding) int { return cmp.Compare(a.CVSS, b.CVSS) }},
	{key: "epss", label: "EPSS", desc: true, num: true, empty: func(f store.Finding) bool { return f.EPSS < 0 },
		compare: func(a, b store.Finding) int { return cmp.Compare(a.EPSS, b.EPSS) }},
	{key: "vuln", label: "Vulnérabilité", // CVE-2024-999 before CVE-2024-1000
		compare: func(a, b store.Finding) int { return versions.Compare(a.VulnID, b.VulnID) }},
	{key: "asset", label: "Actif", compare: func(a, b store.Finding) int {
		return cmp.Or(compareText(a.AssetName, b.AssetName), versions.Compare(a.AssetVersion, b.AssetVersion))
	}},
	{key: "fixed", label: "Corrigée en", empty: func(f store.Finding) bool { return f.FixedIn == "" },
		compare: func(a, b store.Finding) int { return versions.Compare(a.FixedIn, b.FixedIn) }},
	{key: "status", label: "Statut", compare: func(a, b store.Finding) int {
		return cmp.Compare(choice.Rank(tracking.Statuses, a.Status), choice.Rank(tracking.Statuses, b.Status))
	}},
	{key: "recent", label: "Détectée le", desc: true,
		compare: func(a, b store.Finding) int { return a.FirstSeen.Compare(b.FirstSeen) }},
	{key: "due", label: "Échéance", empty: func(f store.Finding) bool { return f.Due.IsZero() || !f.Open() },
		compare: func(a, b store.Finding) int { return a.Due.Compare(b.Due) }},
	{label: "Résumé"},
}

// defaultFindingOrder is the column of a vulnerability list without a choice.
const defaultFindingOrder = "priority"

// levelLink is a tab of a list, with what it holds: a level of the
// vulnerability list, or a view of the watch (A87).
type levelLink struct {
	Level  string // the value of ?level=, or the name of the view
	Label  string
	Href   string
	N      int
	Active bool
}

// Levels of a vulnerability list beside tracking.Levels: the open ones (the
// first three levels, shown by default), the fixed ones, and all of them.
const (
	levelOpen  = "open"
	levelFixed = "fixed"
	levelAll   = "all"
)

// listLevel is the level a vulnerability list shows: the one asked for; else
// the open ones, or everything when statuses are filtered, so that a status
// asked for is shown.
func listLevel(q url.Values) string {
	switch l := q.Get("level"); {
	case l == levelOpen || l == levelFixed || l == levelAll || choice.Has(tracking.Levels, l):
		return l
	case len(q["status"]) > 0:
		return levelAll
	}
	return levelOpen
}

// levelNav are the links to the levels of a vulnerability list (A84): the open
// ones by default, then their three levels; apart, those set aside and the
// fixed ones; and, quietly, all of them. Ouvertes counts the sum of the three
// open levels, and the three groups sum up to all.
type levelNav struct {
	Open   []levelLink
	Closed []levelLink
	All    levelLink
}

// levelLinks returns the links to the levels of a list showing current; they
// keep its filters and its order.
func levelLinks(findings []store.Finding, q url.Values, current string) levelNav {
	counts := tracking.CountLevels(findings)
	counts[levelOpen] = counts[tracking.LevelUrgent] + counts[tracking.LevelPlan] + counts[tracking.LevelWatch]
	counts[levelFixed] = counts[""]
	link := func(level string) string {
		kept := without(q, "msg", "level", "page")
		if level != "" {
			kept.Set("level", level)
		}
		if len(kept) == 0 {
			return "/findings"
		}
		return "/findings?" + kept.Encode()
	}
	tab := func(level, label string, n int) levelLink {
		return levelLink{Level: level, Label: label, Href: link(level), N: n, Active: level == current}
	}
	nav := levelNav{Open: []levelLink{tab(levelOpen, "Ouvertes", counts[levelOpen])}, All: tab(levelAll, "Toutes", len(findings))}
	for _, l := range tracking.Levels {
		if l.Value == tracking.LevelAside {
			nav.Closed = append(nav.Closed, tab(l.Value, l.Label, counts[l.Value]))
			continue
		}
		nav.Open = append(nav.Open, tab(l.Value, l.Label, counts[l.Value]))
	}
	nav.Closed = append(nav.Closed, tab(levelFixed, "Corrigées", counts[levelFixed]))
	return nav
}

// keepLevel keeps the findings of a level (see listLevel); an unknown level
// keeps them all.
func keepLevel(findings []store.Finding, level string) []store.Finding {
	var keep func(store.Finding) bool
	switch {
	case level == levelOpen:
		keep = store.Finding.Open
	case level == levelFixed:
		keep = func(f store.Finding) bool { return f.Status == store.StatusResolved }
	case choice.Has(tracking.Levels, level):
		keep = func(f store.Finding) bool { return tracking.Level(f) == level }
	default:
		return findings
	}
	return slices.DeleteFunc(findings, func(f store.Finding) bool { return !keep(f) })
}

// pageSize is the number of rows of a page of a long list (A85).
const pageSize = 100

// pager tells which rows of a list a page shows, with the links to the
// others: the data of the "pager" template.
type pager struct {
	First, Last, Total int // rows shown, counted from 1, out of Total
	Page, Pages        int
	Prev, Next         string // links to the pages around, "" at the ends
}

// paginate cuts rows, already filtered and sorted on the whole list (A54), to
// the page asked by ?page= (from 1; a number out of range shows the nearest
// page, anything else the first). The links lead to path with the other
// parameters of q, the first page without ?page=.
func paginate[T any](rows []T, q url.Values, path string) ([]T, pager) {
	p := pager{Total: len(rows), Pages: max(1, (len(rows)+pageSize-1)/pageSize)}
	p.Page, _ = strconv.Atoi(q.Get("page"))
	p.Page = min(max(p.Page, 1), p.Pages)
	link := func(page int) string {
		kept := without(q, "msg", "page")
		if page > 1 {
			kept.Set("page", strconv.Itoa(page))
		}
		if len(kept) == 0 {
			return path
		}
		return path + "?" + kept.Encode()
	}
	if p.Page > 1 {
		p.Prev = link(p.Page - 1)
	}
	if p.Page < p.Pages {
		p.Next = link(p.Page + 1)
	}
	start := (p.Page - 1) * pageSize
	end := min(start+pageSize, len(rows))
	if start < end {
		p.First, p.Last = start+1, end
	}
	return rows[start:end], p
}
