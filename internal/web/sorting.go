package web

import (
	"cmp"
	"net/url"
	"slices"
	"strings"

	"github.com/La-Cizaille-Corp/vigil/internal/digest"
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
}

// sortHeader is the title of a column in a template.
type sortHeader struct {
	Label string
	Href  string // sorts by this column, or the other way if it already does; "" when it cannot
	Order string // aria-sort value when the list is sorted by this column
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
		h := sortHeader{Label: c.label}
		if c.compare != nil {
			desc := c.desc
			if c.key == o.key {
				desc = !o.desc
				h.Order = "ascending"
				if o.desc {
					h.Order = "descending"
				}
			}
			link := url.Values{}
			for k, v := range q {
				if k != "msg" {
					link[k] = v
				}
			}
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
		out = append(out, sortHeader{Label: c.label})
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

// optionRank is the position of a value in a list of options: statuses and
// criticalities sort in their own order, not alphabetically.
func optionRank(opts []inventory.Option, value string) int {
	return slices.IndexFunc(opts, func(o inventory.Option) bool { return o.Value == value })
}

// assetIdentifier is what the inventory shows in its Identifier column.
func assetIdentifier(a store.Asset) string {
	return cmp.Or(a.PURL, a.CPE, a.Ecosystem)
}

// assetColumnList are the columns of the inventory, as in assets.html.
var assetColumnList = []column[store.Asset]{
	{key: "name", label: "Nom", compare: func(a, b store.Asset) int {
		return cmp.Or(compareText(a.Name, b.Name), versions.Compare(a.Version, b.Version))
	}},
	textColumn("vendor", "Éditeur", inventory.VendorName),
	{key: "version", label: "Version", empty: func(a store.Asset) bool { return a.Version == "" },
		compare: func(a, b store.Asset) int { return versions.Compare(a.Version, b.Version) }},
	textColumn("kind", "Type", func(a store.Asset) string { return inventory.Label(inventory.Kinds, a.Kind) }),
	textColumn("id", "Identifiant (purl, CPE ou écosystème)", assetIdentifier),
	textColumn("project", "Projet", func(a store.Asset) string { return a.Project }),
	{key: "criticality", label: "Criticité", desc: true, compare: func(a, b store.Asset) int {
		return cmp.Compare(optionRank(inventory.Criticalities, a.Criticality), optionRank(inventory.Criticalities, b.Criticality))
	}},
	textColumn("owner", "Responsable", func(a store.Asset) string { return a.Owner }),
	textColumn("tracking", "Détection", trackingSource),
}

// isOpen reports whether a finding is still to triage or to fix.
func isOpen(f store.Finding) bool { return f.Status == "in_triage" || f.Status == "exploitable" }

// findingColumnList are the columns of a vulnerability list, as in the
// findingTable template. The default order is the priority, most urgent first.
var findingColumnList = []column[store.Finding]{
	{key: "priority", label: "Priorité", desc: true, compare: func(a, b store.Finding) int {
		switch {
		case digest.MoreUrgent(a, b):
			return 1
		case digest.MoreUrgent(b, a):
			return -1
		}
		return 0
	}},
	{key: "cvss", label: "CVSS", desc: true, empty: func(f store.Finding) bool { return f.CVSS < 0 },
		compare: func(a, b store.Finding) int { return cmp.Compare(a.CVSS, b.CVSS) }},
	{key: "epss", label: "EPSS", desc: true, empty: func(f store.Finding) bool { return f.EPSS < 0 },
		compare: func(a, b store.Finding) int { return cmp.Compare(a.EPSS, b.EPSS) }},
	{key: "vuln", label: "Vulnérabilité", // CVE-2024-999 before CVE-2024-1000
		compare: func(a, b store.Finding) int { return versions.Compare(a.VulnID, b.VulnID) }},
	{key: "asset", label: "Actif", compare: func(a, b store.Finding) int {
		return cmp.Or(compareText(a.AssetName, b.AssetName), versions.Compare(a.AssetVersion, b.AssetVersion))
	}},
	{key: "status", label: "Statut", compare: func(a, b store.Finding) int {
		return cmp.Compare(optionRank(tracking.Statuses, a.Status), optionRank(tracking.Statuses, b.Status))
	}},
	{key: "recent", label: "Détectée le", desc: true,
		compare: func(a, b store.Finding) int { return a.FirstSeen.Compare(b.FirstSeen) }},
	{key: "due", label: "Échéance", empty: func(f store.Finding) bool { return f.Due.IsZero() || !isOpen(f) },
		compare: func(a, b store.Finding) int { return a.Due.Compare(b.Due) }},
	{label: "Résumé"},
}

// defaultFindingOrder is the column of a vulnerability list without a choice.
const defaultFindingOrder = "priority"

// levelLink is a level of the vulnerability list, with what it holds.
type levelLink struct {
	Label  string
	Href   string
	N      int
	Active bool
}

// levelLinks returns the links to the levels of a list and to the whole of it;
// they keep its filters and its order.
func levelLinks(findings []store.Finding, q url.Values) []levelLink {
	counts := map[string]int{}
	for _, f := range findings {
		counts[digest.Level(f)]++
	}
	current := q.Get("level")
	if !isLevel(current) {
		current = ""
	}
	link := func(level string) string {
		kept := url.Values{}
		for k, v := range q {
			if k != "msg" && k != "level" {
				kept[k] = v
			}
		}
		if level != "" {
			kept.Set("level", level)
		}
		if len(kept) == 0 {
			return "/findings"
		}
		return "/findings?" + kept.Encode()
	}
	out := make([]levelLink, 0, len(digest.Levels)+1)
	for _, l := range digest.Levels {
		out = append(out, levelLink{Label: l.Label, Href: link(l.Value), N: counts[l.Value], Active: l.Value == current})
	}
	return append(out, levelLink{Label: "Toutes", Href: link(""), N: len(findings), Active: current == ""})
}

func isLevel(v string) bool {
	return slices.ContainsFunc(digest.Levels, func(o inventory.Option) bool { return o.Value == v })
}

// keepLevel keeps the findings of a level; an unknown level keeps them all.
func keepLevel(findings []store.Finding, level string) []store.Finding {
	if !isLevel(level) {
		return findings
	}
	return slices.DeleteFunc(findings, func(f store.Finding) bool { return digest.Level(f) != level })
}
