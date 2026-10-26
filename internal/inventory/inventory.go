// Package inventory validates and normalises tracked assets.
package inventory

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/La-Cizaille-Corp/vigil/internal/store"
)

// Kinds of asset, with their French labels for the UI.
var Kinds = []Option{
	{"package", "Paquet / dépendance"},
	{"technology", "Technologie"},
	{"product", "Produit"},
	{"os", "Système d'exploitation"},
}

// Criticalities of an asset for the organisation.
var Criticalities = []Option{
	{"low", "Faible"},
	{"medium", "Moyenne"},
	{"high", "Haute"},
	{"critical", "Critique"},
}

// Ecosystems supported by OSV.dev (subset, the most common ones).
var Ecosystems = []string{
	"npm", "PyPI", "Go", "Maven", "NuGet", "crates.io", "RubyGems", "Packagist",
	"Pub", "Hex", "Debian", "Ubuntu", "Alpine", "Rocky Linux", "AlmaLinux", "Red Hat",
}

// Option is a value with a display label.
type Option struct {
	Value string
	Label string
}

// Normalize trims fields and applies defaults.
func Normalize(a *store.Asset) {
	for _, f := range []*string{&a.Name, &a.Kind, &a.Ecosystem, &a.Version, &a.PURL, &a.CPE, &a.Criticality, &a.Owner, &a.Notes, &a.Project} {
		*f = strings.TrimSpace(*f)
	}
	if a.Version == "" {
		a.Version = purlVersion(a.PURL)
	}
	if a.Criticality == "" {
		a.Criticality = "medium"
	}
	if a.Source == "" {
		a.Source = "manual"
	}
}

// Validate checks an asset before it is stored.
func Validate(a store.Asset) error {
	var errs []error
	check := func(cond bool, msg string) {
		if !cond {
			errs = append(errs, errors.New(msg))
		}
	}
	check(a.Name != "", "le nom est obligatoire")
	check(maxLen(a.Name, 200) && maxLen(a.Version, 100) && maxLen(a.Owner, 200) && maxLen(a.Project, 200) &&
		maxLen(a.PURL, 500) && maxLen(a.CPE, 500) && maxLen(a.Notes, 4000), "un champ dépasse la longueur maximale")
	check(isOption(Kinds, a.Kind), "type d'actif invalide")
	check(isOption(Criticalities, a.Criticality), "criticité invalide")
	check(a.Ecosystem == "" || contains(Ecosystems, a.Ecosystem), "écosystème non supporté")
	check(a.PURL == "" || strings.HasPrefix(a.PURL, "pkg:"), "un purl doit commencer par « pkg: »")
	check(a.CPE == "" || strings.HasPrefix(a.CPE, "cpe:2.3:"), "un CPE doit commencer par « cpe:2.3: »")
	return errors.Join(errs...)
}

// Queryable reports whether an asset can be checked against OSV, i.e. it is
// identified by a purl or an ecosystem and name, and has a known version.
// Without a version OSV would return every advisory ever published.
func Queryable(a store.Asset) bool {
	if a.PURL != "" {
		return a.Version != "" || strings.Contains(a.PURL, "@")
	}
	return a.Ecosystem != "" && a.Version != ""
}

// Label returns the label of value in opts, or value itself.
func Label(opts []Option, value string) string {
	for _, o := range opts {
		if o.Value == value {
			return o.Label
		}
	}
	return value
}

// purlVersion extracts the version of a purl ("pkg:npm/lodash@4.17.15?x=y" → "4.17.15").
func purlVersion(purl string) string {
	i := strings.LastIndex(purl, "@")
	if i < 0 {
		return ""
	}
	v := purl[i+1:]
	if j := strings.IndexAny(v, "?#"); j >= 0 {
		v = v[:j]
	}
	return v
}

func maxLen(s string, n int) bool { return utf8.RuneCountInString(s) <= n }

func isOption(opts []Option, v string) bool {
	for _, o := range opts {
		if o.Value == v {
			return true
		}
	}
	return false
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// Describe returns a short human identifier, e.g. "lodash 4.17.15".
func Describe(a store.Asset) string {
	if a.Version == "" {
		return a.Name
	}
	return fmt.Sprintf("%s %s", a.Name, a.Version)
}
