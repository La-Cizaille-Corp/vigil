// Package inventory validates and normalises tracked assets.
package inventory

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/choice"
	"github.com/La-Cizaille-Corp/vigil/internal/clip"
	"github.com/La-Cizaille-Corp/vigil/internal/sources/nvd"
	"github.com/La-Cizaille-Corp/vigil/internal/sources/osv"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
)

// Kinds of asset, with their French labels for the UI.
var Kinds = []choice.Option{
	{Value: "package", Label: "Paquet / dépendance"},
	{Value: "technology", Label: "Technologie"},
	{Value: "product", Label: "Produit"},
	{Value: "os", Label: "Système d'exploitation"},
}

// Criticalities of an asset for the organisation.
var Criticalities = []choice.Option{
	{Value: "low", Label: "Faible"},
	{Value: "medium", Label: "Moyenne"},
	{Value: "high", Label: "Haute"},
	{Value: "critical", Label: "Critique"},
}

// Ecosystems supported by OSV.dev (subset, the most common ones).
var Ecosystems = []string{
	"npm", "PyPI", "Go", "Maven", "NuGet", "crates.io", "RubyGems", "Packagist", "Pub", "Hex",
	"Debian:11", "Debian:12", "Debian:13", "Debian:14", "Debian",
	"Ubuntu:20.04:LTS", "Ubuntu:22.04:LTS", "Ubuntu:24.04:LTS", "Ubuntu:26.04:LTS", "Ubuntu",
	"Alpine:v3.20", "Alpine:v3.21", "Alpine:v3.22", "Alpine:v3.23", "Alpine",
	"Rocky Linux:8", "Rocky Linux:9", "Rocky Linux:10", "Rocky Linux",
	"AlmaLinux:8", "AlmaLinux:9", "AlmaLinux:10", "AlmaLinux", "Red Hat", "Linux",
}

// CPEModes are the versions of a CPE-only asset tracked in the NVD. With
// mode "" a CPE without version ("*") tracks every version.
var CPEModes = []choice.Option{
	{Value: "", Label: "Version de l'actif (CPE ou champ Version)"},
	{Value: "all", Label: "Toutes les versions du produit"},
	{Value: "from", Label: "Versions à partir de…"},
}

// Latest is the version of an asset kept up to date on its latest release:
// only the vulnerabilities without a released fix concern it, and they are
// marked fixed once the fix is out.
const Latest = "latest"

// IsLatest reports whether an asset is kept at its latest release.
func IsLatest(a store.Asset) bool { return a.Version == Latest }

// DefaultWindow is how far back a new asset is checked: vulnerabilities
// published earlier are not reported unless exploited (KEV).
const DefaultWindow = 120 * 24 * time.Hour

const dateLayout = "2006-01-02"

// DefaultSince is the start of the tracked period of an asset added at t.
func DefaultSince(t time.Time) string { return t.Add(-DefaultWindow).Format(dateLayout) }

// SinceTime is the start of the tracked period of a, zero for the whole history.
func SinceTime(a store.Asset) time.Time {
	t, _ := time.Parse(dateLayout, a.TrackSince)
	return t
}

// Normalize trims fields and applies defaults.
func Normalize(a *store.Asset) {
	for _, f := range []*string{&a.Name, &a.Kind, &a.Ecosystem, &a.Version, &a.PURL, &a.CPE, &a.CPEMode, &a.CPEFrom, &a.TrackSince, &a.Criticality, &a.Owner, &a.Notes, &a.Project} {
		*f = strings.TrimSpace(*f)
	}
	if a.Version == "" {
		a.Version = osv.PURLVersion(a.PURL)
	}
	if strings.EqualFold(a.Version, Latest) {
		a.Version = Latest
	}
	if a.Criticality == "" {
		a.Criticality = "medium"
	}
	if a.Source == "" {
		a.Source = "manual"
	}
	a.Tags = NormalizeTags(a.Tags)
}

// FollowPURL brings the Version field along when an edit of an asset changes
// the version written in its purl and leaves the field as it was: the field
// overrides the purl (see osv.PURLQuery), so that edit would have no effect.
func FollowPURL(a *store.Asset, old store.Asset) {
	version := osv.PURLVersion(a.PURL)
	if version != "" && version != osv.PURLVersion(old.PURL) && a.Version == old.Version {
		a.Version = ""
		Normalize(a)
	}
}

// Tag limits: enough for team, environment, site, application... MaxTagLen
// is in characters, wherever a tag is read: asset, CSV import, list filters.
const (
	MaxTags   = 20
	MaxTagLen = 40
)

// MaxProjectLen is the longest project name, in characters, wherever a
// project is named: asset, SBOM import, API token.
const MaxProjectLen = 200

// ParseTags reads tags typed in one field, separated by commas or semicolons.
func ParseTags(field string) []string {
	return NormalizeTags(strings.FieldsFunc(field, func(r rune) bool { return r == ',' || r == ';' }))
}

// NormalizeTags trims tags, lowercases them so that "Prod" and "prod" are one
// tag, collapses inner spaces and drops empty ones and duplicates.
func NormalizeTags(tags []string) []string {
	var out []string
	for _, t := range tags {
		t = strings.ToLower(strings.Join(strings.Fields(t), " "))
		if t != "" && !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	return out
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
	check(len(a.Tags) <= MaxTags, fmt.Sprintf("%d étiquettes au plus", MaxTags))
	for _, t := range a.Tags {
		check(clip.Fits(t, MaxTagLen) && !strings.ContainsAny(t, ",;\x00"),
			fmt.Sprintf("étiquette « %s » : %d caractères au plus, sans virgule", t, MaxTagLen))
	}
	check(clip.Fits(a.Name, 200) && clip.Fits(a.Version, 100) && clip.Fits(a.Owner, 200) && clip.Fits(a.Project, MaxProjectLen) &&
		clip.Fits(a.PURL, 500) && clip.Fits(a.CPE, 500) && clip.Fits(a.Notes, 4000), "un champ dépasse la longueur maximale")
	check(choice.Has(Kinds, a.Kind), "type d'actif invalide")
	check(choice.Has(Criticalities, a.Criticality), "criticité invalide")
	check(a.Ecosystem == "" || contains(Ecosystems, a.Ecosystem), "écosystème non supporté")
	check(a.PURL == "" || strings.HasPrefix(a.PURL, "pkg:"), "un purl doit commencer par « pkg: »")
	check(a.CPE == "" || strings.HasPrefix(a.CPE, "cpe:2.3:"), "un CPE doit commencer par « cpe:2.3: »")
	check(choice.Has(CPEModes, a.CPEMode), "mode de suivi NVD invalide")
	check(a.CPEMode != "from" || (a.CPEFrom != "" && clip.Fits(a.CPEFrom, 100) && !strings.ContainsAny(a.CPEFrom, ":*?")),
		"indiquez la version de départ du suivi")
	_, dateErr := time.Parse(dateLayout, a.TrackSince)
	check(a.TrackSince == "" || dateErr == nil, "date de début du suivi invalide")
	return errors.Join(errs...)
}

// Queryable reports whether an asset can be checked against OSV, i.e. it is
// identified by a purl or an ecosystem and name, and has a known version.
// Without a version OSV would return every advisory ever published.
func Queryable(a store.Asset) bool {
	if a.PURL != "" {
		return a.Version != "" || osv.PURLVersion(a.PURL) != ""
	}
	return a.Ecosystem != "" && a.Version != ""
}

// Package is the package an asset designates in OSV, whatever its version.
func Package(a store.Asset) osv.Package {
	if a.PURL != "" {
		p := osv.PURLQuery(a.PURL, "").Package
		p.PURL = osv.WithoutVersion(p.PURL)
		return p
	}
	return osv.Package{Name: osv.SourceName(a.Name, a.Ecosystem), Ecosystem: a.Ecosystem}
}

// WholeDistribution reports whether an asset names a distribution without its
// release: OSV then compares its version with the advisories of all of them,
// where any version of Debian 12 is below the fix of Debian 14.
func WholeDistribution(a store.Asset) bool {
	if !Queryable(a) {
		return false
	}
	p := Package(a)
	switch p.Ecosystem {
	case "Debian", "Ubuntu", "Alpine", "Rocky Linux", "AlmaLinux":
		return true
	}
	return strings.HasPrefix(p.PURL, "pkg:deb/") || strings.HasPrefix(p.PURL, "pkg:apk/") ||
		strings.HasPrefix(p.PURL, "pkg:rpm/rocky/") || strings.HasPrefix(p.PURL, "pkg:rpm/almalinux/")
}

// ByName reports whether an asset is checked by searching its name in the
// descriptions of the CVEs (NVD): it has no purl, no CPE, no ecosystem with
// a version, and does not come from an SBOM, whose components without purl
// are many and named too generically (libc, a file name).
func ByName(a store.Asset) bool {
	return a.PURL == "" && a.CPE == "" && !Queryable(a) && a.Source != "sbom" && a.Name != ""
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

// VendorProduct returns the vendor and the product an asset designates: the
// fields of its CPE, where product "" means every product of the vendor; or
// the namespace and name of its purl (pkg:maven/org.apache.logging.log4j/log4j-core).
func VendorProduct(a store.Asset) (vendor, product string) {
	if f, ok := nvd.SplitCPE(a.CPE); ok {
		vendor, product = f[3], f[4]
		if product == "*" {
			product = ""
		}
		return vendor, product
	}
	if rest, ok := strings.CutPrefix(a.PURL, "pkg:"); ok {
		rest, _, _ = strings.Cut(rest, "#")
		rest, _, _ = strings.Cut(rest, "?")
		rest, _, _ = strings.Cut(rest, "@")
		parts := strings.Split(rest, "/")
		if len(parts) >= 2 {
			vendor, _ = url.PathUnescape(strings.Join(parts[1:len(parts)-1], "/"))
			product, _ = url.PathUnescape(parts[len(parts)-1])
		}
	}
	return vendor, product
}

// VendorName is the vendor an asset is filed under in reports: the CPE
// vendor as a title (fortinet → Fortinet), the purl namespace as written
// (org.apache.logging.log4j), or the packages of an ecosystem when the purl
// has no namespace (Paquets npm). It is "" for an asset with neither.
func VendorName(a store.Asset) string {
	vendor, _ := VendorProduct(a)
	switch {
	case vendor == "*":
	case vendor != "" && a.CPE != "":
		return VendorTitle(vendor)
	case vendor != "":
		return vendor
	}
	kind, _, ok := strings.Cut(strings.TrimPrefix(a.PURL, "pkg:"), "/")
	if !ok || !strings.HasPrefix(a.PURL, "pkg:") {
		return ""
	}
	for _, e := range Ecosystems {
		if strings.EqualFold(e, kind) {
			kind = e
		}
	}
	return "Paquets " + kind
}

// VendorTitle turns a CPE vendor field into a display name: fortinet → Fortinet.
func VendorTitle(vendor string) string {
	words := strings.Fields(strings.ReplaceAll(vendor, "_", " "))
	for i, w := range words {
		r := []rune(w)
		words[i] = strings.ToUpper(string(r[:1])) + string(r[1:])
	}
	return strings.Join(words, " ")
}

// WholeVendor reports whether the asset tracks every product of a vendor.
func WholeVendor(a store.Asset) bool {
	f, ok := nvd.SplitCPE(a.CPE)
	return ok && f[3] != "*" && f[4] == "*"
}
