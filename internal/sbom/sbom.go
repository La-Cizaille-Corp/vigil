// Package sbom turns CycloneDX and SPDX JSON documents into tracked assets.
package sbom

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/inventory"
	"github.com/La-Cizaille-Corp/vigil/internal/limit"
	"github.com/La-Cizaille-Corp/vigil/internal/sources/nvd"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
)

// MaxSize bounds an uploaded SBOM.
const MaxSize = 20 << 20

// maxComponents guards against pathological documents.
const maxComponents = 50000

// Document is the result of parsing an SBOM.
type Document struct {
	Format  string // "CycloneDX" or "SPDX"
	Name    string // main component / document name, used as default project
	Assets  []store.Asset
	Skipped int // components without a purl
}

// Parse reads a CycloneDX or SPDX JSON SBOM from r, at most MaxSize bytes and
// a bounded number of values, decoded one document at a time (limit.AdmitJSON).
func Parse(r io.Reader) (Document, error) {
	data, err := limit.File(r, MaxSize)
	if err != nil {
		return Document{}, err
	}
	done, err := limit.AdmitJSON(data)
	if err != nil {
		return Document{}, err
	}
	defer done()
	var probe struct {
		BOMFormat   string `json:"bomFormat"`
		SPDXVersion string `json:"spdxVersion"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return Document{}, jsonError("", len(data), err)
	}
	switch {
	case probe.BOMFormat == "CycloneDX":
		return parseCycloneDX(data)
	case strings.HasPrefix(probe.SPDXVersion, "SPDX-"):
		return parseSPDX(data)
	}
	return Document{}, errors.New("format non reconnu : CycloneDX ou SPDX au format JSON attendu")
}

// jsonError says in French why a file of size bytes is not a valid SBOM of
// format ("" when it is not known yet), without the Go names of encoding/json
// (A4): « ce n'est pas un SBOM CycloneDX valide : components doit être une
// liste, pas un texte ».
func jsonError(format string, size int, err error) error {
	what := "un SBOM au format JSON"
	if format != "" {
		what = "un SBOM " + format + " valide"
	}
	var syntax *json.SyntaxError
	var typ *json.UnmarshalTypeError
	switch {
	case errors.As(err, &syntax) && syntax.Offset >= int64(size):
		return fmt.Errorf("ce n'est pas %s : le fichier est incomplet", what)
	case errors.As(err, &syntax):
		return fmt.Errorf("ce n'est pas %s : JSON illisible à l'octet %d", what, syntax.Offset)
	case errors.As(err, &typ) && typ.Field != "":
		return fmt.Errorf("ce n'est pas %s : %s doit être %s, pas %s", what, strings.TrimPrefix(typ.Field, "."),
			limit.JSONKind(typ.Type.Kind().String()), limit.JSONKind(typ.Value))
	}
	return fmt.Errorf("ce n'est pas %s", what)
}

type cdxComponent struct {
	Type       string         `json:"type"`
	Name       string         `json:"name"`
	Version    string         `json:"version"`
	PURL       string         `json:"purl"`
	CPE        string         `json:"cpe"`
	Components []cdxComponent `json:"components"`
	Properties []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"properties"`
}

// purl returns the purl of a component. Trivy gives the source package of a
// binary one apart (libssl3, from openssl), and advisories only name the source
// package: it goes in the upstream qualifier, as Syft does.
func (c cdxComponent) purl() string {
	if c.PURL == "" || strings.Contains(c.PURL, "upstream=") {
		return c.PURL
	}
	for _, p := range c.Properties {
		if p.Name == "aquasecurity:trivy:SrcName" && p.Value != "" {
			sep := "?"
			if strings.Contains(c.PURL, "?") {
				sep = "&"
			}
			return c.PURL + sep + "upstream=" + url.QueryEscape(p.Value)
		}
	}
	return c.PURL
}

func parseCycloneDX(data []byte) (Document, error) {
	var bom struct {
		Metadata struct {
			Component cdxComponent `json:"component"`
		} `json:"metadata"`
		Components []cdxComponent `json:"components"`
	}
	if err := json.Unmarshal(data, &bom); err != nil {
		return Document{}, jsonError("CycloneDX", len(data), err)
	}
	doc := Document{Format: "CycloneDX", Name: bom.Metadata.Component.Name}
	var walk func([]cdxComponent)
	walk = func(list []cdxComponent) {
		for _, c := range list {
			doc.add(c.Name, c.Version, c.purl(), c.CPE, c.Type == "operating-system")
			walk(c.Components)
		}
	}
	walk(bom.Components)
	return doc, doc.check()
}

func parseSPDX(data []byte) (Document, error) {
	var spdx struct {
		Name     string `json:"name"`
		Packages []struct {
			Name         string `json:"name"`
			VersionInfo  string `json:"versionInfo"`
			ExternalRefs []struct {
				Type    string `json:"referenceType"`
				Locator string `json:"referenceLocator"`
			} `json:"externalRefs"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &spdx); err != nil {
		return Document{}, jsonError("SPDX", len(data), err)
	}
	doc := Document{Format: "SPDX", Name: spdx.Name}
	for _, p := range spdx.Packages {
		var purl, cpe string
		for _, ref := range p.ExternalRefs {
			switch ref.Type {
			case "purl":
				purl = ref.Locator
			case "cpe23Type":
				cpe = ref.Locator
			}
		}
		doc.add(p.Name, p.VersionInfo, purl, cpe, false)
	}
	return doc, doc.check()
}

// add keeps components identified by a purl, the only reliable key for
// vulnerability matching; others are counted as skipped.
func (d *Document) add(name, version, purl, cpe string, isOS bool) {
	// Beyond the limit the document is refused (check): stop the work early.
	if len(d.Assets)+d.Skipped > maxComponents {
		return
	}
	if purl == "" || name == "" {
		d.Skipped++
		return
	}
	kind := "package"
	if isOS {
		kind = "os"
	}
	a := store.Asset{Name: name, Kind: kind, Version: version, PURL: purl, CPE: cpe, Source: "sbom",
		TrackSince: inventory.DefaultSince(time.Now())}
	inventory.Normalize(&a)
	// A component is kept by its purl: a CPE that is not a CPE 2.3 name is
	// dropped, rather than the component with it (see inventory.Validate).
	if _, ok := nvd.SplitCPE(a.CPE); !ok {
		a.CPE = ""
	}
	if inventory.Validate(a) != nil {
		d.Skipped++
		return
	}
	d.Assets = append(d.Assets, a)
}

func (d *Document) check() error {
	if len(d.Assets)+d.Skipped > maxComponents {
		return fmt.Errorf("SBOM trop volumineux (plus de %d composants)", maxComponents)
	}
	// SECURITY: an import replaces the project's assets, and removing an asset
	// removes its triage history; an empty or unusable file (truncated upload,
	// failed generation) must not wipe a project.
	if len(d.Assets) == 0 {
		return errors.New("aucun composant exploitable dans le SBOM : le projet n'a pas été modifié")
	}
	return nil
}
