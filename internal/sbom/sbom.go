// Package sbom turns CycloneDX and SPDX JSON documents into tracked assets.
package sbom

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/inventory"
	"github.com/La-Cizaille-Corp/vigil/internal/netsafe"
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

// Parse reads a CycloneDX or SPDX JSON SBOM from r.
func Parse(r io.Reader) (Document, error) {
	data, err := netsafe.ReadLimited(r, MaxSize)
	if err != nil {
		return Document{}, err
	}
	// Tools on Windows often prepend a UTF-8 byte order mark.
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	var probe struct {
		BOMFormat   string `json:"bomFormat"`
		SPDXVersion string `json:"spdxVersion"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return Document{}, fmt.Errorf("SBOM JSON invalide : %w", err)
	}
	switch {
	case probe.BOMFormat == "CycloneDX":
		return parseCycloneDX(data)
	case strings.HasPrefix(probe.SPDXVersion, "SPDX-"):
		return parseSPDX(data)
	}
	return Document{}, errors.New("format non reconnu : CycloneDX ou SPDX au format JSON attendu")
}

type cdxComponent struct {
	Type       string         `json:"type"`
	Name       string         `json:"name"`
	Version    string         `json:"version"`
	PURL       string         `json:"purl"`
	CPE        string         `json:"cpe"`
	Components []cdxComponent `json:"components"`
}

func parseCycloneDX(data []byte) (Document, error) {
	var bom struct {
		Metadata struct {
			Component cdxComponent `json:"component"`
		} `json:"metadata"`
		Components []cdxComponent `json:"components"`
	}
	if err := json.Unmarshal(data, &bom); err != nil {
		return Document{}, fmt.Errorf("CycloneDX invalide : %w", err)
	}
	doc := Document{Format: "CycloneDX", Name: bom.Metadata.Component.Name}
	var walk func([]cdxComponent)
	walk = func(list []cdxComponent) {
		for _, c := range list {
			doc.add(c.Name, c.Version, c.PURL, c.CPE, c.Type == "operating-system")
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
		return Document{}, fmt.Errorf("SPDX invalide : %w", err)
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
	if !strings.HasPrefix(a.CPE, "cpe:2.3:") {
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
