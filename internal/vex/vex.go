// Package vex exports and imports triage decisions as CycloneDX VEX
// (https://cyclonedx.org/capabilities/vex/), so that analyses can be shared
// with customers, auditors or other tools such as Dependency-Track.
package vex

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/netsafe"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
)

// MaxSize bounds an imported VEX document.
const MaxSize = 20 << 20

type document struct {
	BOMFormat       string          `json:"bomFormat"`
	SpecVersion     string          `json:"specVersion"`
	Version         int             `json:"version"`
	Metadata        *metadata       `json:"metadata,omitempty"`
	Vulnerabilities []vulnerability `json:"vulnerabilities"`
}

type metadata struct {
	Timestamp string `json:"timestamp"`
	Tools     struct {
		Components []map[string]string `json:"components"`
	} `json:"tools"`
}

type vulnerability struct {
	ID       string    `json:"id"`
	Analysis *analysis `json:"analysis,omitempty"`
	Affects  []struct {
		Ref string `json:"ref"`
	} `json:"affects"`
}

type analysis struct {
	State         string `json:"state,omitempty"`
	Justification string `json:"justification,omitempty"`
	Detail        string `json:"detail,omitempty"`
}

// Export writes the findings as a CycloneDX 1.5 VEX document. Components are
// referenced by purl, or by CPE for products without one.
func Export(w io.Writer, findings []store.Finding, version string) error {
	doc := document{BOMFormat: "CycloneDX", SpecVersion: "1.5", Version: 1,
		Metadata: &metadata{Timestamp: time.Now().UTC().Format(time.RFC3339)}}
	doc.Metadata.Tools.Components = []map[string]string{{"type": "application", "name": "vigil", "version": version}}
	for _, f := range findings {
		ref := f.AssetPURL
		if ref == "" {
			ref = f.AssetCPE
		}
		if ref == "" {
			continue // a manual asset without identifier cannot be referenced
		}
		v := vulnerability{ID: f.VulnID, Analysis: &analysis{
			State: f.Status, Justification: f.Justification, Detail: f.Comment}}
		v.Affects = append(v.Affects, struct {
			Ref string `json:"ref"`
		}{ref})
		doc.Vulnerabilities = append(doc.Vulnerabilities, v)
	}
	if doc.Vulnerabilities == nil {
		doc.Vulnerabilities = []vulnerability{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// Statement is one imported analysis.
type Statement struct {
	VulnID        string
	Ref           string // purl or CPE of the affected component
	State         string
	Justification string
	Detail        string
}

// states maps CycloneDX analysis states to Vigil statuses.
var states = map[string]string{
	"in_triage": "in_triage", "exploitable": "exploitable", "resolved": "resolved",
	"resolved_with_pedigree": "resolved", "not_affected": "not_affected", "false_positive": "false_positive",
}

// Parse reads the analyses of a CycloneDX VEX (or BOM with vulnerabilities).
func Parse(r io.Reader) ([]Statement, error) {
	data, err := netsafe.ReadLimited(r, MaxSize)
	if err != nil {
		return nil, errors.New("fichier VEX trop volumineux ou illisible")
	}
	var doc document
	if err := json.Unmarshal(trimBOM(data), &doc); err != nil || doc.BOMFormat != "CycloneDX" {
		return nil, errors.New("document CycloneDX JSON attendu")
	}
	var out []Statement
	for _, v := range doc.Vulnerabilities {
		if v.Analysis == nil || v.ID == "" {
			continue
		}
		state, ok := states[v.Analysis.State]
		if !ok {
			continue
		}
		for _, a := range v.Affects {
			if a.Ref == "" {
				continue
			}
			out = append(out, Statement{VulnID: v.ID, Ref: a.Ref, State: state,
				Justification: v.Analysis.Justification, Detail: truncate(v.Analysis.Detail, 4000)})
		}
	}
	if len(out) == 0 {
		return nil, errors.New("aucune analyse exploitable dans ce document")
	}
	return out, nil
}

// Match returns the finding a statement applies to: same component (purl or
// CPE) and same vulnerability, directly or through an alias (CVE ↔ GHSA).
func Match(st Statement, findings []store.Finding) (store.Finding, bool) {
	for _, f := range findings {
		if st.Ref != f.AssetPURL && st.Ref != f.AssetCPE {
			continue
		}
		if st.VulnID == f.VulnID || slices.Contains(f.Aliases, st.VulnID) {
			return f, true
		}
	}
	return store.Finding{}, false
}

func trimBOM(b []byte) []byte {
	if len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		return b[3:]
	}
	return b
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return fmt.Sprintf("%.*s…", n, s)
}
