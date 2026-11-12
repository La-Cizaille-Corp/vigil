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

	"github.com/La-Cizaille-Corp/vigil/internal/limit"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
)

// maxSize bounds an imported VEX document.
const maxSize = 20 << 20

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
	Detail        string // as written: the comment made of it is bounded where it is made
}

// states maps CycloneDX analysis states to Vigil statuses.
var states = map[string]string{
	"in_triage": "in_triage", "exploitable": "exploitable", "resolved": "resolved",
	"resolved_with_pedigree": "resolved", "not_affected": "not_affected", "false_positive": "false_positive",
}

// maxStatements bounds the analyses of one document, each matched against
// the inventory on import.
const maxStatements = 20000

// Parse reads the analyses of a CycloneDX VEX (or BOM with vulnerabilities),
// at most maxSize bytes and a bounded number of values, decoded one document
// at a time (limit.AdmitJSON).
func Parse(r io.Reader) ([]Statement, error) {
	data, err := limit.File(r, maxSize)
	if err != nil {
		return nil, errors.New("fichier VEX trop volumineux ou illisible")
	}
	done, err := limit.AdmitJSON(data)
	if err != nil {
		return nil, err
	}
	defer done()
	var doc document
	if err := json.Unmarshal(data, &doc); err != nil || doc.BOMFormat != "CycloneDX" {
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
			if len(out) == maxStatements {
				return nil, fmt.Errorf("fichier VEX trop volumineux (plus de %d analyses)", maxStatements)
			}
			out = append(out, Statement{VulnID: v.ID, Ref: a.Ref, State: state,
				Justification: v.Analysis.Justification, Detail: v.Analysis.Detail})
		}
	}
	if len(out) == 0 {
		return nil, errors.New("aucune analyse exploitable dans ce document")
	}
	return out, nil
}

// Index finds the finding a statement applies to. Scanning every finding for
// each statement made an import quadratic (20 000 analyses against 20 000
// findings: two seconds of matching alone); the index looks only at the
// findings of the statement's component.
type Index struct {
	findings []store.Finding
	byRef    map[string][]int // purl or CPE → positions in findings, in order
}

// NewIndex indexes findings by component reference (purl and CPE).
func NewIndex(findings []store.Finding) Index {
	idx := Index{findings: findings, byRef: make(map[string][]int, len(findings))}
	for i, f := range findings {
		idx.byRef[f.AssetPURL] = append(idx.byRef[f.AssetPURL], i)
		if f.AssetCPE != f.AssetPURL {
			idx.byRef[f.AssetCPE] = append(idx.byRef[f.AssetCPE], i)
		}
	}
	return idx
}

// Match returns the finding a statement applies to: same component (purl or
// CPE) and same vulnerability, directly or through an alias (CVE ↔ GHSA).
// When several apply, it is the first one in the order given to NewIndex.
func (idx Index) Match(st Statement) (store.Finding, bool) {
	for _, i := range idx.byRef[st.Ref] {
		if f := idx.findings[i]; st.VulnID == f.VulnID || slices.Contains(f.Aliases, st.VulnID) {
			return f, true
		}
	}
	return store.Finding{}, false
}
