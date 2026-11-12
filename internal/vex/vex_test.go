package vex

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/La-Cizaille-Corp/vigil/internal/store"
)

func TestRoundTrip(t *testing.T) {
	findings := []store.Finding{
		{VulnID: "GHSA-test", Aliases: []string{"CVE-2020-8203"}, AssetPURL: "pkg:npm/lodash@4.17.15",
			Status: "not_affected", Justification: "code_not_reachable", Comment: "fonction non utilisée"},
		{VulnID: "CVE-2024-21762", AssetCPE: "cpe:2.3:o:fortinet:fortios:7.2.4:*:*:*:*:*:*:*", Status: "exploitable"},
		{VulnID: "X", Status: "in_triage"}, // no identifier: skipped
	}
	var buf bytes.Buffer
	if err := Export(&buf, findings, "test"); err != nil {
		t.Fatal(err)
	}
	st, err := Parse(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(st) != 2 || st[0].State != "not_affected" || st[0].Justification != "code_not_reachable" {
		t.Fatalf("statements = %+v", st)
	}
	idx := NewIndex(findings)
	// A statement using the CVE alias matches the GHSA finding.
	alias := Statement{VulnID: "CVE-2020-8203", Ref: "pkg:npm/lodash@4.17.15"}
	if _, ok := idx.Match(alias); !ok {
		t.Error("alias not matched")
	}
	if _, ok := idx.Match(Statement{VulnID: "CVE-2020-8203", Ref: "pkg:npm/other@1"}); ok {
		t.Error("matched another component")
	}
}

// A VEX saved by a tool on Windows starts with a byte order mark; one past
// maxSize is refused.
func TestParseByteOrderMarkAndSize(t *testing.T) {
	var buf bytes.Buffer
	if err := Export(&buf, []store.Finding{{VulnID: "CVE-2024-21762", AssetPURL: "pkg:npm/x@1", Status: "exploitable"}}, "test"); err != nil {
		t.Fatal(err)
	}
	if st, err := Parse(bytes.NewBufferString("\xef\xbb\xbf" + buf.String())); err != nil || len(st) != 1 {
		t.Errorf("with a byte order mark: %+v, %v", st, err)
	}
	big := bytes.NewBufferString(buf.String() + strings.Repeat(" ", maxSize))
	if _, err := Parse(big); err == nil || err.Error() != "fichier VEX trop volumineux ou illisible" {
		t.Errorf("past %d bytes: %v", maxSize, err)
	}
}

func TestParseRejects(t *testing.T) {
	for _, in := range []string{`not json`, `{"bomFormat":"SPDX"}`, `{"bomFormat":"CycloneDX","vulnerabilities":[]}`} {
		if _, err := Parse(bytes.NewBufferString(in)); err == nil {
			t.Errorf("accepted %q", in)
		}
	}
}

// matchLoop is the matching the index replaces (S9 of the code audit): each
// statement scanned every finding. It is the reference of the tests below.
func matchLoop(st Statement, findings []store.Finding) (store.Finding, bool) {
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

// The index finds the same finding as the scan, the first one in the list
// when several apply: by purl or CPE, directly or through an alias.
func TestIndexMatchesLikeTheScan(t *testing.T) {
	const lodash, fortios = "pkg:npm/lodash@4.17.15", "cpe:2.3:o:fortinet:fortios:7.2.4:*:*:*:*:*:*:*"
	findings := []store.Finding{
		{ID: 1, VulnID: "GHSA-test", Aliases: []string{"CVE-2020-8203"}, AssetPURL: lodash},
		{ID: 2, VulnID: "CVE-2020-8203", AssetPURL: lodash}, // the same vulnerability again: 1 comes first
		{ID: 3, VulnID: "CVE-2021-23337", AssetPURL: lodash, AssetCPE: "cpe:2.3:a:lodash:lodash:4.17.15:*:*:*:*:node.js:*:*"},
		{ID: 4, VulnID: "CVE-2024-21762", AssetCPE: fortios},                     // CPE only
		{ID: 5, VulnID: "CVE-2024-21762", AssetPURL: fortios, AssetCPE: fortios}, // same reference twice
		{ID: 6, VulnID: "CVE-2023-0001"},                                         // no identifier
		{ID: 7, VulnID: "CVE-2023-0002", AssetPURL: "pkg:npm/x@1", Aliases: []string{"GHSA-x", "CVE-2023-0001"}},
	}
	var statements []Statement
	for _, ref := range []string{lodash, fortios, "cpe:2.3:a:lodash:lodash:4.17.15:*:*:*:*:node.js:*:*", "pkg:npm/x@1", "pkg:npm/other@1", ""} {
		for _, id := range []string{"GHSA-test", "CVE-2020-8203", "CVE-2021-23337", "CVE-2024-21762", "CVE-2023-0001", "GHSA-x", "CVE-1999-0001"} {
			statements = append(statements, Statement{VulnID: id, Ref: ref})
		}
	}
	idx, matched := NewIndex(findings), 0
	for _, st := range statements {
		want, wantOK := matchLoop(st, findings)
		got, ok := idx.Match(st)
		if ok != wantOK || got.ID != want.ID {
			t.Errorf("%s on %q: index gives %d (%v), the scan %d (%v)", st.VulnID, st.Ref, got.ID, ok, want.ID, wantOK)
		}
		if ok {
			matched++
		}
	}
	if matched != 12 {
		t.Errorf("%d statements matched, want 12", matched)
	}
}

// BenchmarkMatch is the measure of S9 in the code audit: 20 000 statements
// (the document limit) against 20 000 findings, none of them matching. The
// index is built in each iteration, as an import does.
//
//	go test -run '^$' -bench Match ./internal/vex
func BenchmarkMatch(b *testing.B) {
	const n = maxStatements
	findings := make([]store.Finding, n)
	for i := range findings {
		findings[i] = store.Finding{VulnID: fmt.Sprintf("CVE-2026-%d", i), AssetPURL: fmt.Sprintf("pkg:npm/p%d@1.0.0", i),
			Aliases: []string{fmt.Sprintf("GHSA-%d", i)}}
	}
	statements := make([]Statement, n)
	for i := range statements {
		statements[i] = Statement{VulnID: "CVE-1999-0001", Ref: fmt.Sprintf("pkg:npm/other%d@1.0.0", i)}
	}
	b.Run("loop", func(b *testing.B) {
		for b.Loop() {
			for _, st := range statements {
				matchLoop(st, findings)
			}
		}
	})
	b.Run("index", func(b *testing.B) {
		for b.Loop() {
			idx := NewIndex(findings)
			for _, st := range statements {
				idx.Match(st)
			}
		}
	})
}
