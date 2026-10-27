package vex

import (
	"bytes"
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
	// A statement using the CVE alias matches the GHSA finding.
	alias := Statement{VulnID: "CVE-2020-8203", Ref: "pkg:npm/lodash@4.17.15"}
	if _, ok := Match(alias, findings); !ok {
		t.Error("alias not matched")
	}
	if _, ok := Match(Statement{VulnID: "CVE-2020-8203", Ref: "pkg:npm/other@1"}, findings); ok {
		t.Error("matched another component")
	}
}

func TestParseRejects(t *testing.T) {
	for _, in := range []string{`not json`, `{"bomFormat":"SPDX"}`, `{"bomFormat":"CycloneDX","vulnerabilities":[]}`} {
		if _, err := Parse(bytes.NewBufferString(in)); err == nil {
			t.Errorf("accepted %q", in)
		}
	}
}
