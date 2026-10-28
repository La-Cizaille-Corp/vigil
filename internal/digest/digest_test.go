package digest

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/store"
)

func TestGenerate(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "d.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	id, _ := st.CreateAsset(ctx, store.Asset{Name: "log4j-core", Version: "2.14.1", Kind: "package", Criticality: "high", Source: "manual",
		PURL: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"})
	st.UpsertVulnerability(ctx, store.Vulnerability{ID: "GHSA-jfh8", Aliases: []string{"CVE-2021-44228"},
		Summary: "Log4Shell <script>", Severity: "CRITICAL", CVSS: 10})
	st.ObserveFinding(ctx, id, "GHSA-jfh8", time.Now().Add(-20*24*time.Hour)) // past the 15-day critical deadline
	feed, _ := st.CreateFeed(ctx, store.Feed{Name: "CERT-FR", URL: "https://example.org/feed", Country: "FR", Enabled: true})
	st.InsertCTIItem(ctx, feed, store.CTIItem{GUID: "1", Title: "Campagne contre les hôpitaux", Link: "https://example.org/1",
		Published: time.Now(), Countries: []string{"FR"}, Sectors: []string{"health"}})
	st.InsertCTIItem(ctx, feed, store.CTIItem{GUID: "2", Title: "Log4Shell : correctifs urgents (CVE-2021-44228)", Link: "https://example.org/2",
		Published: time.Now()})

	d, err := Generate(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"GHSA-jfh8", "CVE-2021-44228", "log4j-core", "Campagne contre les hôpitaux",
		"org.apache.logging.log4j (1)", "Exploitées (KEV)",
		"Hors délai de traitement (1)", "Actualités citant vos vulnérabilités (1)", "Log4Shell : correctifs urgents"} {
		if !strings.Contains(d.Markdown, want) || !strings.Contains(d.HTML, want) {
			t.Errorf("digest misses %q", want)
		}
	}
	if !strings.Contains(d.Markdown, "| org.apache.logging.log4j | 1 | 0 | 0 | 0 | 0 | 1 | 0 |") {
		t.Errorf("vendor breakdown missing:\n%s", d.Markdown)
	}
	// SECURITY: the HTML digest is rendered by html/template and later
	// trusted by the UI, so stored text must arrive escaped.
	if strings.Contains(d.HTML, "<script>") {
		t.Error("summary not escaped in HTML digest")
	}
	// The next digest only covers what happened since this one.
	next, err := Generate(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	if !next.Since.After(d.Since) {
		t.Errorf("window did not move: %v then %v", d.Since, next.Since)
	}
}

func TestSortByPriority(t *testing.T) {
	fs := []store.Finding{
		{VulnID: "low", Severity: "LOW", EPSS: -1},
		{VulnID: "critical", Severity: "CRITICAL", EPSS: 0.01},
		{VulnID: "likely", Severity: "MEDIUM", EPSS: 0.5},
		{VulnID: "kev", Severity: "LOW", KEV: true, EPSS: -1},
	}
	SortByPriority(fs)
	var got []string
	for _, f := range fs {
		got = append(got, f.VulnID)
	}
	if strings.Join(got, ",") != "kev,likely,critical,low" {
		t.Errorf("order = %v", got)
	}
}

func TestByVendor(t *testing.T) {
	const fortios = "cpe:2.3:o:fortinet:fortios:7.2.4:*:*:*:*:*:*:*"
	fs := []store.Finding{
		{VulnID: "npm-medium", AssetPURL: "pkg:npm/lodash@4.17.15", Severity: "MODERATE"},
		{VulnID: "forti-high", AssetCPE: fortios, Severity: "HIGH", CVSS: 8.1},
		{VulnID: "forti-scored", AssetCPE: fortios, CVSS: 9.8}, // no advisory severity: rated by its score
		{VulnID: "forti-kev", AssetCPE: fortios, Severity: "HIGH", CVSS: 7.5, KEV: true},
		{VulnID: "log4j", AssetPURL: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", Severity: "LOW"},
		{VulnID: "manual", CVSS: -1},
	}
	b := ByVendor(fs)
	var vendors []string
	for _, g := range b.Groups {
		vendors = append(vendors, g.Vendor)
	}
	if want := "Fortinet,Paquets npm,org.apache.logging.log4j,Éditeur non renseigné"; strings.Join(vendors, ",") != want {
		t.Fatalf("vendors = %v, want %s", vendors, want)
	}
	forti := b.Groups[0]
	var order []string
	for _, f := range forti.Findings {
		order = append(order, f.VulnID)
	}
	if strings.Join(order, ",") != "forti-scored,forti-kev,forti-high" {
		t.Errorf("order = %v", order)
	}
	if fmt.Sprint(forti.Bands) != "[1 2 0 0 0]" || forti.KEV != 1 {
		t.Errorf("bands = %v, kev = %d", forti.Bands, forti.KEV)
	}
	if s := forti.Summary(); s != "1 critique, 2 hautes, dont 1 exploitée" {
		t.Errorf("summary = %q", s)
	}
	if s := b.Groups[3].Summary(); s != "1 de sévérité inconnue" {
		t.Errorf("summary = %q", s)
	}
	if fmt.Sprint(b.Total.Bands) != "[1 2 1 1 1]" || len(b.Total.Findings) != len(fs) {
		t.Errorf("total = %v", b.Total.Bands)
	}
}

func TestListedBound(t *testing.T) {
	fs := make([]store.Finding, maxListed+3)
	for i := range fs {
		fs[i] = store.Finding{VulnID: fmt.Sprint(i), AssetCPE: "cpe:2.3:o:microsoft:windows_11:*:*:*:*:*:*:*:*", Severity: "HIGH"}
	}
	fs[len(fs)-1].Severity = "CRITICAL"
	g := ByVendor(fs).Groups[0]
	if len(g.Listed()) != maxListed || g.Unlisted() != 3 || g.Listed()[0].Severity != "CRITICAL" {
		t.Errorf("listed %d, unlisted %d, first %s", len(g.Listed()), g.Unlisted(), g.Listed()[0].Severity)
	}
}
