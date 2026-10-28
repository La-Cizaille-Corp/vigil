package digest

import (
	"context"
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
	id, _ := st.CreateAsset(ctx, store.Asset{Name: "log4j-core", Version: "2.14.1", Kind: "package", Criticality: "high", Source: "manual"})
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
		"Hors délai de traitement (1)", "Actualités citant vos vulnérabilités (1)", "Log4Shell : correctifs urgents"} {
		if !strings.Contains(d.Markdown, want) || !strings.Contains(d.HTML, want) {
			t.Errorf("digest misses %q", want)
		}
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
