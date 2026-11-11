package tracking

import (
	"context"
	"math"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/La-Cizaille-Corp/vigil/internal/cvss"
	"github.com/La-Cizaille-Corp/vigil/internal/sources/nvd"
	"github.com/La-Cizaille-Corp/vigil/internal/sources/osv"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
)

// A summary taken from a description without a sentence end in its first 300
// bytes was cut there, possibly in the middle of a character.
func TestBriefStaysValidUTF8(t *testing.T) {
	got := brief("a" + strings.Repeat("é", 400))
	if !utf8.ValidString(got) || utf8.RuneCountInString(got) != 300 || !strings.HasSuffix(got, "…") {
		t.Errorf("brief = %q", got)
	}
	if got := brief("Première phrase. La suite."); got != "Première phrase." {
		t.Errorf("first sentence: %q", got)
	}
}

func TestSanitize(t *testing.T) {
	for _, valid := range []store.Vulnerability{
		{ID: "GHSA-ok", Aliases: []string{"CVE-2024-0001"}, Summary: "Résumé", Details: "Détails", Severity: "HIGH", CVSS: 7.5,
			Published: "2024-01-01T00:00:00Z", Refs: []string{"https://example.org/a"}, Raw: `{"id":"GHSA-ok"}`, EPSS: -1},
		{ID: "CVE-2024-0002", Severity: "CRITICAL", CVSS: 10},
		{ID: "CVE-2024-0003", Severity: "LOW", CVSS: 0},
		{ID: "CVE-2024-0004", CVSS: -1}, // neither severity nor score
	} {
		if got := sanitize(valid); !reflect.DeepEqual(got, valid) {
			t.Errorf("valid data changed: %+v, want %+v", got, valid)
		}
	}
	for _, severity := range []string{"<B>PWNED</B>", "UNKNOWN", "NONE", "IMPORTANT"} {
		if got := sanitize(store.Vulnerability{Severity: severity}).Severity; got != "" {
			t.Errorf("severity %q stored as %q, want unknown (\"\")", severity, got)
		}
	}
	for _, score := range []float64{1e300, -0.1, 10.1, math.NaN(), math.Inf(1)} {
		if got := sanitize(store.Vulnerability{CVSS: score}).CVSS; got != cvss.Unknown {
			t.Errorf("CVSS %g stored as %g", score, got)
		}
	}

	long := strings.Repeat("é", maxDetails+1)
	aliases := []string{strings.Repeat("x", maxID+1), "CVE-2024-0001"}
	got := sanitize(store.Vulnerability{Summary: long, Details: long, Aliases: aliases})
	if utf8.RuneCountInString(got.Summary) != maxSummary || utf8.RuneCountInString(got.Details) != maxDetails ||
		!strings.HasSuffix(got.Details, "…") {
		t.Errorf("summary of %d characters, details of %d", utf8.RuneCountInString(got.Summary), utf8.RuneCountInString(got.Details))
	}
	if !slices.Equal(got.Aliases, []string{"CVE-2024-0001"}) || len(aliases[0]) != maxID+1 {
		t.Errorf("aliases %v, first alias of the caller: %d bytes", got.Aliases, len(aliases[0]))
	}
	many := make([]string, maxList+1)
	if got := sanitize(store.Vulnerability{Aliases: many, Refs: many}); len(got.Aliases) != maxList || len(got.Refs) != maxList {
		t.Errorf("%d aliases, %d references", len(got.Aliases), len(got.Refs))
	}
}

// What the sources send is checked before it is stored, at both entry points:
// a record of the NVD (nvdVuln), an advisory of OSV (storeOSV).
func TestSourceDataChecked(t *testing.T) {
	long := strings.Repeat("é", 100_000)
	v := nvdVuln(nvd.CVE{ID: "CVE-2099-0001", Description: long, Severity: "<B>PWNED</B>", CVSS: 1e300})
	if v.Severity != "" || v.CVSS != cvss.Unknown || utf8.RuneCountInString(v.Details) >= 100_000 {
		t.Errorf("NVD: severity %q, CVSS %g, details of %d characters", v.Severity, v.CVSS, utf8.RuneCountInString(v.Details))
	}

	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	adv := osv.Vuln{ID: "GHSA-bad", Modified: "2026-01-01T00:00:00Z", Summary: long}
	adv.DatabaseSpecific.Severity = "<b>pwned</b>"
	if err := (&Syncer{Store: st}).storeOSV(ctx, adv, true); err != nil {
		t.Fatal(err)
	}
	got, err := st.Vulnerability(ctx, "GHSA-bad")
	if err != nil || got.Severity != "" || utf8.RuneCountInString(got.Summary) >= 100_000 {
		t.Errorf("OSV: severity %q, summary of %d characters, %v", got.Severity, utf8.RuneCountInString(got.Summary), err)
	}
}
