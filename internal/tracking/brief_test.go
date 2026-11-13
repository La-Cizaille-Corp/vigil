package tracking

import (
	"context"
	"math"
	"reflect"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/La-Cizaille-Corp/vigil/internal/cvss"
	"github.com/La-Cizaille-Corp/vigil/internal/sources/nvd"
	"github.com/La-Cizaille-Corp/vigil/internal/sources/osv"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
	"github.com/La-Cizaille-Corp/vigil/internal/storetest"
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
	sanitized := func(v store.Vulnerability) store.Vulnerability {
		t.Helper()
		got, err := sanitize(v)
		if err != nil {
			t.Fatalf("%+v: %v", v, err)
		}
		return got
	}
	for _, valid := range []store.Vulnerability{
		{ID: "GHSA-ok", Aliases: []string{"CVE-2024-0001"}, Summary: "Résumé", Details: "Détails", Severity: "HIGH", CVSS: 7.5,
			Published: "2024-01-01T00:00:00Z", Refs: []string{"https://example.org/a"}, Raw: `{"id":"GHSA-ok"}`, EPSS: -1},
		{ID: "CVE-2024-0002", Severity: "CRITICAL", CVSS: 10},
		{ID: "CVE-2024-0003", Severity: "LOW", CVSS: 0},
		{ID: "CVE-2024-0004", CVSS: -1}, // neither severity nor score
		{ID: "CVE-2024-0005", Published: "2024-02-09T09:15:08.087", Modified: "2026-11-12T17:20:40.464641664Z"},
	} {
		if got := sanitized(valid); !reflect.DeepEqual(got, valid) {
			t.Errorf("valid data changed: %+v, want %+v", got, valid)
		}
	}
	for _, severity := range []string{"<B>PWNED</B>", "UNKNOWN", "NONE"} {
		if got := sanitized(store.Vulnerability{ID: "X", Severity: severity}).Severity; got != "" {
			t.Errorf("severity %q stored as %q, want unknown (\"\")", severity, got)
		}
	}
	for _, score := range []float64{1e300, -0.1, 10.1, math.NaN(), math.Inf(1)} {
		if got := sanitized(store.Vulnerability{ID: "X", CVSS: score}).CVSS; got != cvss.Unknown {
			t.Errorf("CVSS %g stored as %g", score, got)
		}
	}

	long := strings.Repeat("é", maxDetails+1)
	aliases := []string{strings.Repeat("x", maxID+1), "CVE-2024-0001"}
	got := sanitized(store.Vulnerability{ID: "X", Summary: long, Details: long, Aliases: aliases})
	if utf8.RuneCountInString(got.Summary) != maxSummary || utf8.RuneCountInString(got.Details) != maxDetails ||
		!strings.HasSuffix(got.Details, "…") {
		t.Errorf("summary of %d characters, details of %d", utf8.RuneCountInString(got.Summary), utf8.RuneCountInString(got.Details))
	}
	if !slices.Equal(got.Aliases, []string{"CVE-2024-0001"}) || len(aliases[0]) != maxID+1 {
		t.Errorf("aliases %v, first alias of the caller: %d bytes", got.Aliases, len(aliases[0]))
	}
	many := make([]string, maxList+1)
	if got := sanitized(store.Vulnerability{ID: "X", Aliases: many, Refs: many}); len(got.Aliases) != maxList || len(got.Refs) != maxList {
		t.Errorf("%d aliases, %d references", len(got.Aliases), len(got.Refs))
	}
	// A date is kept only when it is one, from the day.
	for _, date := range []string{"<b>demain</b>", "2026-13-01T00:00:00Z", "2026-11-12" + strings.Repeat("0", maxDate)} {
		if got := sanitized(store.Vulnerability{ID: "X", Published: date, Modified: date}); got.Published != "" || got.Modified != "" {
			t.Errorf("date %.30q kept: %q, %q", date, got.Published, got.Modified)
		}
	}
	// An advisory without an identifier, or with a longer one, cannot be read.
	for _, id := range []string{"", strings.Repeat("x", maxID+1)} {
		if _, err := sanitize(store.Vulnerability{ID: id}); err == nil {
			t.Errorf("identifier of %d characters stored", len(id))
		}
	}
}

// What is kept of an advisory in the list of a large package (A90) is checked
// as what is stored of it: it was kept as read.
func TestShortChecked(t *testing.T) {
	aliases := append([]string{strings.Repeat("x", maxID+1)}, make([]string, maxList+1)...)
	l, err := short(osv.Vuln{ID: "USN-1", Aliases: aliases, Published: "<b>x</b>", Modified: "2026-01-01T00:00:00Z"})
	if err != nil || len(l.Others) != maxList || l.Others[0] != "" || l.Published != "" || l.Modified != "2026-01-01T00:00:00Z" {
		t.Errorf("%d others, published %q, modified %q, %v", len(l.Others), l.Published, l.Modified, err)
	}
	if _, err := short(osv.Vuln{ID: strings.Repeat("x", maxID+1)}); err == nil {
		t.Error("long identifier kept")
	}
}

// What the sources send is checked before it is stored, at both entry points:
// a record of the NVD (nvdVuln), an advisory of OSV (storeOSV).
func TestSourceDataChecked(t *testing.T) {
	long := strings.Repeat("é", 100_000)
	v, err := nvdVuln(nvd.CVE{ID: "CVE-2099-0001", Description: long, Severity: "<B>PWNED</B>", CVSS: 1e300})
	if err != nil || v.Severity != "" || v.CVSS != cvss.Unknown || utf8.RuneCountInString(v.Details) >= 100_000 {
		t.Errorf("NVD: severity %q, CVSS %g, details of %d characters", v.Severity, v.CVSS, utf8.RuneCountInString(v.Details))
	}

	ctx := context.Background()
	st := storetest.Open(t)
	storeOSV := func(adv osv.Vuln) error { // as for an asset: stored once its advisories are read
		pending := &advisories{store: st}
		if err := (&Syncer{Store: st}).storeOSV(ctx, pending, adv, true); err != nil {
			return err
		}
		return pending.flush(ctx)
	}
	adv := osv.Vuln{ID: "GHSA-bad", Modified: "2026-01-01T00:00:00Z", Summary: long}
	adv.DatabaseSpecific.Severity = "<b>pwned</b>"
	if err := storeOSV(adv); err != nil {
		t.Fatal(err)
	}
	got, err := st.Vulnerability(ctx, "GHSA-bad")
	if err != nil || got.Severity != "" || utf8.RuneCountInString(got.Summary) >= 100_000 {
		t.Errorf("OSV: severity %q, summary of %d characters, %v", got.Severity, utf8.RuneCountInString(got.Summary), err)
	}
	// The scale of a database is translated before the check, not lost by it.
	adv = osv.Vuln{ID: "RHSA-2024:0001", Modified: "2026-01-01T00:00:00Z"}
	adv.DatabaseSpecific.Severity = "Important"
	if err := storeOSV(adv); err != nil {
		t.Fatal(err)
	}
	if got, err := st.Vulnerability(ctx, "RHSA-2024:0001"); err != nil || got.Severity != "HIGH" {
		t.Errorf("Red Hat Important stored as %q, %v", got.Severity, err)
	}
}
