package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/La-Cizaille-Corp/vigil/internal/store"
	"github.com/La-Cizaille-Corp/vigil/internal/tracking"
)

// A long analysis written with accents is kept, cut to the comment limit with
// its "Import VEX" prefix: it was ignored, its length checked in bytes.
func TestVEXImportKeepsALongAccentedDetail(t *testing.T) {
	st, base := newServerWith(t, nil)
	ctx := context.Background()
	id, err := st.CreateAsset(ctx, store.Everything, store.Asset{Name: "x", Kind: "package", Criticality: "high", Source: "manual",
		PURL: "pkg:npm/x@1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	st.UpsertVulnerability(ctx, store.Vulnerability{ID: "CVE-2024-0001", Severity: "HIGH", Modified: "m"})
	st.ObserveFinding(ctx, id, "CVE-2024-0001", "", time.Now())
	doc := `{"bomFormat":"CycloneDX","specVersion":"1.5","vulnerabilities":[{"id":"CVE-2024-0001",
		"analysis":{"state":"false_positive","detail":"` + strings.Repeat("é", 4500) + `"},"affects":[{"ref":"pkg:npm/x@1.0.0"}]}]}`
	c := loginAs(t, base, "analyst", "a-strong-password")
	if code, _ := c.upload("/findings/vex", "vex", "vex.json", doc, url.Values{"csrf": {c.csrf()}}); code != http.StatusSeeOther {
		t.Fatalf("import: %d", code)
	}
	list, _ := st.ListFindings(ctx, store.Everything, store.FindingFilter{AssetID: id})
	if len(list) != 1 || list[0].Status != "false_positive" {
		t.Fatalf("analysis not applied: %+v", list)
	}
	comment := list[0].Comment
	if n := utf8.RuneCountInString(comment); n != tracking.MaxComment || !strings.HasPrefix(comment, "Import VEX : éé") ||
		!strings.HasSuffix(comment, "…") {
		t.Errorf("comment of %d characters: %q…", n, comment[:40])
	}
}
