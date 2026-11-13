package digest

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/store"
	"github.com/La-Cizaille-Corp/vigil/internal/storetest"
)

func TestGenerate(t *testing.T) {
	ctx := context.Background()
	st := storetest.Open(t)
	id := storetest.Asset(t, st, store.Asset{Name: "log4j-core", Version: "2.14.1", Kind: "package", Criticality: "high", Source: "manual",
		PURL: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"})
	storetest.Finding(t, st, id, store.Vulnerability{ID: "GHSA-jfh8", Aliases: []string{"CVE-2021-44228"},
		Summary: "Log4Shell <script>", Severity: "CRITICAL", CVSS: 10}, time.Now().Add(-20*24*time.Hour)) // past the 15-day critical deadline
	feed, _ := st.CreateFeed(ctx, store.Feed{Name: "CERT-FR", URL: "https://example.org/feed", Country: "FR", Enabled: true})
	st.InsertCTIItem(ctx, feed, store.CTIItem{GUID: "1", Title: "Campagne contre les hôpitaux", Link: "https://example.org/1",
		Published: time.Now(), Countries: []string{"FR"}, Sectors: []string{"health"}})
	st.InsertCTIItem(ctx, feed, store.CTIItem{GUID: "2", Title: "Log4Shell : correctifs urgents (CVE-2021-44228)", Link: "https://example.org/2",
		Published: time.Now()})
	st.InsertCTIItem(ctx, feed, store.CTIItem{GUID: "3", Title: "<!channel> [Correctif](https://evil.example) hôpitaux", Link: "https://example.org/3",
		Published: time.Now(), Countries: []string{"FR"}})

	d, err := Generate(ctx, st, store.Everything, store.Group{})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"GHSA-jfh8", "CVE-2021-44228", "log4j-core", "Campagne contre les hôpitaux",
		"Urgentes (0)", "Aucune vulnérabilité urgente.", "Par niveau", "Nouvelles vulnérabilités ouvertes (0)",
		"Hors délai de traitement (1)", "Actualités citant vos vulnérabilités (1)", "Log4Shell : correctifs urgents",
		"Vulnérabilités ouvertes (1)"} {
		if !strings.Contains(d.Markdown, want) || !strings.Contains(d.HTML, want) {
			t.Errorf("digest misses %q", want)
		}
	}
	for _, want := range []string{"| org.apache.logging.log4j | 0 | 1 | 0 | 0 | 0 | 0 | 1 |", "| À planifier | 0 | 1 |", "| Corrigées | 0 | 0 |",
		"- **À planifier** · Critique — GHSA-jfh8 (CVE-2021-44228) — log4j-core 2.14.1 — échéance "} {
		if !strings.Contains(d.Markdown, want) {
			t.Errorf("Markdown digest misses %q:\n%s", want, d.Markdown)
		}
	}
	// SECURITY: untrusted text reaches chat tools through the Markdown digest.
	for _, bad := range []string{"<!channel>", "](https://evil"} {
		if strings.Contains(d.Markdown, bad) {
			t.Errorf("%q survives in the Markdown digest", bad)
		}
	}
	// SECURITY: the HTML digest is rendered by html/template and later
	// trusted by the UI, so stored text must arrive escaped.
	if strings.Contains(d.HTML, "<script>") {
		t.Error("summary not escaped in HTML digest")
	}
	// The next digest only covers what happened since this one.
	next, err := Generate(ctx, st, store.Everything, store.Group{})
	if err != nil {
		t.Fatal(err)
	}
	if !next.Since.After(d.Since) {
		t.Errorf("window did not move: %v then %v", d.Since, next.Since)
	}
}

// The digest follows the levels (A87): it opens on the urgent ones, counts the
// findings of each level, new and in all, lists the new open ones most urgent
// first, and leaves the fixed ones to their count.
func TestDigestByLevels(t *testing.T) {
	ctx := context.Background()
	st := storetest.Open(t)
	asset := storetest.Asset(t, st, store.Asset{Name: "linux", Version: "6.12", Kind: "os", Criticality: "high", Source: "manual",
		CPE: "cpe:2.3:o:linux:linux_kernel:6.12:*:*:*:*:*:*:*"})
	old := time.Now().Add(-30 * 24 * time.Hour)
	for _, v := range []struct {
		id, severity string
		kev, fixed   bool
		seen         time.Time
	}{
		{"CVE-2026-0001", "MEDIUM", true, false, old},          // urgent, before the period
		{"CVE-2026-0002", "HIGH", true, false, time.Now()},     // urgent, new
		{"CVE-2026-0003", "CRITICAL", false, true, time.Now()}, // new, fixed at once: a count only
		{"CVE-2026-0004", "LOW", false, false, time.Now()},     // new, to watch
	} {
		id := storetest.Finding(t, st, asset, store.Vulnerability{ID: v.id, Severity: v.severity, CVSS: -1, EPSS: -1, Summary: "faille " + v.id}, v.seen)
		if _, err := st.SetExploitSignals(ctx, store.ExploitSignal{ID: v.id, KEV: v.kev, EPSS: -1}); err != nil {
			t.Fatal(err)
		}
		if v.fixed {
			if err := st.SetFindingStatus(ctx, store.Everything, id, 0, store.StatusResolved, "", ""); err != nil {
				t.Fatal(err)
			}
		}
	}
	d, err := Generate(ctx, st, store.Everything, store.Group{})
	if err != nil {
		t.Fatal(err)
	}
	md := d.Markdown
	urgent, levels, news := strings.Index(md, "## Urgentes (2)"), strings.Index(md, "## Par niveau"), strings.Index(md, "## Nouvelles vulnérabilités ouvertes (2)")
	if urgent < 0 || levels < urgent || news < levels {
		t.Fatalf("sections at %d, %d, %d:\n%s", urgent, levels, news, md)
	}
	for _, want := range []string{
		"- **Urgente** · Haute · exploitée (CISA KEV) — CVE-2026-0002 — linux 6.12 — nouvelle",
		"- **Urgente** · Moyenne · exploitée (CISA KEV) — CVE-2026-0001 — linux 6.12\n",
		"| Urgentes | 1 | 2 |", "| À surveiller | 1 | 1 |", "| Écartées | 0 | 0 |", "| Corrigées | 1 | 1 |",
		"| Linux | 1 | 0 | 1 | 0 | 1 | 0 | 2 |", // the new open ones: the fixed one is not there
	} {
		if !strings.Contains(md, want) {
			t.Errorf("Markdown digest misses %q:\n%s", want, md)
		}
	}
	if strings.Contains(md[news:], "CVE-2026-0003") || strings.Contains(d.HTML, ">CVE-2026-0003<") {
		t.Error("a fixed vulnerability is listed")
	}
	// The new urgent one is listed once, at the head of the digest.
	if strings.Count(md, "— CVE-2026-0002 —") != 1 || !strings.Contains(md[news:], "Les urgentes sont en tête du digest") ||
		!strings.Contains(md[news:], "- **À surveiller** · Basse — CVE-2026-0004 — linux 6.12 — nouvelle") {
		t.Errorf("new ones:\n%s", md[news:])
	}
	for _, want := range []string{`<a href="/findings?level=urgent">Urgentes</a>`, `<a href="/findings?level=fixed&amp;since=7">1</a>`,
		`<span class="level level-urgent">Urgente</span>`} {
		if !strings.Contains(d.HTML, want) {
			t.Errorf("HTML digest misses %s", want)
		}
	}
}

// A digest stays a summary whatever the volume (A87): each list is cut to
// maxListed lines, with the number of the others and their list.
func TestDigestBound(t *testing.T) {
	ctx := context.Background()
	st := storetest.Open(t)
	asset := storetest.Asset(t, st, store.Asset{Name: "linux", Version: "6.12", Kind: "os", Criticality: "high", Source: "manual"})
	const n = 3 * maxListed
	for i := range n {
		id := fmt.Sprintf("CVE-2026-%04d", i)
		// Past the 15-day deadline of a critical one: every one is overdue.
		storetest.Finding(t, st, asset, store.Vulnerability{ID: id, Severity: "CRITICAL", CVSS: -1, EPSS: -1, Summary: strings.Repeat("résumé long ", 40)},
			time.Now().Add(-20*24*time.Hour+time.Duration(i)*time.Second))
		if _, err := st.SetExploitSignals(ctx, store.ExploitSignal{ID: id, KEV: i%2 == 0, EPSS: -1}); err != nil {
			t.Fatal(err)
		}
	}
	d, err := Generate(ctx, st, store.Everything, store.Group{})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"## Urgentes (75)", "- … et 25 autres, dans Vigil : la liste des urgentes",
		"## Hors délai de traitement (150)", "- … et 100 autres, dans Vigil : la liste des vulnérabilités hors délai"} {
		if !strings.Contains(d.Markdown, want) {
			t.Errorf("Markdown digest misses %q", want)
		}
	}
	if lines := strings.Count(d.Markdown, "\n- **"); lines != 2*maxListed {
		t.Errorf("%d finding lines, want %d", lines, 2*maxListed)
	}
	for _, want := range []string{`… et 25 autres : <a href="/findings?level=urgent">la liste des urgentes</a>`,
		`… et 100 autres : <a href="/findings?overdue=1">la liste des vulnérabilités hors délai</a>`} {
		if !strings.Contains(d.HTML, want) {
			t.Errorf("HTML digest misses %s", want)
		}
	}
	if strings.Contains(d.Markdown, "résumé long") || len(d.Markdown) > 30000 {
		t.Errorf("the digest holds the summaries, or does not fit a chat message: %d bytes", len(d.Markdown))
	}
}

// New findings that are all urgent are listed once, at the head (A87).
func TestDigestOnlyUrgentNew(t *testing.T) {
	ctx := context.Background()
	st := storetest.Open(t)
	asset := storetest.Asset(t, st, store.Asset{Name: "nginx", Version: "1.24", Kind: "product", Criticality: "high", Source: "manual"})
	storetest.Finding(t, st, asset, store.Vulnerability{ID: "CVE-2026-0001", Severity: "HIGH", CVSS: -1, EPSS: -1}, time.Now())
	if _, err := st.SetExploitSignals(ctx, store.ExploitSignal{ID: "CVE-2026-0001", KEV: true, EPSS: -1}); err != nil {
		t.Fatal(err)
	}
	d, err := Generate(ctx, st, store.Everything, store.Group{})
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{d.Markdown, d.HTML} {
		if strings.Count(text, "CVE-2026-0001") != 1 || !strings.Contains(text, "Toutes sont urgentes, en tête du digest.") ||
			strings.Contains(text, "les autres, les plus urgentes d'abord") {
			t.Errorf("digest:\n%s", text)
		}
	}
}

// The lists of a digest of a group lead to the lists of that group (A68, A87).
func TestDigestLinksOfAGroup(t *testing.T) {
	d := data{GroupID: 3}
	if got := d.List("level", "urgent"); got != "/findings?group=3&level=urgent" {
		t.Errorf("link = %s", got)
	}
	if got := (data{}).List(); got != "/findings" {
		t.Errorf("link = %s", got)
	}
}

func TestByVendor(t *testing.T) {
	const fortios = "cpe:2.3:o:fortinet:fortios:7.2.4:*:*:*:*:*:*:*"
	fs := []store.Finding{
		{VulnID: "npm-medium", AssetPURL: "pkg:npm/lodash@4.17.15", Severity: "MEDIUM"},
		{VulnID: "forti-high", AssetCPE: fortios, Severity: "HIGH", CVSS: 8.1, Class: store.AlertSevere},
		{VulnID: "forti-scored", AssetCPE: fortios, CVSS: 9.8, Class: store.AlertSevere}, // no advisory severity: rated by its score
		{VulnID: "forti-kev", AssetCPE: fortios, Severity: "HIGH", CVSS: 7.5, KEV: true, Class: store.AlertPriority},
		{VulnID: "log4j", AssetPURL: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", Severity: "LOW"},
		{VulnID: "manual", CVSS: -1},
		{VulnID: "npm-kev", AssetPURL: "pkg:npm/lodash@4.17.15", Severity: "LOW", KEV: true, Class: store.AlertPriority},
	}
	for i := range fs {
		fs[i].Status = store.StatusInTriage
	}
	b := byVendor(fs)
	var vendors []string
	for _, g := range b.Groups {
		vendors = append(vendors, g.Vendor)
	}
	// The vendors with urgent findings first, then by bands.
	if want := "Fortinet,Paquets npm,org.apache.logging.log4j,Éditeur non renseigné"; strings.Join(vendors, ",") != want {
		t.Fatalf("vendors = %v, want %s", vendors, want)
	}
	forti := b.Groups[0]
	if fmt.Sprint(forti.Bands) != "[1 2 0 0 0]" || forti.Urgent != 1 || forti.N != 3 {
		t.Errorf("fortinet = %+v", forti)
	}
	if fmt.Sprint(b.Total.Bands) != "[1 2 1 2 1]" || b.Total.N != len(fs) || b.Total.Urgent != 2 {
		t.Errorf("total = %+v", b.Total)
	}
}

// A feed link stored with a line break (before links were checked when a feed
// is collected) cannot cut the Markdown link and ping a channel.
func TestLinkCannotBreakOut(t *testing.T) {
	link := funcs["link"].(func(string, string) string)
	got := link("Correctif urgent", "https://evil.example/a\n@channel please read")
	if strings.ContainsAny(got, "\r\n") || got != "[Correctif urgent](https://evil.example/a%0A@channel%20please%20read)" {
		t.Errorf("link = %q", got)
	}
}

// W6 of the 0.5.0 review: a digest covers what its caller sees of the group
// it names, never more. The digest of the zero Group used to read
// store.Everything whoever asked for it.
func TestGenerateKeepsToTheScope(t *testing.T) {
	ctx := context.Background()
	// One base per case: a digest covers the period since the previous one of
	// its target, stored to the second, so a second digest of the whole
	// inventory on the same base would list the findings only when it falls in
	// the same second as the first.
	inventory := func() (*store.Store, map[string]int64) {
		st := storetest.Open(t)
		groups := map[string]int64{}
		for _, name := range []string{"a", "b"} {
			asset := storetest.Asset(t, st, store.Asset{Name: "actif-" + name, Version: "1", Kind: "package",
				Criticality: "high", Source: "manual", Tags: []string{name}})
			storetest.Finding(t, st, asset, store.Vulnerability{ID: "CVE-2026-000" + name, Severity: "HIGH", CVSS: 8, EPSS: -1}, time.Now())
			var err error
			if groups[name], err = st.CreateGroup(ctx, "groupe "+name); err != nil {
				t.Fatal(err)
			}
			if err := st.SetGroupRules(ctx, groups[name], []string{name}, nil); err != nil {
				t.Fatal(err)
			}
		}
		return st, groups
	}
	for _, c := range []struct {
		name         string
		scope, group string // the group's name; "" for store.Everything and the whole inventory
		want         []string
	}{
		{"everything, whole inventory", "", "", []string{"actif-a", "actif-b"}},
		{"everything, group a", "", "a", []string{"actif-a"}},
		{"group a, whole inventory", "a", "", []string{"actif-a"}},
		{"group a, group b", "a", "b", nil},
	} {
		st, groups := inventory()
		sc := store.Everything
		if c.scope != "" {
			sc = store.InGroups(groups[c.scope])
		}
		d, err := Generate(ctx, st, sc, store.Group{ID: groups[c.group]})
		if err != nil {
			t.Fatal(err)
		}
		for _, asset := range []string{"actif-a", "actif-b"} {
			if strings.Contains(d.Markdown, asset) != slices.Contains(c.want, asset) {
				t.Errorf("%s: %s listed: %v", c.name, asset, !slices.Contains(c.want, asset))
			}
		}
	}
}
