package web

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/digest"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
)

var updateSnapshots = flag.Bool("update", false, "rewrite the render snapshots of testdata/snapshots")

// TestMain renders the pages in UTC, whatever the time zone of the machine:
// the times shown are local ones. It is set before any test starts, as a
// server goroutine reads time.Local whenever it calls time.Now.
func TestMain(m *testing.M) {
	time.Local = time.UTC
	os.Exit(m.Run())
}

// snapshotNoise are the parts of a page that change on each run: the CSRF
// token, and the times of a digest generated now.
var snapshotNoise = []struct {
	re   *regexp.Regexp
	with string
}{
	{regexp.MustCompile(`name="csrf" value="[^"]*"`), `name="csrf" value="CSRF"`},
	{regexp.MustCompile(`Généré le [0-9/]+ [0-9:]+ — période depuis le [0-9/]+ [0-9:]+`), "Généré le MAINTENANT — période depuis le IL-Y-A-7-JOURS"},
	{regexp.MustCompile(`Digest du [0-9/]+ [0-9:]+`), "Digest du MAINTENANT"},
}

// The main pages and the digest are rendered as kept in testdata/snapshots:
// a change of what they show, such as how numbers and dates are written,
// shows in the diff of these files. go test ./internal/web -run
// TestRenderSnapshots -update rewrites them.
func TestRenderSnapshots(t *testing.T) {
	st, base := newServerWith(t, nil)
	ctx := context.Background()
	seen := time.Date(2025, 3, 4, 10, 20, 30, 0, time.UTC)
	forti, err := st.CreateAsset(ctx, store.Everything, store.Asset{Name: "fortios", Version: "7.2.4", Kind: "os", Criticality: "high",
		Source: "manual", CPE: "cpe:2.3:o:fortinet:fortios:7.2.4:*:*:*:*:*:*:*", TrackSince: "2025-01-01"})
	if err != nil {
		t.Fatal(err)
	}
	lodash, err := st.CreateAsset(ctx, store.Everything, store.Asset{Name: "lodash", Version: "4.17.15", Kind: "package", Criticality: "medium",
		Source: "manual", PURL: "pkg:npm/lodash@4.17.15", Ecosystem: "npm", TrackSince: "2025-01-01"})
	if err != nil {
		t.Fatal(err)
	}
	for i, v := range []struct {
		asset int64
		vuln  store.Vulnerability
		kev   bool
		due   string
		epss  float64
		fixed string
	}{
		{forti, store.Vulnerability{ID: "CVE-2025-0001", Severity: "CRITICAL", CVSS: 9.8, Published: "2025-02-10T08:00:00Z",
			Summary: "Contournement de l'authentification."}, true, "2025-03-01", 0.9731, ""},
		{forti, store.Vulnerability{ID: "CVE-2025-0002", Severity: "HIGH", CVSS: 7.5, Summary: "Déni de service."}, false, "", 0.123, ""},
		{forti, store.Vulnerability{ID: "CVE-2025-0003", CVSS: 0, Summary: "Score nul."}, false, "", 0.0004, ""},
		{lodash, store.Vulnerability{ID: "GHSA-29mw-wpgm-hmr9", Aliases: []string{"CVE-2025-0004"}, Severity: "MEDIUM", CVSS: 5.3,
			Summary: "Pollution de prototype."}, false, "", -1, "4.17.21"},
		{lodash, store.Vulnerability{ID: "CVE-2025-0005", Severity: "LOW", CVSS: -1, Summary: "Sans score."}, false, "", -1, ""},
	} {
		if err := st.UpsertVulnerability(ctx, v.vuln); err != nil {
			t.Fatal(err)
		}
		if _, err := st.SetExploitSignals(ctx, store.ExploitSignal{ID: v.vuln.ID, KEV: v.kev, KEVDue: v.due, EPSS: v.epss}); err != nil {
			t.Fatal(err)
		}
		if _, err := st.ObserveFinding(ctx, v.asset, v.vuln.ID, v.fixed, seen.Add(time.Duration(i)*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	d, err := digest.Generate(ctx, st, store.Group{})
	if err != nil {
		t.Fatal(err)
	}
	c := loginAs(t, base, "analyst", "a-strong-password")
	digestPath := "/digests/" + strconv.FormatInt(d.ID, 10)
	for name, path := range map[string]string{
		"dashboard.html":     "/",
		"findings.html":      "/findings?level=all",
		"finding-kev.html":   "/findings/1",
		"finding-zero.html":  "/findings/3",
		"asset.html":         "/assets/" + strconv.FormatInt(forti, 10),
		"asset-new.html":     "/assets/new",
		"digest.html":        digestPath,
		"digest-markdown.md": digestPath + "/markdown",
	} {
		code, body := c.get(path)
		if code != 200 {
			t.Fatalf("%s: %d", path, code)
		}
		for _, n := range snapshotNoise {
			body = n.re.ReplaceAllString(body, n.with)
		}
		file := filepath.Join("testdata", "snapshots", name)
		if *updateSnapshots {
			if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if got := body; got != strings.ReplaceAll(string(want), "\r\n", "\n") {
			t.Errorf("%s differs from %s: run with -update and read the diff", path, file)
		}
	}
}
