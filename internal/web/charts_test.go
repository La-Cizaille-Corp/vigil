package web

import (
	"context"
	"math"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/auth"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
	"github.com/La-Cizaille-Corp/vigil/internal/storetest"
)

func TestDonut(t *testing.T) {
	d := newDonut(map[string]int{"CRITICAL": 1, "HIGH": 3, "UNKNOWN": 4})
	if d.Total != 8 || len(d.Segments) != 3 || d.Segments[0].Severity != "CRITICAL" || d.Segments[2].Percent != 50 {
		t.Fatalf("donut: %+v", d)
	}
	// Segments cover the circle, gaps included, without overlapping.
	circumference := 2 * math.Pi * donutRadius
	for _, s := range d.Segments {
		if math.Abs(s.Dash+s.Gap-circumference) > 0.05 {
			t.Errorf("segment %s does not span the circle: %+v", s.Severity, s)
		}
	}
	if !strings.Contains(d.Segments[1].Link, "severity=HIGH") {
		t.Errorf("link: %s", d.Segments[1].Link)
	}
	if newDonut(nil).Total != 0 {
		t.Error("empty donut")
	}
}

func TestAxis(t *testing.T) {
	for v, want := range map[int]int{1: 2, 3: 3, 7: 8, 9: 10, 16: 20, 117: 200, 450: 500} {
		if got := niceCeil(v); got != want {
			t.Errorf("niceCeil(%d) = %d, want %d", v, got, want)
		}
	}
	if compact(1250) != "1,3 k" && compact(1250) != "1,2 k" {
		t.Errorf("compact: %s", compact(1250))
	}
	weeks := []store.WeekCount{{Start: time.Now(), New: 4, Closed: 1}, {Start: time.Now()}}
	c := newWeeklyChart(weeks)
	if c.Empty || len(c.Bars) != 2 || len(c.Ticks) != 3 {
		t.Errorf("weekly chart: %+v", c)
	}
	if !newWeeklyChart(make([]store.WeekCount, 3)).Empty {
		t.Error("chart without data is not empty")
	}
}

func TestDashboardPage(t *testing.T) {
	st, base := newBareServer(t, nil)
	ctx := context.Background()
	addUser(t, st, "viewer", auth.RoleViewer)
	id := storetest.Asset(t, st, store.Asset{Name: "fortios", Kind: "os", Criticality: "high", Source: "manual"})
	storetest.Finding(t, st, id, store.Vulnerability{ID: "CVE-1", Severity: "CRITICAL", EPSS: -1, CVSS: -1}, time.Now())
	if _, err := st.SetExploitSignals(ctx, store.ExploitSignal{ID: "CVE-1", KEV: true, EPSS: 0.5}); err != nil {
		t.Fatal(err)
	}

	c := loginAs(t, base, "viewer", testPassword)
	code, body := c.get("/")
	if code != http.StatusOK {
		t.Fatalf("dashboard: %d", code)
	}
	for _, want := range []string{`class="donut"`, `<span class="kpi-label">Urgentes</span>`, "Activité des 12 dernières semaines",
		"fortios", "<title>Critique : 1 (100 %)</title>", "level=urgent"} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard misses %q", want)
		}
	}
	if strings.Contains(body, "style=") {
		t.Error("inline style breaks the CSP")
	}
}
