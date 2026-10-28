package web

import (
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"

	"github.com/La-Cizaille-Corp/vigil/internal/store"
	"github.com/La-Cizaille-Corp/vigil/internal/tracking"
)

// Charts are drawn on the server as SVG: no JavaScript, no style attribute
// (the CSP forbids both). Geometry is computed here, colors come from CSS
// classes so that light and dark themes apply. Every mark carries a <title>
// (native tooltip) and every chart has a data table.

// openFindings is the query string of the open findings list.
const openFindings = "status=in_triage&status=exploitable"

// donutSegment is one severity of the donut chart.
type donutSegment struct {
	Severity, Label string
	N               int
	Percent         int
	Dash, Gap       float64 // stroke-dasharray
	Offset          float64 // stroke-dashoffset
	Link            string
}

type donutChart struct {
	Total    int
	Segments []donutSegment
}

const (
	donutRadius = 46.0
	segmentGap  = 1.5 // surface gap between segments, in user units
)

// severityOrder is the order of severities in charts: most severe first.
var severityOrder = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}

func newDonut(bySeverity map[string]int) donutChart {
	d := donutChart{}
	for _, sev := range severityOrder {
		d.Total += bySeverity[sev]
	}
	if d.Total == 0 {
		return d
	}
	circumference := 2 * math.Pi * donutRadius
	offset := 0.0
	for _, sev := range severityOrder {
		n := bySeverity[sev]
		if n == 0 {
			continue
		}
		length := circumference * float64(n) / float64(d.Total)
		dash := length
		if n < d.Total {
			dash = math.Max(length-segmentGap, 0.5)
		}
		d.Segments = append(d.Segments, donutSegment{
			Severity: sev, Label: tracking.SeverityLabel(sev), N: n,
			Percent: int(math.Round(100 * float64(n) / float64(d.Total))),
			Dash:    round2(dash), Gap: round2(circumference - dash), Offset: round2(-offset),
			Link: "/findings?" + openFindings + "&severity=" + url.QueryEscape(sev),
		})
		offset += length
	}
	return d
}

// barChart is a column chart of weekly detections and closings.
type barChart struct {
	Width, Height int
	Bars          []bar
	Ticks         []tick // y-axis
	Labels        []tick // x-axis
	Empty         bool
	Weeks         []store.WeekCount
}

type bar struct {
	Class, Title string
	Path         string
}

type tick struct {
	X, Y  float64
	Label string
}

const (
	barWidth  = 12.0
	barRadius = 3.0
)

func newWeeklyChart(weeks []store.WeekCount) barChart {
	c := barChart{Width: 640, Height: 220, Weeks: weeks}
	left, right, top, bottom := 40.0, 632.0, 12.0, 190.0
	peak := 0
	for _, w := range weeks {
		peak = max(peak, w.New, w.Closed)
	}
	if peak == 0 {
		c.Empty = true
		return c
	}
	scale := niceCeil(peak)
	y := func(v int) float64 { return bottom - (bottom-top)*float64(v)/float64(scale) }
	ticks := []int{0, scale}
	if scale%2 == 0 {
		ticks = []int{0, scale / 2, scale}
	}
	for _, v := range ticks {
		c.Ticks = append(c.Ticks, tick{X: left - 6, Y: round2(y(v)), Label: compact(v)})
	}
	band := (right - left) / float64(len(weeks))
	for i, w := range weeks {
		center := left + band*(float64(i)+0.5)
		week := "Semaine du " + w.Start.Format("02/01")
		if w.New > 0 {
			c.Bars = append(c.Bars, bar{Class: "viz-new", Title: fmt.Sprintf("%s : %d nouvelle(s)", week, w.New),
				Path: columnPath(center-barWidth-1, y(w.New), barWidth, bottom-y(w.New))})
		}
		if w.Closed > 0 {
			c.Bars = append(c.Bars, bar{Class: "viz-closed", Title: fmt.Sprintf("%s : %d traitée(s)", week, w.Closed),
				Path: columnPath(center+1, y(w.Closed), barWidth, bottom-y(w.Closed))})
		}
		if i%2 == len(weeks)%2 || i == len(weeks)-1 {
			c.Labels = append(c.Labels, tick{X: round2(center), Y: bottom + 18, Label: w.Start.Format("02/01")})
		}
	}
	return c
}

// stackedRow is an asset with its open findings as a horizontal stacked bar.
type stackedRow struct {
	Asset          store.AssetLoad
	LabelY, ValueY float64
	Segments       []bar
	TotalX         float64
	Link           string
}

type stackedChart struct {
	Width, Height int
	Rows          []stackedRow
}

func newAssetChart(assets []store.AssetLoad) stackedChart {
	const rowHeight, left, right, thickness = 34.0, 0.0, 560.0, 14.0
	c := stackedChart{Width: 600, Height: int(rowHeight * float64(len(assets)))}
	peak := 0
	for _, a := range assets {
		peak = max(peak, a.Total())
	}
	for i, a := range assets {
		top := rowHeight * float64(i)
		row := stackedRow{Asset: a, LabelY: top + 12, ValueY: top + 28, Link: "/assets/" + strconv.FormatInt(a.ID, 10)}
		x := left
		parts := []struct {
			sev string
			n   int
		}{{"CRITICAL", a.Critical}, {"HIGH", a.High}, {"MEDIUM", a.Medium}, {"OTHER", a.Other}}
		last := -1
		for j, p := range parts {
			if p.n > 0 {
				last = j
			}
		}
		for j, p := range parts {
			if p.n == 0 {
				continue
			}
			w := (right - left) * float64(p.n) / float64(peak)
			label := tracking.SeverityLabel(p.sev)
			if p.sev == "OTHER" {
				label = "Basse ou inconnue"
			}
			// A 2px surface gap separates segments; only the end is rounded.
			drawn := math.Max(w-2, 1)
			path := rectPath(x, top+17, drawn, thickness)
			if j == last {
				drawn = math.Max(w, 1)
				path = endPath(x, top+17, drawn, thickness)
			}
			row.Segments = append(row.Segments, bar{Class: "viz-sev-" + strings.ToLower(p.sev),
				Title: fmt.Sprintf("%s : %d %s", a.Name, p.n, strings.ToLower(label)), Path: path})
			x += w
		}
		row.TotalX = round2(x + 8)
		c.Rows = append(c.Rows, row)
	}
	return c
}

// columnPath draws a column rounded at its top, square at the baseline.
func columnPath(x, y, w, h float64) string {
	r := math.Min(barRadius, math.Min(h, w/2))
	return fmt.Sprintf("M%s %sV%sQ%s %s %s %sH%sQ%s %s %s %sV%sZ",
		f(x), f(y+h), f(y+r), f(x), f(y), f(x+r), f(y), f(x+w-r), f(x+w), f(y), f(x+w), f(y+r), f(y+h))
}

// endPath draws a horizontal bar rounded at its right end.
func endPath(x, y, w, h float64) string {
	r := math.Min(barRadius, math.Min(w, h/2))
	return fmt.Sprintf("M%s %sH%sQ%s %s %s %sV%sQ%s %s %s %sH%sZ",
		f(x), f(y), f(x+w-r), f(x+w), f(y), f(x+w), f(y+r), f(y+h-r), f(x+w), f(y+h), f(x+w-r), f(y+h), f(x))
}

func rectPath(x, y, w, h float64) string {
	return fmt.Sprintf("M%s %sH%sV%sH%sZ", f(x), f(y), f(x+w), f(y+h), f(x))
}

// niceCeil rounds v up to a round axis maximum (1, 2, 3, 4, 5, 6 or 8 times a
// power of ten).
func niceCeil(v int) int {
	if v <= 2 {
		return 2
	}
	p := int(math.Pow(10, math.Floor(math.Log10(float64(v)))))
	for _, m := range []int{1, 2, 3, 4, 5, 6, 8} {
		if m*p >= v {
			return m * p
		}
	}
	return 10 * p
}

// compact formats an axis value: 950, 1,2 k, 12 k.
func compact(v int) string {
	switch {
	case v >= 10_000:
		return strconv.Itoa(v/1000) + " k"
	case v >= 1000:
		return strings.Replace(strconv.FormatFloat(float64(v)/1000, 'f', 1, 64), ".", ",", 1) + " k"
	}
	return strconv.Itoa(v)
}

func round2(v float64) float64 { return math.Round(v*100) / 100 }

func f(v float64) string { return strconv.FormatFloat(round2(v), 'f', -1, 64) }
