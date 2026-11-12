package fr

import (
	"testing"
	"time"
)

func TestDates(t *testing.T) {
	paris, err := time.LoadLocation("Europe/Paris")
	if err != nil {
		paris = time.FixedZone("CET", 3600)
	}
	local := time.Local
	time.Local = paris
	t.Cleanup(func() { time.Local = local })

	moment := time.Date(2026, 2, 9, 23, 30, 0, 0, time.UTC)
	if got := DateTime(moment); got != "10/02/2026 00:30" {
		t.Errorf("DateTime = %s, want the local time", got)
	}
	// A deadline is a day: it keeps its date whatever the time zone.
	due, _ := time.Parse(time.DateOnly, "2026-02-09")
	if got := Date(due); got != "09/02/2026" {
		t.Errorf("Date = %s", got)
	}
	if got := DayMonth(due); got != "09/02" {
		t.Errorf("DayMonth = %s", got)
	}
}

func TestNumbers(t *testing.T) {
	for _, c := range []struct{ got, want string }{
		{Decimal(9.8, 1), "9,8"},
		{Decimal(1234.5, 1), "1234,5"}, // no thousands separator
		{Decimal(2, 0), "2"},
		{Decimal(-1.25, 2), "-1,25"},
		{Score(9.8), "9,8"},
		{Score(10), "10,0"},
		{Score(0), "0,0"}, // a score of 0 is a score
		{Score(-1), ""},   // unknown
		{Percent(0.123), "12,3 %"},
		{Percent(0.9731), "97,3 %"},
		{Percent(0), "0,0 %"},
		{Percent(0.00049), "0,0 %"},
		{Percent(1), "100,0 %"},
		{Percent(-1), ""},
		{Days(0.4), "< 1 j"},
		{Days(3.46), "3,5 j"},
		{Days(9.94), "9,9 j"},
		{Days(12.4), "12 j"},
	} {
		if c.got != c.want {
			t.Errorf("got %q, want %q", c.got, c.want)
		}
	}
}

func TestFuncs(t *testing.T) {
	f := Funcs()
	for _, name := range []string{"date", "day", "cvss", "epss", "days", "join"} {
		if f[name] == nil {
			t.Errorf("no %s", name)
		}
	}
	if got := f["cvss"].(func(float64) string)(9.8); got != "9,8" {
		t.Errorf("cvss = %s", got)
	}
	f["date"] = nil
	if Funcs()["date"] == nil {
		t.Error("Funcs shares its map")
	}
}
