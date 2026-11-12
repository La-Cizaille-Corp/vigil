package choice_test

import (
	"slices"
	"testing"

	"github.com/La-Cizaille-Corp/vigil/internal/auth"
	"github.com/La-Cizaille-Corp/vigil/internal/choice"
	"github.com/La-Cizaille-Corp/vigil/internal/cti"
	"github.com/La-Cizaille-Corp/vigil/internal/digest"
	"github.com/La-Cizaille-Corp/vigil/internal/inventory"
	"github.com/La-Cizaille-Corp/vigil/internal/notify"
	"github.com/La-Cizaille-Corp/vigil/internal/tracking"
)

// An option whose label is its value is known: membership is not read from
// the label.
func TestQuestions(t *testing.T) {
	opts := []choice.Option{{Value: "", Label: "Aucune"}, {Value: "Linux", Label: "Linux"}, {Value: "os", Label: "Système"}}
	for _, c := range []struct {
		value, label string
		has          bool
		rank         int
	}{
		{"Linux", "Linux", true, 1},
		{"os", "Système", true, 2},
		{"", "Aucune", true, 0},
		{"bsd", "bsd", false, -1},
	} {
		if got := choice.Label(opts, c.value); got != c.label {
			t.Errorf("Label(%q) = %q, want %q", c.value, got, c.label)
		}
		if got := choice.Has(opts, c.value); got != c.has {
			t.Errorf("Has(%q) = %v", c.value, got)
		}
		if got := choice.Rank(opts, c.value); got != c.rank {
			t.Errorf("Rank(%q) = %d, want %d", c.value, got, c.rank)
		}
	}
	if got := choice.KnownOnly(opts, []string{"os", "bsd", "Linux", "os", ""}); !slices.Equal(got, []string{"os", "Linux", ""}) {
		t.Errorf("KnownOnly = %q", got)
	}
}

// Every list of options has distinct values, each with a label: a value
// listed twice would be offered twice and labelled by the first one only.
func TestNoOptionListedTwice(t *testing.T) {
	for name, opts := range map[string][]choice.Option{
		"auth.Roles":              auth.Roles,
		"inventory.Kinds":         inventory.Kinds,
		"inventory.Criticalities": inventory.Criticalities,
		"inventory.CPEModes":      inventory.CPEModes,
		"tracking.Statuses":       tracking.Statuses,
		"tracking.Severities":     tracking.Severities,
		"tracking.Justifications": tracking.Justifications,
		"notify.Kinds":            notify.Kinds,
		"notify.AlertOptions":     notify.AlertOptions,
		"digest.Levels":           digest.Levels,
		"cti.Countries":           cti.Countries,
		"cti.Sectors":             cti.Sectors,
		"cti.Regulations":         cti.Regulations,
	} {
		if len(opts) == 0 {
			t.Errorf("%s is empty", name)
		}
		seen := map[string]bool{}
		for _, o := range opts {
			if seen[o.Value] {
				t.Errorf("%s lists %q twice", name, o.Value)
			}
			seen[o.Value] = true
			if o.Label == "" {
				t.Errorf("%s: %q has no label", name, o.Value)
			}
		}
	}
}
