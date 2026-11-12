package tracking_test

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/La-Cizaille-Corp/vigil/internal/store"
	"github.com/La-Cizaille-Corp/vigil/internal/tracking"
)

// Each finding counts once, at its level; the fixed ones under "".
func TestCountLevels(t *testing.T) {
	fs := []store.Finding{
		{Status: store.StatusInTriage, Class: store.AlertPriority},
		{Status: store.StatusExploitable, Class: store.AlertPriority},
		{Status: store.StatusInTriage, Class: store.AlertSevere},
		{Status: store.StatusInTriage},
		{Status: store.StatusFalsePositive, Class: store.AlertPriority},
		{Status: store.StatusResolved, Class: store.AlertSevere},
	}
	got := tracking.CountLevels(fs)
	want := map[string]int{tracking.LevelUrgent: 2, tracking.LevelPlan: 1, tracking.LevelWatch: 1, tracking.LevelAside: 1, "": 1}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("counts %v, want %v", got, want)
	}
}

// A list row or a digest line names three aliases at most; the finding page
// keeps them all.
func TestAliasList(t *testing.T) {
	aliases := tracking.TemplateFuncs()["aliases"].(func([]string) string)
	for n, want := range map[int]string{
		0: "", 1: "A0", 3: "A0, A1, A2", 4: "A0, A1, A2 et 1 autre", 1902: "A0, A1, A2 et 1899 autres",
	} {
		list := make([]string, n)
		for i := range list {
			list[i] = "A" + strconv.Itoa(i)
		}
		if got := aliases(list); got != want {
			t.Errorf("%d aliases: %q, want %q", n, got, want)
		}
	}
}
