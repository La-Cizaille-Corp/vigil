package auth

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestPasswordRoundTrip(t *testing.T) {
	hash, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := VerifyPassword("correct horse battery", hash); err != nil || !ok {
		t.Fatalf("valid password rejected: %v", err)
	}
	if ok, _ := VerifyPassword("wrong password!!", hash); ok {
		t.Fatal("wrong password accepted")
	}
	if _, err := HashPassword("short"); err == nil {
		t.Fatal("short password accepted")
	}
}

func TestRoleAtLeast(t *testing.T) {
	cases := []struct {
		role, required string
		want           bool
	}{
		{RoleAdmin, RoleAnalyst, true},
		{RoleAnalyst, RoleAnalyst, true},
		{RoleViewer, RoleAnalyst, false},
		{"", RoleViewer, false},
		{RoleAdmin, "unknown", false},
	}
	for _, c := range cases {
		if got := RoleAtLeast(c.role, c.required); got != c.want {
			t.Errorf("RoleAtLeast(%q, %q) = %v", c.role, c.required, got)
		}
	}
}

func TestLimiter(t *testing.T) {
	l := NewLimiter(2, time.Minute)
	l.Fail("ip")
	if !l.Allowed("ip") {
		t.Fatal("blocked too early")
	}
	l.Fail("ip")
	if l.Allowed("ip") {
		t.Fatal("not blocked after max failures")
	}
	l.Reset("ip")
	if !l.Allowed("ip") {
		t.Fatal("still blocked after reset")
	}
}

// Take counts the attempt before the password check; Forgive only cancels
// that attempt, never earlier failures.
func TestLimiterTakeForgive(t *testing.T) {
	l := NewLimiter(3, time.Minute)
	l.Fail("ip")
	l.Fail("ip")
	if !l.Take("ip") {
		t.Fatal("third attempt refused")
	}
	l.Forgive("ip")
	if !l.Take("ip") || l.Take("ip") {
		t.Fatal("forgive cancelled more than one attempt, or take ignored the limit")
	}
}

// A flood of new keys evicts some counters, never all of them at once.
func TestLimiterEviction(t *testing.T) {
	l := NewLimiter(1, time.Minute)
	for i := range maxTrackedKeys {
		l.failures[fmt.Sprint(i)] = []time.Time{time.Now()}
	}
	l.Fail("new")
	if n := len(l.failures); n < maxTrackedKeys*8/10 || n >= maxTrackedKeys {
		t.Errorf("%d keys after eviction", n)
	}
}

func TestPasswordPolicyAndGenerator(t *testing.T) {
	if _, err := HashPassword("éééééé"); err == nil { // 12 bytes, 6 characters
		t.Error("6-character password accepted")
	}
	p, err := NewPassword()
	if err != nil || len(p) != 23 || strings.ContainsAny(p, "0O1lI") {
		t.Errorf("generated password %q: %v", p, err)
	}
	if q, _ := NewPassword(); q == p {
		t.Error("same password twice")
	}
}
