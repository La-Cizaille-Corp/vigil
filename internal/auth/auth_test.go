package auth

import (
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
