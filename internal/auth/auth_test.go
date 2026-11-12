package auth

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
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
	for i := range 2 {
		if !l.Take("ip") {
			t.Fatalf("attempt %d blocked too early", i+1)
		}
	}
	if l.Take("ip") {
		t.Fatal("not blocked after max attempts")
	}
	l.Reset("ip")
	if !l.Take("ip") {
		t.Fatal("still blocked after reset")
	}
}

// Take counts the attempt before the password check; Forgive only cancels
// that attempt, never earlier failures.
func TestLimiterTakeForgive(t *testing.T) {
	l := NewLimiter(3, time.Minute)
	l.Take("ip")
	l.Take("ip")
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
	l.Take("new")
	if n := len(l.failures); n < maxTrackedKeys*8/10 || n >= maxTrackedKeys {
		t.Errorf("%d keys after eviction", n)
	}
}

func TestPasswordPolicyAndGenerator(t *testing.T) {
	if _, err := HashPassword("éééééé"); err == nil { // 12 bytes, 6 characters
		t.Error("6-character password accepted")
	}
	// S14: every account is created through HashPassword (setup, vigil user
	// add and reset-password), so none gets a password it cannot sign in with.
	if _, err := HashPassword(strings.Repeat("a", 1025)); err == nil {
		t.Error("1,025-byte password accepted")
	}
	if _, err := HashPassword(strings.Repeat("é", 512)); err != nil { // 1,024 bytes
		t.Errorf("1,024-byte password refused: %v", err)
	}
	p, err := NewPassword()
	if err != nil || len(p) != 23 || strings.ContainsAny(p, "0O1lI") {
		t.Errorf("generated password %q: %v", p, err)
	}
	if q, _ := NewPassword(); q == p {
		t.Error("same password twice")
	}
}

// S14 (ASVS V2.1.7): a password among the most common ones is refused
// whatever its case; a strong one is still accepted.
// The help shown beside password fields says the length HashPassword asks.
func TestPasswordHelpNamesThePolicy(t *testing.T) {
	if want := fmt.Sprintf("%d caractères minimum, ", MinPasswordLength); !strings.HasPrefix(PasswordHelp, want) ||
		!strings.Contains(PasswordHelp, "plus courants") {
		t.Errorf("PasswordHelp = %q, want the length (%q) and the common passwords", PasswordHelp, want)
	}
}

func TestCommonPasswordRefused(t *testing.T) {
	for _, p := range []string{"qwerty123456", "QWERTY123456", "Qwerty123456", "1Qaz2Wsx3Edc"} {
		if _, err := HashPassword(p); !errors.Is(err, errCommonPassword) {
			t.Errorf("common password %q: %v", p, err)
		}
	}
	if _, err := HashPassword("Vigil keeps 3 watches"); err != nil {
		t.Errorf("strong password refused: %v", err)
	}
}

// The embedded list loads whole: 3,000 distinct entries, all lower-cased
// (the lookup lower-cases the password) and none shorter than the minimum
// (HashPassword refuses those already). No entry has the shape of a
// generated password, so temporary passwords never hit the list, and the
// timing dummy is not one of them.
func TestCommonPasswordsList(t *testing.T) {
	if n := len(commonPasswords); n != 3000 {
		t.Errorf("%d common passwords loaded, want 3000", n)
	}
	generated := regexp.MustCompile(`^[a-z0-9]{5}(-[a-z0-9]{5}){3}$`)
	for p := range commonPasswords {
		switch {
		case utf8.RuneCountInString(p) < MinPasswordLength:
			t.Errorf("%q is shorter than %d characters", p, MinPasswordLength)
		case p != strings.ToLower(p):
			t.Errorf("%q is not lower-cased", p)
		case generated.MatchString(p):
			t.Errorf("%q has the shape of a generated password", p)
		}
	}
	if dummyHash == "" {
		t.Error("the timing dummy password is refused")
	}
}
