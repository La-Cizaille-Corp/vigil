package store

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Disabling an account ends its sessions and blocks sign-in, without
// removing it from the audit log; the last active administrator stays.
func TestAccountLifecycle(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	admin, _ := st.CreateUser(ctx, "admin", "hash", "admin")
	alice, _ := st.CreateUser(ctx, "alice", "hash", "analyst")
	st.CreateSession(ctx, "alice-session", alice, "csrf", time.Now().Add(time.Hour))
	st.Audit(ctx, alice, "asset_create", "x")

	if err := st.SetRole(ctx, admin, "analyst"); !errors.Is(err, ErrLastAdmin) {
		t.Errorf("demoting the only admin: %v", err)
	}
	if err := st.SetDisabled(ctx, admin, true); !errors.Is(err, ErrLastAdmin) {
		t.Errorf("disabling the only admin: %v", err)
	}
	if err := st.SetRole(ctx, alice, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetRole(ctx, admin, "viewer"); err != nil {
		t.Errorf("demoting an admin when another remains: %v", err)
	}

	if err := st.SetDisabled(ctx, alice, true); !errors.Is(err, ErrLastAdmin) {
		t.Errorf("disabling the last admin: %v", err)
	}
	st.SetRole(ctx, admin, "admin")
	if err := st.SetDisabled(ctx, alice, true); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Session(ctx, "alice-session"); !errors.Is(err, ErrNotFound) {
		t.Error("session of a disabled user still valid")
	}
	if _, err := st.UserByName(ctx, "alice"); !errors.Is(err, ErrNotFound) {
		t.Error("disabled user can still be looked up for sign-in")
	}
	if err := st.SetRole(ctx, alice, "viewer"); !errors.Is(err, ErrNotFound) {
		t.Errorf("role change on a disabled user: %v", err)
	}
	if audit, _ := st.ListAudit(ctx, 10); len(audit) != 1 || audit[0].Username != "alice" {
		t.Errorf("audit log lost the disabled user: %+v", audit)
	}

	accounts, err := st.ListUsers(ctx)
	if err != nil || len(accounts) != 2 || accounts[0].Username != "admin" || !accounts[1].Disabled {
		t.Fatalf("accounts: %+v %v", accounts, err)
	}
	if err := st.SetDisabled(ctx, alice, false); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UserByName(ctx, "alice"); err != nil {
		t.Errorf("re-enabled user: %v", err)
	}

	st.CreateSession(ctx, "alice-2", alice, "csrf", time.Now().Add(time.Hour))
	if err := st.ResetPassword(ctx, alice, "new-hash"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Session(ctx, "alice-2"); !errors.Is(err, ErrNotFound) {
		t.Error("session survived a password reset")
	}
}

// Two first-run forms cannot both create an administrator.
func TestCreateFirstAdmin(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	if _, err := st.CreateFirstAdmin(ctx, "a", "hash"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateFirstAdmin(ctx, "b", "hash"); !errors.Is(err, ErrNotFound) {
		t.Errorf("second first admin: %v", err)
	}
}

// A new name that differs from an existing one only by case is refused,
// accented letters included, and concurrent creations of case variants let
// only one through. Accounts that already overlap stay, and sign-in still
// looks a name up as typed.
func TestUserNamesIgnoreCase(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	if _, err := st.CreateUser(ctx, "Élise", "hash", "viewer"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Élise", "élise", "ÉLISE"} {
		if _, err := st.CreateUser(ctx, name, "hash", "viewer"); !errors.Is(err, ErrExists) {
			t.Errorf("%s: %v, want ErrExists", name, err)
		}
	}
	if _, err := st.CreateUser(ctx, "Elise", "hash", "viewer"); err != nil {
		t.Errorf("a name without the accent is another name: %v", err)
	}

	var wg sync.WaitGroup
	var created atomic.Int32
	for _, name := range []string{"bob", "Bob", "BOB", "bOb"} {
		wg.Go(func() {
			if _, err := st.CreateUser(ctx, name, "hash", "viewer"); err == nil {
				created.Add(1)
			}
		})
	}
	wg.Wait()
	if n := created.Load(); n != 1 {
		t.Errorf("%d case variants of bob created concurrently", n)
	}

	if _, err := st.db.ExecContext(ctx, `INSERT INTO users (username, password_hash, role, created_at)
		VALUES ('alice', 'lower', 'viewer', ?), ('Alice', 'upper', 'viewer', ?)`, now(), now()); err != nil {
		t.Fatal(err)
	}
	if u, err := st.UserByName(ctx, "Alice"); err != nil || u.PasswordHash != "upper" {
		t.Errorf("sign-in lookup of an overlapping account: %+v %v", u, err)
	}
}

func TestPurgeAudit(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	st.Audit(ctx, 0, "login", "x")
	if n, err := st.PurgeAudit(ctx, time.Now().Add(-time.Hour)); err != nil || n != 0 {
		t.Fatalf("recent entry purged: %d %v", n, err)
	}
	if n, err := st.PurgeAudit(ctx, time.Now().Add(time.Hour)); err != nil || n != 1 {
		t.Fatalf("old entry kept: %d %v", n, err)
	}
	if err := st.SetTOTPPolicy(ctx, "sometimes"); err == nil {
		t.Error("unknown policy accepted")
	}
}

// After a leak, every second factor is removed at once and the sessions of
// those accounts end; accounts without one keep theirs.
func TestResetAllTOTP(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	alice, _ := st.CreateUser(ctx, "alice", "hash", "admin")
	bob, _ := st.CreateUser(ctx, "bob", "hash", "analyst")
	carol, _ := st.CreateUser(ctx, "carol", "hash", "viewer")
	st.SetTOTPPending(ctx, alice, "SECRETA")
	st.EnableTOTP(ctx, alice, 1)
	st.SetTOTPPending(ctx, bob, "SECRETB") // enrolling
	for i, id := range []int64{alice, bob, carol} {
		st.CreateSession(ctx, "s"+string(rune('a'+i)), id, "csrf", time.Now().Add(time.Hour))
	}
	n, err := st.ResetAllTOTP(ctx)
	if err != nil || n != 2 {
		t.Fatalf("reset: %d %v", n, err)
	}
	for _, id := range []int64{alice, bob} {
		if secret, pending, _, _ := st.UserTOTP(ctx, id); secret != "" || pending != "" {
			t.Errorf("user %d keeps a second factor", id)
		}
	}
	if _, err := st.Session(ctx, "sa"); !errors.Is(err, ErrNotFound) {
		t.Error("session of a reset account survived")
	}
	if _, err := st.Session(ctx, "sc"); err != nil {
		t.Errorf("session of an account without second factor ended: %v", err)
	}
}

// An unknown account has no second factor to read: ErrNotFound, as for the
// other lookups, rather than the driver's "no rows".
func TestUserTOTPOfUnknownUser(t *testing.T) {
	st := openTest(t)
	if _, _, _, err := st.UserTOTP(context.Background(), 42); !errors.Is(err, ErrNotFound) {
		t.Errorf("UserTOTP of an unknown user: %v, want ErrNotFound", err)
	}
}
