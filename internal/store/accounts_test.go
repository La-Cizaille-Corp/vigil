package store

import (
	"context"
	"errors"
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
	if _, err := st.SessionByHash(ctx, "alice-session"); !errors.Is(err, ErrNotFound) {
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

	accounts, err := st.ListAccounts(ctx)
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
	if _, err := st.SessionByHash(ctx, "alice-2"); !errors.Is(err, ErrNotFound) {
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
	if _, err := st.SessionByHash(ctx, "sa"); !errors.Is(err, ErrNotFound) {
		t.Error("session of a reset account survived")
	}
	if _, err := st.SessionByHash(ctx, "sc"); err != nil {
		t.Errorf("session of an account without second factor ended: %v", err)
	}
}
