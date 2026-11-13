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
	admin, _ := st.CreateUser(ctx, "admin", "hash", "admin", Access{All: true})
	alice, _ := st.CreateUser(ctx, "alice", "hash", "analyst", Access{All: true})
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
	if _, err := st.CreateFirstAdmin(ctx, "b", "hash"); !errors.Is(err, ErrExists) {
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
	if _, err := st.CreateUser(ctx, "Élise", "hash", "viewer", Access{All: true}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Élise", "élise", "ÉLISE"} {
		if _, err := st.CreateUser(ctx, name, "hash", "viewer", Access{All: true}); !errors.Is(err, ErrExists) {
			t.Errorf("%s: %v, want ErrExists", name, err)
		}
	}
	if _, err := st.CreateUser(ctx, "Elise", "hash", "viewer", Access{All: true}); err != nil {
		t.Errorf("a name without the accent is another name: %v", err)
	}

	var wg sync.WaitGroup
	var created atomic.Int32
	for _, name := range []string{"bob", "Bob", "BOB", "bOb"} {
		wg.Go(func() {
			if _, err := st.CreateUser(ctx, name, "hash", "viewer", Access{All: true}); err == nil {
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
	if err := st.Audit(ctx, 0, "login", "x"); err != nil {
		t.Fatal(err)
	}
	if n, err := st.PurgeAudit(ctx, time.Now().Add(-time.Hour)); err != nil || n != 0 {
		t.Fatalf("recent entry purged: %d %v", n, err)
	}
	if n, err := st.PurgeAudit(ctx, time.Now().Add(time.Hour)); err != nil || n != 1 {
		t.Fatalf("old entry kept: %d %v", n, err)
	}
}

// The policy of the second factor is one of three values; another one is
// refused and leaves it as it was.
func TestTOTPPolicy(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	for _, policy := range []string{TOTPAdmins, TOTPEveryone, TOTPOptional} {
		if err := st.SetTOTPPolicy(ctx, policy); err != nil {
			t.Fatalf("%s: %v", policy, err)
		}
		if got, err := st.TOTPPolicy(ctx); err != nil || got != policy {
			t.Errorf("policy %q, %v; want %q", got, err, policy)
		}
	}
	if err := st.SetTOTPPolicy(ctx, "sometimes"); err == nil {
		t.Error("unknown policy accepted")
	}
	if got, err := st.TOTPPolicy(ctx); err != nil || got != TOTPOptional {
		t.Errorf("policy after a refusal: %q, %v", got, err)
	}
}

// A time step of the second factor is used once: neither it nor an earlier
// one is accepted again, even by requests made at the same time, and the step
// of the enrolment counts as used.
func TestUseTOTPStep(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	id, err := st.CreateUser(ctx, "alice", "hash", "analyst", Access{All: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetTOTPPending(ctx, id, "SECRET"); err != nil {
		t.Fatal(err)
	}
	if err := st.EnableTOTP(ctx, id, 100); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		step int64
		ok   bool
	}{{100, false}, {99, false}, {101, true}, {101, false}, {100, false}, {105, true}} {
		if ok, err := st.UseTOTPStep(ctx, id, c.step); err != nil || ok != c.ok {
			t.Errorf("step %d: %v, %v; want %v", c.step, ok, err, c.ok)
		}
	}
	var wg sync.WaitGroup
	var used atomic.Int32
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := st.UseTOTPStep(ctx, id, 106)
			if err != nil {
				t.Error(err)
			}
			if ok {
				used.Add(1)
			}
		}()
	}
	wg.Wait()
	if n := used.Load(); n != 1 {
		t.Errorf("one step used %d times at once", n)
	}
	if ok, err := st.UseTOTPStep(ctx, 999, 200); err != nil || ok {
		t.Errorf("step of an unknown account: %v, %v", ok, err)
	}
}

// Expired sessions are deleted, the others kept.
func TestDeleteExpiredSessions(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	id, err := st.CreateUser(ctx, "alice", "hash", "analyst", Access{All: true})
	if err != nil {
		t.Fatal(err)
	}
	for token, expires := range map[string]time.Time{"old": time.Now().Add(-time.Minute), "live": time.Now().Add(time.Hour)} {
		if err := st.CreateSession(ctx, token, id, "csrf", expires); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.DeleteExpiredSessions(ctx); err != nil {
		t.Fatal(err)
	}
	var left []string
	rows, err := st.db.QueryContext(ctx, `SELECT token_hash FROM sessions`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var token string
		if err := rows.Scan(&token); err != nil {
			t.Fatal(err)
		}
		left = append(left, token)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	rows.Close()
	if len(left) != 1 || left[0] != "live" {
		t.Errorf("sessions left: %v, want the live one", left)
	}
	if _, err := st.Session(ctx, "live"); err != nil {
		t.Errorf("live session: %v", err)
	}
}

// After a leak, every second factor is removed at once and the sessions of
// those accounts end; accounts without one keep theirs.
func TestResetAllTOTP(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	alice, _ := st.CreateUser(ctx, "alice", "hash", "admin", Access{All: true})
	bob, _ := st.CreateUser(ctx, "bob", "hash", "analyst", Access{All: true})
	carol, _ := st.CreateUser(ctx, "carol", "hash", "viewer", Access{All: true})
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
