// Package auth provides password hashing, random tokens and a login rate limiter.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// Roles, from least to most privileged.
const (
	RoleViewer  = "viewer"
	RoleAnalyst = "analyst"
	RoleAdmin   = "admin"
)

// MinPasswordLength follows OWASP ASVS guidance for passwords without MFA.
const MinPasswordLength = 12

// RoleAtLeast reports whether role grants the privileges of required.
func RoleAtLeast(role, required string) bool {
	rank := map[string]int{RoleViewer: 1, RoleAnalyst: 2, RoleAdmin: 3}
	return rank[role] >= rank[required] && rank[required] > 0
}

// ValidRole reports whether role is known.
func ValidRole(role string) bool {
	return role == RoleViewer || role == RoleAnalyst || role == RoleAdmin
}

// Argon2id parameters (OWASP Password Storage Cheat Sheet: m=64 MiB, t=3, p=2 is above the minimum).
const (
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 2
	argonKeyLen  = 32
)

// hashing bounds the argon2 computations running at once: each takes 64 MiB,
// so unbounded concurrent logins could exhaust memory.
// SECURITY: requests beyond the limit wait instead of allocating.
var hashing = make(chan struct{}, min(runtime.NumCPU(), 4))

func idKey(password string, salt []byte, iterations, memory uint32, threads uint8) []byte {
	hashing <- struct{}{}
	defer func() { <-hashing }()
	return argon2.IDKey([]byte(password), salt, iterations, memory, threads, argonKeyLen)
}

// HashPassword returns an encoded argon2id hash.
func HashPassword(password string) (string, error) {
	if utf8.RuneCountInString(password) < MinPasswordLength {
		return "", fmt.Errorf("le mot de passe doit contenir au moins %d caractères", MinPasswordLength)
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := idKey(password, salt, argonTime, argonMemory, argonThreads)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// VerifyPassword checks password against an encoded hash in constant time.
func VerifyPassword(password, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, errors.New("unsupported hash format")
	}
	var version int
	var memory, iterations uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, errors.New("unsupported argon2 version")
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &threads); err != nil {
		return false, fmt.Errorf("parse argon2 parameters: %w", err)
	}
	b64 := base64.RawStdEncoding
	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return false, err
	}
	want, err := b64.DecodeString(parts[5])
	if err != nil {
		return false, err
	}
	if len(want) != argonKeyLen {
		return false, errors.New("unexpected argon2 key length")
	}
	got := idKey(password, salt, iterations, memory, threads)
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// dummyHash is verified when the user does not exist, so that response time
// does not reveal which usernames exist.
var dummyHash, _ = HashPassword("not-a-real-password-just-timing")

// VerifyDummy burns the same CPU time as a real verification.
func VerifyDummy(password string) { _, _ = VerifyPassword(password, dummyHash) }

// NewToken returns a URL-safe random token of 32 bytes.
func NewToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// passwordAlphabet leaves out characters easily confused when read aloud or
// copied by hand (0/O, 1/l/I).
const passwordAlphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// NewPassword returns a random temporary password of 20 characters in groups
// of 5 (about 115 bits), for an administrator to hand over.
func NewPassword() (string, error) {
	var b strings.Builder
	// Bytes above the largest multiple of the alphabet size are skipped, so
	// that every character is equally likely.
	limit := byte(256 / len(passwordAlphabet) * len(passwordAlphabet))
	buf := make([]byte, 64)
	for n := 0; n < 20; {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		for _, r := range buf {
			if r >= limit || n == 20 {
				continue
			}
			if n > 0 && n%5 == 0 {
				b.WriteByte('-')
			}
			b.WriteByte(passwordAlphabet[int(r)%len(passwordAlphabet)])
			n++
		}
	}
	return b.String(), nil
}

// HashToken returns the hex SHA-256 of a token, as stored in the database.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// EqualTokens compares two secrets in constant time.
func EqualTokens(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// Limiter blocks a key (IP address, account) after too many failed logins.
type Limiter struct {
	MaxFailures int
	Window      time.Duration

	mu       sync.Mutex
	failures map[string][]time.Time
}

// NewLimiter returns a limiter allowing max failures per window.
func NewLimiter(max int, window time.Duration) *Limiter {
	return &Limiter{MaxFailures: max, Window: window, failures: map[string][]time.Time{}}
}

// Allowed reports whether key may attempt a login now.
func (l *Limiter) Allowed(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.recent(key)) < l.MaxFailures
}

// Take records an attempt for key and reports whether it was allowed. Unlike
// Allowed followed by Fail, it counts the attempt before the (slow) password
// check, so that concurrent requests cannot all pass. Forgive takes it back
// when the attempt succeeds.
func (l *Limiter) Take(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.recent(key)) >= l.MaxFailures {
		return false
	}
	l.add(key)
	return true
}

// Forgive cancels the last attempt recorded for key.
func (l *Limiter) Forgive(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if f := l.failures[key]; len(f) > 1 {
		l.failures[key] = f[:len(f)-1]
	} else {
		delete(l.failures, key)
	}
}

// maxTrackedKeys caps the limiter memory; when reached, expired entries are
// swept and, if still full, a tenth of the keys is dropped at random. A
// flood of new addresses thus frees only some counters, never all of them.
const maxTrackedKeys = 100_000

// Fail records a failed attempt.
func (l *Limiter) Fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.add(key)
}

func (l *Limiter) add(key string) {
	if len(l.failures) >= maxTrackedKeys {
		l.sweep()
	}
	l.failures[key] = append(l.recent(key), time.Now())
}

// sweep drops the keys whose failures are all outside the window, then
// random keys while the table stays full (map order is random).
func (l *Limiter) sweep() {
	for key := range l.failures {
		l.recent(key)
	}
	for key := range l.failures {
		if len(l.failures) < maxTrackedKeys*9/10 {
			break
		}
		delete(l.failures, key)
	}
}

// Reset clears the failures of key after a successful login.
func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failures, key)
}

func (l *Limiter) recent(key string) []time.Time {
	cutoff := time.Now().Add(-l.Window)
	var kept []time.Time
	for _, t := range l.failures[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if kept == nil {
		delete(l.failures, key)
	} else {
		l.failures[key] = kept
	}
	return kept
}
