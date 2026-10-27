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
	"strings"
	"sync"
	"time"

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

// HashPassword returns an encoded argon2id hash.
func HashPassword(password string) (string, error) {
	if len(password) < MinPasswordLength {
		return "", fmt.Errorf("le mot de passe doit contenir au moins %d caractères", MinPasswordLength)
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
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
	got := argon2.IDKey([]byte(password), salt, iterations, memory, threads, argonKeyLen)
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

// HashToken returns the hex SHA-256 of a token, as stored in the database.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// EqualTokens compares two secrets in constant time.
func EqualTokens(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// Limiter blocks a key (IP address) after too many failed logins.
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

// maxTrackedKeys caps the limiter memory; when reached, expired entries are
// swept and, if still full, the table is reset (fail-open for availability,
// each key still needs MaxFailures new attempts to be blocked).
const maxTrackedKeys = 100_000

// Fail records a failed attempt.
func (l *Limiter) Fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.failures) >= maxTrackedKeys {
		l.sweep()
	}
	l.failures[key] = append(l.recent(key), time.Now())
}

// sweep drops the keys whose failures are all outside the window.
func (l *Limiter) sweep() {
	for key := range l.failures {
		l.recent(key)
	}
	if len(l.failures) >= maxTrackedKeys {
		clear(l.failures)
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
