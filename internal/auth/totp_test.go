package auth

import (
	"testing"
	"time"
)

// RFC 6238 appendix B, SHA-1 secret "12345678901234567890".
func TestTOTPVectors(t *testing.T) {
	key := []byte("12345678901234567890")
	for unix, want := range map[int64]string{59: "287082", 1111111109: "081804", 2000000000: "279037"} {
		if got := totpCode(key, unix/totpPeriod); got != want {
			t.Errorf("t=%d: %s, want %s", unix, got, want)
		}
	}
}

func TestVerifyTOTP(t *testing.T) {
	secret, _ := NewTOTPSecret()
	key, _ := b32.DecodeString(secret)
	now := time.Unix(1_700_000_000, 0)
	code := totpCode(key, now.Unix()/totpPeriod)
	step, ok := VerifyTOTP(secret, code, now, 0)
	if !ok {
		t.Fatal("valid code rejected")
	}
	if _, ok := VerifyTOTP(secret, code, now, step); ok {
		t.Error("replayed code accepted")
	}
	if _, ok := VerifyTOTP(secret, "000000", now.Add(time.Hour), 0); ok && code == "000000" {
		t.Error("stale code accepted")
	}
}
