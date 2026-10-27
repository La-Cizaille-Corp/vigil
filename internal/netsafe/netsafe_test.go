package netsafe

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestValidateURL(t *testing.T) {
	for raw, ok := range map[string]bool{
		"https://example.org/feed":      true,
		"http://example.org/feed":       false,
		"https://user:pw@example.org/x": false,
		"file:///etc/passwd":            false,
		"https://":                      false,
	} {
		if err := ValidateURL(raw); (err == nil) != ok {
			t.Errorf("ValidateURL(%q) = %v", raw, err)
		}
	}
}

func TestClientBlocksLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	_, err := NewClient(5*time.Second, false).Get(srv.URL)
	if !errors.Is(err, ErrForbiddenAddress) {
		t.Fatalf("loopback request not blocked: %v", err)
	}
	resp, err := NewClient(5*time.Second, true).Get(srv.URL)
	if err != nil {
		t.Fatalf("allowPrivate client failed: %v", err)
	}
	resp.Body.Close()
}
