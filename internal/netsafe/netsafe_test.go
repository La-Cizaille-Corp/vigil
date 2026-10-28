package netsafe

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
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

func TestPublic(t *testing.T) {
	for addr, want := range map[string]bool{
		"8.8.8.8": true, "2606:4700::1111": true,
		"127.0.0.1": false, "10.1.2.3": false, "169.254.169.254": false, "0.0.0.0": false,
		"100.64.1.1": false, "198.18.0.1": false, "255.255.255.255": false,
		"::ffff:10.0.0.1": false, "64:ff9b::a00:1": false, "::1": false, "fd00::1": false,
	} {
		if got := Public(net.ParseIP(addr)); got != want {
			t.Errorf("Public(%s) = %v, want %v", addr, got, want)
		}
	}
}

// TestProxy: behind a corporate proxy (itself on a private address), public
// destinations go through it and private ones are refused before reaching it.
func TestProxy(t *testing.T) {
	var connects []string
	proxySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connects = append(connects, r.Method+" "+r.Host)
		w.WriteHeader(http.StatusForbidden) // the test only checks what reaches the proxy
	}))
	defer proxySrv.Close()
	proxyURL, _ := url.Parse(proxySrv.URL)
	saved := proxyFromEnv
	proxyFromEnv = func(*http.Request) (*url.URL, error) { return proxyURL, nil }
	defer func() { proxyFromEnv = saved }()

	client := NewClient(5*time.Second, false)
	if _, err := client.Get("https://10.0.0.5/feed"); !errors.Is(err, ErrForbiddenAddress) {
		t.Errorf("private destination through the proxy: %v", err)
	}
	if _, err := client.Get("https://93.184.215.14/feed"); err == nil {
		t.Error("the fake proxy refuses CONNECT: an error was expected")
	}
	if len(connects) != 1 || connects[0] != "CONNECT 93.184.215.14:443" {
		t.Errorf("requests seen by the proxy: %v", connects)
	}
}
