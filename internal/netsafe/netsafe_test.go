package netsafe

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"testing/iotest"
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

func TestWebURL(t *testing.T) {
	for raw, want := range map[string]string{
		"https://example.org/a":                  "https://example.org/a",
		"  http://example.org/a?b=c#d \n":        "http://example.org/a?b=c#d",
		"https://example.org/a\n@channel please": "", // a line break would cut a Markdown link
		"https://example.org/a\tb":               "",
		"https://trusted.example@evil.example/":  "", // host hidden behind credentials
		"javascript:alert(1)":                    "",
		"file:///etc/passwd":                     "",
		"//example.org/a":                        "",
		"https://":                               "",
		"":                                       "",
		"https://example.org/" + strings.Repeat("a", MaxURLLen): "",
	} {
		got, ok := WebURL(raw)
		if got != want || ok != (want != "") {
			t.Errorf("WebURL(%q) = %q, %t; want %q", raw, got, ok, want)
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
		"0.1.2.3": false, "::7f00:1": false, "fec0::1": false, "2002:7f00:1::1": false, "2001:0:4136:e378::1": false,
		"::ffff:0:7f00:1": false, "::ffff:0:a00:1": false, // SIIT, IPv4-translated 127.0.0.1 and 10.0.0.1
		"192.88.99.1": false, "100::1": false, "2001:20::1": false,
	} {
		if got := Public(net.ParseIP(addr)); got != want {
			t.Errorf("Public(%s) = %v, want %v", addr, got, want)
		}
	}
}

// TestCheckRedirect: 5 redirects at most, in HTTPS only, and the headers to
// drop leave the request when the host changes.
func TestCheckRedirect(t *testing.T) {
	check := CheckRedirect("apiKey")
	first := httptest.NewRequest(http.MethodGet, "https://a.example/x", nil)
	hop := func(raw string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, raw, nil)
		r.Header.Set("apiKey", "k")
		r.Header.Set("Accept", "application/json")
		return r
	}
	via := []*http.Request{first}
	if r := hop("https://a.example/y"); check(r, via) != nil || r.Header.Get("apiKey") != "k" {
		t.Errorf("same host: headers %v", r.Header)
	}
	if r := hop("https://b.example/y"); check(r, via) != nil || r.Header.Get("apiKey") != "" || r.Header.Get("Accept") == "" {
		t.Errorf("other host: headers %v", r.Header)
	}
	if err := check(hop("http://a.example/y"), via); err == nil {
		t.Error("redirect to http followed")
	}
	if err := check(hop("https://a.example/y"), make([]*http.Request, 5)); err == nil {
		t.Error("sixth redirect followed")
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
	// The proxy is dialed without the guard: a URL naming it is refused.
	if _, err := client.Get("https://" + proxyURL.Host + "/"); !errors.Is(err, ErrForbiddenAddress) {
		t.Errorf("request to the proxy itself: %v", err)
	}
}

// A reading stops at its bound with an error, never as if the data were whole,
// whatever the size of the reads.
func TestLimitReader(t *testing.T) {
	for _, c := range []struct {
		data string
		ok   bool
	}{{"", true}, {"12345", true}, {"123456", false}, {strings.Repeat("x", 10_000), false}} {
		for name, r := range map[string]io.Reader{
			"whole":    strings.NewReader(c.data),
			"one byte": iotest.OneByteReader(strings.NewReader(c.data)),
		} {
			got, err := io.ReadAll(LimitReader(r, 5))
			var tooLarge *TooLargeError
			if c.ok && (err != nil || string(got) != c.data) ||
				!c.ok && (!errors.As(err, &tooLarge) || tooLarge.Max != 5 || len(got) != 5) {
				t.Errorf("%d bytes, %s: %q, %v", len(c.data), name, got, err)
			}
		}
		got, err := ReadLimited(strings.NewReader(c.data), 5)
		if c.ok != (err == nil) || !c.ok && (got != nil || err.Error() != "réponse supérieure à 5 octets") {
			t.Errorf("ReadLimited, %d bytes: %q, %v", len(c.data), got, err)
		}
	}
}
