// Package netsafe provides HTTP clients for user-supplied URLs (CTI feeds,
// webhooks) with protection against server-side request forgery.
package netsafe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"syscall"
	"time"
)

// ErrForbiddenAddress is returned when a URL resolves to a blocked address.
var ErrForbiddenAddress = errors.New("adresse de destination interdite (réseau privé ou local)")

// ValidateURL checks that raw is an absolute https URL without credentials.
func ValidateURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("URL invalide")
	}
	if u.Scheme != "https" {
		return errors.New("seules les URL https sont acceptées")
	}
	if u.Host == "" || u.User != nil {
		return errors.New("URL invalide")
	}
	if len(raw) > 2000 {
		return errors.New("URL trop longue")
	}
	return nil
}

// proxyFromEnv is the proxy configuration (HTTPS_PROXY, NO_PROXY), replaced in tests.
var proxyFromEnv = http.ProxyFromEnvironment

// NewClient returns an HTTP client. Unless allowPrivate is set, connections
// to loopback, private, link-local and unspecified addresses are refused at
// dial time, after DNS resolution, which also defeats DNS rebinding.
//
// A proxy set in the environment (HTTPS_PROXY, NO_PROXY) is used, and only
// the proxy's own address may be private. The proxy resolves names itself:
// the destination is checked here first, but a name could resolve to another
// address for the proxy (DNS rebinding). The proxy is still asked for the
// name, not the checked address, because company proxies filter by domain.
// The residual risk is small: only https is allowed, and the certificate is
// checked against the name, which an internal service cannot present, so no
// request reaches it; at most a connection is attempted.
func NewClient(timeout time.Duration, allowPrivate bool) *http.Client {
	direct := &net.Dialer{Timeout: 10 * time.Second}
	dial := direct.DialContext
	proxy := proxyFromEnv
	if !allowPrivate {
		// SECURITY: SSRF guard on the actual IP being connected to.
		guarded := &net.Dialer{Timeout: 10 * time.Second, Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip := net.ParseIP(host)
			if ip == nil || !Public(ip) {
				return ErrForbiddenAddress
			}
			return nil
		}}
		proxyAddr := proxyAddress()
		dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
			if proxyAddr != "" && addr == proxyAddr {
				return direct.DialContext(ctx, network, addr) // the operator's proxy
			}
			return guarded.DialContext(ctx, network, addr)
		}
		proxy = func(req *http.Request) (*url.URL, error) {
			// SECURITY: the proxy is dialed without the guard: a URL naming
			// the proxy itself (direct when NO_PROXY covers it) is refused.
			if proxyAddr != "" && canonicalAddr(req.URL) == proxyAddr {
				return nil, ErrForbiddenAddress
			}
			p, err := proxyFromEnv(req)
			if err != nil || p == nil {
				return p, err
			}
			// SECURITY: through a proxy, the dial check only sees the proxy:
			// check where the request goes before handing it over.
			if err := checkHost(req.Context(), req.URL.Hostname()); err != nil {
				return nil, err
			}
			return p, nil
		}
	}
	transport := &http.Transport{
		Proxy:                 proxy,
		DialContext:           dial,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		MaxIdleConns:          10,
		IdleConnTimeout:       60 * time.Second,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("trop de redirections")
			}
			if req.URL.Scheme != "https" {
				return errors.New("redirection vers une URL non https refusée")
			}
			return nil
		},
	}
}

// proxyAddress returns the host:port of the proxy used for https URLs, as
// the transport dials it, or "" without a proxy.
func proxyAddress() string {
	p, err := proxyFromEnv(&http.Request{URL: &url.URL{Scheme: "https", Host: "vigil.invalid"}})
	if err != nil || p == nil {
		return ""
	}
	return canonicalAddr(p)
}

// canonicalAddr is the host:port a URL is dialed at.
func canonicalAddr(u *url.URL) string {
	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}
	return net.JoinHostPort(u.Hostname(), port)
}

// checkHost refuses a host name that resolves to a non-public address.
func checkHost(ctx context.Context, host string) error {
	if ip := net.ParseIP(host); ip != nil {
		if !Public(ip) {
			return ErrForbiddenAddress
		}
		return nil
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return err
	}
	for _, a := range addrs {
		if !Public(a.IP) {
			return ErrForbiddenAddress
		}
	}
	return nil
}

// nonPublic lists special-purpose ranges not covered by the net.IP helpers.
var nonPublic = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"), // carrier-grade NAT
	netip.MustParsePrefix("192.0.0.0/24"),  // IETF protocol assignments
	netip.MustParsePrefix("198.18.0.0/15"), // benchmarking
	netip.MustParsePrefix("240.0.0.0/4"),   // reserved, includes broadcast
	netip.MustParsePrefix("64:ff9b::/96"),  // NAT64: may reach internal IPv4
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("2001:db8::/32"), // documentation
}

// Public reports whether ip is a globally routable address.
func Public(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() ||
		ip.IsInterfaceLocalMulticast() {
		return false
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	for _, p := range nonPublic {
		if p.Contains(addr) {
			return false
		}
	}
	return true
}

// ReadLimited reads at most max bytes of r and fails if there is more.
func ReadLimited(r io.Reader, max int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("réponse supérieure à %d octets", max)
	}
	return b, nil
}
