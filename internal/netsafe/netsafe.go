// Package netsafe provides HTTP clients for user-supplied URLs (CTI feeds,
// webhooks) with protection against server-side request forgery.
package netsafe

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
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

// NewClient returns an HTTP client. Unless allowPrivate is set, connections
// to loopback, private, link-local and unspecified addresses are refused at
// dial time, after DNS resolution, which also defeats DNS rebinding.
func NewClient(timeout time.Duration, allowPrivate bool) *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	if !allowPrivate {
		// SECURITY: SSRF guard on the actual IP being connected to.
		dialer.Control = func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip := net.ParseIP(host)
			if ip == nil || !Public(ip) {
				return ErrForbiddenAddress
			}
			return nil
		}
	}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
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

// Public reports whether ip is a globally routable address.
func Public(ip net.IP) bool {
	return !(ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() ||
		ip.IsInterfaceLocalMulticast())
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
