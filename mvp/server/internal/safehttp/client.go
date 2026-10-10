// Package safehttp is the only way Tessera makes outbound HTTP requests to
// URLs that tenants or operators configure (OIDC discovery and JWKS, SAML
// metadata, token endpoints, and later the readiness connectors). It defends
// against SSRF (design docs/design/phase-0-platform-security.md §4 I3):
//
//   - https only. Plain http is allowed only in dev, with the loopback
//     exception on, to a literal 127.0.0.1 or [::1] (the dev IdP).
//   - Every address a request connects to is checked after DNS resolution,
//     in the dialer itself, so DNS rebinding cannot slip a private address in
//     between a check and the connect. A host that resolves to any blocked
//     address is refused outright. A net.Dialer Control hook checks the final
//     socket address again.
//   - Blocked: loopback, RFC 1918 and other private, link-local (including
//     the 169.254.169.254 metadata address), CGNAT, multicast, reserved,
//     documentation and translation ranges, IPv4-mapped and -compatible
//     forms of all of these, and the Azure wire server 168.63.129.16.
//   - Redirects are re-checked hop by hop (scheme, address) and may not leave
//     the original host (scheme://host:port) unless the host is explicitly
//     allowed. At most 3 redirects.
//   - 5 s total timeout and a 512 KiB response body limit (after
//     decompression) by default. Proxies from the environment are ignored.
//
// Not yet wired: the readiness connectors (internal/connectors,
// internal/readiness) only simulate their systems today; when a connector
// makes real calls to a customer-configured endpoint, its *http.Client must
// come from New. go-oidc and x/oauth2 take this client through
// oidc.ClientContext and oauth2.HTTPClient (PR6).
package safehttp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
)

// Defaults (§4 I3).
const (
	DefaultTimeout      = 5 * time.Second
	DefaultMaxBodyBytes = 512 << 10
	DefaultMaxRedirects = 3
)

var (
	// ErrScheme: the URL is not https (or http outside the dev loopback exception).
	ErrScheme = errors.New("safehttp: scheme not allowed")
	// ErrURL: the URL has user info or no host.
	ErrURL = errors.New("safehttp: URL not allowed")
	// ErrBlockedAddress: the host is or resolves to a blocked address.
	ErrBlockedAddress = errors.New("safehttp: destination address not allowed")
	// ErrRedirect: a redirect leaves the original host, downgrades the scheme or exceeds the limit.
	ErrRedirect = errors.New("safehttp: redirect not allowed")
	// ErrTooLarge: the response body exceeds the limit.
	ErrTooLarge = errors.New("safehttp: response body too large")
)

// Resolver looks up a host's addresses. *net.Resolver implements it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Options configure a client. The zero value except Env is a production
// client with the defaults.
type Options struct {
	// Env is config.Dev or config.Prod. It is required: the loopback
	// exception and plain http exist only in dev.
	Env string
	// AllowLoopback lets the client reach 127.0.0.1 and ::1 (and use plain
	// http to them). Dev only; New refuses it otherwise.
	AllowLoopback bool
	// AllowedRedirectHosts are extra host names redirects may go to
	// (exact, case-insensitive). The address checks still apply.
	AllowedRedirectHosts []string
	Timeout              time.Duration // total per request, including redirects and the body
	MaxBodyBytes         int64
	MaxRedirects         int
	// RootCAs replaces the system roots (a private CA, or a test server).
	RootCAs *x509.CertPool
	// Resolver replaces DNS resolution (custom DNS, tests).
	Resolver Resolver
}

// ForConfig returns the client for the running configuration.
func ForConfig(c *config.Config) (*http.Client, error) {
	return New(Options{Env: c.Env, AllowLoopback: c.OutboundAllowLoopback})
}

// New returns an SSRF-guarded *http.Client.
func New(o Options) (*http.Client, error) {
	switch o.Env {
	case config.Dev, config.Prod:
	default:
		return nil, fmt.Errorf("safehttp: Options.Env must be %q or %q (got %q)", config.Dev, config.Prod, o.Env)
	}
	if o.AllowLoopback && o.Env != config.Dev {
		return nil, errors.New("safehttp: the loopback exception is only allowed with TESSERA_ENV=dev")
	}
	if o.Timeout <= 0 {
		o.Timeout = DefaultTimeout
	}
	if o.MaxBodyBytes <= 0 {
		o.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if o.MaxRedirects <= 0 {
		o.MaxRedirects = DefaultMaxRedirects
	}
	if o.Resolver == nil {
		o.Resolver = net.DefaultResolver
	}
	allowed := make([]string, 0, len(o.AllowedRedirectHosts))
	for _, h := range o.AllowedRedirectHosts {
		allowed = append(allowed, strings.ToLower(strings.TrimSpace(h)))
	}
	o.AllowedRedirectHosts = allowed

	d := &dialer{o: o}
	d.net = net.Dialer{Timeout: o.Timeout, Control: d.control}
	tr := &http.Transport{
		Proxy:                  nil, // never send to a proxy: the address check would check the proxy
		DialContext:            d.dial,
		ForceAttemptHTTP2:      true,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: o.RootCAs},
		TLSHandshakeTimeout:    o.Timeout,
		ResponseHeaderTimeout:  o.Timeout,
		MaxResponseHeaderBytes: 64 << 10,
		IdleConnTimeout:        30 * time.Second,
		MaxIdleConns:           16,
	}
	return &http.Client{
		Transport:     &guard{next: tr, o: o},
		Timeout:       o.Timeout,
		CheckRedirect: checkRedirect(o),
	}, nil
}

// Response is a fully read, size-limited response.
type Response struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

// Get fetches rawURL with c (a client from New) and reads the whole body.
func Get(ctx context.Context, c *http.Client, rawURL string) (*Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrURL, err)
	}
	resp, err := c.Do(req) // #nosec G704 -- c is a safehttp client: scheme, address and redirect checks apply
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return &Response{StatusCode: resp.StatusCode, Header: resp.Header, Body: body}, nil
}

// ---------------------------------------------------------------- URL and redirect rules

// guard checks every request the client sends (the first and each redirect)
// and limits every response body.
type guard struct {
	next http.RoundTripper
	o    Options
}

func (g *guard) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := checkURL(req.URL, g.o); err != nil {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, err
	}
	resp, err := g.next.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if resp.ContentLength > g.o.MaxBodyBytes {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("%w: %d bytes declared, limit %d", ErrTooLarge, resp.ContentLength, g.o.MaxBodyBytes)
	}
	resp.Body = &limitedBody{rc: resp.Body, left: g.o.MaxBodyBytes}
	return resp, nil
}

func checkURL(u *url.URL, o Options) error {
	scheme, host := strings.ToLower(u.Scheme), u.Hostname()
	if scheme != "https" && scheme != "http" {
		return fmt.Errorf("%w: %q", ErrScheme, u.Scheme)
	}
	if u.User != nil {
		return fmt.Errorf("%w: user info in URL", ErrURL)
	}
	if host == "" {
		return fmt.Errorf("%w: no host", ErrURL)
	}
	if scheme == "http" {
		if o.Env == config.Dev && o.AllowLoopback {
			if a, err := netip.ParseAddr(host); err == nil && isDevLoopback(a) {
				return nil
			}
		}
		return fmt.Errorf("%w: http://%s (https only)", ErrScheme, host)
	}
	return nil
}

func checkRedirect(o Options) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) > o.MaxRedirects {
			return fmt.Errorf("%w: more than %d redirects", ErrRedirect, o.MaxRedirects)
		}
		orig := via[0].URL
		if strings.EqualFold(orig.Scheme, "https") && !strings.EqualFold(req.URL.Scheme, "https") {
			return fmt.Errorf("%w: https downgraded to %s", ErrRedirect, req.URL.Scheme)
		}
		if sameOrigin(orig, req.URL) || slices.Contains(o.AllowedRedirectHosts, strings.ToLower(req.URL.Hostname())) {
			return nil
		}
		return fmt.Errorf("%w: %s redirected to another host %s", ErrRedirect, orig.Host, req.URL.Host)
	}
}

func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Hostname(), b.Hostname()) && port(a) == port(b)
}

func port(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if strings.EqualFold(u.Scheme, "http") {
		return "80"
	}
	return "443"
}

// limitedBody fails (rather than silently truncating) once more than the
// limit has been read.
type limitedBody struct {
	rc   io.ReadCloser
	left int64
}

func (l *limitedBody) Read(p []byte) (int, error) {
	if l.left < 0 {
		return 0, ErrTooLarge
	}
	if int64(len(p)) > l.left+1 {
		p = p[:l.left+1]
	}
	n, err := l.rc.Read(p)
	l.left -= int64(n)
	if l.left < 0 {
		return n + int(l.left), ErrTooLarge
	}
	return n, err
}

func (l *limitedBody) Close() error { return l.rc.Close() }

// ---------------------------------------------------------------- addresses

type dialer struct {
	o   Options
	net net.Dialer
}

// dial resolves the host once, refuses it if any address is blocked, and
// connects only to the checked addresses.
func (d *dialer) dial(ctx context.Context, network, address string) (net.Conn, error) {
	host, p, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	var addrs []netip.Addr
	if a, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{a}
	} else if addrs, err = d.o.Resolver.LookupNetIP(ctx, "ip", host); err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("safehttp: %s has no addresses", host)
	}
	for _, a := range addrs {
		if err := d.check(a); err != nil {
			return nil, fmt.Errorf("%w: %s resolves to %s", ErrBlockedAddress, host, a)
		}
	}
	var errs []error
	for _, a := range addrs {
		conn, err := d.net.DialContext(ctx, network, net.JoinHostPort(a.Unmap().String(), p))
		if err == nil {
			return conn, nil
		}
		errs = append(errs, err)
	}
	return nil, errors.Join(errs...)
}

// control re-checks the socket address just before connect.
func (d *dialer) control(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrBlockedAddress, address)
	}
	return d.check(ap.Addr())
}

func (d *dialer) check(a netip.Addr) error {
	a = a.Unmap()
	if d.o.AllowLoopback && isDevLoopback(a) {
		return nil
	}
	if Blocked(a) {
		return fmt.Errorf("%w: %s", ErrBlockedAddress, a)
	}
	return nil
}

var (
	devLoopback4 = netip.MustParseAddr("127.0.0.1")
	devLoopback6 = netip.IPv6Loopback()
)

func isDevLoopback(a netip.Addr) bool {
	a = a.WithZone("").Unmap()
	return a == devLoopback4 || a == devLoopback6
}

// blockedPrefixes are the special-purpose ranges (IANA IPv4 and IPv6
// special-purpose registries) that are never a legitimate public endpoint.
var blockedPrefixes = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		// IPv4
		"0.0.0.0/8",        // "this network"
		"10.0.0.0/8",       // RFC 1918
		"100.64.0.0/10",    // CGNAT (also Alibaba metadata 100.100.100.200)
		"127.0.0.0/8",      // loopback
		"169.254.0.0/16",   // link-local, cloud metadata 169.254.169.254
		"172.16.0.0/12",    // RFC 1918
		"192.0.0.0/24",     // IETF protocol assignments (Oracle metadata 192.0.0.192)
		"192.0.2.0/24",     // TEST-NET-1
		"192.88.99.0/24",   // 6to4 relay anycast
		"192.168.0.0/16",   // RFC 1918
		"198.18.0.0/15",    // benchmarking
		"198.51.100.0/24",  // TEST-NET-2
		"203.0.113.0/24",   // TEST-NET-3
		"224.0.0.0/4",      // multicast
		"240.0.0.0/4",      // reserved, broadcast
		"168.63.129.16/32", // Azure wire server / metadata
		// IPv6
		"::/96",          // unspecified, loopback, IPv4-compatible
		"::ffff:0:0/96",  // IPv4-mapped (also unmapped before checking)
		"64:ff9b::/96",   // NAT64
		"64:ff9b:1::/48", // local-use NAT64
		"100::/64",       // discard
		"2001::/23",      // IETF protocol assignments (Teredo 2001::/32)
		"2001:db8::/32",  // documentation
		"2002::/16",      // 6to4 (can embed a private IPv4)
		"3fff::/20",      // documentation
		"5f00::/16",      // SRv6 SIDs
		"fc00::/7",       // unique local (AWS IPv6 metadata fd00:ec2::254)
		"fe80::/10",      // link-local
		"fec0::/10",      // site-local (deprecated)
		"ff00::/8",       // multicast
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// Blocked reports whether a is never an allowed outbound destination
// (ignoring the dev loopback exception).
func Blocked(a netip.Addr) bool {
	a = a.WithZone("").Unmap()
	if !a.IsValid() || !a.IsGlobalUnicast() || a.IsPrivate() {
		return true
	}
	for _, p := range blockedPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
