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
//   - Destination ports: 443 and 8443 only, unless the connection's own
//     configuration names the port in its URL (WithConfiguredPorts; that
//     host and port only). The dev loopback exception (127.0.0.1, [::1])
//     allows any port, so the dev IdP on :8001 keeps working.
//   - Host names that are numeric (2130706433, 0177.0.0.1, 0x7f.1: forms a
//     resolver may read as an IPv4 address) and IPv6 literals with a zone
//     are refused before any lookup.
//   - Redirects are re-checked hop by hop (scheme, port, address) and may not
//     leave the original host (scheme://host:port) unless the host is
//     explicitly allowed, and then only to an allowed port. At most 3
//     redirects.
//   - 5 s total timeout and a 512 KiB response body limit (after
//     decompression) by default. Proxies from the environment are ignored.
//
// ForConfig is the only constructor for production code: Env and the
// loopback exception come from a validated *config.Config, never from a call
// site. Tests use NewForTest, which refuses to run outside a test binary
// (and internal/archtest bans it from non-test files).
//
// The demo connectors and the readiness checks only simulate their systems.
// The production connectors (internal/connectors/okta and entra) call a
// customer-configured endpoint with the server's shared outbound client
// (api.Config.OutboundHTTP, built by ForConfig); they never build their own. go-oidc and x/oauth2 take this client through
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
	"strconv"
	"strings"
	"syscall"
	"testing"
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
	// ErrPort: the destination port is not allowed.
	ErrPort = errors.New("safehttp: destination port not allowed")
)

// defaultAllowedPorts are the destination ports allowed without a
// configured URL naming another one.
func defaultAllowedPorts() []int { return []int{443, 8443} }

// Resolver looks up a host's addresses. *net.Resolver implements it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Options configure a test client (NewForTest). The zero value except Env
// is a production client with the defaults. Production clients come only
// from ForConfig.
type Options struct {
	// Env is config.Dev or config.Prod. It is required: the loopback
	// exception and plain http exist only in dev.
	Env string
	// AllowLoopback lets the client reach 127.0.0.1 and ::1 (and use plain
	// http to them, on any port). Dev only; refused otherwise.
	AllowLoopback bool
	// AllowedRedirectHosts are extra host names redirects may go to
	// (exact, case-insensitive). The port and address checks still apply.
	AllowedRedirectHosts []string
	// AllowedPorts replaces the default destination ports (443, 8443).
	AllowedPorts []int
	Timeout      time.Duration // total per request, including redirects and the body
	MaxBodyBytes int64
	MaxRedirects int
	// RootCAs replaces the system roots (a private CA, or a test server).
	RootCAs *x509.CertPool
	// Resolver replaces DNS resolution (custom DNS, tests).
	Resolver Resolver
}

// ForConfig returns the client for the running configuration, the only
// constructor production code may use. The environment and the loopback
// exception are the ones config.Load validated (config.Config.Outbound): a
// hand-built Config is refused, and editing a loaded Config's fields has no
// effect. A TESSERA_ENV=test server gets the production client (no loopback
// exception).
func ForConfig(c *config.Config) (*http.Client, error) {
	env, loopback, ok := c.Outbound()
	if !ok {
		return nil, errors.New("safehttp: ForConfig needs a configuration from config.Load")
	}
	o := Options{Env: config.Prod}
	if env == config.Dev {
		o = Options{Env: config.Dev, AllowLoopback: loopback}
	}
	return newClient(o)
}

// ForConfigLimits is ForConfig with a different total timeout and body limit,
// for a caller whose responses are far larger than OIDC discovery (the AWS
// connector's IAM and Organizations pages). The SSRF guard is unchanged; zero
// values keep the defaults.
func ForConfigLimits(c *config.Config, timeout time.Duration, maxBodyBytes int64) (*http.Client, error) {
	env, loopback, ok := c.Outbound()
	if !ok {
		return nil, errors.New("safehttp: ForConfigLimits needs a configuration from config.Load")
	}
	o := Options{Env: config.Prod}
	if env == config.Dev {
		o = Options{Env: config.Dev, AllowLoopback: loopback}
	}
	o.Timeout, o.MaxBodyBytes = timeout, maxBodyBytes
	return newClient(o)
}

// ForCLIEnv is ForCLI for a command-line tool whose user names the
// environment (the reference CLI reads TESSERA_ENV): only "dev" gets the
// loopback exception and plain http, so a CLI pointed at a local development
// server works; any other value, an empty one included, gets the production
// rules. The server never uses it (ForConfig decides there, from the validated
// configuration). Zero timeout and maxBodyBytes keep the defaults.
func ForCLIEnv(env string, timeout time.Duration, maxBodyBytes int64) (*http.Client, error) {
	o := Options{Env: config.Prod, Timeout: timeout, MaxBodyBytes: maxBodyBytes}
	if env == config.Dev {
		o.Env, o.AllowLoopback = config.Dev, true
	}
	return newClient(o)
}

// ForCLI returns a production client (no loopback exception, https only,
// default ports) with a longer timeout and a larger body limit, for the
// `tessera catalog` command, which runs without a server configuration and
// downloads large public files. Zero values keep the defaults.
func ForCLI(timeout time.Duration, maxBodyBytes int64) (*http.Client, error) {
	return newClient(Options{Env: config.Prod, Timeout: timeout, MaxBodyBytes: maxBodyBytes})
}

// NewForTest returns a client with any Options, for tests only. It refuses
// to run outside a test binary; internal/archtest bans it from non-test
// files.
func NewForTest(tb testing.TB, o Options) (*http.Client, error) {
	if tb == nil || !testing.Testing() {
		return nil, errors.New("safehttp: NewForTest is for tests only; use ForConfig")
	}
	tb.Helper()
	return newClient(o)
}

// ports is a set of host|port pairs a connection's configuration names.
type ports map[string]bool

// portsKey carries a client's configured ports from the guard to the dialer.
// It is unexported, so no caller can add ports through a context.
type portsKey struct{}

// WithConfiguredPorts returns a copy of c (a client from ForConfig) that
// also allows the host and port of each configured URL naming a port
// explicitly (for example an IdP issuer https://idp.example.com:9443). Only
// that host gets the port: a redirect or a discovered endpoint on another
// host still needs an allowed port. Callers pass URLs from the stored
// connection configuration, never from a response. The copy shares c's
// connection pool; c is unchanged. A client that is not a safehttp client is
// returned as is.
func WithConfiguredPorts(c *http.Client, urls ...string) *http.Client {
	g, ok := c.Transport.(*guard)
	if !ok {
		return c
	}
	m := make(ports, len(g.ports)+len(urls))
	for k := range g.ports {
		m[k] = true
	}
	for _, s := range urls {
		u, err := url.Parse(s)
		if err != nil || u.Port() == "" || u.Hostname() == "" {
			continue
		}
		m[hostPort(u.Hostname(), u.Port())] = true
	}
	return &http.Client{Transport: &guard{next: g.next, o: g.o, ports: m}, Timeout: c.Timeout,
		CheckRedirect: checkRedirect(g.o, m), Jar: c.Jar}
}

// WithClientTLS returns a copy of c (a client from ForConfig) that presents certs as its TLS client certificate and,
// when roots is not nil, verifies server certificates against roots instead of the system roots. Every other rule of
// the guard (addresses, ports, redirects, size limits) is unchanged. The copy has its own connection pool, so it is
// meant to live for one pass of work, not forever. ok is false, with c returned as it is, when c is not a safehttp
// client.
func WithClientTLS(c *http.Client, certs []tls.Certificate, roots *x509.CertPool) (*http.Client, bool) {
	g, ok := c.Transport.(*guard)
	if !ok {
		return c, false
	}
	tr, ok := g.next.(*http.Transport)
	if !ok {
		return c, false
	}
	tr = tr.Clone()
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: certs}
	if tr.TLSClientConfig != nil {
		cfg = tr.TLSClientConfig.Clone()
		cfg.Certificates = certs
	}
	if roots != nil {
		cfg.RootCAs = roots
	}
	tr.TLSClientConfig = cfg
	return &http.Client{Transport: &guard{next: tr, o: g.o, ports: g.ports}, Timeout: c.Timeout,
		CheckRedirect: c.CheckRedirect, Jar: c.Jar}, true
}

func hostPort(host, port string) string { return strings.ToLower(host) + "|" + port }

// portAllowed reports whether a request may connect to host:port.
func portAllowed(o Options, configured ports, host, port string) bool {
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return false
	}
	if o.AllowLoopback {
		if a, err := netip.ParseAddr(host); err == nil && a.Zone() == "" && isDevLoopback(a) {
			return true
		}
		if isDevLocalhost(host) {
			return true
		}
	}
	return slices.Contains(o.AllowedPorts, p) || configured[hostPort(host, port)]
}

func newClient(o Options) (*http.Client, error) {
	switch o.Env {
	case config.Dev, config.Prod:
	default:
		return nil, fmt.Errorf("safehttp: Options.Env must be %q or %q (got %q)", config.Dev, config.Prod, o.Env)
	}
	if o.AllowLoopback && o.Env != config.Dev {
		return nil, errors.New("safehttp: the loopback exception is only allowed with TESSERA_ENV=dev")
	}
	if len(o.AllowedPorts) == 0 {
		o.AllowedPorts = defaultAllowedPorts()
	} else {
		o.AllowedPorts = slices.Clone(o.AllowedPorts)
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
		CheckRedirect: checkRedirect(o, nil),
	}, nil
}

// DialFunc opens a connection like net.Dialer.DialContext.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// NewDialer returns the guarded dialer New uses, for protocols other than
// HTTP (the SMTP sender): the host is resolved once, refused if any of its
// addresses is blocked (private, loopback, link-local, metadata and the
// other ranges above), and only the checked addresses are connected to. The
// dev loopback exception applies exactly as for New. Timeout, Env,
// AllowLoopback, AllowedPorts (the relay port; none by default) and
// Resolver are the only options it reads.
func NewDialer(o Options) (DialFunc, error) {
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
	if o.Resolver == nil {
		o.Resolver = net.DefaultResolver
	}
	d := &dialer{o: o}
	d.net = net.Dialer{Timeout: o.Timeout, Control: d.control}
	return d.dial, nil
}

// Response is a fully read, size-limited response.
type Response struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

// Get fetches rawURL with c (a client from ForConfig) and reads the whole body.
func Get(ctx context.Context, c *http.Client, rawURL string) (*Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrURL, err)
	}
	resp, err := c.Do(req)
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
	next  http.RoundTripper
	o     Options
	ports ports // WithConfiguredPorts
}

func (g *guard) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := checkURL(req.URL, g.o, g.ports); err != nil {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, err
	}
	if len(g.ports) > 0 { // for the dialer's own port check
		req = req.WithContext(context.WithValue(req.Context(), portsKey{}, g.ports))
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

func checkURL(u *url.URL, o Options, configured ports) error {
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
	if err := checkHost(host); err != nil {
		return err
	}
	if scheme == "http" {
		a, err := netip.ParseAddr(host)
		if !(o.Env == config.Dev && o.AllowLoopback && ((err == nil && isDevLoopback(a)) || isDevLocalhost(host))) {
			return fmt.Errorf("%w: http://%s (https only)", ErrScheme, host)
		}
	}
	if p := port(u); !portAllowed(o, configured, host, p) {
		return fmt.Errorf("%w: %s port %s", ErrPort, host, p)
	}
	return nil
}

// checkHost refuses host forms that are not a plain DNS name or a canonical
// IP literal: an IPv6 zone (scoped, never a public endpoint), and names whose
// last label is numeric, which inet_aton-style resolvers read as IPv4
// (2130706433 and 0177.0.0.1 are 127.0.0.1; 0x7f.1 too).
func checkHost(host string) error {
	if a, err := netip.ParseAddr(host); err == nil {
		if a.Zone() != "" {
			return fmt.Errorf("%w: %s has an IPv6 zone", ErrBlockedAddress, host)
		}
		return nil
	}
	if strings.ContainsAny(host, "%:[]") {
		return fmt.Errorf("%w: invalid host %q", ErrURL, host)
	}
	labels := strings.Split(strings.TrimSuffix(host, "."), ".")
	last := strings.ToLower(labels[len(labels)-1])
	if numericLabel(last) {
		return fmt.Errorf("%w: numeric host %q is not a canonical IP address", ErrURL, host)
	}
	return nil
}

func numericLabel(l string) bool {
	if h, ok := strings.CutPrefix(l, "0x"); ok {
		l = h
		if l == "" {
			return true
		}
		for _, c := range l {
			if !strings.ContainsRune("0123456789abcdef", c) {
				return false
			}
		}
		return true
	}
	if l == "" {
		return false
	}
	for _, c := range l {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func checkRedirect(o Options, configured ports) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) > o.MaxRedirects {
			return fmt.Errorf("%w: more than %d redirects", ErrRedirect, o.MaxRedirects)
		}
		orig := via[0].URL
		if strings.EqualFold(orig.Scheme, "https") && !strings.EqualFold(req.URL.Scheme, "https") {
			return fmt.Errorf("%w: https downgraded to %s", ErrRedirect, req.URL.Scheme)
		}
		if sameOrigin(orig, req.URL) {
			return nil
		}
		host := strings.ToLower(req.URL.Hostname())
		if !slices.Contains(o.AllowedRedirectHosts, host) {
			return fmt.Errorf("%w: %s redirected to another host %s", ErrRedirect, orig.Host, req.URL.Host)
		}
		// an allowed host is allowed on the allowed ports only
		if p := port(req.URL); !portAllowed(o, configured, host, p) {
			return fmt.Errorf("%w: %s redirected to %s on port %s", ErrRedirect, orig.Host, host, p)
		}
		return nil
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
	// the port and host form again, at the connection: a request that
	// reached the transport without the guard cannot open a socket elsewhere
	if err := checkHost(host); err != nil {
		return nil, err
	}
	configured, _ := ctx.Value(portsKey{}).(ports)
	if !portAllowed(d.o, configured, host, p) {
		return nil, fmt.Errorf("%w: %s port %s", ErrPort, host, p)
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
	if a.Zone() != "" { // a scoped (zoned) address is never a public endpoint
		return fmt.Errorf("%w: %s has an IPv6 zone", ErrBlockedAddress, a)
	}
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

// isDevLocalhost is the exact name "localhost", which run.sh publishes as the
// dev issuer (TESSERA_PUBLIC_URL=http://localhost:$UI_PORT; a WebAuthn RP ID
// cannot be an IP). Only the dev loopback exception uses it, and the dialer
// still checks every resolved address.
func isDevLocalhost(host string) bool { return strings.EqualFold(host, "localhost") }

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
		// ::/8 is reserved by the IETF. It holds the unspecified, loopback,
		// IPv4-compatible and IPv4-mapped forms, and IPv4-translated
		// ::ffff:0:0:0/96 (RFC 2765), which netip calls global unicast but
		// which reaches IPv4 behind a SIIT/NAT46 translator.
		"::/8",
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
