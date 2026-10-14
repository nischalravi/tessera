// Package safedial is the only way Tessera opens raw TCP connections to a
// directory that a tenant configures (readiness live checks, design
// docs/design/deployment-readiness.md §5.3). It is the raw-TCP sibling of
// safehttp and shares its address policy (safehttp.Blocked):
//
//   - The host is resolved once, every address is checked, and the
//     connection goes to the checked IP, never to the name again, so DNS
//     rebinding cannot swap a private address in after the check. A
//     net.Dialer Control hook checks the final socket address as well.
//   - Blocked: loopback, RFC 1918, link-local and cloud metadata, CGNAT,
//     multicast, reserved and translation ranges (see safehttp).
//   - Ports: 636 (LDAPS, TLS from the first byte) and 389 (StartTLS, which
//     the caller must complete before any credential is sent). No other port.
//   - TLS 1.2 or later; connect and handshake timeouts.
//
// A private target is refused unless it is on the operator's dev-only
// allowlist (TESSERA_SAFEDIAL_ALLOW, refused by internal/config in prod).
// Production reaches private directories through the Directory Agent
// (DR-11, not built yet): it implements Transport and is injected through
// Options.Agent; the agent enforces its own local allowlist.
package safedial

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

// LDAP ports and timeouts (design §5.2: connect 5 s).
const (
	PortStartTLS = 389
	PortLDAPS    = 636

	DefaultDialTimeout      = 5 * time.Second
	DefaultHandshakeTimeout = 5 * time.Second
)

var (
	// ErrPort: the port is not 389 or 636.
	ErrPort = errors.New("safedial: port not allowed (LDAP ports 389 and 636 only)")
	// ErrBlockedAddress: the host is or resolves to a blocked address.
	ErrBlockedAddress = errors.New("safedial: destination address not allowed")
	// ErrHost: the host is empty or not a plain host name or IP.
	ErrHost = errors.New("safedial: host not allowed")
	// ErrNoTLS: the connection is not (yet) protected by TLS 1.2 or later.
	ErrNoTLS = errors.New("safedial: connection is not protected by TLS")
)

// Transport carries a connection to a target through something other than a
// direct dial: the Directory Agent (DR-11) implements it. The agent applies
// its own local allowlist and typed operations; Tessera does not check the
// address because it never sees it.
type Transport interface {
	DialTarget(ctx context.Context, host string, port int) (net.Conn, error)
}

// Options configure a Dialer.
type Options struct {
	// Env is config.Dev or config.Prod. Required: the allowlist is dev only.
	Env string
	// Allow lists private targets a dev instance may dial (ParseAllow).
	// New refuses a non-empty list unless Env is dev.
	Allow []AllowEntry
	// Agent, when set, carries every connection (the production path for
	// private directories). No local dial and no allowlist then apply.
	Agent Transport
	// RootCAs replaces the system roots (the connection's CA bundle).
	RootCAs          *x509.CertPool
	Resolver         safehttp.Resolver
	DialTimeout      time.Duration
	HandshakeTimeout time.Duration

	// dial replaces the TCP dial in tests; it receives the checked IP:port.
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Dialer opens policy-checked connections.
type Dialer struct {
	o Options
}

// New returns a Dialer.
func New(o Options) (*Dialer, error) {
	switch o.Env {
	case config.Dev, config.Prod:
	default:
		return nil, fmt.Errorf("safedial: Options.Env must be %q or %q (got %q)", config.Dev, config.Prod, o.Env)
	}
	if len(o.Allow) > 0 && o.Env != config.Dev {
		return nil, errors.New("safedial: the private-target allowlist is only allowed with TESSERA_ENV=dev")
	}
	if o.DialTimeout <= 0 {
		o.DialTimeout = DefaultDialTimeout
	}
	if o.HandshakeTimeout <= 0 {
		o.HandshakeTimeout = DefaultHandshakeTimeout
	}
	if o.Resolver == nil {
		o.Resolver = net.DefaultResolver
	}
	return &Dialer{o: o}, nil
}

// ForConfig returns the dialer for the running configuration.
func ForConfig(c *config.Config, roots *x509.CertPool, agent Transport) (*Dialer, error) {
	allow, err := ParseAllow(c.SafedialAllow)
	if err != nil {
		return nil, fmt.Errorf("TESSERA_SAFEDIAL_ALLOW: %w", err)
	}
	return New(Options{Env: c.Env, Allow: allow, RootCAs: roots, Agent: agent})
}

// Conn is an open connection to a directory. For port 636 the TLS handshake
// is done; for port 389 the caller must run LDAP StartTLS with TLSConfig and
// then call SetTLS with the resulting state. Secure reports whether it is
// safe to send a credential.
type Conn struct {
	net.Conn
	Host         string
	Port         int
	StartTLSPort bool // 389: StartTLS still has to be negotiated
	state        *tls.ConnectionState
	cfg          *tls.Config
}

// TLSConfig is the client config for StartTLS on a 389 connection.
func (c *Conn) TLSConfig() *tls.Config { return c.cfg }

// SetTLS records the state after a StartTLS upgrade. It refuses an absent
// handshake or a protocol older than TLS 1.2.
func (c *Conn) SetTLS(st tls.ConnectionState) error {
	if !st.HandshakeComplete || st.Version < tls.VersionTLS12 {
		return ErrNoTLS
	}
	c.state = &st
	return nil
}

// TLSState returns the negotiated TLS state, if any.
func (c *Conn) TLSState() (tls.ConnectionState, bool) {
	if c.state == nil {
		return tls.ConnectionState{}, false
	}
	return *c.state, true
}

// Secure reports whether TLS 1.2 or later is established.
func (c *Conn) Secure() bool { return c.state != nil && c.state.Version >= tls.VersionTLS12 }

// Dial opens a connection to host:port. With inspect false the TLS handshake
// verifies the chain and host name against the configured roots (use it for
// every credential-carrying connection). With inspect true verification is
// deferred so Inspect can report why a chain is bad; such a connection must
// be closed without sending anything but the handshake.
func (d *Dialer) Dial(ctx context.Context, host string, port int, inspect bool) (*Conn, error) {
	if port != PortStartTLS && port != PortLDAPS {
		return nil, fmt.Errorf("%w: %d", ErrPort, port)
	}
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	if host == "" || strings.ContainsAny(host, "/@ \t\r\n") {
		return nil, ErrHost
	}
	var raw net.Conn
	var err error
	if d.o.Agent != nil {
		raw, err = d.o.Agent.DialTarget(ctx, host, port)
	} else {
		raw, err = d.dialChecked(ctx, host, port)
	}
	if err != nil {
		return nil, err
	}
	c := &Conn{Conn: raw, Host: host, Port: port, StartTLSPort: port == PortStartTLS, cfg: d.TLSConfig(host, inspect)}
	if port == PortLDAPS {
		tc := tls.Client(raw, c.cfg)
		hctx, cancel := context.WithTimeout(ctx, d.o.HandshakeTimeout)
		defer cancel()
		if err := tc.HandshakeContext(hctx); err != nil {
			_ = raw.Close()
			return nil, err
		}
		c.Conn = tc
		if err := c.SetTLS(tc.ConnectionState()); err != nil {
			_ = raw.Close()
			return nil, err
		}
	}
	return c, nil
}

// TLSConfig is the client TLS config: TLS 1.2 or later, verification on
// unless inspect is set.
func (d *Dialer) TLSConfig(host string, inspect bool) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: host,
		RootCAs:    d.o.RootCAs,
		// Inspect connections only read the handshake to report the chain
		// (Inspect re-verifies it); no credential is ever sent over them.
		InsecureSkipVerify: inspect, // #nosec G402 -- inspect-only, see above
	}
}

// ---------------------------------------------------------------- addresses

// dialChecked resolves the host once, refuses it if any address is blocked
// (and not allowlisted) and connects only to a checked address.
func (d *Dialer) dialChecked(ctx context.Context, host string, port int) (net.Conn, error) {
	var addrs []netip.Addr
	if a, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{a}
	} else {
		lctx, cancel := context.WithTimeout(ctx, d.o.DialTimeout)
		defer cancel()
		if addrs, err = d.o.Resolver.LookupNetIP(lctx, "ip", host); err != nil {
			return nil, err
		}
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("safedial: %s has no addresses", host)
	}
	for _, a := range addrs {
		if err := d.check(host, a, port); err != nil {
			return nil, fmt.Errorf("%w: %s resolves to %s", ErrBlockedAddress, host, a.Unmap())
		}
	}
	dial := d.o.dial
	if dial == nil {
		// The socket-level hook only lets the vetted addresses through, so a
		// resolver or dialer surprise cannot reach another one.
		vetted := map[netip.Addr]bool{}
		for _, a := range addrs {
			vetted[a.Unmap().WithZone("")] = true
		}
		nd := net.Dialer{Timeout: d.o.DialTimeout, Control: func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil || !vetted[ap.Addr().Unmap().WithZone("")] {
				return fmt.Errorf("%w: %s", ErrBlockedAddress, address)
			}
			return nil
		}}
		dial = nd.DialContext
	}
	var errs []error
	for _, a := range addrs {
		conn, err := dial(ctx, "tcp", net.JoinHostPort(a.Unmap().String(), strconv.Itoa(port)))
		if err == nil {
			return conn, nil
		}
		errs = append(errs, err)
	}
	return nil, errors.Join(errs...)
}

func (d *Dialer) check(host string, a netip.Addr, port int) error {
	a = a.Unmap().WithZone("")
	if !safehttp.Blocked(a) {
		return nil
	}
	if neverAllowed(a) {
		return fmt.Errorf("%w: %s", ErrBlockedAddress, a)
	}
	for _, e := range d.o.Allow {
		if e.matches(host, a, port) {
			return nil
		}
	}
	return fmt.Errorf("%w: %s", ErrBlockedAddress, a)
}

// neverAllowedPrefixes cannot be allowlisted: cloud metadata, link-local,
// multicast and reserved space. Only private, loopback and CGNAT space can
// be a lab directory.
var neverAllowedPrefixes = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "169.254.0.0/16", "168.63.129.16/32", "224.0.0.0/4", "240.0.0.0/4",
		"100.100.100.200/32", "192.0.0.192/32",
		"::/128", "fe80::/10", "ff00::/8", "fd00:ec2::/32",
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

func neverAllowed(a netip.Addr) bool {
	for _, p := range neverAllowedPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- allowlist

// AllowEntry admits one private target: a host name, an IP or a CIDR, with
// a port.
type AllowEntry struct {
	Host   string       // lower-case host name; empty for IP and CIDR entries
	Prefix netip.Prefix // IP (as /32 or /128) or CIDR
	Port   int
}

func (e AllowEntry) matches(host string, a netip.Addr, port int) bool {
	if e.Port != port {
		return false
	}
	if e.Host != "" {
		return host != "" && strings.EqualFold(e.Host, host)
	}
	return e.Prefix.Contains(a)
}

// Smallest CIDRs an entry may use: a wildcard-like 0.0.0.0/0 or 10.0.0.0/8
// would turn the allowlist into "any private host".
const (
	minAllowBits4 = 16
	minAllowBits6 = 64
)

// ParseAllow parses TESSERA_SAFEDIAL_ALLOW: comma-separated entries of the
// form host:port, ip:port, cidr:port or [ipv6]:port ([ipv6-cidr]:port). Ports
// are 389 or 636. Wildcards and broad CIDRs (shorter than /16 for IPv4, /64
// for IPv6) are refused.
func ParseAllow(s string) ([]AllowEntry, error) {
	var out []AllowEntry
	for _, raw := range strings.Split(s, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if strings.ContainsAny(raw, "*?") {
			return nil, fmt.Errorf("%q: wildcards are not allowed", raw)
		}
		i := strings.LastIndex(raw, ":")
		if i <= 0 {
			return nil, fmt.Errorf("%q: want host:port", raw)
		}
		hostPart, portPart := raw[:i], raw[i+1:]
		port, err := strconv.Atoi(portPart)
		if err != nil || (port != PortStartTLS && port != PortLDAPS) {
			return nil, fmt.Errorf("%q: port must be 389 or 636", raw)
		}
		hostPart = strings.TrimSuffix(strings.TrimPrefix(hostPart, "["), "]")
		e := AllowEntry{Port: port}
		switch {
		case strings.Contains(hostPart, "/"):
			p, err := netip.ParsePrefix(hostPart)
			if err != nil {
				return nil, fmt.Errorf("%q: %v", raw, err)
			}
			p = p.Masked()
			min := minAllowBits4
			if p.Addr().Is6() && !p.Addr().Is4In6() {
				min = minAllowBits6
			}
			if p.Bits() < min {
				return nil, fmt.Errorf("%q: CIDR broader than /%d is not allowed", raw, min)
			}
			e.Prefix = p
		default:
			if a, err := netip.ParseAddr(hostPart); err == nil {
				e.Prefix = netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen())
			} else if validHostName(hostPart) {
				e.Host = strings.ToLower(hostPart)
			} else {
				return nil, fmt.Errorf("%q: not a host name, IP or CIDR", raw)
			}
		}
		out = append(out, e)
	}
	return out, nil
}

func validHostName(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	for _, r := range h {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '.':
		default:
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------- certificate report

// CertReport is what a handshake says about the server certificate.
type CertReport struct {
	TLSVersion    string // "1.2", "1.3"
	ChainValid    bool
	HostnameMatch bool
	NotAfter      time.Time
	Issuer        string
}

// Inspect judges a handshake: the chain against roots (nil means the system
// roots) and the host name. It is separate so a bad chain can be reported as
// a failed check rather than as a connection error.
func Inspect(st tls.ConnectionState, host string, roots *x509.CertPool, now time.Time) CertReport {
	r := CertReport{}
	switch st.Version {
	case tls.VersionTLS13:
		r.TLSVersion = "1.3"
	case tls.VersionTLS12:
		r.TLSVersion = "1.2"
	case tls.VersionTLS11:
		r.TLSVersion = "1.1"
	case tls.VersionTLS10:
		r.TLSVersion = "1.0"
	}
	if len(st.PeerCertificates) == 0 {
		return r
	}
	leaf := st.PeerCertificates[0]
	r.NotAfter = leaf.NotAfter
	r.Issuer = leaf.Issuer.CommonName
	inter := x509.NewCertPool()
	for _, c := range st.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	_, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: now})
	r.ChainValid = err == nil
	r.HostnameMatch = leaf.VerifyHostname(host) == nil
	return r
}
