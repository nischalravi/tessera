package safedial

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
)

type fakeResolver struct {
	mu    sync.Mutex
	addrs map[string][]netip.Addr
	calls int
}

func (r *fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if a, ok := r.addrs[host]; ok {
		return a, nil
	}
	return nil, errors.New("no such host")
}

// recDial records the addresses it is asked to dial and never connects.
type recDial struct {
	mu    sync.Mutex
	addrs []string
}

func (d *recDial) dial(_ context.Context, _, addr string) (net.Conn, error) {
	d.mu.Lock()
	d.addrs = append(d.addrs, addr)
	d.mu.Unlock()
	c, s := net.Pipe()
	_ = s.Close()
	return c, nil
}

func mustAllow(t *testing.T, s string) []AllowEntry {
	t.Helper()
	a, err := ParseAllow(s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// TestSafedial_BlocksPrivateUnlessAgent: private, loopback, CGNAT, link-local
// and metadata targets are refused; a dev allowlist admits private ones but
// never metadata; in production the server-side dialer refuses every private
// target and an allowlist, and only the Directory Agent's own dialer
// (AgentLocal, its local allowlist; DR-11) reaches a listed private host.
func TestSafedial_BlocksPrivateUnlessAgent(t *testing.T) {
	res := &fakeResolver{addrs: map[string][]netip.Addr{
		"lab.example":      {netip.MustParseAddr("192.168.1.10")},
		"meta.example":     {netip.MustParseAddr("169.254.169.254")},
		"mixed.example":    {netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("10.0.0.5")},
		"public.example":   {netip.MustParseAddr("93.184.216.34")},
		"cgnat.example":    {netip.MustParseAddr("100.64.1.1")},
		"loop.example":     {netip.MustParseAddr("127.0.0.1")},
		"v6.example":       {netip.MustParseAddr("fd12::1")},
		"mapped.example":   {netip.MustParseAddr("::ffff:10.0.0.9")},
		"aws6meta.example": {netip.MustParseAddr("fd00:ec2::254")},
	}}
	cases := []struct {
		name    string
		allow   string
		host    string
		port    int
		blocked bool
	}{
		{"private refused", "", "lab.example", 636, true},
		{"private literal refused", "", "192.168.1.10", 636, true},
		{"loopback refused", "", "127.0.0.1", 389, true},
		{"loopback name refused", "", "loop.example", 636, true},
		{"cgnat refused", "", "cgnat.example", 636, true},
		{"metadata refused", "", "169.254.169.254", 636, true},
		{"metadata name refused", "", "meta.example", 636, true},
		{"mapped private refused", "", "mapped.example", 636, true},
		{"ula refused", "", "v6.example", 636, true},
		{"mixed public and private refused", "", "mixed.example", 636, true},
		{"public allowed", "", "public.example", 636, false},
		{"allowlisted ip", "192.168.1.10:636", "192.168.1.10", 636, false},
		{"allowlisted name", "lab.example:636", "lab.example", 636, false},
		{"allowlisted cidr", "192.168.1.0/24:636", "lab.example", 636, false},
		{"allowlist is per port", "192.168.1.10:636", "192.168.1.10", 389, true},
		{"allowlist is per host", "192.168.1.11:636", "lab.example", 636, true},
		{"allowlist cannot admit metadata", "169.254.169.254:636", "169.254.169.254", 636, true},
		{"allowlist cannot admit metadata by name", "meta.example:636", "meta.example", 636, true},
		{"allowlist cannot admit aws v6 metadata", "aws6meta.example:636", "aws6meta.example", 636, true},
		{"allowlist admits a mixed host only when every private address is listed", "10.0.0.0/24:636", "mixed.example", 636, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rd := &recDial{}
			d, err := New(Options{Env: config.Dev, Allow: mustAllow(t, c.allow), Resolver: res, dial: rd.dial})
			if err != nil {
				t.Fatal(err)
			}
			conn, err := d.dialChecked(context.Background(), c.host, c.port)
			if c.blocked {
				if !errors.Is(err, ErrBlockedAddress) {
					t.Fatalf("want ErrBlockedAddress, got %v", err)
				}
				if len(rd.addrs) != 0 {
					t.Fatalf("dialed %v despite the block", rd.addrs)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			_ = conn.Close()
		})
	}

	t.Run("production server refuses private targets", func(t *testing.T) {
		rd := &recDial{}
		d, err := New(Options{Env: config.Prod, Resolver: res, dial: rd.dial})
		if err != nil {
			t.Fatal(err)
		}
		for _, h := range []string{"lab.example", "192.168.1.10", "loop.example"} {
			if _, err := d.Dial(context.Background(), h, 389, false); !errors.Is(err, ErrBlockedAddress) {
				t.Errorf("%s: %v", h, err)
			}
		}
		if len(rd.addrs) != 0 {
			t.Fatalf("dialed %v", rd.addrs)
		}
	})

	t.Run("agent-local allowlist reaches only listed private targets", func(t *testing.T) {
		rd := &recDial{}
		d, err := New(Options{Env: config.Prod, AgentLocal: true, Allow: mustAllow(t, "lab.example:389,10.0.0.0/24:636"),
			Resolver: res, dial: rd.dial})
		if err != nil {
			t.Fatal(err)
		}
		// Port 389: no TLS here, the StartTLS exchange belongs to the caller.
		c, err := d.Dial(context.Background(), "lab.example", 389, false)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if c.Secure() {
			t.Error("an unupgraded 389 connection must not report Secure")
		}
		if len(rd.addrs) != 1 || rd.addrs[0] != "192.168.1.10:389" {
			t.Errorf("dialed %v", rd.addrs)
		}
		// Not listed, wrong port and metadata stay refused even on the agent.
		for _, tc := range []struct {
			host string
			port int
		}{{"192.168.1.10", 389}, {"lab.example", 636}, {"meta.example", 389}, {"cgnat.example", 389}} {
			if _, err := d.Dial(context.Background(), tc.host, tc.port, false); !errors.Is(err, ErrBlockedAddress) {
				t.Errorf("%s:%d: %v", tc.host, tc.port, err)
			}
		}
		if len(rd.addrs) != 1 {
			t.Errorf("dialed %v", rd.addrs)
		}
	})
}

func TestListed(t *testing.T) {
	l := mustAllow(t, "ldap.corp.example:636, 10.1.2.0/24:389, 192.168.1.10:636")
	for _, tc := range []struct {
		host string
		port int
		want bool
	}{
		{"ldap.corp.example", 636, true}, {"LDAP.corp.example.", 636, true}, {"ldap.corp.example", 389, false},
		{"other.corp.example", 636, false}, {"10.1.2.9", 389, true}, {"10.1.3.9", 389, false},
		{"10.1.2.9", 636, false}, {"192.168.1.10", 636, true}, {"::ffff:192.168.1.10", 636, true},
		// a name is never matched against a CIDR entry
		{"nas.corp.example", 389, false}, {"", 636, false}, {"93.184.216.34", 636, false},
	} {
		if got := Listed(l, tc.host, tc.port); got != tc.want {
			t.Errorf("Listed(%q, %d) = %t, want %t", tc.host, tc.port, got, tc.want)
		}
	}
}

// TestSafedial_BlocksRebinding: the name is resolved once, every address is
// checked after resolution and the checked IP (not the name) is dialed.
func TestSafedial_BlocksRebinding(t *testing.T) {
	// A resolver that rebinds: public on the first answer, private after.
	rb := &rebindResolver{}
	rd := &recDial{}
	d, err := New(Options{Env: config.Prod, Resolver: rb, dial: rd.dial})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := d.dialChecked(context.Background(), "rebind.example", 636)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if rb.calls != 1 {
		t.Errorf("resolved %d times; want exactly once", rb.calls)
	}
	if len(rd.addrs) != 1 || rd.addrs[0] != "93.184.216.34:636" {
		t.Errorf("dialed %v; want the checked IP, not the name", rd.addrs)
	}

	// A second lookup would now answer 10.0.0.1: the dial never asks again.
	if _, err := d.dialChecked(context.Background(), "rebind.example", 636); !errors.Is(err, ErrBlockedAddress) {
		t.Errorf("after rebinding got %v; want ErrBlockedAddress", err)
	}

	// Literal private addresses are refused before any dial.
	d2, _ := New(Options{Env: config.Prod, Resolver: &fakeResolver{addrs: map[string][]netip.Addr{
		"x.example": {netip.MustParseAddr("93.184.216.34")}}}, DialTimeout: 50 * time.Millisecond})
	if _, err := d2.dialChecked(context.Background(), "10.1.2.3", 636); !errors.Is(err, ErrBlockedAddress) {
		t.Errorf("private literal: %v", err)
	}
}

type rebindResolver struct{ calls int }

func (r *rebindResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	r.calls++
	if r.calls == 1 {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}
	return []netip.Addr{netip.MustParseAddr("10.0.0.1")}, nil
}

func TestSafedial_PortAllowlist(t *testing.T) {
	d, _ := New(Options{Env: config.Dev, Resolver: &fakeResolver{}})
	for _, p := range []int{0, 22, 80, 443, 3306, 3268, 3269, 8080, 65535, -1} {
		if _, err := d.Dial(context.Background(), "93.184.216.34", p, false); !errors.Is(err, ErrPort) {
			t.Errorf("port %d: got %v; want ErrPort", p, err)
		}
	}
	for _, h := range []string{"", " ", "a/b", "user@host", "a b"} {
		if _, err := d.Dial(context.Background(), h, 636, false); !errors.Is(err, ErrHost) {
			t.Errorf("host %q: got %v; want ErrHost", h, err)
		}
	}
}

// serverCert makes a CA and a leaf for name valid for the given window.
func serverCert(t *testing.T, name string, notAfter time.Time) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caT := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caT, caT, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	lt := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, lt, ca, &key.PublicKey, caKey)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: key}, pool
}

// pipeDial answers every dial with a TLS server on the far end of a pipe.
func pipeDial(cert tls.Certificate, min, max uint16) func(context.Context, string, string) (net.Conn, error) {
	return func(context.Context, string, string) (net.Conn, error) {
		c, s := net.Pipe()
		go func() {
			ts := tls.Server(s, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: min, MaxVersion: max})
			if ts.Handshake() == nil {
				_, _ = ts.Read(make([]byte, 1)) // hold until the client closes
			}
			_ = s.Close()
		}()
		return c, nil
	}
}

func TestSafedial_LDAPSHandshake(t *testing.T) {
	cert, roots := serverCert(t, "ldap.lab.example", time.Now().Add(90*24*time.Hour))
	res := &fakeResolver{addrs: map[string][]netip.Addr{"ldap.lab.example": {netip.MustParseAddr("93.184.216.34")}}}

	d, _ := New(Options{Env: config.Prod, Resolver: res, RootCAs: roots, dial: pipeDial(cert, tls.VersionTLS12, 0)})
	c, err := d.Dial(context.Background(), "ldap.lab.example", PortLDAPS, false)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := c.TLSState()
	if !ok || !c.Secure() {
		t.Fatal("LDAPS connection is not secure")
	}
	rep := Inspect(st, "ldap.lab.example", roots, time.Now())
	if !rep.ChainValid || !rep.HostnameMatch || rep.TLSVersion != "1.3" || rep.Issuer != "Test CA" {
		t.Errorf("report: %+v", rep)
	}
	_ = c.Close()

	// A verifying dial without the CA fails; an inspect dial reports it.
	d2, _ := New(Options{Env: config.Prod, Resolver: res, dial: pipeDial(cert, tls.VersionTLS12, 0)})
	if _, err := d2.Dial(context.Background(), "ldap.lab.example", PortLDAPS, false); err == nil {
		t.Fatal("untrusted chain accepted")
	}
	c, err = d2.Dial(context.Background(), "ldap.lab.example", PortLDAPS, true)
	if err != nil {
		t.Fatal(err)
	}
	st, _ = c.TLSState()
	if rep := Inspect(st, "ldap.lab.example", nil, time.Now()); rep.ChainValid || !rep.HostnameMatch {
		t.Errorf("inspect report: %+v", rep)
	}
	if rep := Inspect(st, "other.example", roots, time.Now()); rep.HostnameMatch || !rep.ChainValid {
		t.Errorf("hostname report: %+v", rep)
	}
	_ = c.Close()
}

func TestSafedial_RefusesOldTLS(t *testing.T) {
	cert, roots := serverCert(t, "ldap.lab.example", time.Now().Add(90*24*time.Hour))
	res := &fakeResolver{addrs: map[string][]netip.Addr{"ldap.lab.example": {netip.MustParseAddr("93.184.216.34")}}}
	d, _ := New(Options{Env: config.Prod, Resolver: res, RootCAs: roots, dial: pipeDial(cert, tls.VersionTLS10, tls.VersionTLS11)})
	if _, err := d.Dial(context.Background(), "ldap.lab.example", PortLDAPS, false); err == nil {
		t.Fatal("TLS 1.1 accepted")
	}
	c := &Conn{}
	if err := c.SetTLS(tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS11}); !errors.Is(err, ErrNoTLS) {
		t.Errorf("SetTLS(TLS1.1) = %v", err)
	}
	if err := c.SetTLS(tls.ConnectionState{}); !errors.Is(err, ErrNoTLS) {
		t.Errorf("SetTLS(none) = %v", err)
	}
	if c.Secure() {
		t.Error("Secure after refused SetTLS")
	}
}

// TestSafedial_PlaintextRefused: a 389 connection is not secure until StartTLS
// has been negotiated, and the config always demands TLS 1.2.
func TestSafedial_PlaintextRefused(t *testing.T) {
	rd := &recDial{}
	d, _ := New(Options{Env: config.Prod, Resolver: &fakeResolver{addrs: map[string][]netip.Addr{
		"ldap.lab.example": {netip.MustParseAddr("93.184.216.34")}}}, dial: rd.dial})
	c, err := d.Dial(context.Background(), "ldap.lab.example", PortStartTLS, false)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if !c.StartTLSPort || c.Secure() {
		t.Error("389 must start insecure and require StartTLS")
	}
	if _, ok := c.TLSState(); ok {
		t.Error("no TLS state before StartTLS")
	}
	cfg := c.TLSConfig()
	if cfg.MinVersion < tls.VersionTLS12 || cfg.InsecureSkipVerify || cfg.ServerName != "ldap.lab.example" {
		t.Errorf("tls config: %+v", cfg)
	}
}

func TestSafedial_ProdRefusesAllowlist(t *testing.T) {
	if _, err := New(Options{Env: config.Prod, Allow: mustAllow(t, "192.168.1.10:636")}); err == nil {
		t.Fatal("prod dialer accepted an allowlist")
	}
	if _, err := New(Options{Env: "staging"}); err == nil {
		t.Fatal("unknown env accepted")
	}
	// The config layer refuses the variable in prod (internal/config tests);
	// ForConfig also rejects bad syntax in dev.
	if _, err := ForConfig(&config.Config{Env: config.Dev, SafedialAllow: "0.0.0.0/0:636"}, nil); err == nil {
		t.Fatal("0.0.0.0/0 accepted")
	}
}

func TestParseAllow(t *testing.T) {
	good := []string{"", "192.168.1.10:636", "lab.example:389", "10.1.0.0/16:636", "[fd12:3456::1]:636", "[fd12:3456:789a:1::/64]:636",
		"192.168.1.10:636, nas.lan:389"}
	for _, s := range good {
		if _, err := ParseAllow(s); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
	bad := []string{"*", "*.lan:636", "0.0.0.0/0:636", "10.0.0.0/8:636", "::/0:636", "[fd00::/16]:636", "192.168.1.10", "192.168.1.10:80",
		"192.168.1.10:0", "host_name:636", ":636", "user@host:636", "192.168.1.10:6360", "10.0.0.0/33:636", "http://x:636"}
	for _, s := range bad {
		if _, err := ParseAllow(s); err == nil {
			t.Errorf("%q accepted", s)
		} else if strings.Contains(err.Error(), "password") {
			t.Errorf("error leaks input: %v", err)
		}
	}
}

func TestParseAllowHTTPS(t *testing.T) {
	got, err := ParseAllowHTTPS("scim.corp.example:443, 10.1.2.0/24:8443")
	if err != nil || len(got) != 2 || got[0].Host != "scim.corp.example" || got[0].Port != 443 || got[1].Port != 8443 {
		t.Fatalf("ParseAllowHTTPS = %+v, %v", got, err)
	}
	for _, bad := range []string{"scim.corp.example:636", "scim.corp.example:389", "scim.corp.example:80", "scim.corp.example",
		"*.corp.example:443", "10.0.0.0/8:443", "scim.corp.example:0"} {
		if _, err := ParseAllowHTTPS(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	// the LDAP list does not admit a web port, so allowing a directory never allows a web service
	if _, err := ParseAllow("scim.corp.example:443"); err == nil {
		t.Error("ParseAllow accepted port 443")
	}
}

// The agent's HTTP client reaches only listed private HTTPS targets, verifies
// their certificate, never speaks plain HTTP and never follows a redirect.
func TestSafedial_HTTPClient(t *testing.T) {
	cert, roots := serverCert(t, "scim.corp.example", time.Now().Add(90*24*time.Hour))
	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("hello")) })
	mux.HandleFunc("/redir", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://other.corp.example/ok", http.StatusFound)
	})
	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()
	res := &fakeResolver{addrs: map[string][]netip.Addr{
		"scim.corp.example":  {netip.MustParseAddr("10.1.2.3")},
		"other.corp.example": {netip.MustParseAddr("10.1.2.4")},
		"meta.corp.example":  {netip.MustParseAddr("169.254.169.254")},
	}}
	allow, err := ParseAllowHTTPS("scim.corp.example:443,other.corp.example:443,meta.corp.example:443")
	if err != nil {
		t.Fatal(err)
	}
	var dialed []string
	d, err := New(Options{Env: config.Prod, AgentLocal: true, Allow: allow, RootCAs: roots, Resolver: res,
		TestDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialed = append(dialed, addr)
			return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
		}})
	if err != nil {
		t.Fatal(err)
	}
	c := d.HTTPClient(5 * time.Second)
	get := func(u string) (*http.Response, error) {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, u, nil)
		return c.Do(req)
	}
	resp, err := get("https://scim.corp.example/ok")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "hello" || len(dialed) != 1 || dialed[0] != "10.1.2.3:443" {
		t.Errorf("GET /ok = %d %q, dialed %v", resp.StatusCode, body, dialed)
	}
	// a redirect is returned, not followed
	if resp, err := get("https://scim.corp.example/redir"); err != nil || resp.StatusCode != http.StatusFound {
		t.Errorf("redirect: %v %v", resp, err)
	} else {
		_ = resp.Body.Close()
	}
	// never-allowed space stays refused even when it is listed
	if _, err := get("https://meta.corp.example/ok"); !errors.Is(err, ErrBlockedAddress) {
		t.Errorf("link-local target: %v", err)
	}
	// a host that is not listed (private, unlisted), a port that is not an HTTPS port, plain HTTP
	if _, err := get("https://unlisted.corp.example/ok"); err == nil {
		t.Error("an unresolvable host was dialed")
	}
	res.mu.Lock()
	res.addrs["unlisted.corp.example"] = []netip.Addr{netip.MustParseAddr("10.9.9.9")}
	res.mu.Unlock()
	if _, err := get("https://unlisted.corp.example/ok"); !errors.Is(err, ErrBlockedAddress) {
		t.Errorf("unlisted private host: %v", err)
	}
	if _, err := get("https://scim.corp.example:8080/ok"); !errors.Is(err, ErrPort) {
		t.Errorf("port 8080: %v", err)
	}
	if _, err := get("http://scim.corp.example/ok"); !errors.Is(err, ErrNoTLS) {
		t.Errorf("plain HTTP: %v", err)
	}
	// a certificate for another name is refused
	res.mu.Lock()
	res.addrs["scim.corp.example"] = []netip.Addr{netip.MustParseAddr("10.1.2.3")}
	res.addrs["wrongname.corp.example"] = []netip.Addr{netip.MustParseAddr("10.1.2.3")}
	res.mu.Unlock()
	allow2, _ := ParseAllowHTTPS("wrongname.corp.example:443")
	d2, _ := New(Options{Env: config.Prod, AgentLocal: true, Allow: allow2, RootCAs: roots, Resolver: res,
		TestDial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
		}})
	c2 := d2.HTTPClient(5 * time.Second)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://wrongname.corp.example/ok", nil)
	if _, err := c2.Do(req); err == nil || !errors.Is(err, ErrHandshake) {
		t.Errorf("a certificate for another host name: %v", err)
	}
}
