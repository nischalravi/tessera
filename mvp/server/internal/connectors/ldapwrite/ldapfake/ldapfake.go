// Package ldapfake is an in-process LDAPv3 server for tests (test-only, loopback). It speaks the
// operations a provisioning target uses over BER (github.com/go-asn1-ber/asn1-ber): simple bind,
// search with the usual filters, add, modify, delete, modify DN, StartTLS and unbind. It keeps the
// directory in memory, records every operation, and behaves like Active Directory for unicodePwd
// (accepted only on an encrypted connection). It is never linked into the server binary.
package ldapfake

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math"
	"math/big"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf16"

	ber "github.com/go-asn1-ber/asn1-ber"
	goldap "github.com/go-ldap/ldap/v3"
)

// Host is the lab host name the server's certificate is for; every lab name resolves to one public
// address so the safedial policy passes, and the dial is redirected to the server.
const Host = "ldap.lab.example"

// Op is one recorded request.
type Op struct {
	Kind   string // bind, search, add, modify, delete, modrdn, starttls, unbind
	DN     string
	Secure bool // the connection was encrypted when the request arrived
}

// Server is the fake directory.
type Server struct {
	// AD makes unicodePwd behave as in Active Directory.
	AD bool
	// DenyWrites answers every add, modify, delete and modify DN with insufficient access.
	DenyWrites bool

	cfg    *tls.Config
	ca     *x509.CertPool
	plain  net.Listener
	secure net.Listener

	mu      sync.Mutex
	entries map[string]map[string][]string // normalized DN -> lower-case attribute -> values
	dns     map[string]string              // normalized DN -> DN as written
	users   map[string]string              // normalized bind DN -> password
	ops     []Op
	pwds    map[string]string // normalized DN -> last unicodePwd / userPassword set
	closed  chan struct{}
	once    sync.Once
}

// New starts a server with a fresh lab CA and certificate.
func New(t testing.TB) *Server {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caT := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Lab CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caT, caT, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	lt := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: Host}, DNSNames: []string{Host},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, lt, ca, &key.PublicKey, caKey)
	s := &Server{entries: map[string]map[string][]string{}, dns: map[string]string{}, users: map[string]string{},
		pwds: map[string]string{}, closed: make(chan struct{}), ca: x509.NewCertPool(),
		cfg: &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der, caDER}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}}
	s.ca.AddCert(ca)
	var err error
	if s.plain, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	if s.secure, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	go s.accept(s.plain, false)
	go s.accept(s.secure, true)
	t.Cleanup(s.Close)
	return s
}

// Close stops the server.
func (s *Server) Close() {
	s.once.Do(func() {
		close(s.closed)
		_ = s.plain.Close()
		_ = s.secure.Close()
	})
}

// CA is the pool that verifies the server's certificate.
func (s *Server) CA() *x509.CertPool { return s.ca }

// Resolver resolves every lab host name to one public address, so the safedial address policy
// passes; DialFunc then redirects the checked connection to the server.
type Resolver struct{}

// LookupNetIP implements safehttp.Resolver.
func (Resolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
}

// DialFunc connects a checked address to this server: port 636 to the TLS listener, anything else
// to the plain one (which upgrades with StartTLS). Tests pass it to safedial as its test dial hook.
func (s *Server) DialFunc(ctx context.Context, _, hostport string) (net.Conn, error) {
	addr := s.plain.Addr().String()
	if strings.HasSuffix(hostport, ":636") {
		addr = s.secure.Addr().String()
	}
	var nd net.Dialer
	return nd.DialContext(ctx, "tcp", addr)
}

func norm(dn string) string {
	p, err := goldap.ParseDN(dn)
	if err != nil {
		return strings.ToLower(dn)
	}
	parts := make([]string, len(p.RDNs))
	for i, r := range p.RDNs {
		a := make([]string, len(r.Attributes))
		for j, x := range r.Attributes {
			a[j] = strings.ToLower(x.Type) + "=" + strings.ToLower(strings.TrimSpace(x.Value))
		}
		sort.Strings(a)
		parts[i] = strings.Join(a, "+")
	}
	return strings.Join(parts, ",")
}

func parent(n string) string {
	// normalized names have no escaped commas in the lab data
	if i := strings.Index(n, ","); i >= 0 {
		return n[i+1:]
	}
	return ""
}

// BindUser lets dn bind with password.
func (s *Server) BindUser(dn, password string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[norm(dn)] = password
}

// Put sets an entry, replacing any entry at dn.
func (s *Server) Put(dn string, attrs map[string][]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := map[string][]string{}
	for k, v := range attrs {
		m[strings.ToLower(k)] = append([]string(nil), v...)
	}
	s.entries[norm(dn)], s.dns[norm(dn)] = m, dn
}

// Get returns a copy of an entry's attributes (lower-case names).
func (s *Server) Get(dn string) (map[string][]string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[norm(dn)]
	if !ok {
		return nil, false
	}
	out := map[string][]string{}
	for k, v := range e {
		out[k] = append([]string(nil), v...)
	}
	return out, true
}

// Password is the last password set on dn (unicodePwd decoded, or userPassword).
func (s *Server) Password(dn string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pwds[norm(dn)]
}

// Ops is a copy of the recorded requests.
func (s *Server) Ops() []Op {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Op(nil), s.ops...)
}

// Writes counts the recorded add, modify, delete and modify DN requests.
func (s *Server) Writes() int {
	n := 0
	for _, o := range s.Ops() {
		switch o.Kind {
		case "add", "modify", "delete", "modrdn":
			n++
		}
	}
	return n
}

func (s *Server) record(kind, dn string, secure bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ops = append(s.ops, Op{kind, dn, secure})
}

func (s *Server) accept(l net.Listener, secure bool) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go s.serve(c, secure)
	}
}

func str(p *ber.Packet) string {
	if v, ok := p.Value.(string); ok {
		return v
	}
	if p.Data != nil {
		return p.Data.String()
	}
	return ""
}

func num(p *ber.Packet) int64 {
	switch v := p.Value.(type) {
	case int64:
		return v
	case uint64:
		if v > math.MaxInt64 {
			return 0
		}
		return int64(v)
	}
	return 0
}

func result(op ber.Tag, code int, diag string) *ber.Packet {
	r := ber.Encode(ber.ClassApplication, ber.TypeConstructed, op, nil, "")
	r.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(code), ""))
	r.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
	r.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, diag, ""))
	return r
}

func envelope(id int64, ops ...*ber.Packet) []byte {
	var out bytes.Buffer
	for _, op := range ops {
		m := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
		m.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, ""))
		m.AppendChild(op)
		out.Write(m.Bytes())
	}
	return out.Bytes()
}

func (s *Server) serve(raw net.Conn, secure bool) {
	var conn net.Conn = raw
	if secure {
		tc := tls.Server(raw, s.cfg)
		if tc.Handshake() != nil {
			_ = raw.Close()
			return
		}
		conn = tc
	}
	defer func() { _ = conn.Close() }()
	encrypted := secure
	var bound string
	for {
		p, err := ber.ReadPacket(conn)
		if err != nil || len(p.Children) < 2 {
			return
		}
		id, op := num(p.Children[0]), p.Children[1]
		send := func(ops ...*ber.Packet) bool { _, err := conn.Write(envelope(id, ops...)); return err == nil }
		switch op.Tag {
		case 0: // bind
			s.record("bind", str(op.Children[1]), encrypted)
			dn, pw := str(op.Children[1]), str(op.Children[2])
			s.mu.Lock()
			want, known := s.users[norm(dn)]
			s.mu.Unlock()
			if known && pw != "" && pw == want {
				bound = dn
				send(result(1, 0, ""))
			} else {
				send(result(1, 49, "invalid credentials"))
			}
		case 2:
			s.record("unbind", "", encrypted)
			return
		case 23: // extended: StartTLS only
			if str(op.Children[0]) != "1.3.6.1.4.1.1466.20037" {
				send(result(24, 2, "unsupported extended operation"))
				continue
			}
			s.record("starttls", "", encrypted)
			if !send(result(24, 0, "")) {
				return
			}
			tc := tls.Server(conn, s.cfg)
			if tc.Handshake() != nil {
				return
			}
			conn, encrypted = tc, true
		case 3:
			s.record("search", str(op.Children[0]), encrypted)
			if bound == "" {
				send(result(5, 50, "bind required"))
				continue
			}
			out, code := s.search(op)
			out = append(out, result(5, code, ""))
			send(out...)
		case 8, 6, 10, 12:
			kind := map[ber.Tag]string{8: "add", 6: "modify", 10: "delete", 12: "modrdn"}[op.Tag]
			dn := str(op)
			if op.Tag != 10 {
				dn = str(op.Children[0])
			}
			s.record(kind, dn, encrypted)
			code, diag := 50, "insufficient access"
			if bound != "" && !s.DenyWrites {
				code, diag = s.write(op, dn, encrypted)
			}
			send(result(op.Tag+1, code, diag))
		default:
			send(result(op.Tag+1, 2, "unsupported"))
		}
	}
}

func attrList(p *ber.Packet) map[string][]string {
	m := map[string][]string{}
	for _, a := range p.Children {
		name := strings.ToLower(str(a.Children[0]))
		for _, v := range a.Children[1].Children {
			m[name] = append(m[name], str(v))
		}
	}
	return m
}

func has(vals []string, v string) bool {
	for _, x := range vals {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}

// decodePwd reads an AD unicodePwd value: UTF-16LE in double quotes.
func decodePwd(b string) (string, bool) {
	raw := []byte(b)
	if len(raw)%2 != 0 || len(raw) < 4 {
		return "", false
	}
	u := make([]uint16, len(raw)/2)
	for i := range u {
		u[i] = uint16(raw[2*i]) | uint16(raw[2*i+1])<<8
	}
	s := string(utf16.Decode(u))
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return "", false
	}
	return s[1 : len(s)-1], true
}

func (s *Server) write(op *ber.Packet, dn string, encrypted bool) (int, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := norm(dn)
	switch op.Tag {
	case 8:
		if _, ok := s.entries[n]; ok {
			return 68, "entry already exists"
		}
		if pn := parent(n); pn != "" {
			if _, ok := s.entries[pn]; !ok {
				return 32, "no such parent"
			}
		}
		attrs := attrList(op.Children[1])
		if _, ok := attrs["unicodepwd"]; ok {
			return 53, "unicodePwd is set by modify"
		}
		if _, ok := attrs["objectclass"]; !ok {
			return 65, "objectClass required"
		}
		if pw, ok := attrs["userpassword"]; ok {
			s.pwds[n] = pw[0]
		}
		s.entries[n], s.dns[n] = attrs, dn
	case 6:
		e, ok := s.entries[n]
		if !ok {
			return 32, "no such object"
		}
		cp := map[string][]string{}
		for k, v := range e {
			cp[k] = append([]string(nil), v...)
		}
		var newPwd string
		var pwSet, pwLast bool
		for _, ch := range op.Children[1].Children {
			kind := num(ch.Children[0])
			name := strings.ToLower(str(ch.Children[1].Children[0]))
			var vals []string
			for _, v := range ch.Children[1].Children[1].Children {
				vals = append(vals, str(v))
			}
			if name == "unicodepwd" {
				if !s.AD {
					return 17, "undefined attribute type"
				}
				if !encrypted {
					return 53, "unwilling to perform: password over a clear connection"
				}
				pw, ok := decodePwd(vals[0])
				if !ok || kind != 2 {
					return 19, "constraint violation"
				}
				newPwd, pwSet = pw, true
				continue
			}
			if name == "pwdlastset" {
				pwLast = true
			}
			switch kind {
			case 0:
				for _, v := range vals {
					if has(cp[name], v) {
						return 20, "value exists"
					}
					cp[name] = append(cp[name], v)
				}
			case 1:
				if len(vals) == 0 {
					if _, ok := cp[name]; !ok {
						return 16, "no such attribute"
					}
					delete(cp, name)
					break
				}
				for _, v := range vals {
					if !has(cp[name], v) {
						return 16, "no such value"
					}
					var keep []string
					for _, x := range cp[name] {
						if !strings.EqualFold(x, v) {
							keep = append(keep, x)
						}
					}
					if len(keep) == 0 {
						delete(cp, name)
					} else {
						cp[name] = keep
					}
				}
			case 2:
				if len(vals) == 0 {
					delete(cp, name)
				} else {
					cp[name] = vals
				}
			}
			if name == "userpassword" && len(vals) > 0 {
				s.pwds[n] = vals[0]
			}
		}
		if pwSet {
			s.pwds[n] = newPwd
			if !pwLast {
				cp["pwdlastset"] = []string{"133000000000000000"}
			}
		}
		s.entries[n] = cp
	case 10:
		if _, ok := s.entries[n]; !ok {
			return 32, "no such object"
		}
		for k := range s.entries {
			if parent(k) == n {
				return 66, "not allowed on non-leaf"
			}
		}
		delete(s.entries, n)
		delete(s.dns, n)
	case 12:
		e, ok := s.entries[n]
		if !ok {
			return 32, "no such object"
		}
		rdn := str(op.Children[1])
		sup := parent(n)
		supRaw := ""
		if i := strings.Index(dn, ","); i >= 0 {
			supRaw = dn[i+1:]
		}
		if len(op.Children) > 3 {
			sup, supRaw = norm(str(op.Children[3])), str(op.Children[3])
			if _, ok := s.entries[sup]; !ok {
				return 32, "no such new superior"
			}
		}
		nn, nraw := norm(rdn+","+supRaw), rdn+","+supRaw
		if sup == "" {
			nn, nraw = norm(rdn), rdn
		}
		if _, exists := s.entries[nn]; exists && nn != n {
			return 68, "entry already exists"
		}
		delete(s.entries, n)
		delete(s.dns, n)
		s.entries[nn], s.dns[nn] = e, nraw
		if pw, ok := s.pwds[n]; ok {
			s.pwds[nn] = pw
			delete(s.pwds, n)
		}
	}
	return 0, ""
}

func inScope(base, dn string, scope int64) bool {
	b, d := norm(base), norm(dn)
	switch scope {
	case 0:
		return b == d
	case 1:
		return parent(d) == b
	}
	return d == b || strings.HasSuffix(d, ","+b) || b == ""
}

func (s *Server) search(op *ber.Packet) ([]*ber.Packet, int) {
	base, scope := str(op.Children[0]), num(op.Children[1])
	var want []string
	for _, a := range op.Children[7].Children {
		want = append(want, strings.ToLower(str(a)))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.entries[norm(base)]; !ok && scope == 0 {
		return nil, 32
	}
	keys := make([]string, 0, len(s.entries))
	for k := range s.entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []*ber.Packet
	for _, k := range keys {
		if !inScope(base, s.dns[k], scope) || !match(op.Children[6], s.entries[k]) {
			continue
		}
		entry := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 4, nil, "")
		entry.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, s.dns[k], ""))
		list := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
		for name, vals := range s.entries[k] {
			if len(want) > 0 && !has(want, name) && !has(want, "*") {
				continue
			}
			if name == "userpassword" || name == "unicodepwd" { // never readable
				continue
			}
			a := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
			a.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, name, ""))
			set := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "")
			for _, v := range vals {
				set.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, v, ""))
			}
			a.AppendChild(set)
			list.AppendChild(a)
		}
		entry.AppendChild(list)
		out = append(out, entry)
	}
	return out, 0
}

// match evaluates a BER search filter against an entry.
func match(f *ber.Packet, attrs map[string][]string) bool {
	switch f.Tag {
	case 0:
		for _, c := range f.Children {
			if !match(c, attrs) {
				return false
			}
		}
		return true
	case 1:
		for _, c := range f.Children {
			if match(c, attrs) {
				return true
			}
		}
		return false
	case 2:
		return len(f.Children) == 1 && !match(f.Children[0], attrs)
	case 3:
		return has(attrs[strings.ToLower(str(f.Children[0]))], str(f.Children[1]))
	case 4:
		for _, v := range attrs[strings.ToLower(str(f.Children[0]))] {
			ok := true
			for _, sub := range f.Children[1].Children {
				val, lv := strings.ToLower(str(sub)), strings.ToLower(v)
				switch sub.Tag {
				case 0:
					ok = ok && strings.HasPrefix(lv, val)
				case 1:
					ok = ok && strings.Contains(lv, val)
				case 2:
					ok = ok && strings.HasSuffix(lv, val)
				}
			}
			if ok {
				return true
			}
		}
		return false
	case 7:
		return len(attrs[strings.ToLower(str(f))]) > 0
	}
	return false
}
