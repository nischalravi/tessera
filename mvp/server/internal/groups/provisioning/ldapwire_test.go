package provisioning

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

// wireLDAP is a small LDAP v3 server over real sockets: simple bind, StartTLS
// and search (every entry, whatever the filter). It exists to exercise the
// connection code of the target (dialer, TLS, StartTLS, bind, search paging
// controls) end to end.
type wireLDAP struct {
	ln       net.Listener
	tls      *tls.Config
	password string
	// implicit: the connection is TLS from the first byte (ldaps)
	implicit bool
	noStart  bool // refuse StartTLS
	mu       sync.Mutex
	binds    []string
	plainOps int // operations received before TLS
	entries  []ldapEntry
	caPEM    string
}

func selfSigned(t *testing.T) (*tls.Config, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ldap.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true,
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func newWireLDAP(t *testing.T, implicit bool) *wireLDAP {
	t.Helper()
	cfg, ca := selfSigned(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &wireLDAP{ln: ln, tls: cfg, password: "right-password", implicit: implicit, caPEM: ca}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c)
		}
	}()
	return s
}

func (s *wireLDAP) url() string {
	scheme := "ldap"
	if s.implicit {
		scheme = "ldaps"
	}
	return scheme + "://" + s.ln.Addr().String()
}

func berString(v string, name string) *ber.Packet {
	return ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, v, name)
}

func ldapResult(tag ber.Tag, code int64) *ber.Packet {
	r := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "result")
	r.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, code, "resultCode"))
	r.AppendChild(berString("", "matchedDN"))
	r.AppendChild(berString("", "diagnostic"))
	return r
}

func reply(id int64, op *ber.Packet) []byte {
	p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, "messageID"))
	p.AppendChild(op)
	return p.Bytes()
}

func (s *wireLDAP) serve(raw net.Conn) {
	defer raw.Close()
	var c net.Conn = raw
	secure := false
	if s.implicit {
		tc := tls.Server(raw, s.tls)
		if tc.Handshake() != nil {
			return
		}
		c, secure = tc, true
	}
	for {
		p, err := ber.ReadPacket(c)
		if err != nil || len(p.Children) < 2 {
			if err != io.EOF {
				_ = err
			}
			return
		}
		id, _ := p.Children[0].Value.(int64)
		op := p.Children[1]
		if !secure {
			s.mu.Lock()
			s.plainOps++
			s.mu.Unlock()
		}
		switch op.Tag {
		case 0: // bind
			name, _ := op.Children[1].Value.(string)
			pw := op.Children[2].Data.String()
			s.mu.Lock()
			s.binds = append(s.binds, name)
			s.mu.Unlock()
			code := int64(0)
			if pw != s.password {
				code = 49
			}
			_, _ = c.Write(reply(id, ldapResult(1, code)))
		case 23: // extended: StartTLS
			if s.noStart {
				_, _ = c.Write(reply(id, ldapResult(24, 2)))
				continue
			}
			_, _ = c.Write(reply(id, ldapResult(24, 0)))
			tc := tls.Server(c, s.tls)
			if tc.Handshake() != nil {
				return
			}
			c, secure = tc, true
		case 3: // search: every entry
			for _, e := range s.entries {
				ent := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 4, nil, "entry")
				ent.AppendChild(berString(e.DN, "dn"))
				attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attrs")
				for _, a := range e.Attrs {
					at := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attr")
					at.AppendChild(berString(a.Name, "type"))
					vals := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "vals")
					for _, v := range a.Vals {
						vals.AppendChild(berString(v, "val"))
					}
					at.AppendChild(vals)
					attrs.AppendChild(at)
				}
				ent.AppendChild(attrs)
				_, _ = c.Write(reply(id, ent))
			}
			_, _ = c.Write(reply(id, ldapResult(5, 0)))
		case 2: // unbind
			return
		default:
			_, _ = c.Write(reply(id, ldapResult(5, 53)))
		}
	}
}

func wireSpec(t *testing.T, s *wireLDAP, security, password string, dial safehttp.DialFunc, extra map[string]any) TargetSpec {
	t.Helper()
	target := map[string]any{"url": s.url(), "base_dn": base, "bind_dn": "cn=svc,dc=example,dc=com", "ca_pem": s.caPEM}
	if security != "" {
		target["security"] = security
	}
	for k, v := range extra {
		target[k] = v
	}
	c, err := ParseCommon(mustJSON(t, map[string]any{"account_system": "dir", "target": target}))
	if err != nil {
		t.Fatal(err)
	}
	return TargetSpec{Type: TypeAD, Common: c, Secret: map[string]string{"bind_password": password},
		Deps: Deps{Dial: dial, AllowPlainLDAP: true}}
}

func devDial(t *testing.T) safehttp.DialFunc {
	t.Helper()
	d, err := safehttp.NewDialer(safehttp.Options{Env: config.Dev, AllowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestLDAPWire(t *testing.T) {
	ctx := context.Background()
	entries := []ldapEntry{{DN: "cn=Eng," + base, Attrs: []ldapAttr{{"sAMAccountName", []string{"Eng"}},
		{"member", []string{"CN=a,DC=x", "CN=b,DC=x"}}, {"modifyTimestamp", []string{"20260101000000.0Z"}}}}}

	t.Run("ldaps", func(t *testing.T) {
		s := newWireLDAP(t, true)
		s.entries = entries
		p, err := openLDAP(ctx, wireSpec(t, s, "", "right-password", devDial(t), nil))
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()
		st, err := p.ReadAll(ctx, Scope{})
		if err != nil || len(st.Groups) != 1 || len(st.Groups["eng"].Members) != 2 || st.Groups["eng"].Ref.ID != "cn=Eng,"+base {
			t.Fatalf("ReadAll = %+v, %v", st.Groups, err)
		}
		if s.binds[0] != "cn=svc,dc=example,dc=com" {
			t.Errorf("binds = %v", s.binds)
		}
	})

	t.Run("starttls: no operation before TLS but the upgrade", func(t *testing.T) {
		s := newWireLDAP(t, false)
		s.entries = entries
		p, err := openLDAP(ctx, wireSpec(t, s, "starttls", "right-password", devDial(t), nil))
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()
		if st, err := p.ReadAll(ctx, Scope{}); err != nil || len(st.Groups["eng"].Members) != 2 {
			t.Fatalf("ReadAll = %+v, %v", st.Groups, err)
		}
		// the only plain-text request is the StartTLS extended operation: the password is never sent in the clear
		if s.plainOps != 1 {
			t.Errorf("%d operations before TLS, want 1 (StartTLS)", s.plainOps)
		}
	})

	t.Run("a refused StartTLS does not fall back to plain text", func(t *testing.T) {
		s := newWireLDAP(t, false)
		s.noStart = true
		if _, err := openLDAP(ctx, wireSpec(t, s, "starttls", "right-password", devDial(t), nil)); err == nil {
			t.Fatal("connected without TLS")
		}
		if len(s.binds) != 0 {
			t.Errorf("a bind was sent: %v", s.binds)
		}
	})

	t.Run("a wrong password", func(t *testing.T) {
		s := newWireLDAP(t, true)
		_, err := openLDAP(ctx, wireSpec(t, s, "", "wrong-password", devDial(t), nil))
		if err == nil || !strings.Contains(err.Error(), "bind") || strings.Contains(err.Error(), "wrong-password") {
			t.Errorf("open with a wrong password: %v", err)
		}
	})

	t.Run("an untrusted certificate", func(t *testing.T) {
		s := newWireLDAP(t, true)
		spec := wireSpec(t, s, "", "right-password", devDial(t), map[string]any{"ca_pem": ""})
		if _, err := openLDAP(ctx, spec); err == nil || !strings.Contains(err.Error(), "TLS") {
			t.Errorf("a self-signed certificate was trusted: %v", err)
		}
	})

	t.Run("a name that is not in the certificate", func(t *testing.T) {
		s := newWireLDAP(t, true)
		spec := wireSpec(t, s, "", "right-password", devDial(t), map[string]any{"server_name": "other.example"})
		if _, err := openLDAP(ctx, spec); err == nil {
			t.Error("the certificate was accepted for another server name")
		}
	})

	t.Run("the address guard applies", func(t *testing.T) {
		s := newWireLDAP(t, true)
		prod, err := safehttp.NewDialer(safehttp.Options{Env: config.Prod})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := openLDAP(ctx, wireSpec(t, s, "", "right-password", prod, nil)); err == nil || !strings.Contains(err.Error(), "not allowed") {
			t.Errorf("a production dialer reached a loopback LDAP server: %v", err)
		}
		if len(s.binds) != 0 {
			t.Errorf("the server saw a bind: %v", s.binds)
		}
	})
}
