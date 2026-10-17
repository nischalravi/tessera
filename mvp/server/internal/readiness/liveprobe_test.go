package readiness

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/ldap"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness/template"
	"github.com/nischalravi/tessera/mvp/server/internal/safedial"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

const ldapCfg = `{"host":"192.168.1.10","port":636,"bind_dn":"uid=svc-tessera,ou=people,dc=tessera,dc=test",
 "base_dns":["ou=people,dc=tessera,dc=test","ou=groups,dc=tessera,dc=test"],"user_filter":"(objectClass=inetOrgPerson)",
 "technical_owner":"Ingrid","business_owner":"Thandiwe"}`

const bindPassword = "ro-secret-pw-7731"

func ldapTmpl(t *testing.T) *template.Resolved {
	t.Helper()
	r, ok := template.MustDefault().Get("ldap")
	if !ok {
		t.Fatal("no ldap template")
	}
	return r
}

func caPEM(t *testing.T) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Lab CA"}, NotBefore: t0,
		NotAfter: t0.Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func liveSvc(t *testing.T) *Service {
	t.Helper()
	s := newSvc(t)
	k, err := seal.New(seal.RandomBytes(seal.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	s.Runner.Live.Sealer = k
	s.Runner.Live.Env = config.Prod
	return s
}

// ldapConn creates an ldap connection with a stored password.
func ldapConn(t *testing.T, s *Service, st Scope, cfg string) (id, ref string) {
	t.Helper()
	write(t, st, func(c *store.TenantTx) error {
		b, err := s.Create(c, CreateInput{Name: "Lab LDAP", ConnectorType: "ldap", System: "lab-ldap", Config: json.RawMessage(cfg)}, "admin", t0)
		if err != nil {
			return err
		}
		id = b.Conn.ID
		b, err = s.SetCredential(c, id, CredentialInput{Secret: bindPassword}, "admin", t0)
		if err != nil {
			return err
		}
		ref = *b.Rev.SecretRef
		return nil
	})
	return id, ref
}

// TestLive_CredentialSealedAndTenantBound: the password is stored sealed under
// the KEK, the revision keeps only the reference, and the blob opens only for
// its own tenant and reference.
func TestLive_CredentialSealedAndTenantBound(t *testing.T) {
	st, s := newStore(t), liveSvc(t)
	id, ref := ldapConn(t, s, st, ldapCfg)
	if !strings.HasPrefix(ref, "sealed:") {
		t.Fatalf("ref %q", ref)
	}
	read(t, st, func(c *store.TenantTx) error {
		k, err := c.Credential(id, store.PurposeBind, ref)
		if err != nil {
			return err
		}
		blob := k.Sealed
		if bytes.Contains(blob, []byte(bindPassword)) {
			t.Error("the stored credential is not encrypted")
		}
		pt, err := s.Runner.Live.Sealer.Open(blob, connectionSecretAAD(c.Tenant(), id, ref))
		if err != nil || string(pt) != bindPassword {
			t.Errorf("open: %q %v", pt, err)
		}
		other := tenancy.MustParse("00000000-0000-4000-8000-0000000000b2")
		if _, err := s.Runner.Live.Sealer.Open(blob, connectionSecretAAD(other, id, ref)); err == nil {
			t.Error("the blob opened under another tenant")
		}
		if _, err := s.Runner.Live.Sealer.Open(blob, connectionSecretAAD(c.Tenant(), id, "sealed:other")); err == nil {
			t.Error("the blob opened under another reference")
		}
		if _, err := s.Runner.Live.Sealer.Open(blob, connectionSecretAAD(c.Tenant(), "other-conn", ref)); err == nil {
			t.Error("the blob opened under another connection")
		}
		if _, err := s.Runner.Live.Sealer.Open(blob, store.CredentialAAD(c.Tenant(), id, store.PurposeContainment, ref)); err == nil {
			t.Error("the blob opened under another purpose")
		}
		b, err := s.Current(c, id, t0)
		if err != nil {
			return err
		}
		if raw, _ := json.Marshal(b.Rev); strings.Contains(string(raw), bindPassword) {
			t.Error("the revision carries the password")
		}
		if b.cred != "" {
			t.Error("a loaded bundle holds the credential outside a run")
		}
		if err := s.loadCredential(c, b); err != nil || string(b.cred) != bindPassword {
			t.Errorf("loadCredential: %v", err)
		}
		if got := fmt.Sprintf("%v %+v %#v", b.cred, b.cred, b.cred); strings.Contains(got, bindPassword) {
			t.Errorf("credential prints: %s", got)
		}
		return nil
	})
	// Without a Sealer the secret is acknowledged and discarded, as before.
	st2, plain := newStore(t), newSvc(t)
	id2, ref2 := ldapConn(t, plain, st2, ldapCfg)
	read(t, st2, func(c *store.TenantTx) error {
		if _, err := c.Credential(id2, store.PurposeBind, ref2); err != store.ErrNotFound {
			t.Errorf("stored without a sealer: %v", err)
		}
		return nil
	})
}

// TestLive_ProberFor: demo types keep the simulated prober; a real ldap
// revision gets the real prober; other real types are unchanged.
func TestLive_ProberFor(t *testing.T) {
	st, s := newStore(t), liveSvc(t)
	adID := readyAD(t, s, st, "AD demo", "")
	ldapID, _ := ldapConn(t, s, st, ldapCfg)
	prober := func(id string, load bool) (connectors.Prober, error) {
		var p connectors.Prober
		var err error
		read(t, st, func(c *store.TenantTx) error {
			b, e := s.Current(c, id, t0)
			if e != nil {
				return e
			}
			if load {
				if e := s.loadCredential(c, b); e != nil {
					return e
				}
			}
			p, err = s.Runner.withDefaults().ProberFor(b, t0)
			return nil
		})
		return p, err
	}
	p, err := prober(adID, true)
	if _, ok := p.(*connectors.ScenarioProber); !ok || err != nil {
		t.Errorf("demo AD: %T %v", p, err)
	}
	p, err = prober(ldapID, true)
	if _, ok := p.(*ldap.Prober); !ok || err != nil {
		t.Errorf("ldap: %T %v", p, err)
	}
	// No credential loaded: fail closed, never a simulated prober for a real type.
	if p, err = prober(ldapID, false); err == nil || p != nil {
		t.Errorf("ldap without credential: %T %v", p, err)
	}
}

// TestLive_ValidateRealLDAP: a validation of a real ldap connection runs the
// real prober (results are not simulated), and a private target without the
// agent or the dev allowlist is refused with an explanation.
func TestLive_ValidateRealLDAP(t *testing.T) {
	st, s := newStore(t), liveSvc(t)
	id, _ := ldapConn(t, s, st, ldapCfg)
	write(t, st, func(c *store.TenantTx) error {
		// the items that need no live evidence are attested, as in readyAD
		for _, item := range []string{"base.owner", "base.correlation.key", "base.stale.threshold"} {
			if _, err := s.Attest(c, id, item, "checked in the console", "admin", t0); err != nil {
				return err
			}
		}
		_, err := s.Transition(c, id, store.StateReadyToValidate, "admin", t0)
		return err
	})
	v, err := s.Validate(context.Background(), st, id, "admin", clockAt(t0))
	if err != nil {
		t.Fatal(err)
	}
	if v.Simulated {
		t.Error("a real connection's run is labelled simulated")
	}
	r := resultFor(v, "ldap.tls.ldaps", "tls_handshake")
	if r == nil || r.Status != "error" || !strings.Contains(r.Message, "Directory Agent") {
		t.Fatalf("tls_handshake: %+v", r)
	}
	if r := resultFor(v, "ldap.bind", "bind"); r == nil || r.Status != "blocked" {
		t.Errorf("bind: %+v", r)
	}
	if got := state(t, s, st, id); got != store.StateReadyToValidate {
		t.Errorf("state after failing validation: %s", got)
	}
	raw, _ := json.Marshal(v)
	if bytes.Contains(raw, []byte(bindPassword)) {
		t.Error("the run view carries the password")
	}
}

// TestLive_SafedialAllowIsDevOnly: the allowlist reaches the dialer only in dev.
func TestLive_SafedialAllowIsDevOnly(t *testing.T) {
	allow, err := safedial.ParseAllow("192.168.1.10:636")
	if err != nil {
		t.Fatal(err)
	}
	b := &Bundle{Conn: &store.Connection{ConnectorType: "ldap"}, Config: ConnConfig{Host: "192.168.1.10", Port: 636, BindDN: "cn=x", BaseDNs: []string{"dc=x"}}, cred: "pw"}
	b.Template = ldapTmpl(t)
	for _, env := range []string{config.Dev, config.Prod, ""} {
		o := LiveOptions{Env: env, Allow: allow}
		if _, ok, err := o.liveProber(b, t0); !ok || err != nil {
			t.Errorf("env %q: %v %v", env, ok, err)
		}
	}
}

func TestConfig_BindDNAndCABundle(t *testing.T) {
	tmpl := ldapTmpl(t)
	base := ConnConfig{Host: "ldap.lab.example", Port: 636, BaseDNs: []string{"dc=x"}, CorrelationKey: "entryUUID"}
	if errs := Validate(base, tmpl); len(errs) != 0 {
		t.Fatalf("base: %v", errs)
	}
	bad := map[string]ConnConfig{}
	c := base
	c.BindDN = "not a dn"
	bad["bind_dn"] = c
	c = base
	c.CABundle = "not pem"
	bad["ca_bundle"] = c
	c = base
	c.CABundle = "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----"
	bad["ca_bundle key"] = c
	for name, cfg := range bad {
		errs := Validate(cfg, tmpl)
		if len(errs) != 1 || !strings.HasPrefix(name, errs[0].Field) {
			t.Errorf("%s: %v", name, errs)
		}
	}
	c = base
	c.BindDN, c.CABundle = "uid=svc,ou=people,dc=x", caPEM(t)
	if errs := Validate(c, tmpl); len(errs) != 0 {
		t.Errorf("valid bind DN: %v", errs)
	}
}
