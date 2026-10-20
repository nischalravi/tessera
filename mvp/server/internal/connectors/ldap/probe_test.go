package ldap

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"log/slog"
	"math/big"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	goldap "github.com/go-ldap/ldap/v3"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness/checks"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness/template"
	"github.com/nischalravi/tessera/mvp/server/internal/safedial"
)

const labHost = "ldap.lab.example"

func labCert(t *testing.T, notAfter time.Time) (*tls.Config, *x509.CertPool) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caT := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Lab CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caT, caT, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	lt := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: labHost}, DNSNames: []string{labHost},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, lt, ca, &key.PublicKey, caKey)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der, caDER}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}, pool
}

// lab describes how to point a probe at a fixture.
type lab struct {
	fixture  string
	bindDN   string
	password string
	bases    []string
}

var (
	lldapLab = lab{"lldap.json", "uid=svc-tessera,ou=people,dc=tessera,dc=test", "ro-secret-pw",
		[]string{"ou=people,dc=tessera,dc=test", "ou=groups,dc=tessera,dc=test"}}
	ds389Lab = lab{"ds389.json", "uid=svc-tessera,ou=people,dc=example,dc=com", "ro-secret-pw",
		[]string{"ou=people,dc=example,dc=com"}}
	openldapLab = lab{"openldap.json", "uid=svc-tessera,ou=people,dc=example,dc=org", "ro-secret-pw",
		[]string{"ou=people,dc=example,dc=org"}}
)

type testEnv struct {
	srv  *fakeServer
	p    *Prober
	cfg  Config
	pool *x509.CertPool
}

func newEnv(t *testing.T, l lab, mutate ...func(*fakeDir, *Config)) *testEnv {
	t.Helper()
	d := loadFixture(t, l.fixture)
	tcfg, pool := labCert(t, time.Now().Add(90*24*time.Hour))
	cfg := Config{Host: labHost, Port: 636, BindDN: l.bindDN, Password: Secret(l.password), BaseDNs: l.bases,
		UserFilter: "(objectClass=inetOrgPerson)", RootCAs: pool}
	for _, m := range mutate {
		m(d, &cfg)
	}
	srv := startFake(t, d, tcfg)
	dialer, err := safedial.New(safedial.Options{Env: config.Prod, RootCAs: cfg.RootCAs, Resolver: labResolver{},
		TestDial: fakeTransport{srv}.dial})
	if err != nil {
		t.Fatal(err)
	}
	cfg.Dialer = dialer
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return &testEnv{srv: srv, p: p, cfg: cfg, pool: pool}
}

func withBind(dn, pw string) func(*fakeDir, *Config) {
	return func(_ *fakeDir, c *Config) { c.BindDN, c.Password = dn, Secret(pw) }
}

// runLive runs every live check of the ldap template (and the base items)
// against the prober through the real check registry, as the runner does.
func runLive(t *testing.T, e *testEnv) map[string]checks.Result {
	t.Helper()
	return runChecks(t, e.p, e.cfg.BaseDNs, e.cfg.UserFilter)
}

// runChecks runs the ldap template's live checks against any prober.
func runChecks(t *testing.T, p connectors.Prober, bases []string, userFilter string) map[string]checks.Result {
	t.Helper()
	reg := template.MustDefault()
	tmpl, ok := reg.Get("ldap")
	if !ok {
		t.Fatal("no ldap template")
	}
	env := checks.Env{Probe: p, Now: time.Now(), TemplateID: "ldap", SecretRef: "sealed:test", BaseDNs: bases,
		Filters: map[string]string{"user_filter": userFilter}, ConfigStrings: map[string]string{},
		RequiredAttrs: tmpl.RequiredAttributes["user"]}
	out := map[string]checks.Result{}
	for _, it := range tmpl.Items {
		for _, v := range it.Verify {
			if v.Kind != template.Live {
				continue
			}
			c, ok := checks.Get(v.Check)
			if !ok {
				t.Fatalf("check %s is not registered", v.Check)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			r := checks.Run(ctx, c, env, checks.Params(v.Params))
			cancel()
			if _, dup := out[v.Check]; !dup {
				out[v.Check] = r
			}
		}
	}
	return out
}

func want(t *testing.T, got map[string]checks.Result, check, status string) checks.Result {
	t.Helper()
	r, ok := got[check]
	if !ok {
		t.Fatalf("check %s did not run", check)
	}
	if r.Status != status {
		t.Errorf("%s = %s (%q); want %s", check, r.Status, r.Message, status)
	}
	return r
}

func wantUnsupported(t *testing.T, got map[string]checks.Result, check string) {
	t.Helper()
	r := want(t, got, check, checks.Skipped)
	if u, _ := r.Observed["unsupported"].(bool); !u || !strings.Contains(r.Message, "attestation") {
		t.Errorf("%s: want unsupported with attestation required, got %+v", check, r)
	}
}

// TestProbe_LLDAPShaped: an LLDAP lab (base dc=tessera,dc=test, users under
// ou=people, groupOfUniqueNames under ou=groups). It has no Get Effective
// Rights, so those checks are unsupported and need an attestation, never pass.
func TestProbe_LLDAPShaped(t *testing.T) {
	e := newEnv(t, lldapLab)
	got := runLive(t, e)
	want(t, got, "tls_handshake", checks.Pass)
	want(t, got, "tls_chain", checks.Pass)
	want(t, got, "bind", checks.Pass)
	want(t, got, "dn_exists", checks.Pass)
	want(t, got, "filter_parse", checks.Pass)
	r := want(t, got, "sample_search", checks.Pass)
	if r.Observed["objects"] != 5 || r.Observed["computers"] != 0 {
		t.Errorf("sample_search observed %v", r.Observed)
	}
	want(t, got, "read_per_class", checks.Pass)
	want(t, got, "paging", checks.Pass)
	want(t, got, "attr_returned", checks.Pass)
	want(t, got, "schema_read", checks.Pass)
	// No Who Am I and no GER on this server: attestation required.
	wantUnsupported(t, got, "bind_identity")
	wantUnsupported(t, got, "effective_rights")
	wantUnsupported(t, got, "clock_skew")
	// No syncrepl or changelog: only modifyTimestamp polling remains.
	r = want(t, got, "incremental_capable", checks.Fail)
	if r.Observed["mechanism"] != "modifytimestamp_polling" {
		t.Errorf("incremental observed %v", r.Observed)
	}
}

// TestProbe_LLDAPGroups: the group classes are read with LLDAP's member /
// uniqueMember, and per-class counts are counts only.
func TestProbe_LLDAPGroups(t *testing.T) {
	e := newEnv(t, lldapLab)
	st, err := e.p.Sample(context.Background(), connectors.SampleQuery{Op: "classes",
		Classes: []string{"inetOrgPerson", "posixAccount", "groupOfNames", "groupOfUniqueNames", "posixGroup"},
		Attrs:   []string{"entryUUID", "uid", "cn", "mail", "createTimestamp", "modifyTimestamp"}, Limit: 500})
	if err != nil {
		t.Fatal(err)
	}
	if st.PerClass["inetOrgPerson"] != 5 || st.PerClass["groupOfUniqueNames"] != 4 || st.PerClass["groupOfNames"] != 0 || st.PerClass["posixGroup"] != 0 {
		t.Errorf("per class: %v", st.PerClass)
	}
	if len(st.Missing) != 0 {
		t.Errorf("missing: %v", st.Missing)
	}
	// Two person classes (inetOrgPerson, posixAccount) see the same five users.
	if st.AttrFill["mail"] != 10 || st.AttrFill["uniqueMember"] != 4 || st.AttrFill["member"] != 4 {
		t.Errorf("fill: %v", st.AttrFill)
	}
	// A group class without any member attribute is reported as missing.
	e2 := newEnv(t, lldapLab, func(d *fakeDir, _ *Config) {
		for i := range d.Entries {
			delete(d.Entries[i].Attrs, "member")
			delete(d.Entries[i].Attrs, "uniqueMember")
		}
	})
	st, _ = e2.p.Sample(context.Background(), connectors.SampleQuery{Op: "classes", Classes: []string{"groupOfUniqueNames"}, Limit: 500})
	if !slices.Contains(st.Missing, "uniqueMember") {
		t.Errorf("missing: %v", st.Missing)
	}
	// Nothing readable at all is a failure, not a pass.
	e3 := newEnv(t, lldapLab, func(_ *fakeDir, c *Config) { c.BaseDNs = []string{"ou=nowhere,dc=tessera,dc=test"} })
	got := runLive(t, e3)
	want(t, got, "read_per_class", checks.Fail)
	want(t, got, "dn_exists", checks.Fail)
}

// TestProbe_LLDAPAdminIsRoot: LLDAP has no Who Am I here, but a member of
// lldap_admin can write everything, so it is reported as a root identity.
func TestProbe_LLDAPAdminIsRoot(t *testing.T) {
	e := newEnv(t, lldapLab, withBind("uid=admin,ou=people,dc=tessera,dc=test", "admin-secret-pw"))
	a, err := e.p.Authenticate(context.Background())
	if err != nil || !a.OK || !a.RootIdentity || a.IdentityUnverified {
		t.Fatalf("admin: %+v %v", a, err)
	}
	r := want(t, runLive(t, e), "bind_identity", checks.Fail)
	if !strings.Contains(r.Message, "administrator") {
		t.Errorf("message %q", r.Message)
	}
	// The strict read-only account is not root but is unverified (no Who Am I).
	e2 := newEnv(t, lldapLab)
	a, _ = e2.p.Authenticate(context.Background())
	if !a.OK || a.RootIdentity || !a.IdentityUnverified {
		t.Errorf("readonly: %+v", a)
	}
}

func TestProbe_389DS(t *testing.T) {
	e := newEnv(t, ds389Lab)
	got := runLive(t, e)
	want(t, got, "bind", checks.Pass)
	want(t, got, "bind_identity", checks.Pass)
	r := want(t, got, "effective_rights", checks.Pass)
	if r.Observed["writable"] != 0 {
		t.Errorf("writable: %v", r.Observed)
	}
	want(t, got, "read_per_class", checks.Pass) // nsUniqueId stands in for entryUUID
	r = want(t, got, "incremental_capable", checks.Pass)
	if r.Observed["mechanism"] != "retro_changelog" {
		t.Errorf("mechanism %v", r.Observed)
	}
	r = want(t, got, "schema_read", checks.Pass)
	if r.Observed["custom_attributes"] != 2 {
		t.Errorf("custom attributes: %v", r.Observed)
	}
	want(t, got, "paging", checks.Pass)

	// A bind identity with write rights fails effective_rights, read from the server.
	w := newEnv(t, ds389Lab, withBind("uid=svc-writer,ou=people,dc=example,dc=com", "rw-secret-pw"))
	r = want(t, runLive(t, w), "effective_rights", checks.Fail)
	if n, _ := r.Observed["writable"].(int); n == 0 {
		t.Errorf("writable: %v", r.Observed)
	}
	// Directory Manager is the root DN.
	dm := newEnv(t, ds389Lab, withBind("cn=Directory Manager", "dm-secret-pw"))
	a, err := dm.p.Authenticate(context.Background())
	if err != nil || !a.OK || !a.RootIdentity {
		t.Fatalf("Directory Manager: %+v %v", a, err)
	}
	want(t, runLive(t, dm), "bind_identity", checks.Fail)
}

func TestProbe_OpenLDAP(t *testing.T) {
	e := newEnv(t, openldapLab)
	got := runLive(t, e)
	want(t, got, "bind_identity", checks.Pass)
	wantUnsupported(t, got, "effective_rights") // OpenLDAP: attest instead
	r := want(t, got, "incremental_capable", checks.Pass)
	if r.Observed["mechanism"] != "syncrepl" {
		t.Errorf("mechanism %v", r.Observed)
	}
	// The rootDN (olcRootDN, readable only by the root) is detected through Who Am I.
	root := newEnv(t, openldapLab, withBind("cn=admin,dc=example,dc=org", "admin-secret-pw"))
	a, err := root.p.Authenticate(context.Background())
	if err != nil || !a.RootIdentity || a.Identity != "cn=admin,dc=example,dc=org" {
		t.Fatalf("rootDN: %+v %v", a, err)
	}
	// Without Who Am I the rootDN is still found from cn=config, and the
	// identity is reported root rather than unverified.
	nw := newEnv(t, openldapLab, withBind("cn=admin,dc=example,dc=org", "admin-secret-pw"),
		func(d *fakeDir, _ *Config) { d.WhoAmI = false })
	a, _ = nw.p.Authenticate(context.Background())
	if !a.RootIdentity || a.IdentityUnverified {
		t.Errorf("rootDN without Who Am I: %+v", a)
	}
	// A configured root DN that the server does not reveal.
	cr := newEnv(t, lldapLab, func(_ *fakeDir, c *Config) { c.RootDNs = []string{c.BindDN} })
	a, _ = cr.p.Authenticate(context.Background())
	if !a.RootIdentity {
		t.Errorf("configured root DN: %+v", a)
	}
}

// TestProbe_SizeLimitAndPaging: a server whose limit is below the directory
// size. Paged reads work when the server honours the control; when it does
// not, the size limit is hit and reported, never silently truncated.
func TestProbe_SizeLimitAndPaging(t *testing.T) {
	many := func(d *fakeDir, _ *Config) {
		for i := 0; i < 250; i++ {
			uid := fmt.Sprintf("u%03d", i)
			d.Entries = append(d.Entries, fakeEntry{DN: "uid=" + uid + ",ou=people,dc=tessera,dc=test", Attrs: map[string][]string{
				"objectClass": {"inetOrgPerson", "top"}, "uid": {uid}, "cn": {uid}, "mail": {uid + "@tessera.test"}}})
		}
		d.SizeLimit = 100
	}
	e := newEnv(t, lldapLab, many)
	st, err := e.p.Sample(context.Background(), connectors.SampleQuery{Op: "page", Limit: 500})
	if err != nil {
		t.Fatal(err)
	}
	if st.SizeLimitHit || !st.PagedBeyond || st.Objects < 200 || st.Objects > connectors.MaxSample {
		t.Errorf("paged: %+v", st)
	}
	want(t, runLive(t, e), "paging", checks.Pass)

	np := newEnv(t, lldapLab, many, func(d *fakeDir, _ *Config) { d.Paged = false })
	st, err = np.p.Sample(context.Background(), connectors.SampleQuery{Op: "page", Limit: 500})
	if err != nil {
		t.Fatal(err)
	}
	if !st.SizeLimitHit || st.PagedBeyond {
		t.Errorf("unpaged: %+v", st)
	}
	r := want(t, runLive(t, np), "paging", checks.Fail)
	if sl, _ := r.Observed["size_limit_hit"].(bool); !sl {
		t.Errorf("observed %v", r.Observed)
	}
	// The class sample also reports the truncation.
	st, _ = np.p.Sample(context.Background(), connectors.SampleQuery{Op: "classes", Classes: []string{"inetOrgPerson"}, Limit: 500})
	if !st.SizeLimitHit || st.PerClass["inetOrgPerson"] != 100 {
		t.Errorf("classes: %+v", st)
	}
}

// TestProbe_SampleBound: at most 500 objects per class are read, and every
// result is counts.
func TestProbe_SampleBound(t *testing.T) {
	e := newEnv(t, lldapLab, func(d *fakeDir, _ *Config) {
		for i := 0; i < 700; i++ {
			uid := fmt.Sprintf("bulk%03d", i)
			d.Entries = append(d.Entries, fakeEntry{DN: "uid=" + uid + ",ou=people,dc=tessera,dc=test", Attrs: map[string][]string{
				"objectClass": {"inetOrgPerson"}, "uid": {uid}, "mail": {"secret-" + uid + "@tessera.test"}}})
		}
	})
	st, err := e.p.Sample(context.Background(), connectors.SampleQuery{Op: "classes", Classes: []string{"inetOrgPerson"},
		Attrs: []string{"uid", "mail"}, Limit: 100000})
	if err != nil {
		t.Fatal(err)
	}
	if st.PerClass["inetOrgPerson"] != connectors.MaxSample || st.Objects != connectors.MaxSample || st.AttrFill["mail"] != connectors.MaxSample {
		t.Errorf("bound: %+v", st)
	}
	b, _ := json.Marshal(st)
	if strings.Contains(string(b), "secret-") || strings.Contains(string(b), "@tessera.test") {
		t.Errorf("stats carry attribute values: %s", b)
	}
	st, _ = e.p.Sample(context.Background(), connectors.SampleQuery{Op: "search", Filter: "(objectClass=inetOrgPerson)", Limit: 500})
	if st.Objects != 50 {
		t.Errorf("sample_search reads %d; want 50", st.Objects)
	}
	if _, err := e.p.Sample(context.Background(), connectors.SampleQuery{Op: "range"}); !errors.Is(err, connectors.ErrUnsupported) {
		t.Errorf("unknown op: %v", err)
	}
}

// TestProbe_Concurrency: never more than two requests in flight at once.
func TestProbe_Concurrency(t *testing.T) {
	e := newEnv(t, lldapLab)
	hold := make(chan struct{})
	e.srv.holdSearch = hold
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = e.p.ObjectExists(context.Background(), "ou=people,dc=tessera,dc=test")
		}()
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		e.srv.mu.Lock()
		n := e.srv.inflight
		e.srv.mu.Unlock()
		if n >= MaxConcurrent {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond) // a third connection would show up now
	close(hold)
	wg.Wait()
	e.srv.mu.Lock()
	defer e.srv.mu.Unlock()
	if e.srv.maxInflight != MaxConcurrent {
		t.Errorf("max concurrent requests = %d; want %d", e.srv.maxInflight, MaxConcurrent)
	}
}

// TestProbe_PlaintextRefused: a credential is never sent in clear text. A
// server that refuses StartTLS, or a chain that does not verify, gets no bind.
func TestProbe_PlaintextRefused(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, lldapLab, func(d *fakeDir, c *Config) { c.Port = 389; d.NoStartTLS = true })
	if _, err := e.p.Authenticate(ctx); !errors.Is(err, safedial.ErrNoTLS) {
		t.Fatalf("Authenticate over a server without StartTLS: %v", err)
	}
	ci, err := e.p.Connect(ctx)
	if err != nil || !ci.Reachable || ci.TLSVersion != "" {
		t.Errorf("Connect: %+v %v", ci, err)
	}
	r := want(t, runLive(t, e), "tls_handshake", checks.Fail)
	if !strings.Contains(r.Message, "No TLS") {
		t.Errorf("tls_handshake: %q", r.Message)
	}
	ops, _ := e.srv.snapshot()
	if slices.Contains(ops, "bind") || slices.Contains(ops, "search") {
		t.Errorf("operations sent without TLS: %v", ops)
	}
	e.srv.mu.Lock()
	if e.srv.plainBinds != 0 || len(e.srv.bindPasswds) != 0 {
		t.Errorf("credentials reached a plaintext connection: %d %v", e.srv.plainBinds, len(e.srv.bindPasswds))
	}
	e.srv.mu.Unlock()

	// A chain the CA bundle does not cover: reported by Connect, and no bind.
	bad := newEnv(t, lldapLab, func(_ *fakeDir, c *Config) { c.RootCAs = x509.NewCertPool() })
	ci, err = bad.p.Connect(ctx)
	if err != nil || ci.ChainValid || !ci.HostnameMatch || ci.TLSVersion != "1.3" {
		t.Errorf("Connect (bad chain): %+v %v", ci, err)
	}
	want(t, runLive(t, bad), "tls_chain", checks.Fail)
	if _, err := bad.p.Authenticate(ctx); err == nil {
		t.Error("Authenticate over an unverified chain succeeded")
	}
	bad.srv.mu.Lock()
	if len(bad.srv.bindPasswds) != 0 {
		t.Error("bind sent over an unverified chain")
	}
	bad.srv.mu.Unlock()

	// StartTLS on 389 works when the server offers it: the bind is encrypted.
	ok := newEnv(t, lldapLab, func(_ *fakeDir, c *Config) { c.Port = 389 })
	a, err := ok.p.Authenticate(ctx)
	if err != nil || !a.OK {
		t.Fatalf("StartTLS bind: %+v %v", a, err)
	}
	ok.srv.mu.Lock()
	if ok.srv.plainBinds != 0 || len(ok.srv.bindPasswds) != 1 {
		t.Errorf("binds: plain=%d total=%d", ok.srv.plainBinds, len(ok.srv.bindPasswds))
	}
	ok.srv.mu.Unlock()
	ci, _ = ok.p.Connect(ctx)
	if !ci.ChainValid || ci.TLSVersion == "" {
		t.Errorf("Connect over StartTLS: %+v", ci)
	}
}

// TestProbe_BindOutcomes: wrong and empty passwords never pass, and an empty
// password is never sent (it would be an anonymous bind that "succeeds").
func TestProbe_BindOutcomes(t *testing.T) {
	ctx := context.Background()
	wrong := newEnv(t, lldapLab, withBind(lldapLab.bindDN, "not-the-password"))
	a, err := wrong.p.Authenticate(ctx)
	if err != nil || a.OK {
		t.Errorf("wrong password: %+v %v", a, err)
	}
	want(t, runLive(t, wrong), "bind", checks.Fail)

	empty := newEnv(t, lldapLab, withBind(lldapLab.bindDN, ""))
	a, err = empty.p.Authenticate(ctx)
	if err != nil || a.OK {
		t.Errorf("empty password: %+v %v", a, err)
	}
	if ops, _ := empty.srv.snapshot(); slices.Contains(ops, "bind") {
		t.Errorf("an empty password was sent: %v", ops)
	}
	unknown := newEnv(t, lldapLab, withBind("uid=ghost,ou=people,dc=tessera,dc=test", "x"))
	if a, err = unknown.p.Authenticate(ctx); err != nil || a.OK {
		t.Errorf("unknown DN: %+v %v", a, err)
	}
}

// TestProbe_PrivateTargetRefused: with no agent, a private directory is
// refused by safedial and surfaces as ErrTargetNotAllowed.
func TestProbe_PrivateTargetRefused(t *testing.T) {
	d, err := safedial.New(safedial.Options{Env: config.Prod})
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(Config{Host: "192.168.1.10", Port: 636, BindDN: "cn=x", Password: "y", Dialer: d})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Connect(context.Background()); !errors.Is(err, connectors.ErrTargetNotAllowed) {
		t.Errorf("Connect: %v", err)
	}
	if _, err := p.Authenticate(context.Background()); !errors.Is(err, connectors.ErrTargetNotAllowed) {
		t.Errorf("Authenticate: %v", err)
	}
	if _, err := New(Config{Host: "h", Port: 3268, Dialer: d}); err == nil {
		t.Error("port 3268 accepted")
	}
	if _, err := New(Config{Host: "h", Port: 636}); err == nil {
		t.Error("no dialer accepted")
	}
}

// TestProbers_ReadOnly: every Prober method is exercised against every lab
// shape (as the owner, a read-only account, and root); the server-side
// recorder fails on any operation other than bind, search, Who Am I,
// StartTLS and unbind. A meta-check proves the recorder sees a write.
func TestProbers_ReadOnly(t *testing.T) {
	labs := []struct {
		name string
		l    lab
		alt  []lab
	}{
		{"lldap", lldapLab, []lab{{"lldap.json", "uid=admin,ou=people,dc=tessera,dc=test", "admin-secret-pw", lldapLab.bases}}},
		{"389ds", ds389Lab, []lab{{"ds389.json", "cn=Directory Manager", "dm-secret-pw", ds389Lab.bases}}},
		{"openldap", openldapLab, nil},
	}
	allowed := []string{"bind", "search", "whoami", "starttls", "unbind"}
	for _, lc := range labs {
		t.Run(lc.name, func(t *testing.T) {
			envs := []*testEnv{newEnv(t, lc.l), newEnv(t, lc.l, func(_ *fakeDir, c *Config) { c.Port = 389 })}
			for _, a := range lc.alt {
				envs = append(envs, newEnv(t, a))
			}
			for _, e := range envs {
				ctx := context.Background()
				_, _ = e.p.Connect(ctx)
				_, _ = e.p.Authenticate(ctx)
				_, _ = e.p.RootInfo(ctx)
				_, _ = e.p.ObjectExists(ctx, e.cfg.BaseDNs[0])
				for _, op := range []string{"search", "classes", "attr", "page"} {
					_, _ = e.p.Sample(ctx, connectors.SampleQuery{Op: op, Filter: e.cfg.UserFilter, Classes: []string{"inetOrgPerson", "groupOfUniqueNames"},
						Attrs: []string{"entryUUID"}, Limit: 500})
				}
				_, _ = e.p.EffectiveRights(ctx, "self")
				_, _ = e.p.ChangeFeed(ctx)
				_, _ = e.p.RateLimits(ctx)
				_, _ = e.p.Time(ctx)
				runLive(t, e)
				ops, writes := e.srv.snapshot()
				if len(writes) != 0 {
					t.Errorf("write operations sent: %v", writes)
				}
				for _, op := range ops {
					if !slices.Contains(allowed, op) {
						t.Errorf("operation %q is not allowed", op)
					}
				}
				if len(ops) == 0 {
					t.Error("recorder saw nothing")
				}
			}
		})
	}
	t.Run("recorder sees writes", func(t *testing.T) {
		e := newEnv(t, lldapLab)
		conn, err := safedialDial(t, e)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_ = conn.Bind(lldapLab.bindDN, lldapLab.password)
		_ = conn.Add(goldap.NewAddRequest("uid=x,ou=people,dc=tessera,dc=test", nil))
		_ = conn.Modify(goldap.NewModifyRequest("uid=alice,ou=people,dc=tessera,dc=test", nil))
		_ = conn.Del(goldap.NewDelRequest("uid=alice,ou=people,dc=tessera,dc=test", nil))
		_ = conn.ModifyDN(goldap.NewModifyDNRequest("uid=alice,ou=people,dc=tessera,dc=test", "uid=al", true, ""))
		_, writes := e.srv.snapshot()
		if len(writes) != 4 {
			t.Errorf("recorder saw %v; want 4 writes", writes)
		}
	})
}

// safedialDial opens a raw go-ldap connection to the fake LDAPS port (for
// the recorder meta-test only; it is not the probe's path).
func safedialDial(t *testing.T, e *testEnv) (*goldap.Conn, error) {
	t.Helper()
	conn, err := e.p.cfg.Dialer.Dial(context.Background(), labHost, 636, false)
	if err != nil {
		return nil, err
	}
	c := goldap.NewConn(conn.Conn, true)
	c.SetTimeout(5 * time.Second)
	c.Start()
	return c, nil
}

// TestProbe_NoWriteAPIs: the package never references the write operations
// of the LDAP library. The probe reaches the library only through client.go.
func TestProbe_NoWriteAPIs(t *testing.T) {
	banned := map[string]bool{"Add": true, "Modify": true, "ModifyWithResult": true, "ModifyDN": true, "Del": true,
		"PasswordModify": true, "Extended": true, "Compare": true, "ExternalBind": true, "NTLMBind": true, "MD5Bind": true,
		"DigestMD5Bind": true, "GSSAPIBind": true, "UnauthenticatedBind": true, "Syncrepl": true, "DirSync": true,
		"NewAddRequest": true, "NewModifyRequest": true, "NewDelRequest": true, "NewModifyDNRequest": true,
		"NewPasswordModifyRequest": true, "NewExtendedRequest": true, "AddRequest": true, "ModifyRequest": true,
		"DelRequest": true, "ModifyDNRequest": true, "PasswordModifyRequest": true, "ExtendedRequest": true}
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, pkg := range pkgs {
		for name, f := range pkg.Files {
			ast.Inspect(f, func(n ast.Node) bool {
				if sel, ok := n.(*ast.SelectorExpr); ok && banned[sel.Sel.Name] {
					t.Errorf("%s: %s references %s", fset.Position(sel.Pos()), name, sel.Sel.Name)
				}
				return true
			})
		}
	}
	if len(pkgs) == 0 {
		t.Fatal("no package parsed")
	}
}

// TestProbe_NoSecretInResults: the password bytes appear in no serialised
// check result, prober value or error, and the Secret type never prints.
func TestProbe_NoSecretInResults(t *testing.T) {
	const pw = "ro-secret-pw"
	for _, l := range []lab{lldapLab, ds389Lab, openldapLab} {
		e := newEnv(t, l)
		var all bytes.Buffer
		for id, r := range runLive(t, e) {
			b, err := json.Marshal(map[string]any{"check": id, "status": r.Status, "message": r.Message, "observed": r.Observed})
			if err != nil {
				t.Fatal(err)
			}
			all.Write(b)
		}
		ctx := context.Background()
		ci, _ := e.p.Connect(ctx)
		a, _ := e.p.Authenticate(ctx)
		ri, _ := e.p.RootInfo(ctx)
		rg, _ := e.p.EffectiveRights(ctx, "self")
		fi, _ := e.p.ChangeFeed(ctx)
		st, _ := e.p.Sample(ctx, connectors.SampleQuery{Op: "classes", Classes: []string{"inetOrgPerson"}, Attrs: []string{"uid"}, Limit: 500})
		for _, v := range []any{ci, a, ri, rg, fi, st} {
			b, _ := json.Marshal(v)
			all.Write(b)
		}
		if bytes.Contains(all.Bytes(), []byte(pw)) {
			t.Errorf("%s: password found in serialised results", l.fixture)
		}
		// Probe errors carry no password either.
		bad := newEnv(t, l, func(_ *fakeDir, c *Config) { c.Port = 389 }, func(d *fakeDir, _ *Config) { d.NoStartTLS = true })
		_, err := bad.p.Authenticate(ctx)
		if err == nil || strings.Contains(err.Error(), pw) {
			t.Errorf("error %v", err)
		}
		// The server did receive it, only in the bind.
		e.srv.mu.Lock()
		if !slices.Contains(e.srv.bindPasswds, pw) {
			t.Error("the bind did not carry the password")
		}
		e.srv.mu.Unlock()
		for _, s := range []string{fmt.Sprint(e.cfg), fmt.Sprintf("%+v", e.cfg), fmt.Sprintf("%#v", e.cfg), fmt.Sprintf("%v", e.cfg.Password)} {
			if strings.Contains(s, pw) {
				t.Errorf("Config formats the password: %s", s)
			}
		}
		var lb bytes.Buffer
		slog.New(slog.NewJSONHandler(&lb, nil)).Info("cfg", "password", e.cfg.Password, "cfg", fmt.Sprintf("%+v", e.cfg))
		if strings.Contains(lb.String(), pw) {
			t.Errorf("slog output has the password: %s", lb.String())
		}
		b, _ := json.Marshal(e.cfg.Password)
		if strings.Contains(string(b), pw) {
			t.Error("Secret marshals its value")
		}
	}
}

func TestHelpers(t *testing.T) {
	for _, c := range []struct {
		def    string
		custom bool
	}{
		{"( 2.5.4.3 NAME ( 'cn' 'commonName' ) )", false},
		{"( 0.9.2342.19200300.100.1.1 NAME 'uid' )", false},
		{"( 1.3.6.1.1.1.1.0 NAME 'uidNumber' )", false},
		{"( 1.3.6.1.1.16.4 NAME 'entryUUID' )", false},
		{"( 2.16.840.1.113730.3.1.610 NAME 'nsAccountLock' )", false},
		{"( 1.3.6.1.4.1.99999.1.1 NAME 'acmeHrId' )", true},
		{"( 1.3.6.1.4.1.1466.115.121.1.15 NAME 'x' )", false},
		{"garbage", false},
		{"", false},
	} {
		if got := isCustomAttributeType(c.def); got != c.custom {
			t.Errorf("isCustomAttributeType(%q) = %v", c.def, got)
		}
	}
	if !sameDN("UID=Alice, OU=People,DC=x", "uid=alice,ou=people,dc=x") || sameDN("uid=a,dc=x", "uid=b,dc=x") {
		t.Error("sameDN")
	}
	if !isGroupCN("cn=lldap_admin,ou=groups,dc=x", "lldap_admin") || isGroupCN("cn=lldap_admin_x,ou=groups,dc=x", "lldap_admin") ||
		isGroupCN("ou=lldap_admin,dc=x", "lldap_admin") {
		t.Error("isGroupCN")
	}
	if tm, ok := parseGeneralized("20260101120000Z"); !ok || tm.Year() != 2026 {
		t.Error("parseGeneralized")
	}
	if _, ok := parseGeneralized("nope"); ok {
		t.Error("parseGeneralized accepted junk")
	}
	if tm, ok := parseGeneralized("20260101120000.0Z"); !ok || tm.Hour() != 12 {
		t.Error("parseGeneralized fraction")
	}
}
