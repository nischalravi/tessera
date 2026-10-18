package transport

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness/template"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

var t0 = time.Date(2026, 10, 11, 9, 0, 0, 0, time.UTC)

type env struct {
	src, dst readiness.Scope
	rd       *readiness.Service
	sealer   *seal.Sealer
}

func newEnv(t *testing.T) *env {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	var a, b store.Tenant
	if err := db.InSystem(context.Background(), "test", func(s *store.SystemTx) error {
		var err error
		if a, err = s.CreateTenant(store.Tenant{Slug: "larkspur-dev", Name: "Larkspur dev"}); err != nil {
			return err
		}
		b, err = s.CreateTenant(store.Tenant{Slug: "larkspur", Name: "Larkspur"})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	s, err := seal.New(seal.RandomBytes(seal.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	return &env{src: readiness.Scope{DB: db, Tenant: a.ID}, dst: readiness.Scope{DB: db, Tenant: b.ID},
		rd: readiness.NewService(template.MustDefault(), ""), sealer: s}
}

func write(t *testing.T, sc readiness.Scope, fn func(tx *store.TenantTx) error) {
	t.Helper()
	if err := sc.Write(context.Background(), fn); err != nil {
		t.Fatal(err)
	}
}

func str(s string) *string { return &s }

// seedSource gives the source tenant two connections, an overlay, an OIDC
// sign-in connection and the dev mock IdP.
func (e *env) seedSource(t *testing.T) {
	write(t, e.src, func(tx *store.TenantTx) error {
		b, err := e.rd.Create(tx, readiness.CreateInput{Name: "Corp AD", ConnectorType: "demo-ad", System: "corp-ad",
			Config: json.RawMessage(`{"host":"dc01.corp.example","base_dns":["DC=corp,DC=example"],"technical_owner":"Ingrid","business_owner":"Thandi"}`)}, "admin", t0)
		if err != nil {
			return err
		}
		if _, err := e.rd.SetCredential(tx, b.Conn.ID, readiness.CredentialInput{Reference: "vault:kv/tessera/ad"}, "admin", t0); err != nil {
			return err
		}
		if _, err := e.rd.Create(tx, readiness.CreateInput{Name: "Workday", ConnectorType: "demo-ad", System: "workday",
			Config: json.RawMessage(`{"host":"wd.corp.example"}`)}, "admin", t0); err != nil {
			return err
		}
		if _, err := e.rd.PutOverlay(tx, "ad", []byte(`{"raise_levels":{"ad.svc.no_interactive":"required"}}`), "admin", t0); err != nil {
			return err
		}
		if err := tx.InsertIdPConnection(&store.IdPConnection{TenantID: tx.Tenant(), Name: "Okta", Protocol: "oidc",
			Profile: store.ProfileOkta, Status: "active", Issuer: str("https://larkspur.okta.com"), ClientID: str("0oa1"),
			CreatedAt: t0, UpdatedAt: t0}); err != nil {
			return err
		}
		return tx.InsertIdPConnection(&store.IdPConnection{TenantID: tx.Tenant(), Name: "Dev IdP", Protocol: "oidc",
			Profile: "dev_mock", Status: "active", Issuer: str("http://localhost:8001"), CreatedAt: t0, UpdatedAt: t0})
	})
}

func (e *env) export(t *testing.T) *Signed {
	t.Helper()
	var s *Signed
	write(t, e.src, func(tx *store.TenantTx) error {
		var err error
		s, _, err = Export(tx, e.rd, e.sealer, Source{Tenant: "larkspur-dev", Env: "dev"}, t0)
		return err
	})
	return s
}

// trust adds the source tenant's key to the destination's trusted signers.
func (e *env) trust(t *testing.T) {
	t.Helper()
	var k *store.ConfigSigningKey
	write(t, e.src, func(tx *store.TenantTx) error {
		var err error
		k, _, err = SigningKey(tx, e.sealer, t0)
		return err
	})
	write(t, e.dst, func(tx *store.TenantTx) error {
		return tx.InsertTrustedSigner(&store.TrustedSigner{KID: k.KID, PublicKey: k.PublicKey, Label: "larkspur dev", AddedAt: t0})
	})
}

func (e *env) plan(t *testing.T, raw []byte, target Target) *Plan {
	t.Helper()
	var p *Plan
	write(t, e.dst, func(tx *store.TenantTx) error {
		v, err := Verify(tx, raw)
		if err != nil {
			return err
		}
		p, err = MakePlan(tx, e.rd, v, target, t0)
		return err
	})
	return p
}

func (e *env) apply(t *testing.T, raw []byte, prune bool) (*Applied, error) {
	t.Helper()
	p := e.plan(t, raw, Target{}) // the preview the admin reviewed
	digest := p.Digest
	if prune {
		digest = p.DigestPrune
	}
	return e.applyDigest(t, raw, prune, digest)
}

func (e *env) applyDigest(t *testing.T, raw []byte, prune bool, digest string) (*Applied, error) {
	t.Helper()
	var a *Applied
	err := e.dst.Write(context.Background(), func(tx *store.TenantTx) error {
		v, err := Verify(tx, raw)
		if err != nil {
			return err
		}
		a, err = Apply(tx, e.rd, v, Target{}, prune, digest, "admin", nil, t0)
		return err
	})
	return a, err
}

func actions(p *Plan) map[string]string {
	out := map[string]string{}
	for _, it := range p.Items {
		out[it.Section+"/"+it.Name] = it.Action
	}
	return out
}

func TestRoundTrip(t *testing.T) {
	e := newEnv(t)
	e.seedSource(t)
	e.trust(t)
	s := e.export(t)
	if strings.Contains(string(s.JWS), "sealed:") || strings.Contains(string(s.JWS), "private") {
		t.Fatalf("bundle leaks key material: %s", s.JWS)
	}

	p := e.plan(t, s.JWS, Target{})
	want := map[string]string{"connections/Corp AD": Add, "connections/Workday": Add, "overlays/ad": Add, "identity_providers/Okta": Add}
	got := actions(p)
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %q, want %q (plan %+v)", k, got[k], v, p.Items)
		}
	}
	if _, ok := got["identity_providers/Dev IdP"]; ok {
		t.Error("the dev mock IdP travelled")
	}
	if p.Counts.Add != 4 || len(p.Refusals) != 0 {
		t.Errorf("counts %+v refusals %v", p.Counts, p.Refusals)
	}

	a, err := e.apply(t, s.JWS, false)
	if err != nil {
		t.Fatal(err)
	}
	if a.ImportID == "" {
		t.Error("no import id")
	}

	write(t, e.dst, func(tx *store.TenantTx) error {
		conns, err := tx.Connections()
		if err != nil {
			return err
		}
		if len(conns) != 2 {
			t.Fatalf("connections %d", len(conns))
		}
		for _, c := range conns {
			cur, err := e.rd.Current(tx, c.ID, t0)
			if err != nil {
				return err
			}
			if cur.Rev.State == "active" {
				t.Errorf("%s was activated by an import", c.Name)
			}
			if c.Name == "Corp AD" && (cur.Rev.SecretRef == nil || *cur.Rev.SecretRef != "vault:kv/tessera/ad") {
				t.Errorf("reference not carried: %v", cur.Rev.SecretRef)
			}
		}
		idps, err := tx.IdPConnections()
		if err != nil {
			return err
		}
		if len(idps) != 1 || idps[0].Status != "pending" || idps[0].Name != "Okta" {
			t.Errorf("idps %+v", idps)
		}
		imps, err := tx.ConfigImports()
		if err != nil {
			return err
		}
		if len(imps) != 1 || imps[0].BundleHash != s.Hash {
			t.Errorf("imports %+v", imps)
		}
		return nil
	})

	// A second plan of the same bundle changes nothing.
	p = e.plan(t, s.JWS, Target{})
	if p.Counts.Add+p.Counts.Change+p.Counts.Remove+p.Counts.Manual != 0 {
		t.Errorf("re-plan not idempotent: %+v %+v", p.Counts, p.Items)
	}
}

func TestDiffAndPrune(t *testing.T) {
	e := newEnv(t)
	e.seedSource(t)
	e.trust(t)
	if _, err := e.apply(t, e.export(t).JWS, false); err != nil {
		t.Fatal(err)
	}
	// Source: change Corp AD's host and drop a key; destination: an extra connection.
	write(t, e.src, func(tx *store.TenantTx) error {
		conns, _ := tx.Connections()
		for _, c := range conns {
			if c.Name == "Corp AD" {
				_, err := e.rd.PatchConfig(tx, c.ID, []byte(`{"host":"dc02.corp.example","business_owner":null}`), "admin", t0)
				return err
			}
		}
		return errors.New("no Corp AD")
	})
	var extra string
	write(t, e.dst, func(tx *store.TenantTx) error {
		b, err := e.rd.Create(tx, readiness.CreateInput{Name: "Local only", ConnectorType: "demo-ad", System: "local",
			Config: json.RawMessage(`{}`)}, "admin", t0)
		if b != nil {
			extra = b.Conn.ID
		}
		return err
	})
	raw := e.export(t).JWS
	p := e.plan(t, raw, Target{})
	got := actions(p)
	if got["connections/Corp AD"] != Change || got["connections/Workday"] != Unchanged || got["connections/Local only"] != Remove {
		t.Fatalf("plan %+v", p.Items)
	}
	for _, it := range p.Items {
		if it.Name == "Corp AD" && strings.Join(it.Fields, ",") != "config.business_owner,config.host" {
			t.Errorf("fields %v", it.Fields)
		}
	}

	if _, err := e.apply(t, raw, false); err != nil {
		t.Fatal(err)
	}
	write(t, e.dst, func(tx *store.TenantTx) error {
		c, err := tx.Connection(extra)
		if err != nil {
			return err
		}
		if c.RetiredAt != nil {
			t.Error("removed without prune")
		}
		return nil
	})
	p = e.plan(t, raw, Target{})
	if got := actions(p); got["connections/Corp AD"] != Unchanged {
		t.Errorf("change not applied: %+v", p.Items)
	}
	if _, err := e.apply(t, raw, true); err != nil {
		t.Fatal(err)
	}
	write(t, e.dst, func(tx *store.TenantTx) error {
		c, err := tx.Connection(extra)
		if err != nil {
			return err
		}
		if c.RetiredAt == nil {
			t.Error("prune did not retire")
		}
		return nil
	})
}

// TestApplyBindsThePlan: an apply is refused, with nothing written, when the
// destination or the prune choice differs from the plan that was reviewed.
func TestApplyBindsThePlan(t *testing.T) {
	e := newEnv(t)
	e.seedSource(t)
	e.trust(t)
	raw := e.export(t).JWS
	reviewed := e.plan(t, raw, Target{})
	if reviewed.Digest == "" || reviewed.Digest == reviewed.DigestPrune {
		t.Fatalf("digests %q %q", reviewed.Digest, reviewed.DigestPrune)
	}
	if again := e.plan(t, raw, Target{}); again.Digest != reviewed.Digest || again.DigestPrune != reviewed.DigestPrune {
		t.Fatal("the digest is not stable for an unchanged destination")
	}
	if p := e.plan(t, raw, Target{Prod: true}); p.Digest == reviewed.Digest {
		t.Error("the digest does not cover the environment")
	}
	notStale := func(label string, err error) {
		t.Helper()
		var te *Error
		if !errors.As(err, &te) || te.Code != "stale_plan" || te.Status != 409 {
			t.Errorf("%s: %v, want 409 stale_plan", label, err)
		}
	}
	_, err := e.applyDigest(t, raw, true, reviewed.Digest) // prune changed after the preview
	notStale("prune changed", err)
	_, err = e.applyDigest(t, raw, false, "")
	notStale("no digest", err)

	write(t, e.dst, func(tx *store.TenantTx) error { // another admin adds a connection
		_, err := e.rd.Create(tx, readiness.CreateInput{Name: "Added later", ConnectorType: "demo-ad", System: "later",
			Config: json.RawMessage(`{}`)}, "admin", t0)
		return err
	})
	_, err = e.applyDigest(t, raw, true, reviewed.DigestPrune)
	notStale("connection added", err)
	write(t, e.dst, func(tx *store.TenantTx) error {
		conns, err := tx.Connections()
		if err != nil {
			return err
		}
		for _, c := range conns {
			if c.RetiredAt != nil {
				t.Errorf("%s retired by a refused apply", c.Name)
			}
			if c.Name == "Corp AD" {
				t.Error("a refused apply created a connection")
			}
		}
		return nil
	})
	if _, err := e.apply(t, raw, false); err != nil { // a fresh preview applies
		t.Fatal(err)
	}
}

func TestVerifyRefusals(t *testing.T) {
	e := newEnv(t)
	e.seedSource(t)
	s := e.export(t)
	verify := func(sc readiness.Scope, raw []byte) error {
		return sc.Write(context.Background(), func(tx *store.TenantTx) error { _, err := Verify(tx, raw); return err })
	}
	code := func(err error) string {
		var te *Error
		if errors.As(err, &te) {
			return te.Code
		}
		return ""
	}
	if c := code(verify(e.dst, s.JWS)); c != "untrusted_signer" {
		t.Errorf("untrusted: %q", c)
	}
	if c := code(verify(e.src, s.JWS)); c != "untrusted_signer" {
		t.Errorf("own key trusted implicitly: %q", c)
	}
	e.trust(t)
	if err := verify(e.dst, s.JWS); err != nil {
		t.Fatal(err)
	}

	// Tamper with the payload, keeping the signature.
	var jws map[string]any
	if err := json.Unmarshal(s.JWS, &jws); err != nil {
		t.Fatal(err)
	}
	obj, _ := jose.ParseSignedJSON(string(s.JWS), []jose.SignatureAlgorithm{jose.EdDSA})
	payload := strings.Replace(string(obj.UnsafePayloadWithoutVerification()), "dc01.corp.example", "evil.example", 1)
	jws["payload"] = b64(payload)
	tampered, _ := json.Marshal(jws)
	if c := code(verify(e.dst, tampered)); c != "bad_signature" {
		t.Errorf("tampered: %q", c)
	}

	for name, raw := range map[string][]byte{"garbage": []byte("not a bundle"), "empty": nil} {
		if c := code(verify(e.dst, raw)); c != "invalid_bundle" {
			t.Errorf("%s: %q", name, c)
		}
	}
	big := make([]byte, MaxBundleBytes+1)
	if c := code(verify(e.dst, big)); c != "bundle_too_large" {
		t.Errorf("too large: %q", c)
	}
}

func TestSecretFree(t *testing.T) {
	b := &Bundle{Connections: []Connection{
		{Name: "ok", Config: json.RawMessage(`{"host":"x","secret_ref":"vault:kv/x","password_policy":""}`), Credential: Credential{Kind: "reference", Reference: "vault:kv/x"}},
		{Name: "pw", Config: json.RawMessage(`{"nested":{"bind_password":"hunter2"}}`)},
		{Name: "sealed", Config: json.RawMessage(`{}`), Credential: Credential{Kind: "reference", Reference: "sealed:abc"}},
	}}
	got := secretFree(b)
	if len(got) != 2 || !strings.Contains(got[0], `"pw"`) || !strings.Contains(got[0], "nested.bind_password") || !strings.Contains(got[1], `"sealed"`) {
		t.Errorf("secretFree = %v", got)
	}
}

func TestProdGuard(t *testing.T) {
	b := &Bundle{
		Connections: []Connection{
			{Name: "internal", Config: json.RawMessage(`{"host":"10.0.0.5","base_url":"https://dc.corp.example"}`)},
			{Name: "loop", Config: json.RawMessage(`{"host":"127.0.0.1:389"}`)},
			{Name: "local", Config: json.RawMessage(`{"base_url":"http://localhost:9000/api"}`)},
		},
		IdentityProviders: []IdP{
			{Name: "Okta", Profile: "okta", Issuer: str("https://larkspur.okta.com")},
			{Name: "mock", Profile: "dev_mock"},
			{Name: "plain", Profile: "generic_oidc", Issuer: str("http://idp.corp.example")},
		},
	}
	got := strings.Join(devOnly(b), "\n")
	for _, want := range []string{`"loop"`, `"local"`, `"mock" is the dev mock IdP`, `"plain" points at http://idp.corp.example`} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %s in:\n%s", want, got)
		}
	}
	for _, not := range []string{`"internal"`, `"Okta"`} {
		if strings.Contains(got, not) {
			t.Errorf("%s refused:\n%s", not, got)
		}
	}
}

func TestApplyRefusedForProd(t *testing.T) {
	e := newEnv(t)
	write(t, e.src, func(tx *store.TenantTx) error {
		_, err := e.rd.Create(tx, readiness.CreateInput{Name: "Lab", ConnectorType: "demo-ad", System: "lab",
			Config: json.RawMessage(`{"host":"localhost"}`)}, "admin", t0)
		return err
	})
	e.trust(t)
	raw := e.export(t).JWS
	if p := e.plan(t, raw, Target{}); len(p.Refusals) != 0 {
		t.Errorf("non-prod refused: %v", p.Refusals)
	}
	if p := e.plan(t, raw, Target{Prod: true}); len(p.Refusals) != 1 {
		t.Errorf("prod refusals %v", p.Refusals)
	}
	digest := e.plan(t, raw, Target{Prod: true}).Digest
	err := e.dst.Write(context.Background(), func(tx *store.TenantTx) error {
		v, err := Verify(tx, raw)
		if err != nil {
			return err
		}
		_, err = Apply(tx, e.rd, v, Target{Prod: true}, false, digest, "admin", nil, t0)
		return err
	})
	var te *Error
	if !errors.As(err, &te) || te.Code != "bundle_refused" {
		t.Fatalf("apply to prod: %v", err)
	}
}

func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

func TestPlan_NameAndSystemClashesAreManual(t *testing.T) {
	e := newEnv(t)
	e.seedSource(t)
	e.trust(t)
	write(t, e.dst, func(tx *store.TenantTx) error {
		// Another name for Corp AD's system, and a retired Workday.
		if _, err := e.rd.Create(tx, readiness.CreateInput{Name: "AD (old)", ConnectorType: "demo-ad", System: "corp-ad",
			Config: json.RawMessage(`{}`)}, "admin", t0); err != nil {
			return err
		}
		b, err := e.rd.Create(tx, readiness.CreateInput{Name: "Workday", ConnectorType: "demo-ad", System: "wd-old",
			Config: json.RawMessage(`{}`)}, "admin", t0)
		if err != nil {
			return err
		}
		return e.rd.Retire(tx, b.Conn.ID, "admin", t0)
	})
	raw := e.export(t).JWS
	got := actions(e.plan(t, raw, Target{}))
	if got["connections/Corp AD"] != Manual || got["connections/Workday"] != Manual {
		t.Fatalf("plan %v", got)
	}
	if _, err := e.apply(t, raw, false); err != nil {
		t.Fatalf("apply with manual items: %v", err)
	}
}
