package keys_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/nischalravi/tessera/mvp/server/internal/keys"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

const day = 24 * time.Hour

var t0 = time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)

type env struct {
	t  *testing.T
	f  *storetest.Fixture
	s  *seal.Sealer
	tn storetest.Tenant
}

func setup(t *testing.T) *env {
	t.Helper()
	s, err := seal.New(seal.RandomBytes(seal.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	f := storetest.TwoTenants(t)
	return &env{t: t, f: f, s: s, tn: f.B}
}

func (e *env) in(fn func(tx *store.TenantTx) error) {
	e.t.Helper()
	if err := e.f.DB.InTenant(context.Background(), e.tn.ID, fn); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) ensure(now time.Time) {
	e.t.Helper()
	e.in(func(tx *store.TenantTx) error { return keys.EnsureKeys(tx, e.tn.Slug, e.s, now) })
}

func (e *env) keys(purpose string) []*store.TenantSigningKey {
	e.t.Helper()
	var out []*store.TenantSigningKey
	e.in(func(tx *store.TenantTx) (err error) { out, err = tx.SigningKeys(purpose); return })
	return out
}

func (e *env) jwks(purpose string, now time.Time) *jose.JSONWebKeySet {
	e.t.Helper()
	var set *jose.JSONWebKeySet
	e.in(func(tx *store.TenantTx) (err error) { set, err = keys.JWKSFor(tx, purpose, now); return })
	return set
}

// statuses renders the key states as "kid0:active kid1:next ...", with kids
// replaced by their creation order, so a table can state the expected states.
func statuses(ks []*store.TenantSigningKey) string {
	var parts []string
	for i, k := range ks {
		parts = append(parts, fmt.Sprintf("k%d:%s", i, k.Status))
	}
	return strings.Join(parts, " ")
}

func kids(set *jose.JSONWebKeySet) []string {
	var out []string
	for _, k := range set.Keys {
		out = append(out, k.KeyID)
	}
	slices.Sort(out)
	return out
}

func TestKIDNaming(t *testing.T) {
	e := setup(t)
	e.ensure(t0)
	for _, p := range keys.TenantPurposes {
		for _, k := range e.keys(p) {
			if !keys.KIDPattern.MatchString(k.KID) || !strings.HasPrefix(k.KID, e.tn.Slug+"-20261008-") {
				t.Errorf("kid %q, want %s-20261008-<6 chars>", k.KID, e.tn.Slug)
			}
			if k.Alg != keys.AlgES256 || k.Purpose != p {
				t.Errorf("key %s: alg %s purpose %s", k.KID, k.Alg, k.Purpose)
			}
		}
	}
	seen := map[string]bool{}
	for range 200 {
		kid, err := keys.NewKID("acme", t0.In(time.FixedZone("x", -11*3600)))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(kid, "acme-20261008-") || seen[kid] {
			t.Fatalf("kid %q (UTC date, unique)", kid)
		}
		seen[kid] = true
	}
	for _, bad := range []string{"", "_platform", "Acme", "a", "has space"} {
		if _, err := keys.NewKID(bad, t0); err == nil {
			t.Errorf("NewKID(%q) accepted", bad)
		}
	}
}

// TestRotationStates walks a tenant's access-token keys through their life:
// each step runs EnsureKeys (and optionally an action first) at a time and
// checks every key's state and which keys the JWKS publishes.
func TestRotationStates(t *testing.T) {
	steps := []struct {
		name      string
		at        time.Duration
		action    string // "", "revoke k<i>"
		want      string
		published []int // indexes of keys in the JWKS
	}{
		{"bootstrap: one active, one next", 0, "", "k0:active k1:next", []int{0, 1}},
		{"idempotent", time.Hour, "", "k0:active k1:next", []int{0, 1}},
		{"day 29: no rotation yet", 29 * day, "", "k0:active k1:next", []int{0, 1}},
		{"day 30: rotate", 30 * day, "", "k0:retired k1:active k2:next", []int{0, 1, 2}},
		{"retired key still published within 24 h", 30*day + 23*time.Hour, "", "k0:retired k1:active k2:next", []int{0, 1, 2}},
		{"retired key dropped from JWKS after 24 h", 31 * day, "", "k0:retired k1:active k2:next", []int{1, 2}},
		{"revoke the next key: a new next is created", 40 * day, "revoke 2", "k0:retired k1:active k2:revoked k3:next", []int{1, 3}},
		{"day 60: active expired, next only 20 days old: rotate", 60 * day, "", "k0:retired k1:retired k2:revoked k3:active k4:next", []int{1, 3, 4}},
		{"revoke the active key: next activates at once", 61 * day, "revoke 3", "k0:retired k1:retired k2:revoked k3:revoked k4:active k5:next", []int{4, 5}},
		{"revoke a retired key", 61*day + time.Hour, "revoke 1", "k0:retired k1:revoked k2:revoked k3:revoked k4:active k5:next", []int{4, 5}},
	}
	e := setup(t)
	purpose := store.KeyPurposeAccessToken
	for _, st := range steps {
		now := t0.Add(st.at)
		if st.action != "" {
			var i int
			if _, err := fmt.Sscanf(st.action, "revoke %d", &i); err != nil {
				t.Fatal(err)
			}
			kid := e.keys(purpose)[i].KID
			e.in(func(tx *store.TenantTx) error { return keys.RevokeKey(tx, e.tn.Slug, kid, e.s, now) })
		}
		e.ensure(now)
		ks := e.keys(purpose)
		if got := statuses(ks); got != st.want {
			t.Fatalf("%s: states %q, want %q", st.name, got, st.want)
		}
		var want []string
		for _, i := range st.published {
			want = append(want, ks[i].KID)
		}
		slices.Sort(want)
		if got := kids(e.jwks(purpose, now)); !slices.Equal(got, want) {
			t.Fatalf("%s: JWKS kids %v, want %v", st.name, got, want)
		}
		// the other purpose is maintained independently and never mixed in
		for _, k := range e.jwks(store.KeyPurposeIdPClientAuth, now).Keys {
			for _, a := range ks {
				if a.KID == k.KeyID {
					t.Fatalf("%s: idp_client_auth JWKS contains access_token key %s", st.name, k.KeyID)
				}
			}
		}
	}
}

// TestNextKeyLeadTime: an expired active key is not rotated until the next
// key has been published for 7 days.
func TestNextKeyLeadTime(t *testing.T) {
	e := setup(t)
	p := store.KeyPurposeAccessToken
	e.ensure(t0)
	kid := e.keys(p)[1].KID
	e.in(func(tx *store.TenantTx) error { return keys.RevokeKey(tx, e.tn.Slug, kid, e.s, t0.Add(25*day)) })
	for _, c := range []struct {
		at   time.Duration
		want string
	}{
		{30 * day, "k0:active k1:revoked k2:next"},
		{31*day + 23*time.Hour, "k0:active k1:revoked k2:next"},
		{32 * day, "k0:retired k1:revoked k2:active k3:next"},
	} {
		e.ensure(t0.Add(c.at))
		if got := statuses(e.keys(p)); got != c.want {
			t.Errorf("day %v: %q, want %q", c.at/day, got, c.want)
		}
	}
}

func TestRevokeUnknownKey(t *testing.T) {
	e := setup(t)
	e.ensure(t0)
	var aKID string
	e.tn = e.f.A
	e.ensure(t0)
	aKID = e.keys(store.KeyPurposeAccessToken)[0].KID
	e.tn = e.f.B
	for _, kid := range []string{"nope", aKID} {
		err := e.f.DB.InTenant(context.Background(), e.tn.ID, func(tx *store.TenantTx) error {
			return keys.RevokeKey(tx, e.tn.Slug, kid, e.s, t0)
		})
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("RevokeKey(%s) in B = %v, want ErrNotFound", kid, err)
		}
	}
}

// TestJWKSContent: the JWKS holds only public EC P-256 signing keys with the
// kid, alg and use members, and the active key verifies a token signed with
// the unsealed private key.
func TestJWKSContent(t *testing.T) {
	e := setup(t)
	e.ensure(t0)
	p := store.KeyPurposeAccessToken
	set := e.jwks(p, t0)
	raw, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Keys) != 2 {
		t.Fatalf("%d keys in %s", len(doc.Keys), raw)
	}
	for _, k := range doc.Keys {
		for member, want := range map[string]string{"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig"} {
			if k[member] != want {
				t.Errorf("%s = %v, want %s (%v)", member, k[member], want, k)
			}
		}
		if !keys.KIDPattern.MatchString(fmt.Sprint(k["kid"])) {
			t.Errorf("kid %v", k["kid"])
		}
		if k["x"] == nil || k["y"] == nil {
			t.Errorf("missing coordinates: %v", k)
		}
		for _, private := range []string{"d", "p", "q", "dp", "dq", "qi", "k"} {
			if _, ok := k[private]; ok {
				t.Errorf("JWKS publishes private member %q", private)
			}
		}
	}

	var sk *keys.SigningKey
	e.in(func(tx *store.TenantTx) (err error) { sk, err = keys.ActiveSigningKey(tx, p, e.s); return })
	if d := sk.Key.(*ecdsa.PrivateKey).D.String(); strings.Contains(fmt.Sprintf("%v %+v %#v %s", sk, sk, sk, sk), d) {
		t.Error("SigningKey printed private material")
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: sk.Key},
		(&jose.SignerOptions{}).WithType("at+jwt").WithHeader("kid", sk.KID))
	if err != nil {
		t.Fatal(err)
	}
	tok, err := jwt.Signed(signer).Claims(jwt.Claims{Subject: "usr_1"}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := jwt.ParseSigned(tok, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	pub := set.Key(parsed.Headers[0].KeyID)
	if len(pub) != 1 {
		t.Fatalf("kid %s not in the JWKS", parsed.Headers[0].KeyID)
	}
	var claims jwt.Claims
	if err := parsed.Claims(pub[0].Key, &claims); err != nil || claims.Subject != "usr_1" {
		t.Errorf("token signed with the active key does not verify against the JWKS: %v", err)
	}
	// the next key (published, not active) must not verify it
	for _, k := range set.Keys {
		if k.KeyID != sk.KID {
			if err := parsed.Claims(k.Key, &claims); err == nil {
				t.Error("token verified with the wrong key")
			}
		}
	}
}

// TestPrivateKeysStoredSealed: the stored blob is not the private key, opens
// only with the AAD of its own tenant and kid, and a row whose public key
// does not match its private key is refused.
func TestPrivateKeysStoredSealed(t *testing.T) {
	e := setup(t)
	e.ensure(t0)
	p := store.KeyPurposeAccessToken
	var sk *keys.SigningKey
	e.in(func(tx *store.TenantTx) (err error) { sk, err = keys.ActiveSigningKey(tx, p, e.s); return })
	der, err := x509.MarshalPKCS8PrivateKey(sk.Key)
	if err != nil {
		t.Fatal(err)
	}
	ks := e.keys(p)
	active := ks[0]
	if bytes.Contains(active.PrivateKeyEnc, der[len(der)-32:]) || bytes.Contains(active.PrivateKeyEnc, der) {
		t.Fatal("private key stored in plaintext")
	}
	if b, _ := json.Marshal(active); bytes.Contains(b, []byte("PrivateKeyEnc")) {
		t.Error("the sealed private key is serialized to JSON")
	}

	// Copy B's sealed private key into a row of tenant A: opening fails.
	e.tn = e.f.A
	e.in(func(tx *store.TenantTx) error {
		return tx.InsertSigningKey(&store.TenantSigningKey{KID: "copied-20261008-aaaaaa", TenantID: tx.Tenant(),
			Purpose: p, Alg: keys.AlgES256, PublicJWK: active.PublicJWK, PrivateKeyEnc: active.PrivateKeyEnc,
			Status: store.KeyActive, CreatedAt: t0, ActivatedAt: &t0})
	})
	err = e.f.DB.InTenant(context.Background(), e.tn.ID, func(tx *store.TenantTx) error {
		_, err := keys.ActiveSigningKey(tx, p, e.s)
		return err
	})
	if !errors.Is(err, seal.ErrOpen) {
		t.Errorf("a sealed key copied to another tenant opened: %v", err)
	}

	// Another KEK cannot open it.
	other, _ := seal.New(seal.RandomBytes(seal.KeySize))
	e.tn = e.f.B
	err = e.f.DB.InTenant(context.Background(), e.tn.ID, func(tx *store.TenantTx) error {
		_, err := keys.ActiveSigningKey(tx, p, other)
		return err
	})
	if !errors.Is(err, seal.ErrOpen) {
		t.Errorf("opened with another KEK: %v", err)
	}
}

// TestPublicKeyMismatchRefused: a row whose sealed private key (validly
// sealed for that row) does not match its stored public key is refused.
func TestPublicKeyMismatchRefused(t *testing.T) {
	e := setup(t)
	e.ensure(t0)
	p := store.KeyPurposeAccessToken
	var sk *keys.SigningKey
	e.in(func(tx *store.TenantTx) (err error) { sk, err = keys.ActiveSigningKey(tx, p, e.s); return })
	der, err := x509.MarshalPKCS8PrivateKey(sk.Key)
	if err != nil {
		t.Fatal(err)
	}
	ks := e.keys(p)
	const kid = "mismatch-20261008-bbbbbb"
	var otherPub map[string]any // the next key's public JWK, relabelled
	if err := json.Unmarshal(ks[1].PublicJWK, &otherPub); err != nil {
		t.Fatal(err)
	}
	otherPub["kid"] = kid
	pubJWK, _ := json.Marshal(otherPub)
	enc, err := e.s.Seal(der, seal.AAD(e.tn.ID, "tenant_signing_keys", "private_key_enc", kid))
	if err != nil {
		t.Fatal(err)
	}
	e.in(func(tx *store.TenantTx) error {
		if err := tx.RetireSigningKey(ks[0].KID, t0); err != nil {
			return err
		}
		if err := tx.InsertSigningKey(&store.TenantSigningKey{KID: kid, TenantID: tx.Tenant(), Purpose: p,
			Alg: keys.AlgES256, PublicJWK: pubJWK, PrivateKeyEnc: enc, Status: store.KeyActive, CreatedAt: t0,
			ActivatedAt: &t0}); err != nil {
			return err
		}
		if _, err := keys.ActiveSigningKey(tx, p, e.s); err == nil || !strings.Contains(err.Error(), "does not match") {
			t.Errorf("mismatched public key accepted: %v", err)
		}
		return nil
	})
}

// TestJWKSRefusesTamperedRows: a stored public_jwk that carries private
// material or another kid is never published.
func TestJWKSRefusesTamperedRows(t *testing.T) {
	e := setup(t)
	p := store.KeyPurposeIdPClientAuth
	var sk *keys.SigningKey
	e.ensure(t0)
	e.in(func(tx *store.TenantTx) (err error) { sk, err = keys.ActiveSigningKey(tx, p, e.s); return })
	priv, err := json.Marshal(jose.JSONWebKey{Key: sk.Key, KeyID: "evil-20261008-cccccc", Algorithm: "ES256", Use: "sig"})
	if err != nil {
		t.Fatal(err)
	}
	other := e.keys(p)[0].PublicJWK // a valid public JWK with another kid
	for name, c := range map[string]struct {
		kid string
		jwk []byte
	}{
		"private JWK":  {"evil-20261008-cccccc", priv},
		"kid mismatch": {"evil-20261008-dddddd", other},
	} {
		t.Run(name, func(t *testing.T) {
			e := setup(t)
			e.in(func(tx *store.TenantTx) error {
				return tx.InsertSigningKey(&store.TenantSigningKey{KID: c.kid, TenantID: tx.Tenant(), Purpose: p,
					Alg: keys.AlgES256, PublicJWK: c.jwk, PrivateKeyEnc: []byte{1}, Status: store.KeyNext, CreatedAt: t0})
			})
			err := e.f.DB.InTenant(context.Background(), e.tn.ID, func(tx *store.TenantTx) error {
				_, err := keys.JWKSFor(tx, p, t0)
				return err
			})
			if err == nil {
				t.Error("JWKS published a tampered key")
			}
		})
	}
}

func TestPlatformKey(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	sys := func(fn func(*store.SystemTx) error) {
		t.Helper()
		if err := e.f.DB.InSystem(ctx, "test", fn); err != nil {
			t.Fatal(err)
		}
	}
	ensure := func(now time.Time) {
		t.Helper()
		sys(func(s *store.SystemTx) error { return keys.EnsurePlatformKey(s, e.s, now) })
	}
	list := func() []store.PlatformKey {
		var ks []store.PlatformKey
		sys(func(s *store.SystemTx) (err error) { ks, err = s.PlatformKeys(store.KeyPurposeAuditCheckpoint); return })
		return ks
	}
	ensure(t0)
	ensure(t0.Add(364 * day))
	ks := list()
	if len(ks) != 1 || ks[0].Status != store.KeyActive || !strings.HasPrefix(ks[0].KID, "platform-20261008-") ||
		ks[0].Alg != keys.AlgEdDSA {
		t.Fatalf("platform keys: %+v", ks)
	}
	ensure(t0.Add(365 * day))
	ks = list()
	if len(ks) != 2 || ks[0].Status != store.KeyRetired || ks[1].Status != store.KeyActive {
		t.Fatalf("after a year: %+v", ks)
	}
	var set *jose.JSONWebKeySet
	var sk *keys.SigningKey
	sys(func(s *store.SystemTx) (err error) {
		if set, err = keys.PlatformJWKS(s); err != nil {
			return err
		}
		sk, err = keys.ActivePlatformKey(s, e.s)
		return err
	})
	if len(set.Keys) != 2 {
		t.Fatalf("retired platform keys must stay published: %v", kids(set))
	}
	for _, k := range set.Keys {
		if !k.IsPublic() || k.Algorithm != "EdDSA" {
			t.Errorf("platform JWK %+v", k)
		}
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: sk.Key},
		(&jose.SignerOptions{}).WithHeader("kid", sk.KID))
	if err != nil {
		t.Fatal(err)
	}
	jws, err := signer.Sign([]byte(`{"seq":1}`))
	if err != nil {
		t.Fatal(err)
	}
	compact, _ := jws.CompactSerialize()
	parsed, err := jose.ParseSigned(compact, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parsed.Verify(set.Key(sk.KID)[0].Key); err != nil {
		t.Errorf("checkpoint signature does not verify: %v", err)
	}
}

// TestEnsureAll is the ensure_keys bootstrap: the platform key and both key
// purposes for every active tenant, never for _platform, idempotently.
func TestEnsureAll(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	for range 2 {
		if err := keys.EnsureAll(ctx, e.f.DB, e.s, t0); err != nil {
			t.Fatal(err)
		}
	}
	for _, tn := range []storetest.Tenant{e.f.A, e.f.B} {
		e.tn = tn
		for _, p := range keys.TenantPurposes {
			if got := statuses(e.keys(p)); got != "k0:active k1:next" {
				t.Errorf("%s %s: %s", tn.Slug, p, got)
			}
		}
	}
	err := e.f.DB.InSystem(ctx, "test", func(s *store.SystemTx) error {
		ks, err := s.PlatformKeys(store.KeyPurposeAuditCheckpoint)
		if len(ks) != 1 {
			t.Errorf("%d platform keys", len(ks))
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}
