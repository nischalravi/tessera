package claim_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth/normalize"
	"github.com/nischalravi/tessera/mvp/server/internal/guests/claim"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

var tenantA = tenancy.MustParse("00000000-0000-4000-8000-0000000000a1")
var tenantB = tenancy.MustParse("00000000-0000-4000-8000-0000000000b2")

func TestToken_ShapeAndHash(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		tok := claim.NewToken()
		if len(tok) != 43 || !claim.WellFormed(tok) || seen[tok] {
			t.Fatalf("token %q", tok)
		}
		seen[tok] = true
	}
	for _, bad := range []string{"", "short", strings.Repeat("a", 44), strings.Repeat("!", 43)} {
		if claim.WellFormed(bad) {
			t.Errorf("%q is not a token", bad)
		}
	}
	// the stored form: SHA-256 over "tessera-claim-v1|" + tenant + "|" + token
	tok := strings.Repeat("A", 43)
	sum := sha256.Sum256([]byte("tessera-claim-v1|" + tenantA.String() + "|" + tok))
	if got := claim.HashToken(tenantA, tok); got != hex.EncodeToString(sum[:]) {
		t.Errorf("HashToken = %s", got)
	}
	if claim.HashToken(tenantA, tok) == claim.HashToken(tenantB, tok) {
		t.Error("the hash does not depend on the tenant")
	}
	if claim.HashToken(tenantA, tok) == claim.HashToken(tenantA, tok+"A") {
		t.Error("the hash does not depend on the token")
	}
}

func TestLifetime(t *testing.T) {
	for pop, want := range map[string]time.Duration{store.PopVisitor: 7 * 24 * time.Hour, store.PopContractor: 14 * 24 * time.Hour,
		store.PopVolunteer: 14 * 24 * time.Hour, store.PopPartner: 14 * 24 * time.Hour} {
		if got := claim.Lifetime(pop); got != want {
			t.Errorf("%s: %v, want %v", pop, got, want)
		}
	}
}

func TestMeetsAAL(t *testing.T) {
	for _, c := range []struct {
		required, aal int
		acr           string
		want          bool
	}{
		{1, 1, normalize.ACRAAL1, true}, {1, 0, "", false}, {2, 1, normalize.ACRAAL1, false}, {2, 2, normalize.ACRAAL2, true},
		{2, 2, normalize.ACRPhr, true}, {3, 2, normalize.ACRPhr, false}, {3, 3, normalize.ACRPhrh, true}, {3, 3, normalize.ACRAAL2, false},
	} {
		if got := claim.MeetsAAL(c.required, c.aal, c.acr); got != c.want {
			t.Errorf("MeetsAAL(%d, %d, %s) = %t", c.required, c.aal, c.acr, got)
		}
	}
}

// keyPair makes a page's key and its JWK.
func keyPair(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b := func(n *big.Int) string { return base64.RawURLEncoding.EncodeToString(n.FillBytes(make([]byte, 32))) }
	return k, fmt.Sprintf(`{"kty":"EC","crv":"P-256","x":%q,"y":%q}`, b(k.X), b(k.Y))
}

// emptyBody is claim.BodyHash of an empty body.
var emptyBody = claim.BodyHash(nil)

func sign(t *testing.T, k *ecdsa.PrivateKey, method, path string, at time.Time, nonce string, body ...string) string {
	t.Helper()
	ts := fmt.Sprint(at.Unix())
	b := ""
	if len(body) > 0 {
		b = body[0]
	}
	sum := sha256.Sum256([]byte("tessera-claim-proof-v2\n" + method + "\n" + path + "\n" + ts + "\n" + nonce + "\n" + claim.BodyHash([]byte(b))))
	r, s, err := ecdsa.Sign(rand.Reader, k, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return ts + "." + base64.RawURLEncoding.EncodeToString(append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...))
}

func TestParseKey(t *testing.T) {
	_, jwk := keyPair(t)
	pub, canon, jkt, err := claim.ParseKey([]byte(jwk))
	if err != nil || pub == nil || jkt == "" || !strings.HasPrefix(canon, `{"crv":"P-256","kty":"EC","x":"`) {
		t.Fatalf("ParseKey = %v, %q, %q, %v", pub, canon, jkt, err)
	}
	if _, canon2, jkt2, err := claim.ParseKey([]byte(canon)); err != nil || canon2 != canon || jkt2 != jkt {
		t.Errorf("the canonical form is not stable: %v", err)
	}
	for name, bad := range map[string]string{
		"empty":          ``,
		"not json":       `x`,
		"private member": strings.Replace(jwk, `"kty":"EC"`, `"kty":"EC","d":"AAAA"`, 1),
		"wrong kty":      strings.Replace(jwk, `"EC"`, `"RSA"`, 1),
		"wrong curve":    strings.Replace(jwk, `P-256`, `P-384`, 1),
		"short x":        strings.Replace(jwk, `"x":"`, `"x":"AA`, 1)[:0] + `{"kty":"EC","crv":"P-256","x":"AA","y":"AA"}`,
		"off the curve":  `{"kty":"EC","crv":"P-256","x":"` + strings.Repeat("A", 43) + `","y":"` + strings.Repeat("A", 43) + `"}`,
		"unknown member": strings.Replace(jwk, `"kty":"EC"`, `"kty":"EC","zzz":1`, 1),
	} {
		if _, _, _, err := claim.ParseKey([]byte(bad)); err == nil {
			t.Errorf("%s: a key that must be refused was accepted", name)
		}
	}
}

func TestVerify(t *testing.T) {
	k, jwk := keyPair(t)
	other, _ := keyPair(t)
	pub, _, _, err := claim.ParseKey([]byte(jwk))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)
	const path, nonce = "/public/t/x/claim/status", "n0nce-n0nce-n0nce"
	for _, c := range []struct {
		name    string
		header  func() string
		method  string
		path    string
		nonce   string
		wantErr error
	}{
		{"good", func() string { return sign(t, k, "GET", path, now, nonce) }, "GET", path, nonce, nil},
		{"five seconds old", func() string { return sign(t, k, "GET", path, now.Add(-5*time.Second), nonce) }, "GET", path, nonce, nil},
		{"59 seconds ahead", func() string { return sign(t, k, "GET", path, now.Add(59*time.Second), nonce) }, "GET", path, nonce, nil},
		{"missing", func() string { return "" }, "GET", path, nonce, claim.ErrProofMissing},
		{"no dot", func() string { return "123" }, "GET", path, nonce, claim.ErrProofBad},
		{"bad timestamp", func() string { return "x.AAAA" }, "GET", path, nonce, claim.ErrProofBad},
		{"short signature", func() string { return fmt.Sprint(now.Unix()) + ".AAAA" }, "GET", path, nonce, claim.ErrProofBad},
		{"another key", func() string { return sign(t, other, "GET", path, now, nonce) }, "GET", path, nonce, claim.ErrProofBad},
		{"another method", func() string { return sign(t, k, "POST", path, now, nonce) }, "GET", path, nonce, claim.ErrProofBad},
		{"another path", func() string { return sign(t, k, "GET", path+"x", now, nonce) }, "GET", path, nonce, claim.ErrProofBad},
		{"another nonce", func() string { return sign(t, k, "GET", path, now, "other") }, "GET", path, nonce, claim.ErrProofBad},
		{"two minutes old", func() string { return sign(t, k, "GET", path, now.Add(-2*time.Minute), nonce) }, "GET", path, nonce, claim.ErrProofStale},
		{"two minutes ahead", func() string { return sign(t, k, "GET", path, now.Add(2*time.Minute), nonce) }, "GET", path, nonce, claim.ErrProofStale},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := claim.Verify(pub, c.header(), c.method, c.path, c.nonce, emptyBody, now, claim.NewReplays())
			if err != c.wantErr {
				t.Errorf("Verify = %v, want %v", err, c.wantErr)
			}
		})
	}
	t.Run("replay", func(t *testing.T) {
		rp := claim.NewReplays()
		h := sign(t, k, "GET", path, now, nonce)
		if _, err := claim.Verify(pub, h, "GET", path, nonce, emptyBody, now, rp); err != nil {
			t.Fatal(err)
		}
		if _, err := claim.Verify(pub, h, "GET", path, nonce, emptyBody, now, rp); err != claim.ErrProofReplay {
			t.Errorf("replay = %v", err)
		}
		// once the window has passed the entry is forgotten (the timestamp check refuses it anyway)
		if _, err := claim.Verify(pub, h, "GET", path, nonce, emptyBody, now.Add(10*time.Minute), rp); err != claim.ErrProofStale {
			t.Errorf("an old replay = %v", err)
		}
	})
	// ECDSA malleability (review on #202): (r, N-s) verifies for the same
	// message. It is the same proof, so it is a replay, not a fresh proof.
	t.Run("malleated replay", func(t *testing.T) {
		rp := claim.NewReplays()
		h := sign(t, k, "GET", path, now, nonce)
		ts, sig, _ := strings.Cut(h, ".")
		raw, _ := base64.RawURLEncoding.DecodeString(sig)
		s := new(big.Int).SetBytes(raw[32:])
		s.Sub(elliptic.P256().Params().N, s)
		mall := ts + "." + base64.RawURLEncoding.EncodeToString(append(raw[:32:32], s.FillBytes(make([]byte, 32))...))
		if mall == h {
			t.Fatal("the malleated form is the same string")
		}
		p1, err := claim.Verify(pub, h, "GET", path, nonce, emptyBody, now, nil)
		if err != nil {
			t.Fatal(err)
		}
		p2, err := claim.Verify(pub, mall, "GET", path, nonce, emptyBody, now, nil)
		if err != nil {
			t.Fatalf("the malleated signature should verify (it is valid ECDSA): %v", err)
		}
		if p1.ID != p2.ID {
			t.Fatalf("a signature and its malleated form have different proof IDs: %s, %s", p1.ID, p2.ID)
		}
		if _, err := claim.Verify(pub, h, "GET", path, nonce, emptyBody, now, rp); err != nil {
			t.Fatal(err)
		}
		if _, err := claim.Verify(pub, mall, "GET", path, nonce, emptyBody, now, rp); err != claim.ErrProofReplay {
			t.Errorf("malleated replay = %v, want ErrProofReplay", err)
		}
	})
	// The proof signs the body: the same proof with another body does not verify.
	t.Run("body bound", func(t *testing.T) {
		h := sign(t, k, "POST", path, now, nonce, `{"code":"123456"}`)
		if _, err := claim.Verify(pub, h, "POST", path, nonce, claim.BodyHash([]byte(`{"code":"123456"}`)), now, nil); err != nil {
			t.Fatal(err)
		}
		if _, err := claim.Verify(pub, h, "POST", path, nonce, claim.BodyHash([]byte(`{"code":"654321"}`)), now, nil); err != claim.ErrProofBad {
			t.Errorf("another body = %v, want ErrProofBad", err)
		}
	})
	for err, want := range map[error]string{claim.ErrProofMissing: "proof_missing", claim.ErrProofStale: "proof_stale",
		claim.ErrProofReplay: "proof_replay", claim.ErrProofBad: "proof_invalid"} {
		if got := claim.Reason(err); got != want {
			t.Errorf("Reason(%v) = %s", err, got)
		}
	}
}
