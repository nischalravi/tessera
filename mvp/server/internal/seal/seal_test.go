package seal_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

var (
	tenantA = tenancy.MustParse("11111111-1111-4111-8111-111111111111")
	tenantB = tenancy.MustParse("22222222-2222-4222-8222-222222222222")
)

func newSealer(t *testing.T) *seal.Sealer {
	t.Helper()
	s, err := seal.New(seal.RandomBytes(seal.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestNewRejectsBadKEK(t *testing.T) {
	for name, kek := range map[string][]byte{
		"nil":      nil,
		"short":    make([]byte, 16),
		"long":     make([]byte, 33),
		"all zero": make([]byte, seal.KeySize),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := seal.New(kek); !errors.Is(err, seal.ErrKEK) {
				t.Errorf("New(%s) = %v, want ErrKEK", name, err)
			}
		})
	}
}

func TestRoundTrip(t *testing.T) {
	s := newSealer(t)
	aad := seal.AAD(tenantA, "tenant_signing_keys", "private_key_enc", "acme-20261008-k3f9qa")
	for name, pt := range map[string][]byte{
		"empty":  {},
		"short":  []byte("x"),
		"secret": []byte("client-secret-value"),
		"large":  bytes.Repeat([]byte{0xA5}, 1<<16),
	} {
		t.Run(name, func(t *testing.T) {
			sealed, err := s.Seal(pt, aad)
			if err != nil {
				t.Fatal(err)
			}
			if len(pt) > 4 && bytes.Contains(sealed, pt) {
				t.Fatal("sealed value contains the plaintext")
			}
			got, err := s.Open(sealed, aad)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, pt) {
				t.Fatalf("round trip changed the value")
			}
			again, err := s.Seal(pt, aad)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(sealed, again) {
				t.Error("two seals of the same value are identical (nonce reuse)")
			}
		})
	}
}

func TestOpenFails(t *testing.T) {
	s := newSealer(t)
	aad := seal.AAD(tenantA, "idp_connections", "client_secret_enc")
	sealed, err := s.Seal([]byte("the secret"), aad)
	if err != nil {
		t.Fatal(err)
	}
	flip := func(i int) []byte {
		c := append([]byte(nil), sealed...)
		c[i] ^= 0x01
		return c
	}
	cases := []struct {
		name   string
		sealer *seal.Sealer
		blob   []byte
		aad    []byte
	}{
		{"wrong AAD: other tenant", s, sealed, seal.AAD(tenantB, "idp_connections", "client_secret_enc")},
		{"wrong AAD: other table", s, sealed, seal.AAD(tenantA, "api_clients", "client_secret_enc")},
		{"wrong AAD: other column", s, sealed, seal.AAD(tenantA, "idp_connections", "pkce_verifier_enc")},
		{"wrong AAD: extra row part", s, sealed, seal.AAD(tenantA, "idp_connections", "client_secret_enc", "r1")},
		{"wrong AAD: empty", s, sealed, nil},
		{"wrong key", newSealer(t), sealed, aad},
		{"tampered version", s, flip(0), aad},
		{"tampered nonce", s, flip(1), aad},
		{"tampered ciphertext", s, flip(1 + 12), aad},
		{"tampered tag", s, flip(len(sealed) - 1), aad},
		{"truncated", s, sealed[:len(sealed)-1], aad},
		{"too short", s, sealed[:10], aad},
		{"empty blob", s, nil, aad},
		{"appended byte", s, append(append([]byte(nil), sealed...), 0), aad},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pt, err := c.sealer.Open(c.blob, c.aad)
			if !errors.Is(err, seal.ErrOpen) || pt != nil {
				t.Errorf("Open = %q, %v; want nil, ErrOpen", pt, err)
			}
		})
	}
}

func TestSealNeedsAAD(t *testing.T) {
	if _, err := newSealer(t).Seal([]byte("x"), nil); err == nil {
		t.Error("Seal without an AAD succeeded")
	}
}

func TestAAD(t *testing.T) {
	if got := string(seal.AAD(tenantA, "t", "c")); got != tenantA.String()+"|t|c" {
		t.Errorf("AAD = %q", got)
	}
	if got := string(seal.AAD(tenantA, "t", "c", "kid")); got != tenantA.String()+"|t|c|kid" {
		t.Errorf("AAD with row = %q", got)
	}
	for name, fn := range map[string]func(){
		"zero tenant": func() { seal.AAD(tenancy.ID{}, "t", "c") },
		"empty table": func() { seal.AAD(tenantA, "", "c") },
		"pipe":        func() { seal.AAD(tenantA, "t|x", "c") },
		"empty row":   func() { seal.AAD(tenantA, "t", "c", "") },
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Error("no panic")
				}
			}()
			fn()
		})
	}
}

func TestSealerNeverPrintsKey(t *testing.T) {
	kek := seal.RandomBytes(seal.KeySize)
	s, err := seal.New(kek)
	if err != nil {
		t.Fatal(err)
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		out := fmt.Sprintf(verb, s)
		if strings.Contains(out, fmt.Sprintf("%x", kek)) || strings.Contains(out, base64.StdEncoding.EncodeToString(kek)) ||
			strings.Contains(out, string(kek)) {
			t.Errorf("%s printed the KEK: %s", verb, out)
		}
	}
}

func TestDeriveKey(t *testing.T) {
	s := newSealer(t)
	a, err := s.DeriveKey("dpop-nonce", 32)
	if err != nil {
		t.Fatal(err)
	}
	a2, _ := s.DeriveKey("dpop-nonce", 32)
	b, _ := s.DeriveKey("csrf", 32)
	if len(a) != 32 || !bytes.Equal(a, a2) || bytes.Equal(a, b) {
		t.Errorf("DeriveKey not deterministic per label or not separated across labels")
	}
	other, _ := newSealer(t).DeriveKey("dpop-nonce", 32)
	if bytes.Equal(a, other) {
		t.Error("different KEKs derived the same key")
	}
	if _, err := s.DeriveKey("", 32); err == nil {
		t.Error("empty label accepted")
	}
	// key separation: no DeriveKey label can produce the sealing key
	for _, l := range []string{"seal/v1", "seal", "seal/v2", "sealing"} {
		if k, err := s.DeriveKey(l, 32); err == nil {
			t.Errorf("DeriveKey(%q) = %x, want refused (reserved for the sealing key)", l, k)
		}
	}
}

// legacyV1 seals pt in the version 1 format (raw KEK as the AES-GCM key),
// written independently of the package, as old databases hold it.
func legacyV1(t *testing.T, kek, pt, aad []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(kek)
	if err != nil {
		t.Fatal(err)
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	out := append([]byte{seal.Version1}, seal.RandomBytes(12)...)
	return g.Seal(out, out[1:], pt, append([]byte{seal.Version1}, aad...))
}

// TestSealVersions (L3): Seal writes version 2 under HKDF(KEK,
// "tessera/seal/v1"), not under the raw KEK; version 1 values still open;
// Reseal upgrades them; and the version byte cannot be swapped.
func TestSealVersions(t *testing.T) {
	kek := seal.RandomBytes(seal.KeySize)
	s, err := seal.New(kek)
	if err != nil {
		t.Fatal(err)
	}
	aad := seal.AAD(tenantA, "idp_connections", "client_secret_enc")
	v2, err := s.Seal([]byte("v2 secret"), aad)
	if err != nil {
		t.Fatal(err)
	}
	if seal.Version(v2) != seal.Version2 {
		t.Fatalf("Seal wrote version %d, want 2", seal.Version(v2))
	}
	// the v2 key is the HKDF output, computed independently here
	sk, err := hkdf.Key(sha256.New, kek, nil, "tessera/seal/v1", 32)
	if err != nil {
		t.Fatal(err)
	}
	for name, key := range map[string][]byte{"derived key": sk, "raw KEK": kek} {
		block, _ := aes.NewCipher(key)
		g, _ := cipher.NewGCM(block)
		pt, err := g.Open(nil, v2[1:13], v2[13:], append([]byte{seal.Version2}, aad...))
		if want := name == "derived key"; (err == nil) != want {
			t.Errorf("v2 blob opened with the %s: %v (want ok=%t)", name, err, want)
		}
		if err == nil && string(pt) != "v2 secret" {
			t.Errorf("v2 plaintext %q", pt)
		}
	}

	v1 := legacyV1(t, kek, []byte("v1 secret"), aad)
	if pt, err := s.Open(v1, aad); err != nil || string(pt) != "v1 secret" {
		t.Fatalf("legacy v1 value: %q, %v", pt, err)
	}
	if _, err := s.Open(v1, seal.AAD(tenantB, "idp_connections", "client_secret_enc")); !errors.Is(err, seal.ErrOpen) {
		t.Errorf("v1 value opened under another AAD: %v", err)
	}
	// downgrade / upgrade by rewriting the version byte: the key changes too
	for name, blob := range map[string][]byte{"v2 relabelled v1": v2, "v1 relabelled v2": v1} {
		c := append([]byte(nil), blob...)
		c[0] ^= 3 // 1 <-> 2
		if _, err := s.Open(c, aad); !errors.Is(err, seal.ErrOpen) {
			t.Errorf("%s opened: %v", name, err)
		}
	}
	for _, b := range []byte{0, 3, 0xff} {
		c := append([]byte(nil), v2...)
		c[0] = b
		if _, err := s.Open(c, aad); !errors.Is(err, seal.ErrOpen) {
			t.Errorf("version %d opened: %v", b, err)
		}
	}

	// lazy migration
	up, changed, err := s.Reseal(v1, aad)
	if err != nil || !changed || seal.Version(up) != seal.Version2 {
		t.Fatalf("Reseal(v1) = version %d, changed=%t, %v", seal.Version(up), changed, err)
	}
	if pt, err := s.Open(up, aad); err != nil || string(pt) != "v1 secret" {
		t.Errorf("resealed value: %q, %v", pt, err)
	}
	same, changed, err := s.Reseal(v2, aad)
	if err != nil || changed || !bytes.Equal(same, v2) {
		t.Errorf("Reseal(v2) changed it: %t %v", changed, err)
	}
	if _, _, err := s.Reseal(v1, seal.AAD(tenantB, "idp_connections", "client_secret_enc")); !errors.Is(err, seal.ErrOpen) {
		t.Errorf("Reseal under a wrong AAD: %v", err)
	}
	if _, _, err := newSealer(t).Reseal(v1, aad); !errors.Is(err, seal.ErrOpen) {
		t.Errorf("Reseal under a wrong KEK: %v", err)
	}
}

func TestRandomSecret(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		v := seal.RandomSecret(32)
		if len(v) != 43 || strings.ContainsAny(v, "+/=") {
			t.Fatalf("RandomSecret(32) = %q, want 43 base64url characters", v)
		}
		if seen[v] {
			t.Fatal("duplicate secret")
		}
		seen[v] = true
	}
	defer func() {
		if recover() == nil {
			t.Error("RandomSecret(8) did not panic")
		}
	}()
	seal.RandomSecret(8)
}

func TestRandomString(t *testing.T) {
	const alphabet = "BCDFGHJKLMNPQRSTVWXZ"
	counts := map[rune]int{}
	for range 2000 {
		v := seal.RandomString(8, alphabet)
		if len(v) != 8 {
			t.Fatalf("len %d", len(v))
		}
		for _, r := range v {
			if !strings.ContainsRune(alphabet, r) {
				t.Fatalf("%q outside the alphabet", r)
			}
			counts[r]++
		}
	}
	// 16000 draws over 20 symbols: expect 800 each; a biased sampler or a
	// missing symbol shows up far outside this band.
	for _, r := range alphabet {
		if c := counts[r]; c < 600 || c > 1000 {
			t.Errorf("symbol %q drawn %d times, want about 800", r, c)
		}
	}
}

func TestHashing(t *testing.T) {
	// SHA-256("abc"), FIPS 180-2 test vector.
	const abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got := seal.SHA256Hex([]byte("abc")); got != abc {
		t.Errorf("SHA256Hex = %s", got)
	}
	if !seal.MatchesHash([]byte("abc"), abc) {
		t.Error("MatchesHash rejected the right secret")
	}
	for _, bad := range []string{"", abc[:63], strings.ToUpper(abc), abc[:63] + "0"} {
		if seal.MatchesHash([]byte("abc"), bad) {
			t.Errorf("MatchesHash accepted %q", bad)
		}
	}
	if !seal.Equal([]byte("a"), []byte("a")) || seal.Equal([]byte("a"), []byte("b")) || seal.Equal([]byte("a"), []byte("ab")) {
		t.Error("Equal is wrong")
	}
}
