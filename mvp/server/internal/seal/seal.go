// Package seal encrypts secrets at rest under the key-encryption key (KEK) and
// provides the random-secret and hashing helpers every other package uses
// (design docs/design/phase-0-platform-security.md §7.1, §10.3, §10.6).
//
// Only the Go standard library is used: AES-256-GCM from crypto/aes and
// crypto/cipher, crypto/rand, crypto/sha256, crypto/subtle and crypto/hkdf.
// Nothing here is a home-made primitive.
//
// Sealed format:
//
//	version (1 byte) || nonce (12 random bytes) || AES-256-GCM ciphertext and 16-byte tag
//
// Version 2 (written by Seal) encrypts under a sealing key derived from the
// KEK, HKDF-SHA256(KEK, info "tessera/seal/v1"), so the KEK itself is only
// ever an HKDF input (key separation: DeriveKey's subkeys and the sealing
// key are all distinct HKDF outputs, and DeriveKey refuses the "seal/"
// labels). Version 1, written before, used the raw KEK as the AES key; Open
// still reads it, so existing databases keep working.
//
// Migration from version 1 is lazy: every new Seal writes version 2 (the
// key rotation of internal/keys replaces tenant keys within 30 days and
// re-seals nothing old), and Reseal rewrites one value in place for a caller
// that is updating the row anyway. Version 1 support can be removed once a
// re-seal CLI (with KEK rotation, §21) has rewritten every sealed column.
//
// The additional authenticated data is the version byte followed by the
// caller's AAD, so a blob cannot be moved to another tenant, table, column or
// row (see AAD) and the version byte cannot be changed (a changed version
// also selects another key). A random 96-bit nonce per Seal is safe for well
// under 2^32 seals per KEK, far above what sealing keys and client secrets
// needs. KEK rotation (and KMS envelope encryption) arrives with production
// key custody (§21); the version byte leaves room for it.
package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// KeySize is the KEK length in bytes (AES-256).
const KeySize = 32

const (
	// Version1 is the legacy format: AES-256-GCM under the raw KEK (read only).
	Version1 byte = 1
	// Version2 is the current format: AES-256-GCM under SealKeyInfo's HKDF output.
	Version2 byte = 2

	nonceSize = 12
	overhead  = 1 + nonceSize + 16
)

// SealKeyInfo is the HKDF info of the version 2 sealing key. DeriveKey labels
// are prefixed "tessera/" and may not start with "seal", so no subkey can
// equal it.
const SealKeyInfo = "tessera/seal/v1"

var (
	// ErrKEK is returned by New for a key that is not KeySize bytes or is all
	// zero.
	ErrKEK = errors.New("seal: the KEK must be 32 random bytes")
	// ErrOpen is returned by Open for any failure: a wrong key, a wrong AAD,
	// a tampered or truncated blob or an unknown version. It deliberately
	// does not say which.
	ErrOpen = errors.New("seal: cannot open sealed value")
)

// Sealer seals and opens values under one KEK. It is safe for concurrent use.
type Sealer struct {
	v1  cipher.AEAD // raw KEK: opens legacy version 1 values only
	v2  cipher.AEAD // HKDF(KEK, SealKeyInfo): seals and opens version 2
	kek []byte      // kept only as the HKDF input of DeriveKey
}

// New returns a Sealer for kek, which must be KeySize random bytes. The
// slice is copied.
func New(kek []byte) (*Sealer, error) {
	if len(kek) != KeySize || subtle.ConstantTimeCompare(kek, make([]byte, KeySize)) == 1 {
		return nil, ErrKEK
	}
	k := append([]byte(nil), kek...)
	v1, err := gcm(k)
	if err != nil {
		return nil, err
	}
	sk, err := hkdf.Key(sha256.New, k, nil, SealKeyInfo, KeySize)
	if err != nil {
		return nil, err
	}
	defer clear(sk)
	v2, err := gcm(sk)
	if err != nil {
		return nil, err
	}
	return &Sealer{v1: v1, v2: v2, kek: k}, nil
}

func gcm(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// String never reveals the key.
func (s *Sealer) String() string { return "seal.Sealer{KEK:REDACTED}" }

// GoString never reveals the key (fmt %#v).
func (s *Sealer) GoString() string { return s.String() }

// Seal encrypts plaintext bound to aad. aad must not be empty: every sealed
// value is bound to where it is stored (build it with AAD).
func (s *Sealer) Seal(plaintext, aad []byte) ([]byte, error) {
	if len(aad) == 0 {
		return nil, errors.New("seal: Seal needs an AAD")
	}
	out := make([]byte, 1+nonceSize, overhead+len(plaintext))
	out[0] = Version2
	if _, err := rand.Read(out[1:]); err != nil {
		return nil, err
	}
	return s.v2.Seal(out, out[1:], plaintext, additional(Version2, aad)), nil
}

// Open decrypts a value produced by Seal (either version) with the same
// aad. Any mismatch returns ErrOpen.
func (s *Sealer) Open(sealed, aad []byte) ([]byte, error) {
	if len(aad) == 0 || len(sealed) < overhead {
		return nil, ErrOpen
	}
	var aead cipher.AEAD
	switch sealed[0] {
	case Version2:
		aead = s.v2
	case Version1:
		aead = s.v1
	default:
		return nil, ErrOpen
	}
	nonce, ct := sealed[1:1+nonceSize], sealed[1+nonceSize:]
	pt, err := aead.Open(nil, nonce, ct, additional(sealed[0], aad))
	if err != nil {
		return nil, ErrOpen
	}
	return pt, nil
}

// Reseal returns sealed rewritten in the current version, and whether it
// changed. A current-version value is returned as is after it opens; any
// value that does not open returns ErrOpen. It is the lazy migration step
// for a caller that is writing the row anyway.
func (s *Sealer) Reseal(sealed, aad []byte) ([]byte, bool, error) {
	pt, err := s.Open(sealed, aad)
	if err != nil {
		return nil, false, err
	}
	defer clear(pt)
	if sealed[0] == Version2 {
		return sealed, false, nil
	}
	out, err := s.Seal(pt, aad)
	if err != nil {
		return nil, false, err
	}
	return out, true, nil
}

// Version returns the format version byte of a sealed value (0 if empty).
func Version(sealed []byte) byte {
	if len(sealed) == 0 {
		return 0
	}
	return sealed[0]
}

func additional(version byte, aad []byte) []byte {
	return append([]byte{version}, aad...)
}

// DeriveKey derives an n-byte subkey from the KEK with HKDF-SHA256 and a
// fixed, distinct label per use (for example "dpop-nonce", §10.5). Labels
// starting with "seal" are reserved for the sealing key (SealKeyInfo).
func (s *Sealer) DeriveKey(label string, n int) ([]byte, error) {
	if label == "" {
		return nil, errors.New("seal: DeriveKey needs a label")
	}
	if strings.HasPrefix(label, "seal") {
		return nil, fmt.Errorf("seal: DeriveKey label %q is reserved for the sealing key", label)
	}
	return hkdf.Key(sha256.New, s.kek, nil, "tessera/"+label, n)
}

// AAD builds the additional data for a sealed column:
// tenantID|table|column, plus |row when the value belongs to one row (a key
// id), so a sealed blob cannot be copied to another tenant, column or row.
// The parts are code constants and ids; a part that is empty or contains "|"
// is a programming error and panics.
func AAD(tenant tenancy.ID, table, column string, row ...string) []byte {
	if tenant.IsZero() {
		panic("seal: AAD with the zero tenant id")
	}
	parts := append([]string{tenant.String(), table, column}, row...)
	for _, p := range parts {
		if p == "" || strings.Contains(p, "|") {
			panic(fmt.Sprintf("seal: invalid AAD part %q", p))
		}
	}
	return []byte(strings.Join(parts, "|"))
}

// MinSecretBytes is the smallest RandomSecret accepted (128 bits).
const MinSecretBytes = 16

// RandomBytes returns n bytes from crypto/rand.
func RandomBytes(n int) []byte {
	b := make([]byte, n)
	// crypto/rand.Read never returns an error (Go 1.24+); it crashes the
	// program if the system's randomness source fails.
	_, _ = rand.Read(b)
	return b
}

// RandomSecret returns n random bytes (at least MinSecretBytes) encoded as
// unpadded base64url, the form used for session cookies, refresh tokens and
// device codes (§10.3). It panics if n is too small.
func RandomSecret(n int) string {
	if n < MinSecretBytes {
		panic(fmt.Sprintf("seal: RandomSecret(%d): at least %d bytes", n, MinSecretBytes))
	}
	return base64.RawURLEncoding.EncodeToString(RandomBytes(n))
}

// RandomString returns n characters drawn uniformly from alphabet (2 to 256
// distinct ASCII bytes), by rejection sampling over crypto/rand bytes so there
// is no modulo bias.
func RandomString(n int, alphabet string) string {
	l := len(alphabet)
	if l < 2 || l > 256 {
		panic("seal: RandomString alphabet must have 2 to 256 characters")
	}
	limit := 256 - 256%l // accept bytes below the largest multiple of l
	out := make([]byte, 0, n)
	buf := make([]byte, 2*n+8)
	for len(out) < n {
		_, _ = rand.Read(buf)
		for _, b := range buf {
			if int(b) < limit {
				out = append(out, alphabet[int(b)%l])
				if len(out) == n {
					break
				}
			}
		}
	}
	return string(out)
}

// SHA256Hex returns the lower-case hex SHA-256 of b. Bearer secrets are
// stored only in this form (§7.1).
func SHA256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Equal compares two secrets in constant time (for equal lengths; the
// length itself is not secret).
func Equal(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }

// MatchesHash reports whether secret hashes to storedHex, comparing the
// hashes in constant time.
func MatchesHash(secret []byte, storedHex string) bool {
	return Equal([]byte(SHA256Hex(secret)), []byte(storedHex))
}
