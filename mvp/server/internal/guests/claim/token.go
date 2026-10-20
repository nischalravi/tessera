// Package claim is how a guest turns an invitation into a sign-in (guest
// accounts design §6, issue #69 / GU-6): the claim link, the claim session,
// the confirmation code, the "do you already have an account?" question and
// the credential step.
//
// The security properties, in short:
//
//   - The claim link carries a 256-bit single-use secret in the URL fragment.
//     Only SHA-256("tessera-claim-v1|"+tenant+"|"+token) is stored; the secret is
//     never logged, audited, or written to a notification row. Consuming it is
//     one atomic UPDATE, so two concurrent starts cannot both win.
//   - A consumed token buys a claim session: a cookie (stored as a hash) that is
//     also bound to a key the page holds (a WebCrypto non-extractable ECDSA
//     P-256 key); every request carries a signature by that key (proof.go), so a
//     stolen cookie alone is useless.
//   - Contact is verified by a separate 6-digit code mailed to the invited
//     address: stored keyed-hashed, valid 10 minutes, 5 attempts.
//   - The invitation is self-asserted intake (K3): nothing here links the
//     claimant to an existing person. The "do you already have an account?"
//     question is asked of everyone, and a "yes" is only recorded for review.
//   - The claim completes only after a sign-in at the required assurance level
//     through the bound credential authority (credential package).
package claim

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// HashPrefix is the domain separation of the stored token hash.
const HashPrefix = "tessera-claim-v1|"

// TokenBytes is the size of a claim token: 256 bits.
const TokenBytes = 32

// TokenLen is the length of a token's text: 43 characters of unpadded base64url.
const TokenLen = 43

// NewToken returns a fresh claim token from crypto/rand.
func NewToken() string { return seal.RandomSecret(TokenBytes) }

// HashToken is what is stored of a token: the hex SHA-256 over
// "tessera-claim-v1|"+tenant+"|"+token.
func HashToken(tenant tenancy.ID, token string) string {
	sum := sha256.Sum256([]byte(HashPrefix + tenant.String() + "|" + token))
	return hex.EncodeToString(sum[:])
}

// WellFormed reports whether s has the shape of a token (43 base64url
// characters). A malformed one is still hashed and looked up, so it takes the
// same path as an unknown token; this is for tests and cheap client checks.
func WellFormed(s string) bool {
	if len(s) != TokenLen {
		return false
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil && len(b) == TokenBytes
}

// Lifetimes of a claim link by population (design §6.2).
const (
	VisitorLifetime = 7 * 24 * time.Hour
	OtherLifetime   = 14 * 24 * time.Hour
)

// Lifetime is how long a link for the population works.
func Lifetime(population string) time.Duration {
	if population == store.PopVisitor {
		return VisitorLifetime
	}
	return OtherLifetime
}
