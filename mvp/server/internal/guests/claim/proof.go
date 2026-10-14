package claim

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Session key binding (threat T20): the claim page makes an ECDSA P-256 key
// with WebCrypto, non-extractable, and sends only the public key with
// "start". Every later claim request carries
//
//	X-Claim-Proof: <unix seconds>.<base64url(r||s)>
//
// a signature over "tessera-claim-proof-v2\n" + METHOD + "\n" + PATH + "\n" +
// seconds + "\n" + the session's nonce (empty at start) + "\n" +
// base64url(SHA-256(request body)). The server verifies it against the
// session's key, accepts timestamps within ProofWindow and lets each proof be
// used once. Without the private key, which cannot be exported from the
// browser, a stolen cookie cannot make a valid request, and a captured proof
// cannot carry a different body.
//
// One use is keyed on r, not on the signature bytes: ECDSA signatures are
// malleable, so (r, N-s) verifies for the same message as (r, s). r is fixed
// by the signer's random nonce k, so an honest client never repeats it, and
// both forms of one signature share it. Uses are recorded in the tenant's
// database (claim_proof_uses), so a replay is refused across restarts and
// processes; the in-memory Replays is a first line for requests that have no
// tenant to record against.

// ProofHeader is the request header.
const ProofHeader = "X-Claim-Proof"

// ProofWindow is how far a proof's timestamp may be from the server's clock.
const ProofWindow = 60 * time.Second

const proofDomain = "tessera-claim-proof-v2"

// Proof errors. Callers answer all of them the same way; the reason is audited.
var (
	ErrProofMissing = errors.New("claim: no proof")
	ErrProofBad     = errors.New("claim: proof does not verify")
	ErrProofStale   = errors.New("claim: proof timestamp outside the window")
	ErrProofReplay  = errors.New("claim: proof already used")
)

// IsProofError reports whether err is one of the proof errors (and not, say, a
// database failure while recording the proof's use).
func IsProofError(err error) bool {
	return errors.Is(err, ErrProofMissing) || errors.Is(err, ErrProofBad) || errors.Is(err, ErrProofStale) || errors.Is(err, ErrProofReplay)
}

// Reason is the short audit name of a proof error.
func Reason(err error) string {
	switch {
	case errors.Is(err, ErrProofMissing):
		return "proof_missing"
	case errors.Is(err, ErrProofStale):
		return "proof_stale"
	case errors.Is(err, ErrProofReplay):
		return "proof_replay"
	}
	return "proof_invalid"
}

type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// ParseKey reads the public JWK the page sends with start: an EC P-256 key
// without any private part. It returns the key, its canonical JSON (what is
// stored) and its RFC 7638 thumbprint.
func ParseKey(raw []byte) (pub *ecdsa.PublicKey, canonical, jkt string, err error) {
	var all map[string]json.RawMessage
	if err := json.Unmarshal(raw, &all); err != nil {
		return nil, "", "", errors.New("claim: key is not a JWK")
	}
	for k := range all {
		switch k {
		case "kty", "crv", "x", "y", "ext", "key_ops", "alg", "use", "kid":
		default:
			return nil, "", "", errors.New("claim: unexpected JWK member") // above all "d": never accept a private key
		}
	}
	var k jwk
	if err := json.Unmarshal(raw, &k); err != nil || k.Kty != "EC" || k.Crv != "P-256" {
		return nil, "", "", errors.New("claim: key must be an EC P-256 JWK")
	}
	x, err1 := base64.RawURLEncoding.DecodeString(k.X)
	y, err2 := base64.RawURLEncoding.DecodeString(k.Y)
	if err1 != nil || err2 != nil || len(x) != 32 || len(y) != 32 {
		return nil, "", "", errors.New("claim: bad key coordinates")
	}
	point := append([]byte{4}, append(x, y...)...)
	if _, err := ecdh.P256().NewPublicKey(point); err != nil { // checks the point is on the curve
		return nil, "", "", errors.New("claim: key is not a point on P-256")
	}
	pub, err = ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	if err != nil {
		return nil, "", "", errors.New("claim: key is not a point on P-256")
	}
	// RFC 7638: members in lexicographic order, no whitespace
	canonical = `{"crv":"P-256","kty":"EC","x":"` + k.X + `","y":"` + k.Y + `"}`
	sum := sha256.Sum256([]byte(canonical))
	return pub, canonical, base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// proofMessage is what the page signs.
func proofMessage(method, path, ts, nonce, bodyHash string) []byte {
	return []byte(proofDomain + "\n" + method + "\n" + path + "\n" + ts + "\n" + nonce + "\n" + bodyHash)
}

// BodyHash is the body digest a proof signs: base64url(SHA-256(body)), also for
// an empty body.
func BodyHash(body []byte) string {
	sum := sha256.Sum256(body)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// Proof is an accepted proof: ID identifies it for one-use (it is the same for
// a signature and its malleated form) and UseUntil is how long to remember it.
type Proof struct {
	ID       string
	UseUntil time.Time
}

// Verify checks a proof header for a request. nonce is the session's ("" at
// start); bodyHash is BodyHash of the request body. replays may be nil (no
// in-memory replay check: tests of the signature alone). The caller records
// the returned proof's ID in the tenant's database to enforce one use.
func Verify(pub *ecdsa.PublicKey, header, method, path, nonce, bodyHash string, now time.Time, replays *Replays) (Proof, error) {
	if header == "" {
		return Proof{}, ErrProofMissing
	}
	ts, sig, ok := strings.Cut(header, ".")
	if !ok || len(header) > 200 {
		return Proof{}, ErrProofBad
	}
	secs, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return Proof{}, ErrProofBad
	}
	raw, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || len(raw) != 64 {
		return Proof{}, ErrProofBad
	}
	der, err := asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:])})
	if err != nil {
		return Proof{}, ErrProofBad
	}
	digest := sha256.Sum256(proofMessage(method, path, ts, nonce, bodyHash))
	if !ecdsa.VerifyASN1(pub, digest[:], der) {
		return Proof{}, ErrProofBad
	}
	if d := now.Sub(time.Unix(secs, 0)); d > ProofWindow || d < -ProofWindow {
		return Proof{}, ErrProofStale
	}
	// r alone: (r, s) and (r, N-s) are the same proof
	sum := sha256.Sum256(append([]byte("tessera-claim-proof-r|"), raw[:32]...))
	p := Proof{ID: hex.EncodeToString(sum[:]), UseUntil: now.Add(2 * ProofWindow)}
	if replays != nil && !replays.Fresh(p.ID, now) {
		return Proof{}, ErrProofReplay
	}
	return p, nil
}

// Replays remembers, in memory, the proofs accepted within the window.
type Replays struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

// maxReplays bounds the memory; a full table refuses (fails closed).
const maxReplays = 50000

// NewReplays returns an empty replay memory.
func NewReplays() *Replays { return &Replays{seen: map[string]time.Time{}} }

// Fresh records a proof ID and reports whether it had not been seen.
func (r *Replays) Fresh(sig string, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.seen) >= maxReplays {
		for k, until := range r.seen {
			if !now.Before(until) {
				delete(r.seen, k)
			}
		}
		if len(r.seen) >= maxReplays {
			return false
		}
	}
	if until, ok := r.seen[sig]; ok && now.Before(until) {
		return false
	}
	r.seen[sig] = now.Add(2 * ProofWindow)
	return true
}
