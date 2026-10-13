package claim

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
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
// a signature over "tessera-claim-proof-v1\n" + METHOD + "\n" + PATH + "\n" +
// seconds + "\n" + the session's nonce (empty at start). The server verifies it
// against the session's key, accepts timestamps within ProofWindow and refuses
// a signature it has seen (ECDSA signatures are randomized, so an honest client
// never repeats one). Without the private key, which cannot be exported from the
// browser, a stolen cookie cannot make a valid request.

// ProofHeader is the request header.
const ProofHeader = "X-Claim-Proof"

// ProofWindow is how far a proof's timestamp may be from the server's clock.
const ProofWindow = 60 * time.Second

const proofDomain = "tessera-claim-proof-v1"

// Proof errors. Callers answer all of them the same way; the reason is audited.
var (
	ErrProofMissing = errors.New("claim: no proof")
	ErrProofBad     = errors.New("claim: proof does not verify")
	ErrProofStale   = errors.New("claim: proof timestamp outside the window")
	ErrProofReplay  = errors.New("claim: proof already used")
)

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
func proofMessage(method, path, ts, nonce string) []byte {
	return []byte(proofDomain + "\n" + method + "\n" + path + "\n" + ts + "\n" + nonce)
}

// Verify checks a proof header for a request. nonce is the session's ("" at
// start). replays may be nil (no replay memory: tests of the signature alone).
func Verify(pub *ecdsa.PublicKey, header, method, path, nonce string, now time.Time, replays *Replays) error {
	if header == "" {
		return ErrProofMissing
	}
	ts, sig, ok := strings.Cut(header, ".")
	if !ok || len(header) > 200 {
		return ErrProofBad
	}
	secs, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return ErrProofBad
	}
	raw, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || len(raw) != 64 {
		return ErrProofBad
	}
	der, err := asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:])})
	if err != nil {
		return ErrProofBad
	}
	digest := sha256.Sum256(proofMessage(method, path, ts, nonce))
	if !ecdsa.VerifyASN1(pub, digest[:], der) {
		return ErrProofBad
	}
	if d := now.Sub(time.Unix(secs, 0)); d > ProofWindow || d < -ProofWindow {
		return ErrProofStale
	}
	if replays != nil && !replays.Fresh(sig, now) {
		return ErrProofReplay
	}
	return nil
}

// Replays remembers the signatures accepted within the window.
type Replays struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

// maxReplays bounds the memory; a full table refuses (fails closed).
const maxReplays = 50000

// NewReplays returns an empty replay memory.
func NewReplays() *Replays { return &Replays{seen: map[string]time.Time{}} }

// Fresh records sig and reports whether it had not been seen.
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
