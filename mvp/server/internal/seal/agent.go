package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Sealing a secret to one agent (issue #302).
//
// The KEK seals what Tessera keeps at rest and never leaves the server. A
// Directory Agent in a customer network is a different party: it holds its own
// key pair and Tessera holds the public half. To hand a server-held credential
// (the bearer token of a private SCIM target) to one agent for one job without
// putting it in the clear in the job row, in the log or on the wire beyond the
// TLS channel, the server seals it to that agent's public key:
//
//	version (1 byte) || ephemeral X25519 public key (32) || nonce (12) || AES-256-GCM ciphertext and tag
//
// The key is HKDF-SHA256 of the X25519 shared secret, salted with both public
// keys, with an info string that names the purpose and the binding, so the
// same key pair cannot be tricked into opening a blob made for another
// purpose. The GCM additional data is the version byte followed by the binding
// (AgentAAD): tenant, agent, connection and job. A blob cannot be replayed to
// another agent (it cannot open it), to another tenant, connection or job (the
// binding differs), or have its version or ephemeral key changed. Only the
// standard library is used (crypto/ecdh, crypto/hkdf, crypto/cipher): this is
// ECIES with the usual pieces, not a home-made primitive.
//
// It is sealing, not authentication of the sender: the agent trusts the blob
// because it arrived over the mutual-TLS channel that pins Tessera's CA; the
// seal's job is confidentiality and binding at rest and in logs.

// AgentVersion is the format version byte of a blob sealed to an agent.
const AgentVersion byte = 0x41

// AgentKeySize is the length of an agent's public or private X25519 key.
const AgentKeySize = 32

const agentInfo = "tessera/seal/agent/v1"

// ErrAgentKey is returned for a public key that is not a valid X25519 key.
var ErrAgentKey = errors.New("seal: not a valid agent public key")

// GenerateAgentKey makes a new agent key pair.
func GenerateAgentKey() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}

// ParseAgentPublicKey checks and returns an agent public key (32 bytes, a
// valid X25519 point that is not the all-zero or low-order element).
func ParseAgentPublicKey(b []byte) (*ecdh.PublicKey, error) {
	if len(b) != AgentKeySize {
		return nil, ErrAgentKey
	}
	pub, err := ecdh.X25519().NewPublicKey(b)
	if err != nil {
		return nil, ErrAgentKey
	}
	// a low-order point makes the shared secret all zero (ECDH reports it): refuse it up front
	probe, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if _, err := probe.ECDH(pub); err != nil {
		return nil, ErrAgentKey
	}
	return pub, nil
}

// AgentKeyID is the short, stable identifier of a public key shown in audit
// events and the API (the first 16 hex digits of its SHA-256).
func AgentKeyID(pub []byte) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:8])
}

// AgentAAD is the binding of a credential sealed to an agent: tenant, agent,
// connection and job. Every part must be a non-empty id without "|"; ok is
// false otherwise (AAD itself would panic).
func AgentAAD(tenant tenancy.ID, agentID, connectionID, jobID string) (aad []byte, ok bool) {
	if tenant.IsZero() {
		return nil, false
	}
	for _, p := range []string{agentID, connectionID, jobID} {
		if p == "" || strings.Contains(p, "|") {
			return nil, false
		}
	}
	return AAD(tenant, "agent_jobs", "sealed_credential", agentID, connectionID, jobID), true
}

func agentKey(secret, ephPub, agentPub, aad []byte) ([]byte, error) {
	salt := append(append([]byte(nil), ephPub...), agentPub...)
	info := agentInfo + "|" + string(aad)
	return hkdf.Key(sha256.New, secret, salt, info, KeySize)
}

// SealToAgent encrypts plaintext so that only the holder of the private key
// of pub can open it, bound to aad (AgentAAD).
func SealToAgent(pub *ecdh.PublicKey, plaintext, aad []byte) ([]byte, error) {
	if pub == nil || len(aad) == 0 {
		return nil, errors.New("seal: SealToAgent needs a public key and an AAD")
	}
	if len(plaintext) > MaxPlaintext {
		return nil, ErrTooLarge
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	secret, err := eph.ECDH(pub)
	if err != nil {
		return nil, ErrAgentKey
	}
	defer clear(secret)
	key, err := agentKey(secret, eph.PublicKey().Bytes(), pub.Bytes(), aad)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	aead, err := agentGCM(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 1+AgentKeySize+nonceSize+len(plaintext)+16)
	out = append(out, AgentVersion)
	out = append(out, eph.PublicKey().Bytes()...)
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out = append(out, nonce...)
	return aead.Seal(out, nonce, plaintext, additional(AgentVersion, aad)), nil
}

// OpenFromAgent decrypts a blob made by SealToAgent for priv's public key
// with the same aad. Any mismatch returns ErrOpen.
func OpenFromAgent(priv *ecdh.PrivateKey, sealed, aad []byte) ([]byte, error) {
	const head = 1 + AgentKeySize + nonceSize
	if priv == nil || len(aad) == 0 || len(sealed) < head+16 || sealed[0] != AgentVersion {
		return nil, ErrOpen
	}
	ephPub, err := ecdh.X25519().NewPublicKey(sealed[1 : 1+AgentKeySize])
	if err != nil {
		return nil, ErrOpen
	}
	secret, err := priv.ECDH(ephPub)
	if err != nil {
		return nil, ErrOpen
	}
	defer clear(secret)
	key, err := agentKey(secret, ephPub.Bytes(), priv.PublicKey().Bytes(), aad)
	if err != nil {
		return nil, ErrOpen
	}
	defer clear(key)
	aead, err := agentGCM(key)
	if err != nil {
		return nil, ErrOpen
	}
	pt, err := aead.Open(nil, sealed[1+AgentKeySize:head], sealed[head:], additional(AgentVersion, aad))
	if err != nil {
		return nil, ErrOpen
	}
	return pt, nil
}

func agentGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
