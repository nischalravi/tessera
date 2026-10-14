// Package ssf is Tessera's receiver for the OpenID Shared Signals Framework
// (SSF): a transmitter such as Okta tells Tessera that a session was revoked,
// a credential changed or an account was disabled, and Tessera runs the kill
// switch (internal/containment) on the subject's other linked accounts, so
// a revocation at one provider propagates downstream.
//
// Events arrive as Security Event Tokens (SET, RFC 8417), pushed to a public
// endpoint (RFC 8935) or polled from the transmitter (RFC 8936). Rules:
//
//   - A SET is trusted only after its JWS signature verifies against the
//     transmitter's JWKS (RS256, ES256 or PS256 only: alg none and HMAC are
//     refused) and its claims match the transmitter's configuration: issuer,
//     audience, a recent iat, an unexpired exp, a jti and exactly one event.
//   - A jti is accepted once per transmitter (the ssf_events unique key).
//   - Unknown event types are acknowledged and recorded as ignored, and a
//     subject that does not resolve is recorded as unmatched. Nothing is
//     dropped silently.
//   - The receive path never returns detail that reveals whether a tenant or
//     a transmitter exists; that is the API layer's job (internal/api).
//   - Secrets are sealed (internal/seal); audit details carry no token.
//   - Every outbound call goes through an internal/safehttp client.
package ssf

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Event types Tessera knows.
const (
	EventSessionRevoked   = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
	EventCredentialChange = "https://schemas.openid.net/secevent/caep/event-type/credential-change"
	EventAccountDisabled  = "https://schemas.openid.net/secevent/risc/event-type/account-disabled"
	EventVerification     = "https://schemas.openid.net/secevent/ssf/event-type/verification"
)

// EventName is the short name of a known event type.
func EventName(uri string) string {
	switch uri {
	case EventSessionRevoked:
		return "session-revoked"
	case EventCredentialChange:
		return "credential-change"
	case EventAccountDisabled:
		return "account-disabled"
	case EventVerification:
		return "verification"
	}
	return ""
}

// Actionable reports whether uri runs the kill switch.
func Actionable(uri string) bool {
	return uri == EventSessionRevoked || uri == EventCredentialChange || uri == EventAccountDisabled
}

// RFC 8935 error codes a receiver answers with.
const (
	ErrInvalidRequest       = "invalid_request"
	ErrInvalidKey           = "invalid_key"
	ErrAuthenticationFailed = "authentication_failed"
	ErrAccessDenied         = "access_denied"
)

// Error is a refusal the transmitter can act on (RFC 8935 section 2.4 / RFC 8936 setErrs).
type Error struct {
	Code string `json:"err"`
	Msg  string `json:"description"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

func invalid(format string, a ...any) *Error {
	return &Error{Code: ErrInvalidRequest, Msg: fmt.Sprintf(format, a...)}
}

// Limits.
const (
	// MaxSETBytes bounds a SET (they are a few hundred bytes).
	MaxSETBytes = 64 << 10
	// DefaultSkew is how far in the future an iat or nbf may be.
	DefaultSkew = 2 * time.Minute
	// DefaultMaxAge is how old a SET's iat may be. Polled events can wait.
	DefaultMaxAge = 24 * time.Hour
	maxJTIBytes   = 255
	maxIDBytes    = 512
)

// Expect is what a SET must match.
type Expect struct {
	Issuer   string
	Audience string
	Now      time.Time
	Skew     time.Duration // 0: DefaultSkew
	MaxAge   time.Duration // 0: DefaultMaxAge
}

// Subject is who an event is about (SSF subject identifiers, RFC 9493).
type Subject struct {
	Format string // iss_sub, email, opaque, account, complex, or an unknown format
	// ID is the identifier: sub (iss_sub), email, id (opaque) or the account URI.
	ID      string
	Issuer  string   // iss of an iss_sub subject
	User    *Subject // the user of a complex subject
	Session string   // the session of a complex subject (id or sub)
	// Problem says why the subject cannot be used ("" when it can).
	Problem string
}

// SET is a validated Security Event Token.
type SET struct {
	JTI       string
	Issuer    string
	IssuedAt  time.Time
	ExpiresAt *time.Time
	// EventType is the single event URI of the token.
	EventType string
	Known     bool
	Payload   map[string]any
	Subject   Subject
}

// Key is a transmitter signing key.
type Key = jose.JSONWebKey

// allowedAlgs are the only JWS algorithms accepted.
var allowedAlgs = []jose.SignatureAlgorithm{jose.RS256, jose.ES256, jose.PS256}

// ParseJWKS reads a JWKS: public RSA and P-256 EC keys only. A private or
// symmetric key is refused (a transmitter's JWKS never holds one).
func ParseJWKS(raw []byte) ([]Key, error) {
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(raw, &set); err != nil {
		return nil, errors.New("the JWKS is not valid")
	}
	if len(set.Keys) == 0 || len(set.Keys) > 32 {
		return nil, errors.New("the JWKS must hold 1 to 32 keys")
	}
	var out []Key
	for _, k := range set.Keys {
		if !k.Valid() || !k.IsPublic() {
			return nil, errors.New("the JWKS holds a key that is invalid or not a public key")
		}
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		switch k.Key.(type) {
		case *rsa.PublicKey, *ecdsa.PublicKey:
		default:
			return nil, errors.New("the JWKS holds an unsupported key")
		}
		out = append(out, k)
	}
	if len(out) == 0 {
		return nil, errors.New("the JWKS holds no signing key")
	}
	return out, nil
}

// ParseSET verifies and validates a compact-serialized SET against the
// transmitter's keys and the expected claims. Every refusal is an *Error.
func ParseSET(raw string, keys []Key, ex Expect) (*SET, error) {
	raw = strings.TrimSpace(raw)
	switch {
	case raw == "":
		return nil, invalid("the request carries no SET")
	case len(raw) > MaxSETBytes:
		return nil, invalid("the SET is larger than %d bytes", MaxSETBytes)
	}
	jws, err := jose.ParseSignedCompact(raw, allowedAlgs)
	if err != nil || len(jws.Signatures) != 1 {
		return nil, invalid("the SET is not a JWS in compact form signed with RS256, ES256 or PS256")
	}
	payload, kerr := verify(jws, keys)
	if kerr != nil {
		return nil, kerr
	}
	return validateClaims(payload, ex)
}

// verify checks the signature against the key named by kid (or, without a
// kid, every key) and returns the payload.
func verify(jws *jose.JSONWebSignature, keys []Key) ([]byte, *Error) {
	hdr := jws.Signatures[0].Header
	var cands []Key
	for _, k := range keys {
		if hdr.KeyID != "" && k.KeyID != hdr.KeyID {
			continue
		}
		if k.Algorithm != "" && k.Algorithm != hdr.Algorithm {
			continue
		}
		cands = append(cands, k)
	}
	if len(cands) == 0 {
		return nil, &Error{Code: ErrInvalidKey, Msg: "no key of the transmitter matches the SET's key id and algorithm"}
	}
	for _, k := range cands {
		if payload, err := jws.Verify(k.Key); err == nil {
			return payload, nil
		}
	}
	return nil, &Error{Code: ErrInvalidKey, Msg: "the SET's signature does not verify"}
}

type rawClaims struct {
	Iss    string                     `json:"iss"`
	Aud    json.RawMessage            `json:"aud"`
	Iat    json.Number                `json:"iat"`
	Exp    *json.Number               `json:"exp"`
	Nbf    *json.Number               `json:"nbf"`
	Jti    string                     `json:"jti"`
	Sub    string                     `json:"sub"`
	SubID  json.RawMessage            `json:"sub_id"`
	Events map[string]json.RawMessage `json:"events"`
}

func numericDate(n json.Number) (time.Time, bool) {
	f, err := n.Float64()
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f < 0 || f > 1e11 {
		return time.Time{}, false
	}
	return time.Unix(int64(math.Floor(f)), 0).UTC(), true
}

func audiences(raw json.RawMessage) []string {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return []string{one}
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		return many
	}
	return nil
}

func validateClaims(payload []byte, ex Expect) (*SET, error) {
	var c rawClaims
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	if err := dec.Decode(&c); err != nil {
		return nil, invalid("the SET's claims are not a JSON object")
	}
	skew, maxAge := ex.Skew, ex.MaxAge
	if skew <= 0 {
		skew = DefaultSkew
	}
	if maxAge <= 0 {
		maxAge = DefaultMaxAge
	}
	switch {
	case c.Iss == "" || c.Iss != ex.Issuer:
		return nil, invalid("iss does not match the transmitter's issuer")
	case !containsString(audiences(c.Aud), ex.Audience):
		return nil, invalid("aud does not contain this receiver's audience")
	case c.Jti == "" || len(c.Jti) > maxJTIBytes || strings.ContainsAny(c.Jti, "\x00\r\n"):
		return nil, invalid("jti is required (at most %d bytes)", maxJTIBytes)
	}
	iat, ok := numericDate(c.Iat)
	if c.Iat == "" || !ok {
		return nil, invalid("iat is required")
	}
	if iat.After(ex.Now.Add(skew)) {
		return nil, invalid("iat is in the future")
	}
	if ex.Now.Sub(iat) > maxAge {
		return nil, invalid("iat is older than %s", maxAge)
	}
	set := &SET{JTI: c.Jti, Issuer: c.Iss, IssuedAt: iat}
	if c.Exp != nil {
		exp, ok := numericDate(*c.Exp)
		if !ok {
			return nil, invalid("exp is not a valid time")
		}
		if !exp.After(ex.Now) {
			return nil, invalid("the SET has expired")
		}
		set.ExpiresAt = &exp
	}
	if c.Nbf != nil {
		nbf, ok := numericDate(*c.Nbf)
		if !ok || nbf.After(ex.Now.Add(skew)) {
			return nil, invalid("nbf is in the future")
		}
	}
	switch len(c.Events) {
	case 0:
		return nil, invalid("events is required")
	case 1:
	default:
		return nil, invalid("a SET carries exactly one event")
	}
	for uri, body := range c.Events {
		set.EventType = uri
		set.Known = EventName(uri) != ""
		if len(uri) > maxIDBytes {
			set.EventType = uri[:maxIDBytes]
		}
		var payload map[string]any
		d := json.NewDecoder(bytes.NewReader(body))
		d.UseNumber()
		if err := d.Decode(&payload); err != nil {
			return nil, invalid("the event's payload is not a JSON object")
		}
		set.Payload = payload
		set.Subject = subjectOf(payload, c)
	}
	return set, nil
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// subjectOf finds the subject: the event's "subject", else the SET's sub_id,
// else the legacy "sub" claim (an iss_sub of the SET's issuer).
func subjectOf(payload map[string]any, c rawClaims) Subject {
	if v, ok := payload["subject"]; ok {
		return parseSubject(v, 0)
	}
	if len(c.SubID) > 0 {
		var v any
		if json.Unmarshal(c.SubID, &v) == nil {
			return parseSubject(v, 0)
		}
	}
	if c.Sub != "" {
		return parseSubject(map[string]any{"format": "iss_sub", "iss": c.Iss, "sub": c.Sub}, 0)
	}
	return Subject{Problem: "the event names no subject"}
}

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

func parseSubject(v any, depth int) Subject {
	m, ok := v.(map[string]any)
	if !ok {
		return Subject{Problem: "the subject is not an object"}
	}
	format := str(m, "format")
	if format == "" {
		if _, ok := m["user"]; ok {
			format = "complex" // Okta and early drafts omit the format
		}
	}
	s := Subject{Format: truncate(format, 64)}
	need := func(field string) {
		if s.ID = str(m, field); s.ID == "" {
			s.Problem = fmt.Sprintf("the %s subject has no %s", format, field)
		} else if len(s.ID) > maxIDBytes {
			s.ID, s.Problem = "", "the subject identifier is too long"
		}
	}
	switch format {
	case "iss_sub":
		s.Issuer = truncate(str(m, "iss"), maxIDBytes)
		need("sub")
	case "email":
		need("email")
	case "opaque":
		need("id")
	case "account":
		need("uri")
		s.ID = strings.TrimPrefix(s.ID, "acct:")
	case "complex":
		if depth > 0 {
			s.Problem = "a complex subject inside a complex subject"
			break
		}
		if u, ok := m["user"]; ok {
			user := parseSubject(u, depth+1)
			s.User = &user
		} else {
			s.Problem = "the complex subject names no user"
		}
		if sess, ok := m["session"].(map[string]any); ok {
			if s.Session = str(sess, "id"); s.Session == "" {
				s.Session = str(sess, "sub")
			}
			s.Session = truncate(s.Session, maxIDBytes)
		}
	case "":
		s.Problem = "the subject has no format"
	default:
		s.Problem = "unsupported subject format"
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// Label is the subject as one string for the event list (never empty).
func (s Subject) Label() string {
	switch {
	case s.Format == "complex" && s.User != nil:
		l := s.User.Label()
		if s.Session != "" {
			l += " (session " + s.Session + ")"
		}
		return l
	case s.ID != "":
		return truncate(s.ID, maxIDBytes)
	}
	return "(none)"
}
