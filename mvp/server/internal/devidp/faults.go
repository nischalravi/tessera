package devidp

import (
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Fault makes the dev IdP produce one specific defect so relying-party tests
// can prove it is refused (docs/design/phase-0-platform-security.md §18.5).
// Each fault changes exactly one property of the response; everything else
// stays valid.
type Fault string

// OIDC faults.
const (
	FaultNone            Fault = ""
	FaultWrongIss        Fault = "wrong_iss"            // ID token iss is not the issuer
	FaultWrongAud        Fault = "wrong_aud"            // ID token aud is not the client_id
	FaultAlgNone         Fault = "alg_none"             // unsigned token, alg "none"
	FaultHS256WithPubkey Fault = "hs256_with_pubkey"    // HS256, keyed with the public signing key (alg confusion)
	FaultBadSignature    Fault = "bad_signature"        // RS256 header and kid, signature bytes corrupted
	FaultExpired         Fault = "expired"              // exp well in the past
	FaultFutureIat       Fault = "future_iat"           // iat well in the future
	FaultNonceMismatch   Fault = "nonce_mismatch"       // nonce is not the request's nonce
	FaultMissingAuthTime Fault = "missing_auth_time"    // no auth_time claim
	FaultStaleAuthTime   Fault = "stale_auth_time"      // auth_time a day old, regardless of max_age
	FaultKidUnknown      Fault = "kid_unknown"          // kid not in the JWKS (signature by the real key)
	FaultJKUHeader       Fault = "jku_header"           // jku names an attacker JWKS whose key signed the token under the real kid
	FaultSubChangeStepUp Fault = "sub_change_on_stepup" // another sub on a re-authentication (step-up only)
	FaultACRUnrequested  Fault = "acr_unrequested"      // acr=phr (Entra: acrs=[c1]) although not requested; a normalization defect, not a refusal
	FaultNoIssParam      Fault = "no_iss_param"         // the authorization response has no iss parameter
)

// How far each fault moves its value. The offsets are well outside any
// relying party's clock-skew allowance (§10.4 allows 60 s).
const (
	staleAuthTimeAge = 24 * time.Hour
	expiredAge       = 10 * time.Minute
	futureIatSkew    = 10 * time.Minute
	faultSubSuffix   = "-changed"
	faultAudPrefix   = "wrong-aud-"
	faultIssSuffix   = "/wrong-issuer"
	faultUnknownKid  = "devidp-unknown-kid"
	faultJKUPath     = "/attacker/jwks"
)

// OIDCFaults lists the OIDC faults.
func OIDCFaults() []Fault {
	return []Fault{FaultWrongIss, FaultWrongAud, FaultAlgNone, FaultHS256WithPubkey, FaultBadSignature,
		FaultExpired, FaultFutureIat, FaultNonceMismatch, FaultMissingAuthTime, FaultStaleAuthTime,
		FaultKidUnknown, FaultJKUHeader, FaultSubChangeStepUp, FaultACRUnrequested, FaultNoIssParam}
}

// SAMLFaults lists the SAML faults of §18.5 (saml.go). The design's SAML
// "expired" is named saml_expired here so it cannot be confused with the
// OIDC fault. A SAML fault has no effect on OIDC sign-ins and vice versa.
func SAMLFaults() []Fault {
	return []Fault{FaultUnsignedAssertion, FaultSignedResponseOnly,
		FaultXSW1, FaultXSW2, FaultXSW3, FaultXSW4, FaultXSW5, FaultXSW6, FaultXSW7, FaultXSW8,
		FaultCommentInNameID, FaultWrongAudience, FaultWrongRecipient, FaultSAMLExpired, FaultReplay,
		FaultUnsolicited, FaultWrongInResponseTo}
}

// ParseFault accepts "" (no fault), an OIDC, SAML or GitHub fault name.
func ParseFault(s string) (Fault, error) {
	f := Fault(s)
	if f == FaultNone || slices.Contains(OIDCFaults(), f) || slices.Contains(SAMLFaults(), f) || slices.Contains(GitHubFaults(), f) {
		return f, nil
	}
	return FaultNone, fmt.Errorf("unknown fault %q", s)
}

// handleAttackerJWKS serves the key that signs jku_header fault tokens, at
// the URL their jku header names (faults enabled only).
func (s *Server) handleAttackerJWKS(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key: s.attackerKey.Public(), KeyID: s.kid, Algorithm: string(jose.RS256), Use: "sig"}}})
}
