package auth

import (
	"net/http"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// The DPoP token principal path (design §10.4, §12.4, PR10). The Authenticator
// does not parse tokens itself: internal/oauth verifies the access token and
// its DPoP proof (it imports this package, so the dependency is an interface)
// and this package then loads the live session, user and roles, exactly as it
// does for the cookie, and builds the Principal. Roles are never read from the
// token: removing a role takes effect on the next request (§10.1).

// Reasons a token authentication failed (the anonymous_reason of the
// request's http.request event; the client only sees 401 login_required with
// a WWW-Authenticate challenge).
const (
	FailInvalidToken = "invalid_token"
	FailInvalidDPoP  = "invalid_dpop_proof"
	FailDPoPNonce    = "use_dpop_nonce"
)

// VerifiedToken is an access token whose signature, claims and DPoP proof were
// checked against its tenant's keys. The session it names is not yet checked.
type VerifiedToken struct {
	Tenant    store.Tenant
	UserID    uuid.UUID
	SessionID uuid.UUID
	ClientID  string
	Scopes    []string
}

// TokenFailure is why a token was refused: the reason for the audit event,
// the WWW-Authenticate value of the 401 and, for use_dpop_nonce, the nonce
// the client must use (sent in DPoP-Nonce).
type TokenFailure struct {
	Reason    string
	Challenge string
	Nonce     string
}

// TokenVerifier verifies the Authorization: DPoP credentials of a request.
// err is set only when the check could not be made (the database failed): the
// caller fails closed with 500.
type TokenVerifier interface {
	VerifyAccessToken(r *http.Request) (*VerifiedToken, *TokenFailure, error)
}

// Failure is why a request is not authenticated.
type Failure struct {
	// Reason is FailNoSession, ..., or a token failure.
	Reason string
	// Challenge is the WWW-Authenticate value of a refused token ("" for a
	// cookie failure); Nonce goes in the DPoP-Nonce header when set.
	Challenge string
	Nonce     string
}

// ScopeSetOf converts token scopes to a ScopeSet, dropping unknown scopes.
// The result is never nil: a token principal with no known scope has no
// permission beyond PermAuthenticated.
func ScopeSetOf(scopes []string) ScopeSet {
	out := ScopeSet{}
	for _, s := range scopes {
		switch sc := Scope(s); sc {
		case ScopeRead, ScopeWrite, ScopeAudit, ScopeAdmin:
			out[sc] = true
		}
	}
	return out
}
