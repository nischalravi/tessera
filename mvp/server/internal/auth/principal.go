// Package auth is Tessera's authentication and platform authorization core
// (design docs/design/phase-0-platform-security.md §8, §11, §12):
//
//   - principal.go: Principal and the normalized AuthnContext, and the
//     request-context helpers.
//   - rbac.go: roles, permissions, role activation (admin roles need a
//     phishing-resistant context) and Check/Require.
//   - stepup.go: authentication requirements (StepUpPolicy, StepUpAdmin) and
//     the RFC 9470 challenge (the step-up flow itself lands in PR8).
//   - sessions.go: server-side browser sessions (hash-only storage, idle and
//     absolute expiry, rotation, revocation) and the __Host- cookie.
//   - csrf.go: the session-bound CSRF token and the Origin check.
//   - middleware.go: Authenticator, which resolves the session cookie to a
//     Principal.
//   - normalize/: claims -> AuthnContext mapping per IdP profile.
//   - authtest/: the test-only LoginAs helper.
//
// The principal's tenant comes only from the session row (§14.2), never from
// a header, query parameter or body.
package auth

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/auth/normalize"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// ACR is a Tessera ACR value (design §8.1).
type ACR string

// Tessera ACR values, weakest first.
const (
	ACRAAL1 ACR = normalize.ACRAAL1
	ACRAAL2 ACR = normalize.ACRAAL2
	ACRPhr  ACR = normalize.ACRPhr
	ACRPhrh ACR = normalize.ACRPhrh
)

// Rank orders ACRs (0 for an unknown value, which satisfies nothing).
func (a ACR) Rank() int {
	switch a {
	case ACRAAL1:
		return 1
	case ACRAAL2:
		return 2
	case ACRPhr:
		return 3
	case ACRPhrh:
		return 4
	}
	return 0
}

// ClockSkew is how far in the future an auth_time may be and still count.
const ClockSkew = 60 * time.Second

// AuthnContext is the normalized authentication context of a session
// (immutable; copied by value).
type AuthnContext struct {
	ID                uuid.UUID
	UserID            uuid.UUID
	Protocol          string
	AAL               int
	PhishingResistant bool
	PhrBasis          string
	Methods           []string
	ACR               string // raw IdP value ("" if absent)
	AMR               []string
	TesseraACR        ACR
	AuthTime          time.Time
	IdPConnectionID   *uuid.UUID
	// Device is the device posture the IdP asserted at sign-in (issue #163).
	Device normalize.Device
}

// ContextFromRecord converts a stored record.
func ContextFromRecord(x *store.AuthnContextRecord) AuthnContext {
	c := AuthnContext{ID: x.ID, UserID: x.UserID, Protocol: x.Protocol, AAL: x.AAL, PhishingResistant: x.PhishingResistant,
		PhrBasis: x.PhrBasis, Methods: x.Methods, AMR: x.AMR, TesseraACR: ACR(x.TesseraACR), AuthTime: x.AuthTime,
		IdPConnectionID: x.IdPConnectionID, Device: normalize.ParseDevice(x.Device)}
	if x.ACR != nil {
		c.ACR = *x.ACR
	}
	return c
}

// Age is how long ago the user authenticated.
func (c AuthnContext) Age(now time.Time) time.Duration { return now.Sub(c.AuthTime) }

// Satisfies reports whether the context meets req at now: its ACR ranks at
// least the required one and, when req.MaxAge is set, the authentication is
// no older than MaxAge (and not from the future beyond ClockSkew).
func (c AuthnContext) Satisfies(req AuthnRequirement, now time.Time) bool {
	if c.TesseraACR.Rank() == 0 || c.TesseraACR.Rank() < req.ACR.Rank() {
		return false
	}
	// phr also requires the phishing-resistance flag itself, so a record
	// whose ACR and flag disagree never satisfies a phr requirement.
	if req.ACR.Rank() >= ACRPhr.Rank() && !c.PhishingResistant {
		return false
	}
	age := c.Age(now)
	if age < -ClockSkew {
		return false
	}
	return req.MaxAge <= 0 || age <= req.MaxAge
}

// Principal kinds.
const (
	KindUser      = "user"
	KindAPIClient = "api_client"
)

// Principal is the authenticated caller of a request.
type Principal struct {
	Kind          string // user | api_client
	TenantID      tenancy.ID
	UserID        *uuid.UUID
	ClientID      string
	Display       string
	SessionID     *uuid.UUID
	Authn         *AuthnContext // nil for api_client
	AssignedRoles RoleSet
	ActiveRoles   RoleSet
	// InactiveRoles are assigned roles the current authentication context
	// does not activate, with the reason (design §12.2).
	InactiveRoles map[Role]string
	Scopes        ScopeSet // nil = cookie session (all scopes implicitly)
	Via           string   // cookie | dpop

	csrfSecret string
	session    *store.Session
}

// User returns the principal as a store.UserRef (who did something).
func (p *Principal) User() store.UserRef {
	if p == nil || p.UserID == nil {
		return store.UserRef{}
	}
	return store.UserRef{ID: *p.UserID, Display: p.Display}
}

// Session returns the session row the principal was resolved from (nil for
// token principals).
func (p *Principal) Session() *store.Session { return p.session }

// CSRFToken is the token the browser must echo in X-Tessera-CSRF.
func (p *Principal) CSRFToken() string {
	if p.csrfSecret == "" {
		return ""
	}
	return CSRFToken(p.csrfSecret)
}

// AuditActor is the principal as the audit ledger records it.
func (p *Principal) AuditActor() store.AuditActor {
	typ := store.ActorUser
	if p.Kind == KindAPIClient {
		typ = store.ActorAPIClient
	}
	a := store.AuditActor{Type: typ}
	switch {
	case p.UserID != nil:
		id := p.UserID.String()
		a.ID = &id
	case p.ClientID != "":
		id := p.ClientID
		a.ID = &id
	}
	if p.Display != "" {
		d := p.Display
		a.Display = &d
	}
	return a
}

// AuditAuthn is the authn summary of audit events (§13: ctx id, aal, phr,
// acr, auth_time, auth age), or nil without an authentication context.
func (p *Principal) AuditAuthn(now time.Time) json.RawMessage {
	if p == nil || p.Authn == nil {
		return nil
	}
	c := p.Authn
	id, acr := c.ID.String(), string(c.TesseraACR)
	at := c.AuthTime.UTC().Format("2006-01-02T15:04:05.000000Z")
	aal, phr := c.AAL, c.PhishingResistant
	age := int64(c.Age(now) / time.Second)
	b, err := json.Marshal(store.AuditAuthn{CtxID: &id, AAL: &aal, Phr: &phr, ACR: &acr, AuthTime: &at, AuthAgeS: &age})
	if err != nil {
		return nil
	}
	return b
}

type principalKey struct{}

// WithPrincipal returns ctx carrying p.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// PrincipalFrom returns the request's principal.
func PrincipalFrom(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(*Principal)
	return p, ok && p != nil
}
