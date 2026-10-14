// Package containment is Tessera's kill switch for an identity: it revokes
// live IdP sessions and refresh tokens, and OAuth consents and similar
// credentials, at the providers (Okta, Microsoft Entra, Google Workspace,
// GitHub), then re-reads each provider to prove nothing is left.
//
// A leaver plan, the "contain identity" action and an agent kill switch all
// use the same two steps, revoke_sessions and revoke_grants. The rules:
//
//   - Fail closed. A provider that rejects a call, a user the provider does
//     not know, a call that is still rate limited after its retries, or a
//     verification that still finds a session or a grant fails the step. It is
//     never reported as done.
//   - Never claim what was not done. With no live credential for a connection,
//     or for what no API can revoke (GitHub PATs and SSH keys), the step is a
//     manual task with instructions, not a success.
//   - Every outbound call goes through an internal/safehttp client.
//   - Provider tokens are sealed at rest (internal/seal) and never logged or
//     put in a report; error text carries the method, path and status only.
package containment

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"
)

// The containment steps (also the plan step actions of internal/jml).
const (
	ActionRevokeSessions = "revoke_sessions"
	ActionRevokeGrants   = "revoke_grants"
)

// Providers, by the system name of an account.
const (
	Okta   = "okta"
	Entra  = "entra"
	Google = "google"
	GitHub = "github"
)

// SessionCapable reports whether system is an IdP whose sessions and refresh
// tokens Tessera can revoke.
func SessionCapable(system string) bool {
	return system == Okta || system == Entra || system == Google
}

// GrantCapable reports whether system has OAuth consents or credential
// authorizations Tessera can revoke.
func GrantCapable(system string) bool { return SessionCapable(system) || system == GitHub }

// Target is one account to contain at one provider.
type Target struct {
	System   string // okta, entra, google, github
	UserID   string // Okta and Entra user id, Google userKey (email or id), GitHub login
	Username string // for reports
}

var userIDRE = regexp.MustCompile(`^[A-Za-z0-9._@+:-]{1,254}$`)

// ErrBadTarget: the provider user id is empty or has characters no provider id has.
var ErrBadTarget = errors.New("containment: invalid provider user id")

func (t Target) check() error {
	if !userIDRE.MatchString(t.UserID) {
		return ErrBadTarget
	}
	return nil
}

// Outcome is what one revoke call did.
type Outcome struct {
	Revoked int      // sessions, tokens or grants the provider confirmed revoked (a call that cannot count reports 1)
	Manual  []string // what no API can revoke, as instructions for a person
}

// Check selects what Verify re-reads.
type Check uint8

// Verify scopes.
const (
	CheckSessions Check = 1 << iota
	CheckGrants
)

// Remaining is what a provider still shows after a revoke.
type Remaining struct {
	Sessions   int      // live sessions or refresh tokens still found
	Grants     int      // OAuth consents or credential authorizations still found
	Unverified []string // what the provider offers no read API for (reported, never silently counted as clean)
}

// Revoker revokes and verifies one provider. Every method is idempotent.
type Revoker interface {
	RevokeSessions(ctx context.Context, t Target) (Outcome, error)
	RevokeGrants(ctx context.Context, t Target) (Outcome, error)
	// Verify re-reads the provider. since is when the revoke started: a
	// provider that stamps a "sessions valid from" time (Entra) must show one
	// at or after it (less a small clock skew).
	Verify(ctx context.Context, t Target, since time.Time, c Check) (Remaining, error)
}

// Credential is what a revoker needs to call a provider. Token is a bearer
// token (Okta: an API token, sent as SSWS).
type Credential struct {
	BaseURL string // provider API origin; defaults per provider (Okta has none: required)
	Org     string // GitHub organization
	Token   string
}

// ErrNotFound: the provider does not know the user. The step fails: a stale
// or wrong external id must not look like a clean leaver.
var ErrNotFound = errors.New("containment: provider does not know the user")

// ErrRateLimited: the provider still answered 429 after the retries.
var ErrRateLimited = errors.New("containment: provider rate limit, retries exhausted")

// StatusError is a provider's refusal. It carries no response body.
type StatusError struct {
	Method, Path string
	Status       int
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("provider answered %d to %s %s", e.Status, e.Method, e.Path)
}
