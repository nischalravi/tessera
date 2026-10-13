// Package credential is where a guest's credential lives (guest accounts design
// §7.1, issue #69): Tessera orchestrates, the credential authority holds the
// secret. An Authority makes the guest known to an identity provider so the
// claim can send them to its sign-in; the claim completes only after a
// sign-in at the required assurance level through that authority (the
// callback checks it), never because the authority was merely asked.
//
// This release ships one implementation, DevIdP, for development and tests:
// it registers the guest with the dev IdP at runtime (a dev-only endpoint of
// internal/devidp, reached over HTTP: the API never imports the dev IdP).
// Customer IdP activation (Okta, Entra, Google, LDAP), home-IdP federation and
// the Tessera-hosted service are GU-8. With no authority configured the claim
// stops at the credential step and stays pending.
package credential

import (
	"context"
	"errors"
)

// Guest is the person to set up at the authority.
type Guest struct {
	Tenant string // tenant slug
	// Ref is a stable, opaque reference to the person (their external id's
	// uuid): the authority derives the account's subject from it, so
	// registering twice is the same account.
	Ref   string
	Email string
	Name  string
}

// Connection is how to reach the authority: the tenant's identity-provider
// connection, with its client secret opened for this one call.
type Connection struct {
	Issuer       string
	ClientID     string
	ClientSecret string
}

// Registration is what the authority made of the guest.
type Registration struct {
	// Subject is the identifier the authority will assert for the guest at
	// sign-in. The claim completes only for exactly this subject.
	Subject string
	// LoginHint preselects the guest at the authority's sign-in page.
	LoginHint string
}

// Authority is a place a guest's credential can live.
type Authority interface {
	// Kind names the authority (recorded in the audit event).
	Kind() string
	// Profile is the identity-provider connection profile the authority
	// manages: the claim signs the guest in through the tenant's active
	// OIDC connection with this profile.
	Profile() string
	// Register makes the guest known to the authority and returns the
	// subject it will assert and the login hint.
	Register(ctx context.Context, c Connection, g Guest) (Registration, error)
}

// ErrUnavailable is returned when the authority cannot be reached or refuses.
var ErrUnavailable = errors.New("credential: authority unavailable")
