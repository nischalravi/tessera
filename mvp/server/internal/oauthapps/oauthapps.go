// Package oauthapps is Tessera's inventory of third-party OAuth apps and the
// grants they hold at Google Workspace, Microsoft Entra ID, Salesforce and
// GitHub (issue #107). Stolen SaaS-to-SaaS tokens (Salesloft Drift, Gainsight,
// UNC6040, Context.ai, Klue) are the reason: the app's grants, not a
// password, are the access.
//
// The package has four parts:
//
//   - Readers (google.go, entra.go, salesforce.go, github.go) read one
//     provider through an internal/safehttp client and return a Snapshot.
//     They are read-only. A reader that fails part-way returns an error and no
//     snapshot, so a failed sync never replaces what was stored.
//   - The risk catalog (risk.go): a versioned table of scope risk, and the
//     0-100 score of an app.
//   - Sync (sync.go): readers run with no transaction open, then Apply writes
//     the snapshots in one transaction (upsert, removal marking, risk, owner,
//     correlation of the granting user, audit).
//   - Revoke (revoke.go): revoke one grant, one app, or every app of a vendor,
//     re-read the provider to verify, and audit. What no API can do is a
//     manual task, never a success.
//
// Credentials are the ones of identity containment (containment_credentials:
// a sealed provider token, a base URL, a GitHub org), so one place holds them.
package oauthapps

import (
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Providers (also the system name of the connection that holds the credential).
const (
	Google     = store.OAuthGoogle
	Entra      = store.OAuthEntra
	Salesforce = store.OAuthSalesforce
	GitHub     = store.OAuthGitHub
)

// Providers lists every provider, in the order a sync runs them.
var Providers = []string{Google, Entra, Salesforce, GitHub}

// Grant kinds.
const (
	KindToken        = "token"        // a user's OAuth token (Google, Salesforce)
	KindDelegated    = "delegated"    // an Entra oauth2PermissionGrant
	KindAppRole      = "app_role"     // an Entra application permission
	KindInstallation = "installation" // a GitHub app installation
	KindCredential   = "credential"   // a GitHub credential authorization
)

// Consent types.
const (
	ConsentUser  = "user"
	ConsentAdmin = "admin"
)

// Limits of one read.
const (
	// MaxPages caps the pages followed for one list.
	MaxPages = 100
	// MaxUsers caps the users whose tokens a Google read lists one by one.
	MaxUsers = 5000
)

// Grant is one grant as a provider reports it.
type Grant struct {
	Key          string // stable per grant at the provider (unique within the app)
	Ref          string // what a revoke names: a grant id, a token id, a user
	Kind         string
	UserRef      string // the provider's reference to the granting user ("" for tenant-wide grants)
	UserEmail    string // the granting user's email or login when known (correlation)
	GranterAdmin bool   // the provider says the granting user is an administrator
	Scopes       []string
	Consent      string // user or admin
	GrantedAt    *time.Time
	LastUsed     *time.Time
}

// App is one app as a provider reports it, with its grants.
type App struct {
	Provider  string
	ClientID  string
	Name      string
	Publisher string
	Verified  bool
	LastUsed  *time.Time
	Grants    []Grant
}

// Snapshot is everything one provider reports. It is complete: a grant that
// is not in it no longer exists at the provider.
type Snapshot struct {
	Provider string
	Apps     []App
	// Notes are things the provider did not offer (for the sync report).
	Notes []string
}

// GrantCount counts the grants of the snapshot.
func (s *Snapshot) GrantCount() int {
	n := 0
	for _, a := range s.Apps {
		n += len(a.Grants)
	}
	return n
}
