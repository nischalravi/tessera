// Package ghtokens inventories the credentials of a GitHub organization
// (issue #476): fine-grained and classic personal access tokens the
// organization approved, OAuth app tokens (the GitHub CLI among them) and
// Actions secrets. Stolen GitHub CLI OAuth tokens published a malicious
// LiteLLM release, and GhostAction stole CI secrets, so these are non-human
// credentials with an age and an owner that someone has to answer for.
//
// Only metadata is read: a name, an owner login, scopes or permissions and
// dates. The GitHub APIs return no token or secret value, and the structs
// below have no field that could hold one (the partial "last eight" characters
// and fingerprints the credential list offers are not decoded either).
//
//   - Reader (reader.go) reads one organization with the credential of identity
//     containment, through its safehttp client, and returns a complete Snapshot
//     or an error and nothing.
//   - Apply (service.go) stores a complete snapshot; a credential a full read no
//     longer lists is marked removed.
//   - Assess (risk.go) scores a stored credential from its age, expiry, last use,
//     scopes and owner when it is listed.
package ghtokens

import "time"

// System is the connection (and containment credential) the reader uses.
const System = "github"

// Kinds of credential (the values of github_tokens.kind).
const (
	ClassicPAT     = "classic_pat"
	FineGrainedPAT = "fine_grained_pat"
	OAuthAppToken  = "oauth_app_token" // #nosec G101 -- the name of a token kind, not a credential
	ActionsSecret  = "actions_secret"  // #nosec G101 -- the name of a secret kind, not a credential
)

// Kinds lists every kind.
var Kinds = []string{ClassicPAT, FineGrainedPAT, OAuthAppToken, ActionsSecret}

// Limits of one read.
const (
	// MaxPages caps the pages followed for one list; more fails the read, so a
	// partial list never looks like credentials that disappeared.
	MaxPages = 100
	perPage  = 100
)

// Token is one credential as GitHub reports it.
type Token struct {
	Key        string // stable per credential at GitHub
	Kind       string
	Name       string
	OwnerLogin string // "" for an Actions secret: the organization owns it
	Scopes     []string
	Visibility string // Actions secrets: all, private or selected
	CreatedAt  *time.Time
	RotatedAt  *time.Time // Actions secrets: last updated
	ExpiresAt  *time.Time
	LastUsedAt *time.Time
}

// Snapshot is everything one read of the organization reports. It is
// complete: a credential that is not in it no longer exists at GitHub.
type Snapshot struct {
	Tokens []Token
	// Notes are things GitHub did not offer (for the sync report).
	Notes []string
}
