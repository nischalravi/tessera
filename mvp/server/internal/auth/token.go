package auth

import (
	"errors"
	"net/http"
	"slices"
	"time"

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
	// Machine is a client-credentials token (§9.5): no user and no session;
	// ClientRowID is the api_clients row its sub names. Bound is whether it is
	// DPoP-bound (a machine client may be configured without DPoP; a user's
	// token is always bound).
	Machine     bool
	Bound       bool
	ClientRowID uuid.UUID
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

// MachineRolesDenied is why a machine client's admin role is inactive.
const MachineRolesDenied = "machine_clients_cannot_hold_admin_roles"

// MachineRoles reads a machine client's configured roles (§9.5): the known
// roles are assigned, and only the non-admin ones are active. A client row
// that holds an admin role (it cannot be created that way) gets nothing from
// it, so the rule does not depend on how the row was written.
func MachineRoles(configured []string) (assigned, active RoleSet, inactive map[Role]string) {
	assigned, active, inactive = RoleSet{}, RoleSet{}, map[Role]string{}
	for _, name := range configured {
		r := Role(name)
		if !slices.Contains(AllRoles(), r) {
			continue
		}
		assigned[r] = true
		if r.IsAdmin() {
			inactive[r] = MachineRolesDenied
		} else {
			active[r] = true
		}
	}
	return assigned, active, inactive
}

// authenticateMachine builds the principal of a client-credentials token
// (§9.5, §12.3): the client must still be an active machine client, its roles
// are read now (so removing one takes effect at once), and its scopes are the
// token's narrowed to what the client may still be granted. effective =
// perms(roles) ∩ perms(scopes), exactly as for a user.
func (a *Authenticator) authenticateMachine(r *http.Request, vt *VerifiedToken) (*Principal, *Failure, error) {
	var p *Principal
	var reason string
	err := a.DB.ReadTenant(r.Context(), vt.Tenant.ID, func(tx *store.TenantTx) error {
		cl, err := tx.APIClientByClientID(vt.ClientID)
		if err != nil {
			return err
		}
		if cl.ID != vt.ClientRowID || cl.Kind != store.ClientMachine || cl.Status != store.ClientActive {
			reason = FailClientDisabled
			return nil
		}
		assigned, active, inactive := MachineRoles(cl.Roles)
		var scopes []string
		for _, s := range vt.Scopes {
			if slices.Contains(cl.AllowedScopes, s) {
				scopes = append(scopes, s)
			}
		}
		via := ViaDPoP
		if !vt.Bound {
			via = ViaBearer
		}
		// a client made before the creator check (issue #509), or whose approver has since lost a role, must not do what
		// its approver cannot (issue #522)
		missing, err := ClientExceedsApprover(tx, cl, scopes, a.Clock().UTC())
		if err != nil {
			return err
		}
		if len(missing) > 0 {
			reason = FailClientExceedsApprover
			return nil
		}
		p = &Principal{Kind: KindAPIClient, TenantID: vt.Tenant.ID, ClientID: cl.ClientID, Display: cl.Name,
			AssignedRoles: assigned, ActiveRoles: active, InactiveRoles: inactive, Scopes: ScopeSetOf(scopes), Via: via}
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return nil, &Failure{Reason: FailClientDisabled, Challenge: `DPoP error="invalid_token"`}, nil
	}
	if err != nil {
		return nil, nil, err
	}
	if p == nil {
		return nil, &Failure{Reason: reason, Challenge: `DPoP error="invalid_token"`}, nil
	}
	return p, nil, nil
}

// ScopeSetOf converts token scopes to a ScopeSet, dropping unknown scopes.
// The result is never nil: a token principal with no known scope has no
// permission beyond PermAuthenticated.
func ScopeSetOf(scopes []string) ScopeSet {
	out := ScopeSet{}
	for _, s := range scopes {
		switch sc := Scope(s); sc {
		case ScopeRead, ScopeWrite, ScopeAudit, ScopeAdmin, ScopeEmailDSN, ScopePolicyGitHubCheck, ScopeConfigPropose:
			out[sc] = true
		}
	}
	return out
}

// ClientExceedsApprover lists the permissions a machine client would hold with these scopes (perms(roles) ∩
// perms(scopes), the rule of its token principal) that the person who vouched for it does not hold now (issue #522).
// #509 refuses such a client at creation and key rotation, against the signed-in admin, and records that admin in
// ApprovedBy; this is the check at every token and request, so an approver who lost a role, or left, also takes the
// client's extra permissions away, and so is a client made before #509. The approver is the user in ApprovedBy (their
// assigned roles, step-up or not; none at all when the user is gone or disabled). A client made with the CLI
// (ApprovedByOperator) is the operator's call and passes. A client with no approver on record (made before this was
// recorded) is held to its owner's permissions, which re-keying it by an admin who holds them, or giving the owner the
// roles, sets right.
func ClientExceedsApprover(tx *store.TenantTx, cl *store.APIClient, scopes []string, now time.Time) ([]string, error) {
	who := cl.OwnerUserID
	switch cl.ApprovedBy {
	case store.ApprovedByOperator:
		return nil, nil
	case "":
	default:
		id, err := uuid.Parse(cl.ApprovedBy)
		if err != nil {
			return nil, nil
		}
		who = &id
	}
	if who == nil {
		return nil, nil
	}
	_, active, _ := MachineRoles(cl.Roles)
	want := EffectivePermissions(&Principal{ActiveRoles: active, Scopes: ScopeSetOf(scopes)})
	// config.propose is vouched for by its own two-admin grant (api_client.propose.grant), not by what one approver holds
	delete(want, PermConfigPropose)
	have := PermissionSet{PermAuthenticated: true}
	u, err := tx.PlatformUser(*who)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	if err == nil && u.Status == "active" {
		as, err := tx.RoleAssignments(u.ID)
		if err != nil {
			return nil, err
		}
		have = EffectivePermissions(&Principal{ActiveRoles: AssignedRoles(as, now)})
	}
	var missing []string
	for _, p := range want.Sorted() {
		if !have.Has(p) {
			missing = append(missing, string(p))
		}
	}
	return missing, nil
}
