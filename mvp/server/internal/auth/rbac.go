package auth

import (
	"encoding/json"
	"net/http"
	"slices"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Role is a platform role (design §12.1).
type Role string

// Roles.
const (
	RoleViewer      Role = store.RoleViewer
	RoleOperator    Role = store.RoleOperator
	RoleAuditor     Role = store.RoleAuditor
	RolePolicyAdmin Role = store.RolePolicyAdmin
	RoleTenantAdmin Role = store.RoleTenantAdmin
	RoleBreakGlass  Role = store.RoleBreakGlass
)

// AllRoles lists every role.
func AllRoles() []Role {
	return []Role{RoleViewer, RoleOperator, RoleAuditor, RolePolicyAdmin, RoleTenantAdmin, RoleBreakGlass}
}

// IsAdmin reports whether r is an admin role (phr floor, AAL3-style session
// timeouts, never granted from an IdP group).
func (r Role) IsAdmin() bool {
	return r == RolePolicyAdmin || r == RoleTenantAdmin || r == RoleBreakGlass
}

// Permission is a platform permission (design §12.1; deployment readiness
// §9 adds the connections.* permissions).
type Permission string

// Permissions.
const (
	// PermAuthenticated is held by every authenticated principal, whatever
	// its roles: the session's own routes (/api/auth/session, logout, own
	// sessions) and the API description. It is still a declared permission:
	// such routes are not public.
	PermAuthenticated Permission = "auth.self"

	PermGraphRead         Permission = "graph.read"
	PermJITRequest        Permission = "jit.request"
	PermJITDecide         Permission = "jit.decide"
	PermJITDenyRevoke     Permission = "jit.deny_revoke"
	PermReviewsManage     Permission = "reviews.manage"
	PermReviewsDecide     Permission = "reviews.decide"
	PermHRISSimulateEvent Permission = "hris.simulate_event"
	PermGrantsRevoke      Permission = "grants.revoke"
	PermHRISExecute       Permission = "hris.execute"
	PermJITSweep          Permission = "jit.sweep"
	PermConnectorsSync    Permission = "connectors.sync"
	// PermOwnershipManage assigns owners to applications, entitlements,
	// resources and machine identities (issue #167).
	PermOwnershipManage   Permission = "ownership.manage"
	PermAuditRead         Permission = "audit.read"
	PermAuditVerify       Permission = "audit.verify"
	PermAdminRead         Permission = "admin.read"
	PermAdminChangeReq    Permission = "admin.change.request"
	PermAdminChangeAppr   Permission = "admin.change.approve"
	PermAdminUsersDisable Permission = "admin.users.disable"
	PermAdminSessionsRev  Permission = "admin.sessions.revoke"
	PermBreakGlassRecover Permission = "breakglass.recover"
	// Deployment readiness (docs/design/deployment-readiness.md §9).
	PermConnectionsRead     Permission = "connections.read"
	PermConnectionsManage   Permission = "connections.manage"
	PermConnectionsActivate Permission = "connections.activate"
	// Job run history (issue #172).
	PermJobsRead Permission = "jobs.read"

	// Closed-loop provisioning (issue #103). Configuring a target needs
	// connections.manage; retrying, cancelling and running operations needs
	// provisioning.manage.
	PermProvisioningRead   Permission = "provisioning.read"
	PermProvisioningManage Permission = "provisioning.manage"
	// Config transport between tenants (issue #170).
	PermConfigTransport Permission = "config.transport"
	// account correlation (issue #160)
	PermIdentitiesCorrelate Permission = "identities.correlate"
	PermIdentitiesMerge     Permission = "identities.merge"
	// affiliations of a person (guest accounts design, issue #64)
	PermIdentitiesAffiliate Permission = "identities.affiliate"
	// access requests (issue #164)
	PermRequestsCreate       Permission = "requests.create"
	PermRequestsCreateOthers Permission = "requests.create_for_others"
	PermRequestsDecide       Permission = "requests.decide"
	PermCatalogManage        Permission = "catalog.manage"
	// business roles (issue #161)
	PermRolesManage Permission = "roles.manage"
	// identity lifecycle (issue #159)
	PermLifecycleManage Permission = "lifecycle.manage"
	// guest sponsorships (issue #65): guests.sponsor is anyone who may attempt
	// to sponsor (the sponsor policy decides eligibility), guests.read sees every
	// guest, sponsorships.approve is the second approver.
	PermGuestsSponsor       Permission = "guests.sponsor"
	PermGuestsRead          Permission = "guests.read"
	PermSponsorshipsApprove Permission = "sponsorships.approve"
	// email delivery log (issue #189)
	PermEmailRead   Permission = "email.read"
	PermEmailManage Permission = "email.manage"
	// kill switch (issue #106)
	PermIdentitiesContain Permission = "identities.contain"
	// native groups (issue #44, GR-1): folder and group CRUD. tenant_admin only,
	// until GR-4 brings the per-object privilege model.
	PermGroupsAdmin Permission = "groups.admin"
)

// rolePermissions is the static role -> permission map (Cedar-ready, §12.1).
// tenant_admin deliberately has no data-plane write permission: admins run
// the platform, policy admins change access (separation of duties).
// Everyone but break-glass may request access for themselves; operators
// and policy admins may also request for others and decide (issue #164).
var rolePermissions = map[Role][]Permission{
	RoleViewer: {PermGraphRead, PermRequestsCreate, PermGuestsSponsor},
	RoleOperator: {PermGraphRead, PermJITRequest, PermJITDecide, PermJITDenyRevoke, PermReviewsManage,
		PermReviewsDecide, PermHRISSimulateEvent, PermRequestsCreate, PermRequestsCreateOthers, PermRequestsDecide,
		PermGuestsSponsor, PermGuestsRead, PermJobsRead, PermProvisioningRead, PermOwnershipManage},
	RoleAuditor: {PermGraphRead, PermAuditRead, PermAuditVerify, PermAdminRead, PermConnectionsRead, PermRequestsCreate, PermEmailRead,
		PermGuestsSponsor, PermGuestsRead, PermJobsRead, PermProvisioningRead},
	RolePolicyAdmin: {PermGraphRead, PermJITRequest, PermJITDecide, PermJITDenyRevoke, PermReviewsManage,
		PermReviewsDecide, PermHRISSimulateEvent, PermGrantsRevoke, PermHRISExecute, PermJITSweep, PermConnectorsSync,
		PermIdentitiesCorrelate, PermIdentitiesMerge, PermIdentitiesAffiliate,
		PermRequestsCreate, PermRequestsCreateOthers, PermRequestsDecide, PermCatalogManage, PermRolesManage, PermLifecycleManage,
		PermGuestsSponsor, PermGuestsRead, PermSponsorshipsApprove, PermIdentitiesContain,
		PermJobsRead, PermProvisioningRead, PermProvisioningManage, PermOwnershipManage},
	RoleTenantAdmin: {PermGraphRead, PermAuditRead, PermAuditVerify, PermAdminRead, PermAdminChangeReq,
		PermAdminChangeAppr, PermAdminUsersDisable, PermAdminSessionsRev, PermConnectionsRead, PermConnectionsManage,
		PermConnectionsActivate, PermRequestsCreate, PermEmailRead, PermEmailManage, PermGuestsSponsor, PermGuestsRead, PermGroupsAdmin,
		PermJobsRead, PermProvisioningRead, PermProvisioningManage, PermConfigTransport},
	RoleBreakGlass: {PermAdminRead, PermBreakGlassRecover},
}

// RolePermissions returns a copy of the permissions of r.
func RolePermissions(r Role) []Permission { return slices.Clone(rolePermissions[r]) }

// AllPermissions lists every permission granted by some role, plus PermAuthenticated.
func AllPermissions() []Permission {
	seen := map[Permission]bool{PermAuthenticated: true}
	out := []Permission{PermAuthenticated}
	for _, r := range AllRoles() {
		for _, p := range rolePermissions[r] {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	return out
}

// RoleSet is a set of roles.
type RoleSet map[Role]bool

// Has reports membership.
func (s RoleSet) Has(r Role) bool { return s[r] }

// Sorted lists the roles in AllRoles order.
func (s RoleSet) Sorted() []Role {
	var out []Role
	for _, r := range AllRoles() {
		if s[r] {
			out = append(out, r)
		}
	}
	return out
}

// HasAdmin reports whether the set holds an admin role.
func (s RoleSet) HasAdmin() bool {
	for r := range s {
		if s[r] && r.IsAdmin() {
			return true
		}
	}
	return false
}

// PermissionSet is a set of permissions.
type PermissionSet map[Permission]bool

// Has reports membership.
func (s PermissionSet) Has(p Permission) bool { return s[p] }

// Sorted lists the permissions in AllPermissions order.
func (s PermissionSet) Sorted() []Permission {
	var out []Permission
	for _, p := range AllPermissions() {
		if s[p] {
			out = append(out, p)
		}
	}
	return out
}

// Scope is an OAuth scope of a token principal (§12.3, PR10).
type Scope string

// ScopeSet is a set of scopes; nil means a cookie session (every scope).
type ScopeSet map[Scope]bool

// Scopes and what they cover (§12.3).
const (
	ScopeRead  Scope = "tessera:read"
	ScopeWrite Scope = "tessera:write"
	ScopeAudit Scope = "tessera:audit"
	ScopeAdmin Scope = "tessera:admin"
)

var scopePermissions = map[Scope][]Permission{
	ScopeRead: {PermGraphRead, PermConnectionsRead, PermJobsRead, PermProvisioningRead},
	ScopeWrite: {PermJITRequest, PermJITDecide, PermJITDenyRevoke, PermReviewsManage, PermReviewsDecide,
		PermHRISSimulateEvent, PermGrantsRevoke, PermHRISExecute, PermJITSweep, PermConnectorsSync,
		PermConnectionsManage, PermConnectionsActivate, PermRolesManage, PermLifecycleManage, PermGroupsAdmin, PermProvisioningManage, PermOwnershipManage},
	ScopeAudit: {PermAuditRead, PermAuditVerify},
	ScopeAdmin: {PermEmailRead, PermEmailManage, PermAdminRead, PermAdminChangeReq, PermAdminChangeAppr, PermAdminUsersDisable, PermAdminSessionsRev,
		PermBreakGlassRecover, PermConfigTransport},
}

// perms returns the union of the roles' permissions.
func perms(roles RoleSet) PermissionSet {
	out := PermissionSet{}
	for r, ok := range roles {
		if !ok {
			continue
		}
		for _, p := range rolePermissions[r] {
			out[p] = true
		}
	}
	return out
}

// EffectivePermissions is perms(active roles) ∩ perms(scopes), plus
// PermAuthenticated for any principal (§12.3). Cookie principals have every
// scope implicitly.
func EffectivePermissions(p *Principal) PermissionSet {
	if p == nil {
		return PermissionSet{}
	}
	out := perms(p.ActiveRoles)
	if p.Scopes != nil {
		allowed := PermissionSet{}
		for s, ok := range p.Scopes {
			if !ok {
				continue
			}
			for _, perm := range scopePermissions[s] {
				allowed[perm] = true
			}
		}
		for perm := range out {
			if !allowed[perm] {
				delete(out, perm)
			}
		}
	}
	out[PermAuthenticated] = true
	return out
}

// ---------------------------------------------------------------- role activation

// Reasons a role is inactive.
const (
	InactiveNeedsPhr      = "phishing_resistant_authentication_required"
	InactiveNeedsAAL2     = "multi_factor_authentication_required"
	InactiveNeedsWebAuthn = "break_glass_key_required"
)

// ActivationSettings are the tenant settings that move role floors (§18.3).
type ActivationSettings struct {
	RequirePhrForAll bool // require_phr_for_all: raises the floor of every role to phr
}

// TenantSettings reads the activation settings from a tenant's settings
// JSON (Tenant.Settings, §18.3). Keys other PRs own are ignored. Settings
// that cannot be read fail closed: the strictest floors apply, so a damaged
// row never lowers what a role needs.
func TenantSettings(raw string) ActivationSettings {
	strict := ActivationSettings{RequirePhrForAll: true}
	if raw == "" {
		return ActivationSettings{}
	}
	var v map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &v); err != nil || v == nil {
		return strict
	}
	var s ActivationSettings
	if b, ok := v["require_phr_for_all"]; ok {
		if err := json.Unmarshal(b, &s.RequirePhrForAll); err != nil {
			return strict
		}
	}
	return s
}

// RoleFloor is the AuthnContext a role needs to be active (§12.2).
func RoleFloor(r Role, s ActivationSettings) AuthnRequirement {
	switch {
	case r == RoleBreakGlass:
		return AuthnRequirement{ACR: ACRPhrh}
	case r.IsAdmin() || s.RequirePhrForAll:
		return AuthnRequirement{ACR: ACRPhr}
	}
	return AuthnRequirement{ACR: ACRAAL2}
}

// ActivateRoles splits assigned roles into active and inactive under the
// session's current authentication context (§12.2). An admin role is
// active only when the context is phishing-resistant; break_glass only for
// a WebAuthn-attested AAL3 context. Floors have no max_age: freshness is a
// step-up requirement of individual routes, not of role activation.
func ActivateRoles(assigned RoleSet, ctx *AuthnContext, s ActivationSettings, now time.Time) (RoleSet, map[Role]string) {
	active, inactive := RoleSet{}, map[Role]string{}
	for _, r := range assigned.Sorted() {
		floor := RoleFloor(r, s)
		ok := ctx != nil && ctx.Satisfies(floor, now)
		if r == RoleBreakGlass {
			ok = ok && ctx.Protocol == "webauthn" && ctx.PhrBasis == "webauthn_attested" && ctx.AAL >= 3
		}
		switch {
		case ok:
			active[r] = true
		case r == RoleBreakGlass:
			inactive[r] = InactiveNeedsWebAuthn
		case floor.ACR == ACRPhr:
			inactive[r] = InactiveNeedsPhr
		default:
			inactive[r] = InactiveNeedsAAL2
		}
	}
	return active, inactive
}

// AssignedRoles collects the unexpired role assignments.
func AssignedRoles(as []*store.RoleAssignment, now time.Time) RoleSet {
	out := RoleSet{}
	for _, a := range as {
		if a.ExpiresAt != nil && !now.Before(*a.ExpiresAt) {
			continue
		}
		r := Role(a.Role)
		if slices.Contains(AllRoles(), r) {
			out[r] = true
		}
	}
	return out
}

// ---------------------------------------------------------------- authorization

// Denial is why Check refused a request: the HTTP status and the error code
// of the design's error contract (§16.2).
type Denial struct {
	Status      int
	Error       string // login_required | forbidden | role_inactive | interactive_authentication_required | step_up_required
	Permission  Permission
	Requirement *AuthnRequirement
}

// Check decides whether p may use a route that declares perm and authn
// (nil: no step-up requirement). nil means allowed.
func Check(p *Principal, perm Permission, authn *AuthnRequirement, now time.Time) *Denial {
	if p == nil {
		return &Denial{Status: http.StatusUnauthorized, Error: "login_required"}
	}
	if perm == "" { // a route without a declared permission never runs
		return &Denial{Status: http.StatusForbidden, Error: "forbidden"}
	}
	if !EffectivePermissions(p).Has(perm) {
		if perms(p.AssignedRoles).Has(perm) {
			return &Denial{Status: http.StatusForbidden, Error: "role_inactive", Permission: perm}
		}
		return &Denial{Status: http.StatusForbidden, Error: "forbidden", Permission: perm}
	}
	if authn != nil {
		if p.Kind == KindAPIClient {
			return &Denial{Status: http.StatusForbidden, Error: "interactive_authentication_required", Permission: perm}
		}
		if p.Authn == nil || !p.Authn.Satisfies(*authn, now) {
			req := *authn
			return &Denial{Status: http.StatusUnauthorized, Error: "step_up_required", Permission: perm, Requirement: &req}
		}
	}
	return nil
}

// Require is Check as net/http middleware (design §12.4). The API's router
// calls Check directly for every route it registers.
func Require(perm Permission, authn *AuthnRequirement, now func() time.Time) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, _ := PrincipalFrom(r.Context())
			if d := Check(p, perm, authn, now()); d != nil {
				WriteDenial(w, d)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
