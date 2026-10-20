package auth_test

import (
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
)

// TestMachineRoles: a machine client's configured roles (§9.5): unknown names
// are dropped, admin roles are assigned but never active, whatever the row says.
func TestMachineRoles(t *testing.T) {
	tests := []struct {
		name     string
		in       []string
		assigned []auth.Role
		active   []auth.Role
		inactive []auth.Role
	}{
		{"none", nil, nil, nil, nil},
		{"non-admin roles", []string{"viewer", "operator", "auditor"},
			[]auth.Role{auth.RoleViewer, auth.RoleOperator, auth.RoleAuditor},
			[]auth.Role{auth.RoleViewer, auth.RoleOperator, auth.RoleAuditor}, nil},
		{"admin roles are inactive", []string{"tenant_admin", "policy_admin", "break_glass", "viewer"},
			[]auth.Role{auth.RoleViewer, auth.RolePolicyAdmin, auth.RoleTenantAdmin, auth.RoleBreakGlass},
			[]auth.Role{auth.RoleViewer}, []auth.Role{auth.RolePolicyAdmin, auth.RoleTenantAdmin, auth.RoleBreakGlass}},
		{"unknown and empty names", []string{"root", "", "VIEWER"}, nil, nil, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assigned, active, inactive := auth.MachineRoles(tc.in)
			if !sameRoles(assigned.Sorted(), tc.assigned) || !sameRoles(active.Sorted(), tc.active) || len(inactive) != len(tc.inactive) {
				t.Errorf("assigned %v active %v inactive %v", assigned.Sorted(), active.Sorted(), inactive)
			}
			for _, r := range tc.inactive {
				if inactive[r] != auth.MachineRolesDenied {
					t.Errorf("%s: reason %q", r, inactive[r])
				}
			}
		})
	}
}

func sameRoles(a, b []auth.Role) bool {
	if len(a) != len(b) {
		return false
	}
	have := map[auth.Role]bool{}
	for _, r := range a {
		have[r] = true
	}
	for _, r := range b {
		if !have[r] {
			return false
		}
	}
	return true
}

// TestMachinePrincipalIdentity: a machine principal is attributed to its
// client, has no user id, and is a token principal.
func TestMachinePrincipalIdentity(t *testing.T) {
	p := &auth.Principal{Kind: auth.KindAPIClient, ClientID: "tsc_x", Display: "ETL", Via: auth.ViaBearer}
	if a := p.AuditActor(); a.Type != "api_client" || a.ID == nil || *a.ID != "tsc_x" || a.Display == nil || *a.Display != "ETL" {
		t.Errorf("actor %+v", a)
	}
	if u := p.User(); u.Display != "ETL" || u.ID.String() != "00000000-0000-0000-0000-000000000000" {
		t.Errorf("user ref %+v", u)
	}
	if !p.IsToken() || (&auth.Principal{Via: auth.ViaCookie}).IsToken() || !(&auth.Principal{Via: auth.ViaDPoP}).IsToken() {
		t.Error("IsToken")
	}
	if ap := p.AuditAuthn(time.Unix(1_800_000_000, 0)); ap != nil {
		t.Errorf("a machine principal has no authentication context: %s", ap)
	}
}
