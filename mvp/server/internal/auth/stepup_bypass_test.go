package auth

import (
	"net/http"
	"testing"
	"time"
)

func TestCheck_StepUpBypass(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	old := &AuthnContext{AAL: 2, PhishingResistant: true, TesseraACR: ACRPhr, AuthTime: now.Add(-time.Hour)}
	mk := func(kind string, bypass bool, perms RoleSet) (*Principal, *int) {
		n := new(int)
		p := &Principal{Kind: kind, Authn: old, AssignedRoles: perms, ActiveRoles: perms}
		if bypass {
			p.BypassStepUp(func() { *n++ })
		}
		return p, n
	}
	for _, tc := range []struct {
		name   string
		kind   string
		bypass bool
		roles  RoleSet
		status int
		err    string
		used   int
	}{
		{"enforced", KindUser, false, RoleSet{RoleTenantAdmin: true}, http.StatusUnauthorized, "step_up_required", 0},
		{"bypassed", KindUser, true, RoleSet{RoleTenantAdmin: true}, 0, "", 1},
		{"permission still required", KindUser, true, RoleSet{RoleViewer: true}, http.StatusForbidden, "forbidden", 0},
		{"machine client cannot be bypassed", KindAPIClient, true, RoleSet{RoleTenantAdmin: true}, http.StatusForbidden, "interactive_authentication_required", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, used := mk(tc.kind, tc.bypass, tc.roles)
			d := Check(p, PermAdminChangeReq, &StepUpAdmin, now)
			switch {
			case tc.err == "" && d != nil:
				t.Fatalf("denied: %+v", d)
			case tc.err != "" && (d == nil || d.Status != tc.status || d.Error != tc.err):
				t.Fatalf("denial %+v, want %d %s", d, tc.status, tc.err)
			}
			if *used != tc.used {
				t.Errorf("bypass used %d times, want %d", *used, tc.used)
			}
		})
	}
}
