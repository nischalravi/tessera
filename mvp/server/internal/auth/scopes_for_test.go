package auth_test

import (
	"slices"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
)

func TestScopesFor(t *testing.T) {
	for _, tc := range []struct {
		perm auth.Permission
		want []auth.Scope
	}{
		{auth.PermGraphRead, []auth.Scope{auth.ScopeRead}},
		{auth.PermJITRequest, []auth.Scope{auth.ScopeWrite}},
		{auth.PermAuditRead, []auth.Scope{auth.ScopeAudit}},
		{auth.PermAdminRead, []auth.Scope{auth.ScopeAdmin}},
		{auth.PermEmailDSN, []auth.Scope{auth.ScopeEmailDSN}},
		{auth.PermPolicyGitHubCheck, []auth.Scope{auth.ScopePolicyGitHubCheck}},
		{auth.PermPolicySync, []auth.Scope{auth.ScopePolicySync}},
		{auth.PermConfigPropose, []auth.Scope{auth.ScopeConfigPropose}},
		{auth.PermAuthenticated, []auth.Scope{auth.ScopeRead, auth.ScopeWrite, auth.ScopeAudit, auth.ScopeAdmin, auth.ScopeEmailDSN, auth.ScopePolicyGitHubCheck, auth.ScopePolicySync, auth.ScopeConfigPropose}},
		{auth.Permission("no.such"), nil},
	} {
		if got := auth.ScopesFor(tc.perm); !slices.Equal(got, tc.want) {
			t.Errorf("ScopesFor(%s) = %v, want %v", tc.perm, got, tc.want)
		}
	}
}
