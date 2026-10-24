package worker

import (
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/agent"
)

// TestMapped: only the (scope, target) pairs the job's attr_map lists are
// accepted from an agent's result.
func TestMapped(t *testing.T) {
	m := []agent.AttrMap{{LDAP: "department", Target: "dept", Scope: "identity"}}
	for name, tc := range map[string]struct {
		x    agent.SyncExtra
		want bool
	}{
		"listed":      {agent.SyncExtra{Scope: "identity", Target: "dept", Value: "x"}, true},
		"wrong scope": {agent.SyncExtra{Scope: "account", Target: "dept", Value: "x"}, false},
		"unlisted":    {agent.SyncExtra{Scope: "identity", Target: "admin", Value: "x"}, false},
		"empty map":   {agent.SyncExtra{Scope: "identity", Target: "dept", Value: "x"}, false},
	} {
		in := m
		if name == "empty map" {
			in = nil
		}
		if got := mapped(in, tc.x); got != tc.want {
			t.Errorf("%s: %v", name, got)
		}
	}
}
