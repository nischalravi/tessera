package policy_test

import (
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

// Issue #542: an AI agent (identity type ai_agent, which is what an agent
// discovered by a connector becomes) that has no owner at all is a finding of
// the existing nhi-ownership policy, not only one whose owner left.
func TestNHIOwnershipFlagsAnAgentWithNoOwner(t *testing.T) {
	st, ids := testkit.Tiny(t)
	pols := testkit.Policies(t)
	testkit.Write(t, st, func(c *store.TenantTx) error {
		return c.UpsertIdentity(&store.Identity{TenantID: st.Tenant, ExternalID: "ownerless-agent", Name: "ownerless-agent",
			Type: "ai_agent", Status: "active", CreatedAt: testkit.Now})
	})
	var found bool
	for _, v := range violations(t, st, "nhi-ownership", pols) {
		if v.IdentityName == "ownerless-agent" && strings.Contains(v.Message, "has no owner") {
			found = true
		}
		if v.IdentityID != nil && *v.IdentityID == ids["helper-bot"] {
			t.Errorf("helper-bot has an active owner but was flagged: %s", v.Message)
		}
	}
	if !found {
		t.Error("an ai_agent with no owner was not flagged by nhi-ownership")
	}
}
