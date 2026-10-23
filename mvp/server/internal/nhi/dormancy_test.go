package nhi_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// The dormancy threshold is the tenant's, per identity type (Admin > Identity rules): a service identity and an AI agent
// that were last used ten days ago are dormant under a 5-day threshold and not under a 30-day one, each by its own type's.
func TestInventoryDormancyIsPerIdentityType(t *testing.T) {
	f := storetest.TwoTenants(t)
	ctx := context.Background()
	if err := f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		ids, err := c.Identities()
		if err != nil {
			return err
		}
		perms, err := c.Permissions()
		if err != nil {
			return err
		}
		var rows []store.UsageEvent
		for _, i := range ids {
			if i.Type == "service" || i.Type == "ai_agent" {
				rows = append(rows, store.UsageEvent{TenantID: f.A.ID, IdentityID: i.ID, PermissionID: perms[0].ID, Day: storetest.Now.Add(-10 * 24 * time.Hour), Count: 1})
			}
		}
		return c.InsertUsageEvents(rows)
	}); err != nil {
		t.Fatal(err)
	}
	dormant := func(service, agent int) (svc, bot bool) {
		t.Helper()
		if err := f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
			return c.PutIdentityRules(&store.IdentityRulesRow{CorrelationOrder: `["external_id","email"]`, Authoritative: `{}`,
				DormantServiceDays: service, DormantAIAgentDays: agent, UpdatedBy: "test"}, storetest.Now)
		}); err != nil {
			t.Fatal(err)
		}
		inv := inventory(t, f, f.A)
		return slices.Contains(inv["svc-etl"].Flags, "dormant"), slices.Contains(inv["Helper "].Flags, "dormant")
	}
	for _, tc := range []struct {
		service, agent int
		svc, bot       bool
	}{
		{5, 5, true, true},
		{30, 5, false, true},
		{5, 30, true, false},
		{30, 30, false, false},
	} {
		if svc, bot := dormant(tc.service, tc.agent); svc != tc.svc || bot != tc.bot {
			t.Errorf("service %d days, agent %d days: svc-etl dormant %v, Helper Bot dormant %v; want %v, %v", tc.service, tc.agent, svc, bot, tc.svc, tc.bot)
		}
	}
}
