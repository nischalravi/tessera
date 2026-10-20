package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// agentFixture seeds both tenants with an agent of the same name and an
// enrolment code each. Tenant B's rows carry the readiness sentinel.
type agentFixture struct {
	f                     *storetest.Fixture
	aAgent, bAgent        string
	aEnrol, bEnrol        string
	aHash, bHash          string
	aPin, bPin            string
	enrolExpiry, issuedAt time.Time
}

func hex64(c string) string { return strings.Repeat(c, 64) }

func seedAgents(t *testing.T) *agentFixture {
	t.Helper()
	x := &agentFixture{f: storetest.TwoTenants(t), aAgent: store.NewID(), bAgent: store.NewID(), aEnrol: store.NewID(),
		bEnrol: store.NewID(), aHash: hex64("a"), bHash: hex64("b"), aPin: hex64("1"), bPin: hex64("2")}
	x.issuedAt = storetest.Now
	x.enrolExpiry = storetest.Now.Add(15 * time.Minute)
	ctx := context.Background()
	for _, s := range []struct {
		tn                  storetest.Tenant
		agent, enrol, token string
		by                  string
	}{
		{x.f.A, x.aAgent, x.aEnrol, x.aHash, "admin-a"},
		{x.f.B, x.bAgent, x.bEnrol, x.bHash, "admin-b-" + storetest.ReadinessSentinel},
	} {
		if err := x.f.DB.InTenant(ctx, s.tn.ID, func(c *store.TenantTx) error {
			// the same name in both tenants is fine
			if err := c.InsertDirectoryAgent(&store.DirectoryAgent{ID: s.agent, Name: "dc-agent", CreatedBy: s.by,
				CreatedAt: x.issuedAt}); err != nil {
				return err
			}
			return c.InsertAgentEnrolment(&store.AgentEnrolment{ID: s.enrol, AgentID: s.agent, TokenHash: s.token,
				ExpiresAt: x.enrolExpiry, CreatedBy: s.by, CreatedAt: x.issuedAt})
		}); err != nil {
			t.Fatal(err)
		}
	}
	return x
}

// TestIsolation_DirectoryAgents: agents and their enrolment codes are scoped
// to the tenant. A cannot read, activate, touch, revoke or consume B's rows
// (all answer as if they did not exist), a name is unique per tenant only,
// the two hash lookups return the owning tenant, and a code or key pin is
// unique across tenants.
func TestIsolation_DirectoryAgents(t *testing.T) {
	x := seedAgents(t)
	f, ctx := x.f, context.Background()
	tel := store.AgentTelemetry{Hostname: "h", OS: "linux", Version: "0.1.0", AllowlistHash: hex64("c")}

	inA(t, f, func(c *store.TenantTx) error {
		list, err := c.DirectoryAgents()
		if err != nil || len(list) != 1 || list[0].ID != x.aAgent {
			t.Errorf("A's agents: %v %v", list, err)
		}
		if _, err := c.DirectoryAgent(x.bAgent); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("B's agent read as A: %v", err)
		}
		if _, err := c.AgentEnrolment(x.bEnrol); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("B's enrolment read as A: %v", err)
		}
		if err := c.InsertDirectoryAgent(&store.DirectoryAgent{ID: store.NewID(), Name: "dc-agent", CreatedBy: "x",
			CreatedAt: x.issuedAt}); !errors.Is(err, store.ErrDuplicate) {
			t.Errorf("duplicate name in one tenant: %v", err)
		}
		// writes naming B's rows change nothing
		if err := c.ActivateDirectoryAgent(x.bAgent, hex64("9"), tel, x.issuedAt); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("activate B's agent as A: %v", err)
		}
		if err := c.ConsumeAgentEnrolment(x.bEnrol, x.issuedAt); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("consume B's code as A: %v", err)
		}
		if err := c.RevokeDirectoryAgent(x.bAgent, "a", x.issuedAt); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("revoke B's agent as A: %v", err)
		}
		// an enrolment may not name another tenant's agent (cross-tenant trigger)
		if err := c.InsertAgentEnrolment(&store.AgentEnrolment{ID: store.NewID(), AgentID: x.bAgent, TokenHash: hex64("d"),
			ExpiresAt: x.enrolExpiry, CreatedBy: "a", CreatedAt: x.issuedAt}); err == nil ||
			!strings.Contains(err.Error(), "cross-tenant") {
			t.Errorf("enrolment for B's agent as A: %v", err)
		}
		return nil
	})
	if err := f.DB.ReadTenant(ctx, f.B.ID, func(c *store.TenantTx) error {
		a, err := c.DirectoryAgent(x.bAgent)
		if err != nil || a.Status != store.AgentPending || a.CertPin != "" || a.RevokedAt != nil {
			t.Errorf("B's agent after A's attempts: %+v %v", a, err)
		}
		e, err := c.AgentEnrolment(x.bEnrol)
		if err != nil || e.ConsumedAt != nil {
			t.Errorf("B's code after A's attempts: %+v %v", e, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// lookups return the owning tenant, and nothing for an unknown hash
	if err := f.DB.ReadSystem(ctx, "agent lookup test", func(s *store.SystemTx) error {
		tid, id, err := s.LookupAgentEnrolmentByTokenHash(x.bHash)
		if err != nil || tid != f.B.ID || id.String() != x.bEnrol {
			t.Errorf("code lookup: %v %v %v", tid, id, err)
		}
		if _, id, err := s.LookupAgentEnrolmentByTokenHash(hex64("e")); !errors.Is(err, store.ErrNotFound) || id != uuid.Nil {
			t.Errorf("unknown code: %v %v", id, err)
		}
		if _, _, err := s.LookupDirectoryAgentByCertPin(x.aPin); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("pin before enrolment: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// each tenant activates its own agent; the pin resolves to its tenant
	for _, s := range []struct {
		tn         storetest.Tenant
		agent, pin string
	}{{f.A, x.aAgent, x.aPin}, {f.B, x.bAgent, x.bPin}} {
		if err := f.DB.InTenant(ctx, s.tn.ID, func(c *store.TenantTx) error {
			return c.ActivateDirectoryAgent(s.agent, s.pin, tel, x.issuedAt)
		}); err != nil {
			t.Fatal(err)
		}
	}
	// a key pinned to one agent cannot be pinned to another, even across tenants
	other := store.NewID()
	inA(t, f, func(c *store.TenantTx) error {
		if err := c.InsertDirectoryAgent(&store.DirectoryAgent{ID: other, Name: "second", CreatedBy: "a", CreatedAt: x.issuedAt}); err != nil {
			return err
		}
		return nil
	})
	if err := f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		if err := c.ActivateDirectoryAgent(other, x.bPin, tel, x.issuedAt); !errors.Is(err, store.ErrDuplicate) {
			t.Errorf("B's key pinned to a second agent: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.DB.ReadSystem(ctx, "agent lookup test", func(s *store.SystemTx) error {
		for _, w := range []struct {
			pin string
			tn  storetest.Tenant
			id  string
		}{{x.aPin, f.A, x.aAgent}, {x.bPin, f.B, x.bAgent}} {
			tid, id, err := s.LookupDirectoryAgentByCertPin(w.pin)
			if err != nil || tid != w.tn.ID || id.String() != w.id {
				t.Errorf("pin lookup: %v %v %v", tid, id, err)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// a read-only transaction cannot write
	if err := f.DB.ReadTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		if err := c.RevokeDirectoryAgent(x.aAgent, "a", x.issuedAt); !errors.Is(err, store.ErrReadOnly) {
			t.Errorf("write in a read transaction: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TestIsolation_AgentEnrolmentSingleUse: a code is consumed exactly once,
// never after its expiry, and is void once its agent is revoked; the row
// keeps only the hash (the code itself is the agent package's concern, see
// TestEnrolment_SingleUseHashed).
func TestIsolation_AgentEnrolmentSingleUse(t *testing.T) {
	x := seedAgents(t)
	f, ctx := x.f, context.Background()
	consume := func(at time.Time) error {
		return f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error { return c.ConsumeAgentEnrolment(x.aEnrol, at) })
	}
	if err := consume(x.enrolExpiry); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("consumed at the expiry instant: %v", err)
	}
	if err := consume(x.issuedAt.Add(14 * time.Minute)); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if err := consume(x.issuedAt.Add(14 * time.Minute)); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("second use: %v", err)
	}
	inA(t, f, func(c *store.TenantTx) error {
		e, err := c.AgentEnrolment(x.aEnrol)
		if err != nil || e.ConsumedAt == nil || e.TokenHash != x.aHash || len(e.TokenHash) != 64 {
			t.Errorf("row: %+v %v", e, err)
		}
		return nil
	})
	// revoking voids an unused code
	if err := f.DB.InTenant(ctx, f.B.ID, func(c *store.TenantTx) error {
		if err := c.RevokeDirectoryAgent(x.bAgent, "admin", x.issuedAt); err != nil {
			return err
		}
		if err := c.RevokeDirectoryAgent(x.bAgent, "admin", x.issuedAt); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("second revoke: %v", err)
		}
		if err := c.ConsumeAgentEnrolment(x.bEnrol, x.issuedAt); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("revoked agent's code consumed: %v", err)
		}
		if err := c.ActivateDirectoryAgent(x.bAgent, x.bPin, store.AgentTelemetry{}, x.issuedAt); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("revoked agent activated: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
