// Package seed creates the demo tenants in a fresh database: "larkspur" (the
// configured connectors, demo by default, plus sample JIT requests and a
// review campaign) and "globex" (the tiny world with a sentinel string in
// every name). Each tenant is seeded in its own tenant transaction.
package seed

import (
	"context"
	"fmt"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/ingest"
	"github.com/nischalravi/tessera/mvp/server/internal/jit"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/reviews"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Fixed ids of the demo tenants, so a reseed keeps them stable.
var (
	LarkspurID = tenancy.MustParse("00000000-0000-4000-8000-00000000000a")
	GlobexID   = tenancy.MustParse("00000000-0000-4000-8000-00000000000b")
)

// Demo tenant slugs and the sentinel in every Globex name.
const (
	LarkspurSlug   = "larkspur"
	GlobexSlug     = "globex"
	GlobexSentinel = "ZZ-GLOBEX-SENTINEL"
)

func one[T any](items []*T, err error, what string) (*T, error) {
	if err != nil {
		return nil, err
	}
	if len(items) != 1 {
		return nil, fmt.Errorf("seed: expected exactly one %s, found %d", what, len(items))
	}
	return items[0], nil
}

// Workflows adds sample JIT requests and an initial review campaign so every
// page has data. now is the wall clock.
func Workflows(c *store.TenantTx, now time.Time, policies []*policy.Policy) error {
	groups, err := c.Groups()
	if err != nil {
		return err
	}
	idents, err := c.Identities()
	if err != nil {
		return err
	}
	role := func(system, name string) (*store.Group, error) {
		var gs []*store.Group
		for _, g := range groups {
			if g.System == system && g.Name == name {
				gs = append(gs, g)
			}
		}
		return one(gs, nil, system+" role "+name)
	}
	ident := func(name string) (*store.Identity, error) {
		var is []*store.Identity
		for _, i := range idents {
			if i.Name == name {
				is = append(is, i)
			}
		}
		return one(is, nil, "identity "+name)
	}
	prodAdmin, err := role("aws", "ProdAdmin")
	if err != nil {
		return err
	}
	breakGlass, err := role("aws", "BreakGlassAdmin")
	if err != nil {
		return err
	}
	acctadmin, err := role("snowflake", "ACCOUNTADMIN")
	if err != nil {
		return err
	}
	alice, err := ident("Alice Okafor")
	if err != nil {
		return err
	}
	kofi, err := ident("Kofi Mensah")
	if err != nil {
		return err
	}
	sreAgent, err := ident("SRE On-call Agent")
	if err != nil {
		return err
	}
	// pending: an AI agent asking for prod admin, and an engineer for a hotfix
	if _, err := jit.CreateRequest(c, now, sreAgent.ID, prodAdmin.ID, jit.Hours{N: 1, Whole: true}, "PagerDuty INC-4821: restart wedged ECS tasks in prod", store.UserRef{}); err != nil {
		return err
	}
	if _, err := jit.CreateRequest(c, now, alice.ID, prodAdmin.ID, jit.Hours{N: 4, Whole: true}, "Hotfix for orders-db connection pool exhaustion (INC-4817)", store.UserRef{}); err != nil {
		return err
	}
	// active: Kofi has break-glass for 2h
	r, err := jit.CreateRequest(c, now, kofi.ID, breakGlass.ID, jit.Hours{N: 2, Whole: true}, "Rotate compromised KMS grant during incident INC-4790", store.UserRef{})
	if err != nil {
		return err
	}
	if _, err := jit.Approve(c, r.ID, store.UserRef{Display: "Ingrid Lindqvist"}, now.Add(-20*time.Minute), now); err != nil {
		return err
	}
	// expired: yesterday's Snowflake admin session
	var data []*store.Identity
	for _, i := range idents {
		if i.Department != nil && *i.Department == "Data" && i.Status == "active" && i.Name != "Sana Iyer" {
			data = append(data, i)
		}
	}
	if len(data) == 0 {
		return fmt.Errorf("seed: no active Data identity")
	}
	r2, err := jit.CreateRequest(c, now, data[len(data)-1].ID, acctadmin.ID, jit.Hours{N: 3, Whole: true}, "Resize warehouse for quarter-end backfill", store.UserRef{})
	if err != nil {
		return err
	}
	if _, err := jit.Approve(c, r2.ID, store.UserRef{Display: "Sana Iyer"}, now.Add(-24*time.Hour), now); err != nil {
		return err
	}
	if _, err := jit.Sweep(c, now); err != nil {
		return err
	}
	_, err = reviews.GenerateCampaign(c, now, "Q4 exception-only review", 60, policies)
	return err
}

// CampaignOnly seeds just the initial review campaign (the Globex workflows).
func CampaignOnly(c *store.TenantTx, now time.Time, policies []*policy.Policy) error {
	_, err := reviews.GenerateCampaign(c, now, "Q4 exception-only review", 60, policies)
	return err
}

// Tenant is one tenant to seed.
type Tenant struct {
	ID         tenancy.ID
	Slug, Name string
	Connectors []connectors.Connector
	// Workflows, if set, runs after the connectors are synced.
	Workflows func(c *store.TenantTx, now time.Time, policies []*policy.Policy) error
	// DevIdP, when set, is the issuer of a dev_mock IdP connection seeded
	// with Users as its bootstrap users (WithDevIdP; dev and test only).
	DevIdP string
	Users  []User
}

// Larkspur is the Larkspur Labs demo tenant over conns.
func Larkspur(conns []connectors.Connector) Tenant {
	return Tenant{ID: LarkspurID, Slug: LarkspurSlug, Name: "Larkspur Labs", Connectors: conns, Workflows: Workflows}
}

// Globex is the second demo tenant: the tiny world with GlobexSentinel in
// every name, so a leak into another tenant is easy to spot.
func Globex(now time.Time) Tenant {
	return Tenant{ID: GlobexID, Slug: GlobexSlug, Name: "Globex Corporation",
		Connectors: []connectors.Connector{connectors.Tiny{Now: now, Sentinel: GlobexSentinel, Domain: "globex.example"}},
		Workflows:  CampaignOnly}
}

// DefaultTenants are the tenants `tessera seed` creates: Larkspur over conns,
// then Globex. Larkspur goes first so its ids match a single-tenant seed.
func DefaultTenants(conns []connectors.Connector, now time.Time) []Tenant {
	return []Tenant{Larkspur(conns), Globex(now)}
}

// Stats summarizes the seed of one tenant.
type Stats struct {
	Tenant   store.Tenant
	Sync     ingest.SyncStats
	Requests int
}

// Run drops and recreates the schema, then for each tenant creates it (in a
// system transaction) and syncs its connectors and runs its workflows (in its
// own tenant transaction).
func Run(ctx context.Context, db *store.DB, now time.Time, policies []*policy.Policy, tenants []Tenant) ([]Stats, error) {
	if err := db.Migrate(ctx, true); err != nil {
		return nil, err
	}
	out := make([]Stats, 0, len(tenants))
	for _, t := range tenants {
		var st Stats
		if err := db.InSystem(ctx, "seed: create tenant "+t.Slug, func(s *store.SystemTx) error {
			var err error
			st.Tenant, err = s.CreateTenant(store.Tenant{ID: t.ID, Slug: t.Slug, Name: t.Name, CreatedAt: now})
			return err
		}); err != nil {
			return out, fmt.Errorf("seed: tenant %s: %w", t.Slug, err)
		}
		err := db.InTenant(ctx, st.Tenant.ID, func(c *store.TenantTx) error {
			var err error
			if st.Sync, err = ingest.Sync(c, now, t.Connectors, nil); err != nil {
				return err
			}
			if t.Workflows != nil {
				if err := t.Workflows(c, now, policies); err != nil {
					return err
				}
			}
			if err := seedAuth(c, t, now); err != nil {
				return err
			}
			st.Requests, err = c.CountRequests()
			return err
		})
		if err != nil {
			return out, fmt.Errorf("seed: tenant %s: %w", t.Slug, err)
		}
		out = append(out, st)
	}
	return out, nil
}
