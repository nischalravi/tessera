// Package storetest holds the shared tenant-isolation fixture (design §14.4):
// two tenants with the same external ids, tenant A's names, emails and tags
// carrying a sentinel string, and one of every kind of row in each.
package storetest

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/ingest"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Sentinel appears in tenant A's names, emails (lower-cased), tags, campaign
// name, HRIS payload and audit detail. No response or read in tenant B may
// contain it.
const Sentinel = "ZZ-LARKSPUR-SENTINEL"

// Now is the fixture's reference time.
var Now = time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)

// Tenant ids of the fixture.
var (
	AID = tenancy.MustParse("00000000-0000-4000-8000-0000000000a1")
	BID = tenancy.MustParse("00000000-0000-4000-8000-0000000000b2")
)

// Tenant is one fixture tenant and the ids of its rows. Keys: external ids
// ("alice"), "acct:<system>:<xid>", "group:<system>:<xid>",
// "perm:<system>:<xid>", "resource:<system>:<xid>", "edge:<n>" (every grant
// edge, in id order), and "request:pending", "request:approved",
// "request:expired", "edge:jit-active", "edge:jit-expired", "campaign",
// "item", "hris:leaver", "hris:joiner", "secret", "delegation".
type Tenant struct {
	ID   tenancy.ID
	Slug string
	IDs  map[string]int64
}

// Fixture is a database with tenants A (sentinel) and B.
type Fixture struct {
	DB   *store.DB
	A, B Tenant
}

// TwoTenants builds the fixture in a temporary directory. A is seeded first,
// so its integer ids are the lower ones.
func TwoTenants(tb testing.TB) *Fixture {
	tb.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(tb.TempDir(), "two-tenants.db"))
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = db.Close() })
	f := &Fixture{DB: db}
	f.A = seedTenant(tb, db, AID, "tenant-a", Sentinel)
	f.B = seedTenant(tb, db, BID, "tenant-b", "")
	return f
}

func seedTenant(tb testing.TB, db *store.DB, id tenancy.ID, slug, sentinel string) Tenant {
	tb.Helper()
	ctx := context.Background()
	if err := db.InSystem(ctx, "storetest", func(s *store.SystemTx) error {
		_, err := s.CreateTenant(store.Tenant{ID: id, Slug: slug, Name: slug, CreatedAt: Now})
		return err
	}); err != nil {
		tb.Fatal(err)
	}
	t := Tenant{ID: id, Slug: slug, IDs: map[string]int64{}}
	mark := func(s string) string {
		if sentinel == "" {
			return s
		}
		return s + " " + sentinel
	}
	err := db.InTenant(ctx, id, func(c *store.TenantTx) error {
		if _, err := ingest.Sync(c, Now, []connectors.Connector{connectors.Tiny{Now: Now, Sentinel: sentinel}}, nil); err != nil {
			return err
		}
		if err := loadIDs(c, t.IDs); err != nil {
			return err
		}
		key := func(kind, k string) string { return fmt.Sprintf("%s:%d", kind, t.IDs[k]) }
		// JIT: a pending request, an active grant and one whose grant expired an hour ago.
		var err error
		if t.IDs["request:pending"], err = c.InsertRequest(&store.AccessRequest{IdentityID: t.IDs["alice"],
			AccountID: t.IDs["acct:okta:alice"], GroupID: t.IDs["group:aws:ProdAdmin"], Justification: mark("pending"),
			DurationHours: 1, Status: "pending", RequestedAt: Now}); err != nil {
			return err
		}
		for _, j := range []struct{ name, who string }{{"active", "bob"}, {"expired", "carol"}} {
			exp := Now.Add(time.Hour)
			if j.name == "expired" {
				exp = Now.Add(-time.Hour)
			}
			edge, err := c.InsertEdge(&store.GrantEdge{Src: key("account", "acct:okta:"+j.who),
				Dst: key("group", "group:aws:ProdAdmin"), Relation: "member_of", Source: "jit", ExpiresAt: &exp,
				CreatedAt: Now.Add(-2 * time.Hour)})
			if err != nil {
				return err
			}
			t.IDs["edge:jit-"+j.name] = edge
			decided, by := Now.Add(-2*time.Hour), mark("approver")
			rid, err := c.InsertRequest(&store.AccessRequest{IdentityID: t.IDs[j.who], AccountID: t.IDs["acct:okta:"+j.who],
				GroupID: t.IDs["group:aws:ProdAdmin"], Justification: mark(j.name), DurationHours: 1, Status: "approved",
				RequestedAt: decided, DecidedAt: &decided, DecidedBy: &by, ExpiresAt: &exp, EdgeID: &edge})
			if err != nil {
				return err
			}
			if j.name == "active" {
				t.IDs["request:approved"] = rid
			} else {
				t.IDs["request:expired"] = rid
			}
		}
		// A review campaign with one item on bob's approver grant.
		if t.IDs["campaign"], err = c.InsertCampaign(&store.ReviewCampaign{Name: mark("Q4 review"), CreatedAt: Now,
			Status: "open", UnusedDays: 60, TotalGrants: 1}); err != nil {
			return err
		}
		edge, err := c.EdgeBetween(key("account", "acct:okta:bob"), key("group", "group:okta:payments-approvers"))
		if err != nil {
			return err
		}
		ctxJSON, _ := json.Marshal(map[string]string{"note": mark("context")})
		reviewer := t.IDs["carol"]
		if err := c.InsertReviewItem(&store.ReviewItem{CampaignID: t.IDs["campaign"], IdentityID: t.IDs["bob"],
			EdgeID: &edge.ID, EdgeSrc: edge.Src, EdgeDst: edge.Dst, GrantLabel: mark("bob → payments-approvers"),
			Reasons: []string{"policy_violation"}, Context: ctxJSON, ReviewerID: &reviewer}); err != nil {
			return err
		}
		items, err := c.CampaignItems(t.IDs["campaign"])
		if err != nil || len(items) != 1 {
			return fmt.Errorf("storetest: campaign items: %v %w", items, err)
		}
		t.IDs["item"] = items[0].ID
		// HRIS: a pending leaver for alice and a pending joiner.
		alice := t.IDs["alice"]
		if t.IDs["hris:leaver"], err = c.InsertHrisEvent(&store.HrisEvent{ExternalID: "evt-leaver", Type: "leaver",
			IdentityID: &alice, Payload: ojson.Object{{Key: "reason", Value: mark("leaving")}}, EffectiveAt: Now,
			Status: "pending"}); err != nil {
			return err
		}
		if t.IDs["hris:joiner"], err = c.InsertHrisEvent(&store.HrisEvent{ExternalID: "evt-joiner", Type: "joiner",
			Payload: ojson.Object{{Key: "name", Value: mark("New Hire")}, {Key: "team", Value: "backend"},
				{Key: "email", Value: "new.hire@t.example"}}, EffectiveAt: Now, Status: "pending"}); err != nil {
			return err
		}
		secrets, err := c.Secrets()
		if err != nil || len(secrets) != 1 {
			return fmt.Errorf("storetest: secrets: %v %w", secrets, err)
		}
		t.IDs["secret"] = secrets[0].ID
		dels, err := c.Delegations()
		if err != nil || len(dels) != 1 {
			return fmt.Errorf("storetest: delegations: %v %w", dels, err)
		}
		t.IDs["delegation"] = dels[0].ID
		edges, err := c.Edges()
		if err != nil {
			return err
		}
		for i, e := range edges {
			t.IDs[fmt.Sprintf("edge:%d", i)] = e.ID
		}
		return c.Audit(Now, mark("auditor"), "storetest.seeded", ojson.Object{{Key: "tenant", Value: mark(slug)}})
	})
	if err != nil {
		tb.Fatal(err)
	}
	return t
}

func loadIDs(c *store.TenantTx, ids map[string]int64) error {
	idents, err := c.Identities()
	if err != nil {
		return err
	}
	for _, i := range idents {
		ids[i.ExternalID] = i.ID
	}
	accts, err := c.Accounts()
	if err != nil {
		return err
	}
	for _, a := range accts {
		ids["acct:"+a.System+":"+a.ExternalID] = a.ID
	}
	groups, err := c.Groups()
	if err != nil {
		return err
	}
	for _, g := range groups {
		ids["group:"+g.System+":"+g.ExternalID] = g.ID
	}
	perms, err := c.Permissions()
	if err != nil {
		return err
	}
	for _, p := range perms {
		ids["perm:"+p.System+":"+p.ExternalID] = p.ID
	}
	res, err := c.Resources()
	if err != nil {
		return err
	}
	for _, r := range res {
		ids["resource:"+r.System+":"+r.ExternalID] = r.ID
	}
	return nil
}

// Dump reads every row of a tenant through the tenant-scoped repositories and
// returns it as JSON, so a test can assert that operations in another tenant
// left it byte-for-byte unchanged.
func Dump(tb testing.TB, db *store.DB, t tenancy.ID) string {
	tb.Helper()
	out := map[string]any{}
	err := db.ReadTenant(context.Background(), t, func(c *store.TenantTx) error {
		var err error
		get := func(name string, v any, e error) {
			if err == nil {
				err = e
			}
			out[name] = v
		}
		v1, e := c.Identities()
		get("identities", v1, e)
		v2, e := c.Accounts()
		get("accounts", v2, e)
		v3, e := c.Groups()
		get("groups", v3, e)
		v4, e := c.Resources()
		get("resources", v4, e)
		v5, e := c.Permissions()
		get("permissions", v5, e)
		v6, e := c.Edges()
		get("grant_edges", v6, e)
		v7, e := c.Secrets()
		get("secrets", v7, e)
		v8, e := c.Delegations()
		get("agent_delegations", v8, e)
		v9, e := c.UsageAggregates(time.Time{})
		get("usage_events", v9, e)
		n, e := c.CountUsageEvents()
		get("usage_events_count", n, e)
		v10, e := c.RequestsByRecency()
		get("access_requests", v10, e)
		v11, e := c.CampaignsNewestFirst()
		get("review_campaigns", v11, e)
		var items []*store.ReviewItem
		for _, cmp := range v11 {
			it, e := c.CampaignItems(cmp.ID)
			get("review_items", nil, e)
			items = append(items, it...)
		}
		out["review_items"] = items
		v12, e := c.HrisEvents()
		get("hris_events", v12, e)
		v13, e := c.AuditLog(-1)
		get("audit_log", v13, e)
		return err
	})
	if err != nil {
		tb.Fatal(err)
	}
	b, err := json.Marshal(out)
	if err != nil {
		tb.Fatal(err)
	}
	return string(b)
}
