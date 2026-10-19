package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/jit"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Tenant isolation tests for the store (design §14.4). Fixture: tenants A
// (sentinel in every name) and B with the same external ids. Reads run as B.

func hasSentinel(v any) bool {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return strings.Contains(strings.ToLower(string(b)), strings.ToLower(storetest.Sentinel))
}

func inB(t *testing.T, f *storetest.Fixture, fn func(*store.TenantTx) error) {
	t.Helper()
	if err := f.DB.InTenant(context.Background(), f.B.ID, fn); err != nil {
		t.Fatal(err)
	}
}

func key(kind string, id int64) string { return fmt.Sprintf("%s:%d", kind, id) }

func sp(s string) *string { return &s }

func bp(b bool) *bool { return &b }

// listCases are the tenant-scoped list/aggregate repositories, keyed by
// method name. ids are the calling tenant's ids (or the other tenant's, to
// probe parameterized lists).
var listCases = map[string]func(c *store.TenantTx, ids map[string]int64) (any, error){
	"Identities":          func(c *store.TenantTx, _ map[string]int64) (any, error) { return c.Identities() },
	"IdentitiesOwnedBy":   func(c *store.TenantTx, ids map[string]int64) (any, error) { return c.IdentitiesOwnedBy(ids["dave"]) },
	"IdentitiesManagedBy": func(c *store.TenantTx, ids map[string]int64) (any, error) { return c.IdentitiesManagedBy(ids["carol"]) },
	"IdentityMap": func(c *store.TenantTx, _ map[string]int64) (any, error) {
		_, all, err := c.IdentityMap()
		return all, err
	},
	"Accounts":                 func(c *store.TenantTx, _ map[string]int64) (any, error) { return c.Accounts() },
	"AccountsBySystemUsername": func(c *store.TenantTx, _ map[string]int64) (any, error) { return c.AccountsBySystemUsername(nil) },
	"AccountsBySystemUsername/okta": func(c *store.TenantTx, _ map[string]int64) (any, error) {
		return c.AccountsBySystemUsername(sp("okta"))
	},
	"IdentityAccounts":   func(c *store.TenantTx, ids map[string]int64) (any, error) { return c.IdentityAccounts(ids["alice"]) },
	"Groups":             func(c *store.TenantTx, _ map[string]int64) (any, error) { return c.Groups() },
	"GroupsBySystemName": func(c *store.TenantTx, _ map[string]int64) (any, error) { return c.GroupsBySystemName(nil) },
	"GroupsBySystemName/requestable": func(c *store.TenantTx, _ map[string]int64) (any, error) {
		return c.GroupsBySystemName(bp(true))
	},
	"Resources":             func(c *store.TenantTx, _ map[string]int64) (any, error) { return c.Resources() },
	"ResourcesBySystemName": func(c *store.TenantTx, _ map[string]int64) (any, error) { return c.ResourcesBySystemName() },
	"Permissions":           func(c *store.TenantTx, _ map[string]int64) (any, error) { return c.Permissions() },
	"Edges":                 func(c *store.TenantTx, _ map[string]int64) (any, error) { return c.Edges() },
	"EdgesFrom": func(c *store.TenantTx, ids map[string]int64) (any, error) {
		return c.EdgesFrom(key("account", ids["acct:okta:bob"]))
	},
	"Secrets": func(c *store.TenantTx, _ map[string]int64) (any, error) { return c.Secrets() },
	"AccountSecrets": func(c *store.TenantTx, ids map[string]int64) (any, error) {
		return c.AccountSecrets(ids["acct:aws:svc-etl"])
	},
	"SecretsWithAccounts": func(c *store.TenantTx, _ map[string]int64) (any, error) { return c.SecretsWithAccounts() },
	"Delegations":         func(c *store.TenantTx, _ map[string]int64) (any, error) { return c.Delegations() },
	"UsageAggregates":     func(c *store.TenantTx, _ map[string]int64) (any, error) { return c.UsageAggregates(time.Time{}) },
	"UsageTrend":          func(c *store.TenantTx, _ map[string]int64) (any, error) { return c.UsageTrend(time.Time{}) },
	"RequestsByRecency":   func(c *store.TenantTx, _ map[string]int64) (any, error) { return c.RequestsByRecency() },
	"ExpiredApprovedRequests": func(c *store.TenantTx, _ map[string]int64) (any, error) {
		return c.ExpiredApprovedRequests(storetest.Now.Add(1000 * time.Hour))
	},
	"OpenRequestsFor":      func(c *store.TenantTx, ids map[string]int64) (any, error) { return c.OpenRequestsFor(ids["alice"]) },
	"CampaignsNewestFirst": func(c *store.TenantTx, _ map[string]int64) (any, error) { return c.CampaignsNewestFirst() },
	"CampaignItems":        func(c *store.TenantTx, ids map[string]int64) (any, error) { return c.CampaignItems(ids["campaign"]) },
	"HrisEvents":           func(c *store.TenantTx, _ map[string]int64) (any, error) { return c.HrisEvents() },
	"HrisEventsForUI":      func(c *store.TenantTx, _ map[string]int64) (any, error) { return c.HrisEventsForUI() },
	"AuditLog":             func(c *store.TenantTx, _ map[string]int64) (any, error) { return c.AuditLog(-1) },
}

// parameterized lists take an id; called with the other tenant's id they must be empty.
var parameterizedLists = []string{"IdentitiesOwnedBy", "IdentitiesManagedBy", "IdentityAccounts", "EdgesFrom",
	"AccountSecrets", "OpenRequestsFor", "CampaignItems"}

func TestIsolation_RepoReturnsOnlyOwnRows(t *testing.T) {
	f := storetest.TwoTenants(t)
	bIdentities := map[int64]bool{}
	for _, k := range []string{"alice", "bob", "carol", "dave", "svc-etl", "helper-bot"} {
		bIdentities[f.B.IDs[k]] = true
	}
	for name, fn := range listCases {
		t.Run(name, func(t *testing.T) {
			inB(t, f, func(c *store.TenantTx) error {
				got, err := fn(c, f.B.IDs)
				if err != nil {
					return err
				}
				if reflect.ValueOf(got).Len() == 0 {
					t.Fatalf("%s returned nothing for tenant B (the fixture should give it rows)", name)
				}
				if hasSentinel(got) {
					t.Errorf("%s in tenant B returned tenant A data", name)
				}
				b, _ := json.Marshal(got)
				if strings.Contains(string(b), f.A.ID.String()) {
					t.Errorf("%s in tenant B returned a row stamped with tenant A", name)
				}
				if aggs, ok := got.([]*store.UsageAggregate); ok {
					for _, a := range aggs {
						if !bIdentities[a.IdentityID] {
							t.Errorf("usage aggregate for identity %d, not one of B's", a.IdentityID)
						}
					}
				}
				if slices.Contains(parameterizedLists, name) {
					other, err := fn(c, f.A.IDs)
					if err != nil {
						return err
					}
					if n := reflect.ValueOf(other).Len(); n != 0 {
						t.Errorf("%s with tenant A's id returned %d rows in tenant B", name, n)
					}
				}
				return nil
			})
		})
	}
}

// getCases are the single-row repositories. Given the other tenant's id they
// must return ErrNotFound.
var getCases = map[string]func(c *store.TenantTx, ids map[string]int64) (any, error){
	"Identity": func(c *store.TenantTx, ids map[string]int64) (any, error) { return c.Identity(ids["alice"]) },
	"Account":  func(c *store.TenantTx, ids map[string]int64) (any, error) { return c.Account(ids["acct:okta:alice"]) },
	"Group":    func(c *store.TenantTx, ids map[string]int64) (any, error) { return c.Group(ids["group:aws:ProdAdmin"]) },
	"Permission": func(c *store.TenantTx, ids map[string]int64) (any, error) {
		return c.Permission(ids["perm:aws:get-pii"])
	},
	"ResourceName": func(c *store.TenantTx, ids map[string]int64) (any, error) {
		return c.ResourceName(ids["resource:aws:customer-pii"])
	},
	"Edge": func(c *store.TenantTx, ids map[string]int64) (any, error) { return c.Edge(ids["edge:jit-active"]) },
	"EdgeBetween": func(c *store.TenantTx, ids map[string]int64) (any, error) {
		return c.EdgeBetween(key("account", ids["acct:okta:bob"]), key("group", ids["group:okta:payments-approvers"]))
	},
	"Request":   func(c *store.TenantTx, ids map[string]int64) (any, error) { return c.Request(ids["request:pending"]) },
	"Campaign":  func(c *store.TenantTx, ids map[string]int64) (any, error) { return c.Campaign(ids["campaign"]) },
	"Item":      func(c *store.TenantTx, ids map[string]int64) (any, error) { return c.Item(ids["item"]) },
	"HrisEvent": func(c *store.TenantTx, ids map[string]int64) (any, error) { return c.HrisEvent(ids["hris:leaver"]) },
	"HasStandingEdge": func(c *store.TenantTx, ids map[string]int64) (any, error) {
		ok, err := c.HasStandingEdge(key("account", ids["acct:okta:bob"]), key("group", ids["group:okta:payments-approvers"]))
		if err == nil && !ok {
			err = store.ErrNotFound
		}
		return ok, err
	},
}

// naturalKeyGets look rows up by external id, which both tenants share:
// each tenant must get its own row.
var naturalKeyGets = map[string]func(c *store.TenantTx) (any, error){
	"IdentityByExternalID":   func(c *store.TenantTx) (any, error) { return c.IdentityByExternalID("alice") },
	"ActiveIdentityMatching": func(c *store.TenantTx) (any, error) { return c.ActiveIdentityMatching("", "alice") },
	"GroupByXID":             func(c *store.TenantTx) (any, error) { return c.GroupByXID("aws", "ProdAdmin") },
}

func TestIsolation_GetOtherTenantNotFound(t *testing.T) {
	f := storetest.TwoTenants(t)
	for name, fn := range getCases {
		t.Run(name, func(t *testing.T) {
			inB(t, f, func(c *store.TenantTx) error {
				own, err := fn(c, f.B.IDs)
				if err != nil {
					t.Fatalf("own row: %v", err)
				}
				if hasSentinel(own) {
					t.Errorf("own row carries A's sentinel: %v", own)
				}
				if _, err := fn(c, f.A.IDs); !errors.Is(err, store.ErrNotFound) {
					t.Errorf("tenant A's row from tenant B: err = %v, want ErrNotFound", err)
				}
				return nil
			})
		})
	}
	for name, fn := range naturalKeyGets {
		t.Run(name, func(t *testing.T) {
			for _, tn := range []storetest.Tenant{f.A, f.B} {
				err := f.DB.ReadTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
					got, err := fn(c)
					if err != nil {
						return err
					}
					b, _ := json.Marshal(got)
					if !strings.Contains(string(b), tn.ID.String()) {
						t.Errorf("%s in %s returned another tenant's row: %s", name, tn.Slug, b)
					}
					return nil
				})
				if err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

// countCases are the aggregate counts. A and B hold the same data, so each
// count must be the same in both; an unscoped count would be twice as large.
var countCases = map[string]func(c *store.TenantTx, ids map[string]int64) (int, error){
	"CountAccounts":       func(c *store.TenantTx, _ map[string]int64) (int, error) { return c.CountAccounts() },
	"CountAccountSystems": func(c *store.TenantTx, _ map[string]int64) (int, error) { return c.CountAccountSystems() },
	"CountEdges":          func(c *store.TenantTx, _ map[string]int64) (int, error) { return c.CountEdges() },
	"CountRequests":       func(c *store.TenantTx, _ map[string]int64) (int, error) { return c.CountRequests() },
	"CountRequestsByStatus": func(c *store.TenantTx, _ map[string]int64) (int, error) {
		return c.CountRequestsByStatus("approved")
	},
	"CountUndecidedItems": func(c *store.TenantTx, _ map[string]int64) (int, error) { return c.CountUndecidedItems() },
	"CountOpenItems":      func(c *store.TenantTx, ids map[string]int64) (int, error) { return c.CountOpenItems(ids["campaign"]) },
	"CountHrisEvents":     func(c *store.TenantTx, _ map[string]int64) (int, error) { return c.CountHrisEvents() },
	"CountHrisEventsByStatus": func(c *store.TenantTx, _ map[string]int64) (int, error) {
		return c.CountHrisEventsByStatus("pending")
	},
	"CountUsageEvents": func(c *store.TenantTx, _ map[string]int64) (int, error) { return c.CountUsageEvents() },
	"CountSystem": func(c *store.TenantTx, _ map[string]int64) (int, error) {
		n, err := c.CountSystem("okta")
		return n.Accounts*1000000 + n.Groups*10000 + n.Resources*100 + n.Permissions, err
	},
	"JITSweepPending": func(c *store.TenantTx, _ map[string]int64) (int, error) { return c.JITSweepPending(storetest.Now) },
}

func TestIsolation_CountsOnlyOwnRows(t *testing.T) {
	f := storetest.TwoTenants(t)
	for name, fn := range countCases {
		t.Run(name, func(t *testing.T) {
			counts := map[tenancy.ID]int{}
			for _, tn := range []storetest.Tenant{f.A, f.B} {
				err := f.DB.ReadTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
					n, err := fn(c, tn.IDs)
					counts[tn.ID] = n
					return err
				})
				if err != nil {
					t.Fatal(err)
				}
			}
			if counts[f.A.ID] == 0 || counts[f.A.ID] != counts[f.B.ID] {
				t.Errorf("A=%d B=%d, want equal and non-zero", counts[f.A.ID], counts[f.B.ID])
			}
			err := f.DB.ReadTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
				if name == "CountOpenItems" { // parameterized: A's campaign is not B's
					if n, err := fn(c, f.A.IDs); err != nil || n != 0 {
						t.Errorf("A's campaign from B: %d %v", n, err)
					}
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

// mutations run in tenant B with tenant A's ids and keys (or with natural
// keys both tenants share). Afterwards tenant A must be byte-for-byte unchanged.
var mutations = map[string]func(c *store.TenantTx, a, b map[string]int64) error{
	"SetIdentityRefsByExternalID": func(c *store.TenantTx, a, _ map[string]int64) error {
		return c.SetIdentityRefsByExternalID("alice", nil, nil)
	},
	"SetIdentityOwner": func(c *store.TenantTx, a, _ map[string]int64) error { return c.SetIdentityOwner(a["svc-etl"], nil) },
	"SetIdentityManager": func(c *store.TenantTx, a, _ map[string]int64) error {
		return c.SetIdentityManager(a["alice"], nil)
	},
	"TerminateIdentity": func(c *store.TenantTx, a, _ map[string]int64) error {
		return c.TerminateIdentity(a["alice"], storetest.Now)
	},
	"SetIdentityDepartmentTitle": func(c *store.TenantTx, a, _ map[string]int64) error {
		return c.SetIdentityDepartmentTitle(a["alice"], sp("x"), sp("y"))
	},
	"DisableAccount": func(c *store.TenantTx, a, _ map[string]int64) error { return c.DisableAccount(a["acct:okta:alice"]) },
	"SetEdgeExpiry": func(c *store.TenantTx, a, _ map[string]int64) error {
		return c.SetEdgeExpiry(a["edge:jit-active"], storetest.Now)
	},
	"DeleteEdge": func(c *store.TenantTx, a, _ map[string]int64) error { return c.DeleteEdge(a["edge:0"]) },
	"RevokeEdge": func(c *store.TenantTx, a, _ map[string]int64) error {
		return c.RevokeEdge(a["edge:0"], storetest.Now, "test")
	},
	"DeleteJITEdge": func(c *store.TenantTx, a, _ map[string]int64) error { return c.DeleteJITEdge(a["edge:jit-active"]) },
	"DeleteExpiredJITEdges": func(c *store.TenantTx, _, _ map[string]int64) error {
		_, err := c.DeleteExpiredJITEdges(storetest.Now.Add(1000 * time.Hour))
		return err
	},
	"SetSecretRotated": func(c *store.TenantTx, a, _ map[string]int64) error {
		return c.SetSecretRotated(a["secret"], storetest.Now)
	},
	"DeleteAgentDelegations": func(c *store.TenantTx, _, _ map[string]int64) error {
		n, err := c.DeleteAgentDelegations()
		if err == nil && n != 1 {
			err = fmt.Errorf("deleted %d delegations, want tenant B's 1", n)
		}
		return err
	},
	"DeleteDelegation": func(c *store.TenantTx, a, _ map[string]int64) error { return c.DeleteDelegation(a["delegation"]) },
	"SaveRequest": func(c *store.TenantTx, a, _ map[string]int64) error {
		return c.SaveRequest(&store.AccessRequest{ID: a["request:pending"], Status: "approved"})
	},
	"CancelRequest": func(c *store.TenantTx, a, _ map[string]int64) error {
		return c.CancelRequest(a["request:approved"], storetest.Now)
	},
	"SetCampaignTotals": func(c *store.TenantTx, a, _ map[string]int64) error { return c.SetCampaignTotals(a["campaign"], 9, 9) },
	"CompleteCampaign":  func(c *store.TenantTx, a, _ map[string]int64) error { return c.CompleteCampaign(a["campaign"]) },
	"DecideItem": func(c *store.TenantTx, a, _ map[string]int64) error {
		_, err := c.DecideItem(a["item"], "revoke", nil, storetest.Now, store.UserRef{})
		return err
	},
	"SetHrisEventIdentity": func(c *store.TenantTx, a, _ map[string]int64) error {
		return c.SetHrisEventIdentity(a["hris:joiner"], a["bob"])
	},
	"MarkHrisEventExecuted": func(c *store.TenantTx, a, _ map[string]int64) error {
		return c.MarkHrisEventExecuted(a["hris:leaver"], storetest.Now, store.UserRef{})
	},
	// Upserts on natural keys both tenants share update B's row only.
	"UpsertIdentity": func(c *store.TenantTx, _, _ map[string]int64) error {
		return c.UpsertIdentity(&store.Identity{ExternalID: "alice", Name: "B Alice", Type: "human", Status: "active",
			CreatedAt: storetest.Now})
	},
	"UpsertAccount": func(c *store.TenantTx, _, _ map[string]int64) error {
		return c.UpsertAccount(&store.Account{System: "okta", ExternalID: "alice", Username: "b", Kind: "user", Status: "disabled"})
	},
	"UpsertGroup": func(c *store.TenantTx, _, _ map[string]int64) error {
		return c.UpsertGroup(&store.Group{System: "aws", ExternalID: "ProdAdmin", Name: "B", Kind: "role"})
	},
	"UpsertResource": func(c *store.TenantTx, _, _ map[string]int64) error {
		return c.UpsertResource(&store.Resource{System: "aws", ExternalID: "prod", Name: "B", Kind: "aws_account"})
	},
	"UpsertPermission": func(c *store.TenantTx, _, b map[string]int64) error {
		return c.UpsertPermission(&store.Permission{System: "aws", ExternalID: "get-pii", Action: "s3:*",
			ResourceID: b["resource:aws:prod"]})
	},
	"UpsertConnectorEdge": func(c *store.TenantTx, _, b map[string]int64) error {
		// B's own edge: the conflict target includes tenant_id. (A's keys are
		// refused outright; see TestIsolation_CrossTenantForeignKeys.)
		return c.UpsertConnectorEdge(key("account", b["acct:okta:alice"]), key("group", b["group:okta:eng"]), "x", storetest.Now)
	},
	"UpsertSecret": func(c *store.TenantTx, _, b map[string]int64) error {
		acct := b["acct:aws:svc-etl"]
		return c.UpsertSecret(&store.Secret{System: "aws", ExternalID: "svc-etl-key", Kind: "access_key", Name: "B",
			CreatedAt: storetest.Now}, &acct)
	},
	"UpsertHrisEvent": func(c *store.TenantTx, _, _ map[string]int64) error {
		return c.UpsertHrisEvent(&store.HrisEvent{ExternalID: "evt-leaver", Type: "mover", EffectiveAt: storetest.Now,
			Status: "executed"})
	},
	"jit.Sweep": func(c *store.TenantTx, _, _ map[string]int64) error {
		_, err := jit.Sweep(c, storetest.Now.Add(1000*time.Hour))
		return err
	},
}

func TestIsolation_BulkUpdateDeleteScoped(t *testing.T) {
	f := storetest.TwoTenants(t)
	before := storetest.Dump(t, f.DB, f.A.ID)
	beforeB := storetest.Dump(t, f.DB, f.B.ID)
	for name, fn := range mutations {
		t.Run(name, func(t *testing.T) {
			inB(t, f, func(c *store.TenantTx) error { return fn(c, f.A.IDs, f.B.IDs) })
			if after := storetest.Dump(t, f.DB, f.A.ID); after != before {
				t.Fatalf("%s in tenant B changed tenant A", name)
			}
		})
	}
	if storetest.Dump(t, f.DB, f.B.ID) == beforeB {
		t.Error("the mutations changed nothing in tenant B; the test is not exercising them")
	}
}

// insertCases insert or upsert a row stamped with tenant A inside tenant B.
var insertCases = map[string]func(c *store.TenantTx, a tenancy.ID) error{
	"InsertIdentity": func(c *store.TenantTx, a tenancy.ID) error {
		_, err := c.InsertIdentity(&store.Identity{TenantID: a, ExternalID: "x", Name: "x", Type: "human", Status: "active"})
		return err
	},
	"UpsertIdentity": func(c *store.TenantTx, a tenancy.ID) error {
		return c.UpsertIdentity(&store.Identity{TenantID: a, ExternalID: "x", Name: "x", Type: "human", Status: "active"})
	},
	"InsertAccount": func(c *store.TenantTx, a tenancy.ID) error {
		_, err := c.InsertAccount(&store.Account{TenantID: a, System: "x", ExternalID: "x", Username: "x", Kind: "user", Status: "active"})
		return err
	},
	"UpsertAccount": func(c *store.TenantTx, a tenancy.ID) error {
		return c.UpsertAccount(&store.Account{TenantID: a, System: "x", ExternalID: "x", Username: "x", Kind: "user", Status: "active"})
	},
	"UpsertGroup": func(c *store.TenantTx, a tenancy.ID) error {
		return c.UpsertGroup(&store.Group{TenantID: a, System: "x", ExternalID: "x", Name: "x", Kind: "group"})
	},
	"UpsertResource": func(c *store.TenantTx, a tenancy.ID) error {
		return c.UpsertResource(&store.Resource{TenantID: a, System: "x", ExternalID: "x", Name: "x", Kind: "x"})
	},
	"UpsertPermission": func(c *store.TenantTx, a tenancy.ID) error {
		return c.UpsertPermission(&store.Permission{TenantID: a, System: "x", ExternalID: "x", Action: "x", ResourceID: 1})
	},
	"InsertEdge": func(c *store.TenantTx, a tenancy.ID) error {
		_, err := c.InsertEdge(&store.GrantEdge{TenantID: a, Src: "account:1", Dst: "group:1", Relation: "member_of", Source: "manual"})
		return err
	},
	"UpsertSecret": func(c *store.TenantTx, a tenancy.ID) error {
		one := int64(1)
		return c.UpsertSecret(&store.Secret{TenantID: a, System: "x", ExternalID: "x", Kind: "x", Name: "x"}, &one)
	},
	"InsertDelegations": func(c *store.TenantTx, a tenancy.ID) error {
		return c.InsertDelegations([]store.Delegation{{TenantID: a, AgentID: 1, PrincipalID: 1}})
	},
	"InsertUsageEvents": func(c *store.TenantTx, a tenancy.ID) error {
		return c.InsertUsageEvents([]store.UsageEvent{{TenantID: a, IdentityID: 1, PermissionID: 1, Count: 1}})
	},
	"InsertRequest": func(c *store.TenantTx, a tenancy.ID) error {
		_, err := c.InsertRequest(&store.AccessRequest{TenantID: a, IdentityID: 1, AccountID: 1, GroupID: 1, Status: "pending"})
		return err
	},
	"InsertCampaign": func(c *store.TenantTx, a tenancy.ID) error {
		_, err := c.InsertCampaign(&store.ReviewCampaign{TenantID: a, Name: "x", Status: "open"})
		return err
	},
	"InsertReviewItem": func(c *store.TenantTx, a tenancy.ID) error {
		return c.InsertReviewItem(&store.ReviewItem{TenantID: a, CampaignID: 1, IdentityID: 1, Reasons: []string{},
			Context: json.RawMessage(`{}`)})
	},
	"UpsertHrisEvent": func(c *store.TenantTx, a tenancy.ID) error {
		return c.UpsertHrisEvent(&store.HrisEvent{TenantID: a, ExternalID: "x", Type: "joiner", Status: "pending"})
	},
	"InsertHrisEvent": func(c *store.TenantTx, a tenancy.ID) error {
		_, err := c.InsertHrisEvent(&store.HrisEvent{TenantID: a, ExternalID: "x", Type: "joiner", Status: "pending"})
		return err
	},
}

func TestIsolation_InsertWrongTenantRejected(t *testing.T) {
	f := storetest.TwoTenants(t)
	before := storetest.Dump(t, f.DB, f.B.ID)
	for name, fn := range insertCases {
		t.Run(name, func(t *testing.T) {
			err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error { return fn(c, f.A.ID) })
			if !errors.Is(err, store.ErrCrossTenant) {
				t.Errorf("err = %v, want ErrCrossTenant", err)
			}
		})
	}
	if storetest.Dump(t, f.DB, f.B.ID) != before {
		t.Error("a rejected insert left a row behind")
	}
}

func TestIsolation_ZeroTenantFailsClosed(t *testing.T) {
	f := storetest.TwoTenants(t)
	ctx := context.Background()
	called := false
	fn := func(*store.TenantTx) error { called = true; return nil }
	if err := f.DB.InTenant(ctx, tenancy.ID{}, fn); !errors.Is(err, store.ErrNoTenant) {
		t.Errorf("InTenant(zero) = %v", err)
	}
	if err := f.DB.ReadTenant(ctx, tenancy.ID{}, fn); !errors.Is(err, store.ErrNoTenant) {
		t.Errorf("ReadTenant(zero) = %v", err)
	}
	if err := f.DB.InTenant(ctx, tenancy.New(), fn); !errors.Is(err, store.ErrNoTenant) {
		t.Errorf("InTenant(unknown) = %v", err)
	}
	if called {
		t.Error("fn ran without a valid tenant")
	}
	var events []*store.AuditEvent
	if err := f.DB.ReadTenant(ctx, tenancy.Platform, func(c *store.TenantTx) error {
		var err error
		events, err = c.AuditLog(-1)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range events {
		if e.Action == "tenancy.context_missing" {
			n++
		}
	}
	if n != 2 {
		t.Errorf("platform tenant has %d tenancy.context_missing events, want 2 (one per zero-tenant call)", n)
	}
	defer func() {
		if _, ok := recover().(store.MissingTenantContext); !ok {
			t.Error("TxFrom without a tenant transaction must panic with MissingTenantContext")
		}
	}()
	store.TxFrom(ctx)
}

func TestIsolation_ForEachActiveTenantVisitsEachOnce(t *testing.T) {
	f := storetest.TwoTenants(t)
	seen := map[tenancy.ID]int{}
	err := f.DB.ForEachActiveTenant(context.Background(), func(_ context.Context, c *store.TenantTx) error {
		seen[c.Tenant()]++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 || seen[f.A.ID] != 1 || seen[f.B.ID] != 1 {
		t.Errorf("visited %v, want A and B once each (and not _platform)", seen)
	}
	// One tenant's error does not stop the other.
	visited := 0
	err = f.DB.ForEachActiveTenant(context.Background(), func(_ context.Context, c *store.TenantTx) error {
		visited++
		if c.Tenant() == f.A.ID {
			return errors.New("boom")
		}
		return nil
	})
	if err == nil || visited != 2 {
		t.Errorf("err = %v, visited = %d; want the error and both tenants visited", err, visited)
	}
}

// crossRefs write, inside B, a row whose reference points at one of A's rows
// (integer foreign keys and graph node keys). Each must be refused.
var crossRefs = map[string]func(c *store.TenantTx, a, b map[string]int64) error{
	"InsertAccount.identity_id": func(c *store.TenantTx, a, _ map[string]int64) error {
		id := a["alice"]
		_, err := c.InsertAccount(&store.Account{System: "evil", ExternalID: "x", IdentityID: &id, Username: "evil",
			Kind: "user", Status: "active"})
		return err
	},
	"UpsertAccount.identity_id": func(c *store.TenantTx, a, _ map[string]int64) error {
		id := a["alice"]
		return c.UpsertAccount(&store.Account{System: "okta", ExternalID: "alice", IdentityID: &id, Username: "evil",
			Kind: "user", Status: "active"})
	},
	"InsertIdentity.manager_id": func(c *store.TenantTx, a, _ map[string]int64) error {
		id := a["carol"]
		_, err := c.InsertIdentity(&store.Identity{ExternalID: "evil", Name: "evil", Type: "human", Status: "active",
			ManagerID: &id, CreatedAt: storetest.Now})
		return err
	},
	"SetIdentityManager": func(c *store.TenantTx, a, b map[string]int64) error {
		id := a["carol"]
		return c.SetIdentityManager(b["alice"], &id)
	},
	"SetIdentityOwner": func(c *store.TenantTx, a, b map[string]int64) error {
		id := a["dave"]
		return c.SetIdentityOwner(b["svc-etl"], &id)
	},
	"SetIdentityRefsByExternalID": func(c *store.TenantTx, a, _ map[string]int64) error {
		id := a["carol"]
		return c.SetIdentityRefsByExternalID("alice", &id, nil)
	},
	"UpsertPermission.resource_id": func(c *store.TenantTx, a, _ map[string]int64) error {
		return c.UpsertPermission(&store.Permission{System: "evil", ExternalID: "x", Action: "x",
			ResourceID: a["resource:aws:prod"]})
	},
	"UpsertSecret.account_id": func(c *store.TenantTx, a, _ map[string]int64) error {
		id := a["acct:aws:svc-etl"]
		return c.UpsertSecret(&store.Secret{System: "evil", ExternalID: "s", Kind: "k", Name: "evil",
			CreatedAt: storetest.Now}, &id)
	},
	"InsertDelegations": func(c *store.TenantTx, a, b map[string]int64) error {
		return c.InsertDelegations([]store.Delegation{{AgentID: b["helper-bot"], PrincipalID: a["alice"],
			Scopes: []string{"x"}, CreatedAt: storetest.Now}})
	},
	"InsertUsageEvents": func(c *store.TenantTx, a, b map[string]int64) error {
		return c.InsertUsageEvents([]store.UsageEvent{{IdentityID: b["alice"], PermissionID: a["perm:aws:get-pii"],
			Day: storetest.Now, Count: 1}})
	},
	"InsertEdge.dst": func(c *store.TenantTx, a, b map[string]int64) error {
		_, err := c.InsertEdge(&store.GrantEdge{Src: key("account", b["acct:okta:alice"]),
			Dst: key("group", a["group:aws:ProdAdmin"]), Relation: "member_of", Source: "manual", CreatedAt: storetest.Now})
		return err
	},
	"InsertEdge.src": func(c *store.TenantTx, a, b map[string]int64) error {
		_, err := c.InsertEdge(&store.GrantEdge{Src: key("account", a["acct:okta:alice"]),
			Dst: key("group", b["group:aws:ProdAdmin"]), Relation: "member_of", Source: "manual", CreatedAt: storetest.Now})
		return err
	},
	"UpsertConnectorEdge": func(c *store.TenantTx, a, b map[string]int64) error {
		return c.UpsertConnectorEdge(key("identity", a["alice"]), key("perm", b["perm:aws:get-pii"]), "x", storetest.Now)
	},
	"InsertRequest": func(c *store.TenantTx, a, b map[string]int64) error {
		_, err := c.InsertRequest(&store.AccessRequest{IdentityID: b["alice"], AccountID: b["acct:okta:alice"],
			GroupID: a["group:aws:ProdAdmin"], Justification: "x", DurationHours: 1, Status: "pending",
			RequestedAt: storetest.Now})
		return err
	},
	"InsertReviewItem.campaign_id": func(c *store.TenantTx, a, b map[string]int64) error {
		return c.InsertReviewItem(&store.ReviewItem{CampaignID: a["campaign"], IdentityID: b["alice"],
			EdgeSrc: "x", EdgeDst: "y", Reasons: []string{}, Context: json.RawMessage(`{}`)})
	},
	"SetHrisEventIdentity": func(c *store.TenantTx, a, b map[string]int64) error {
		return c.SetHrisEventIdentity(b["hris:joiner"], a["bob"])
	},
}

// TestIsolation_CrossTenantForeignKeys: a reference crafted inside B to point
// at A's row (integer foreign key or graph node key) is refused with
// ErrCrossTenant, so it can never surface A's data through a join or the
// graph. The reads afterwards confirm B still sees nothing of A.
func TestIsolation_CrossTenantForeignKeys(t *testing.T) {
	f := storetest.TwoTenants(t)
	a := f.A.IDs
	before := storetest.Dump(t, f.DB, f.B.ID)
	for name, fn := range crossRefs {
		t.Run(name, func(t *testing.T) {
			err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error { return fn(c, a, f.B.IDs) })
			if !errors.Is(err, store.ErrCrossTenant) {
				t.Fatalf("err = %v, want ErrCrossTenant", err)
			}
		})
	}
	if storetest.Dump(t, f.DB, f.B.ID) != before {
		t.Error("a refused cross-tenant write changed tenant B")
	}
	if dump := storetest.Dump(t, f.DB, f.B.ID); hasSentinel(dump) {
		t.Error("tenant B's rows expose tenant A data")
	}
	err := f.DB.ReadTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		pairs, err := c.SecretsWithAccounts()
		if err != nil {
			return err
		}
		for _, p := range pairs {
			if p.Account.TenantID != f.B.ID || p.Account.ID == a["acct:aws:svc-etl"] {
				t.Errorf("secret %s joined to tenant A's account %d", p.Secret.Name, p.Account.ID)
			}
		}
		g, err := graph.Build(c, storetest.Now)
		if err != nil {
			return err
		}
		if hasSentinel(g.Nodes()) {
			t.Error("tenant B's graph contains tenant A's nodes")
		}
		for _, k := range []string{key("identity", a["alice"]), key("group", a["group:aws:ProdAdmin"]),
			key("perm", a["perm:aws:get-pii"]), key("account", a["acct:okta:alice"])} {
			if g.HasNode(k) {
				t.Errorf("tenant B's graph has tenant A's node %s", k)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestIsolation_EveryRepoMethodClassified fails when a *TenantTx method is
// added without an isolation case above, so new repositories are covered.
func TestIsolation_EveryRepoMethodClassified(t *testing.T) {
	covered := map[string]bool{
		// metadata, not data access
		"Tenant": true, "Context": true, "ReadOnly": true,
		// Audit appends a domain event stamped by the executor; AuditLog is in listCases.
		"Audit": true,
		// RevokedGrants has its own test: the shared fixture holds no tombstones.
		"RevokedGrants": true,
		// Sealed connection credentials: TestIsolation_ConnectionSecrets.
		"PutConnectionSecret": true, "ConnectionSecret": true,
		// HasPendingRequest has its own test (TestIsolation_PendingRequestUniquePerTenant).
		"HasPendingRequest": true,
	}
	for _, m := range []map[string]bool{keys(listCases), keys(getCases), keys(naturalKeyGets), keys(countCases),
		keys(mutations), keys(insertCases), readinessCovered(), keysCovered(), auditCovered(), authCovered(), jobsCovered(), provisioningCovered(), correlationCovered(), identityModelCovered(), containmentCovered(), groupsCovered(), transportCovered(), alertsCovered(), siemCovered(),
		approvalsCovered(), lifecycleCovered(), notificationsCovered(), requestsCovered(), rolesCovered(), abacCovered(), sodCovered(), sponsorshipsCovered(), adminCovered(), disablesCovered(), removalsCovered(), requestDraftsCovered(), reviewSchedulesCovered(), ownershipCovered(), breakGlassCovered()} {
		for k := range m {
			covered[strings.SplitN(k, "/", 2)[0]] = true
		}
	}
	typ := reflect.TypeOf(&store.TenantTx{})
	for i := 0; i < typ.NumMethod(); i++ {
		if name := typ.Method(i).Name; !covered[name] {
			t.Errorf("(*store.TenantTx).%s has no tenant isolation case", name)
		}
	}
}

func keys[V any](m map[string]V) map[string]bool {
	out := map[string]bool{}
	for k := range m {
		out[k] = true
	}
	return out
}

// TestIsolation_AuditStampedWithOwnTenant: an audit append in B is visible
// only in B.
func TestIsolation_AuditStampedWithOwnTenant(t *testing.T) {
	f := storetest.TwoTenants(t)
	inB(t, f, func(c *store.TenantTx) error {
		return c.Audit(storetest.Now, "b-actor", "b.action", ojson.Object{{Key: "k", Value: "v"}})
	})
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		err := f.DB.ReadTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			log, err := c.AuditLog(-1)
			if err != nil {
				return err
			}
			found := slices.ContainsFunc(log, func(e *store.AuditEvent) bool { return e.Action == "b.action" })
			if found != (tn.ID == f.B.ID) {
				t.Errorf("tenant %s sees B's audit event: %v", tn.Slug, found)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

// TestIsolation_PendingRequestUniquePerTenant: both tenants hold a pending
// request for alice and ProdAdmin (the fixture). HasPendingRequest sees only
// the caller's tenant (A's ids are unknown to B), a second pending request in
// B is refused with ErrDuplicate by the partial unique index, and a decided
// request does not count.
func TestIsolation_PendingRequestUniquePerTenant(t *testing.T) {
	f := storetest.TwoTenants(t)
	inB(t, f, func(c *store.TenantTx) error {
		if ok, err := c.HasPendingRequest(f.A.IDs["alice"], f.A.IDs["group:aws:ProdAdmin"]); err != nil || ok {
			t.Errorf("tenant B sees A's pending request: %v, %v", ok, err)
		}
		bAlice, bGroup := f.B.IDs["alice"], f.B.IDs["group:aws:ProdAdmin"]
		if ok, err := c.HasPendingRequest(bAlice, bGroup); err != nil || !ok {
			t.Errorf("tenant B misses its own pending request: %v, %v", ok, err)
		}
		dup := &store.AccessRequest{IdentityID: bAlice, AccountID: f.B.IDs["acct:okta:alice"], GroupID: bGroup,
			Justification: "again", DurationHours: 1, Status: "pending", RequestedAt: storetest.Now}
		if _, err := c.InsertRequest(dup); !errors.Is(err, store.ErrDuplicate) {
			t.Errorf("second pending request: err = %v, want ErrDuplicate", err)
		}
		dup.Status = "denied"
		if _, err := c.InsertRequest(dup); err != nil {
			t.Errorf("a decided request must not collide: %v", err)
		}
		return nil
	})
}

// TestIsolation_RevokedGrantsOwnTenantOnly: a tombstone written in A is not
// visible in B, and a revoke in B leaves A's grant in place.
func TestIsolation_RevokedGrantsOwnTenantOnly(t *testing.T) {
	f := storetest.TwoTenants(t)
	if err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		return c.RevokeEdge(f.A.IDs["edge:0"], storetest.Now, "test")
	}); err != nil {
		t.Fatal(err)
	}
	inB(t, f, func(c *store.TenantTx) error {
		got, err := c.RevokedGrants()
		if err != nil {
			return err
		}
		if len(got) != 0 {
			t.Errorf("tenant B sees %d tombstones of tenant A", len(got))
		}
		return nil
	})
	if err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		got, err := c.RevokedGrants()
		if err != nil {
			return err
		}
		if len(got) != 1 || got[0].TenantID != f.A.ID {
			t.Errorf("tenant A tombstones = %+v", got)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
