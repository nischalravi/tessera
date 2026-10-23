package ingest_test

import (
	"context"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/ingest"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

func sptr(s string) *string { return &s }

func setRules(t *testing.T, f *storetest.Fixture, order, auth string) {
	t.Helper()
	if err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		return c.PutIdentityRules(&store.IdentityRulesRow{CorrelationOrder: order, Authoritative: auth, DormantServiceDays: 30,
			DormantAIAgentDays: 30, UpdatedBy: "test"}, storetest.Now)
	}); err != nil {
		t.Fatal(err)
	}
}

// The tenant's authoritative source per attribute (Admin > Identity rules): another system's value for a person already
// known is ignored, the authoritative system's value is taken, and a person not known yet takes the first source's.
func TestDiscoveryKeepsTheAuthoritativeSourcesAttributes(t *testing.T) {
	f := storetest.TwoTenants(t)
	now := storetest.Now
	person := func(system, dept, title string) *connectors.DiscoveryResult {
		return &connectors.DiscoveryResult{System: system, Identities: []connectors.IdentityRecord{
			{ExternalID: "auth-1", Name: "Ada " + system, Type: "human", Status: "active", Department: sptr(dept), Title: sptr(title)}}}
	}
	run := func(r *connectors.DiscoveryResult) {
		t.Helper()
		if err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
			_, err := ingest.Discovery(c, now, []*connectors.DiscoveryResult{r}, false)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	read := func() *store.Identity {
		t.Helper()
		var id *store.Identity
		if err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) (err error) {
			id, err = c.IdentityByExternalID("auth-1")
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return id
	}
	setRules(t, f, `["external_id","email"]`, `{"department":"workday","name":"workday"}`)
	run(person("okta", "Sales", "Rep")) // not known yet: the first source's values are taken
	if id := read(); *id.Department != "Sales" || id.Name != "Ada okta" {
		t.Fatalf("a new person = %q %q", *id.Department, id.Name)
	}
	run(person("workday", "Engineering", "Engineer")) // the authoritative system overwrites
	if id := read(); *id.Department != "Engineering" || id.Name != "Ada workday" || *id.Title != "Engineer" {
		t.Fatalf("after workday = %q %q %q", *id.Department, id.Name, *id.Title)
	}
	run(person("okta", "Sales", "Rep")) // department and name stay; the title has no authoritative source
	if id := read(); *id.Department != "Engineering" || id.Name != "Ada workday" || *id.Title != "Rep" {
		t.Fatalf("after okta = %q %q %q", *id.Department, id.Name, *id.Title)
	}
	// without rules every source overwrites, as before
	setRules(t, f, `["external_id","email"]`, `{}`)
	run(person("okta", "Sales", "Rep"))
	if id := read(); *id.Department != "Sales" || id.Name != "Ada okta" {
		t.Fatalf("without rules = %q %q", *id.Department, id.Name)
	}
}

// The correlation order is the tenant's: external id then email by default, email first when it says so, and a key left
// out is not tried.
func TestResolverFollowsTheCorrelationOrder(t *testing.T) {
	cases := []struct {
		name  string
		order string
		ref   connectors.IdentityRef
		want  string // external id of the person resolved, "" for none
	}{
		{"default: external id first", `["external_id","email"]`, connectors.IdentityRef{ExternalID: "x-1", Email: "b@example.com"}, "x-1"},
		{"email first", `["email","external_id"]`, connectors.IdentityRef{ExternalID: "x-1", Email: "b@example.com"}, "x-2"},
		{"email only ignores the external id", `["email"]`, connectors.IdentityRef{ExternalID: "x-1", Email: "nobody@example.com"}, ""},
		{"external id only ignores the email", `["external_id"]`, connectors.IdentityRef{ExternalID: "unknown", Email: "b@example.com"}, ""},
		{"falls through to the second key", `["external_id","email"]`, connectors.IdentityRef{ExternalID: "unknown", Email: "B@Example.com"}, "x-2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := storetest.TwoTenants(t)
			res := &connectors.DiscoveryResult{System: "hr", Identities: []connectors.IdentityRecord{
				{ExternalID: "x-1", Name: "One", Type: "human", Status: "active", Email: sptr("a@example.com")},
				{ExternalID: "x-2", Name: "Two", Type: "human", Status: "active", Email: sptr("b@example.com")}}}
			setRules(t, f, tc.order, `{}`)
			if err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
				if _, err := ingest.Discovery(c, storetest.Now, []*connectors.DiscoveryResult{res}, false); err != nil {
					return err
				}
				r, err := ingest.NewResolver(c)
				if err != nil {
					return err
				}
				got := ""
				if id := r.Identity(&tc.ref); id != nil {
					i, err := c.Identity(*id)
					if err != nil {
						return err
					}
					got = i.ExternalID
				}
				if got != tc.want {
					t.Errorf("resolved %q, want %q", got, tc.want)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
