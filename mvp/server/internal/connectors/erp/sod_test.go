package erp_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/erp"
	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/ingest"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/sod"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

func TestMain(m *testing.M) { testkit.Main(m) }

// The permissions an ERP connector emits are what the SoD functions of issue
// #298 select: "enter a vendor invoice" and "release a payment" are two
// functions over t-codes, and whoever holds both through any role (a composite
// included) violates the risk. Authorization objects work the same way with a
// pattern over the field values.
func TestSoDFunctionsSelectERPEntitlements(t *testing.T) {
	for _, system := range erp.Systems {
		t.Run(system, func(t *testing.T) {
			r := newRig(t, system)
			res, err := erp.NewConnector(r.sys, func() time.Time { return t0 }).Discover(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			st, _ := testkit.Tiny(t)
			now := testkit.Now
			people := map[string]string{"ada.clerk@corp.example": "ap-clerk", "bo@corp.example": "ap-boss", "ex@corp.example": "ex"}
			for mail, x := range people {
				m := mail
				res.Identities = append(res.Identities, connectors.IdentityRecord{ExternalID: x, Name: x, Type: "human", Email: &m, Status: "active"})
			}
			testkit.Write(t, st, func(c *store.TenantTx) error {
				_, err := ingest.Import(c, now, res)
				return err
			})
			run := func(fn1, fn2 []sod.Selector) []string {
				b := &sod.Bundle{Ruleset: sod.RulesetDoc{Key: "erp", Name: "ERP", Enabled: true}}
				b.Functions = []sod.FunctionDoc{{Key: "a", Name: "A", Selectors: fn1}, {Key: "b", Name: "B", Selectors: fn2}}
				b.Risks = []sod.RiskDoc{{Key: "r", Name: "R", Priority: "high", Functions: []string{"a", "b"}}}
				vs := testkit.Get(t, st, func(c *store.TenantTx) ([]sod.Violation, error) {
					g, err := graph.Build(c, now)
					if err != nil {
						return nil, err
					}
					return policy.NewContext(g, c, now).SoD(sod.CompileBundle(b)), nil
				})
				var who []string
				for _, v := range vs {
					who = append(who, v.IdentityName)
				}
				slices.Sort(who)
				return who
			}
			invoice := []sod.Selector{{System: system, NamePattern: "FB60"}}
			pay := []sod.Selector{{System: system, NamePattern: "F110"}}
			// the clerk only enters invoices; the boss holds the composite that has both
			if got := run(invoice, pay); !slices.Equal(got, []string{"ap-boss"}) {
				t.Errorf("invoice x payment: %v, want only ap-boss (through a composite role)", got)
			}
			// the same through an authorization object pattern: change on invoice documents
			change := []sod.Selector{{System: system, NamePattern: "F_BKPF_BUK[*ACTVT=*02*"}}
			if got := run(change, pay); !slices.Equal(got, []string{"ap-boss"}) {
				t.Errorf("change authorization x payment: %v", got)
			}
			// a role that expired and one not yet valid hold nothing: "ex" has both display and payment on paper
			if got := run([]sod.Selector{{System: system, NamePattern: "FB03"}}, pay); !slices.Equal(got, []string{"ap-boss"}) {
				t.Errorf("display x payment: %v (ex holds neither: one role expired, the other is not valid yet)", got)
			}
		})
	}
}
