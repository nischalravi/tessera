package provision_test

import (
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync/connsynctest"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/pam/pamfake"
	"github.com/nischalravi/tessera/mvp/server/internal/provision"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/fake"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Safe membership in a vault goes through the provisioning engine like any
// other change: queued, sent, then re-read before it counts as done.
func TestEngine_VaultSafeMembership(t *testing.T) {
	for _, vendor := range provision.PAMKinds {
		t.Run(vendor, func(t *testing.T) {
			e := setup(t, fake.Options{})
			fk := pamfake.New(vendor, "svc", "pw")
			fk.Users, fk.Groups = []string{"bob@larkspur.example"}, []string{"bob@larkspur.example"}
			fk.Set(pamfake.Safe{ID: "7", Name: "Prod-DB"})
			srv := connsynctest.New(t, fk)
			hc, err := safehttp.NewForTest(t, srv.Options(0))
			if err != nil {
				t.Fatal(err)
			}
			e.eng.HTTP, e.eng.Runtime = hc, connsynctest.Runtime
			id := store.NewID()
			enc, err := provision.SealToken(e.sealer, e.f.A.ID, id, "svc:pw")
			if err != nil {
				t.Fatal(err)
			}
			e.inA(func(c *store.TenantTx) error {
				if old, err := c.ProvTarget(e.conn); err == nil {
					id = old.ID
					enc, _ = provision.SealToken(e.sealer, e.f.A.ID, id, "svc:pw")
				}
				return c.UpsertProvTarget(&store.ProvTarget{ID: id, ConnectionID: e.conn, Kind: vendor, BaseURL: srv.URL, Settings: "{}",
					CredentialEnc: enc, WriteBack: true, CreatedBy: "admin"}, e.now)
			})
			change := func(kind, key string) *store.ProvOp {
				var op *store.ProvOp
				e.inA(func(c *store.TenantTx) (err error) {
					op, _, err = provision.Submit(c, e.now, provision.Change{System: e.system, Kind: kind, Account: target.Account{Username: "bob@larkspur.example"},
						Group: target.Group{ExternalID: "7/list", Name: "Prod-DB / list"}, Source: provision.SourceJML, Key: key})
					return
				})
				return op
			}
			op := change(target.AddEntitlement, "v:"+vendor+":add")
			if st := e.run(); st.Verified != 1 {
				t.Fatalf("add: stats %+v, op %+v", st, e.op(op.ID))
			}
			if s, _ := fk.SafeState("7"); len(s.Members) != 1 {
				t.Fatalf("members = %+v", s.Members)
			}
			op = change(target.RemoveEntitlement, "v:"+vendor+":rm")
			if st := e.run(); st.Verified != 1 {
				t.Fatalf("remove: stats %+v, op %+v", st, e.op(op.ID))
			}
			if s, _ := fk.SafeState("7"); len(s.Members) != 0 {
				t.Fatalf("members after the remove = %+v", s.Members)
			}
			// a vault that accepts a write and drops it: the re-read does not agree, so it is not done
			fk.SetFaults(pamfake.Faults{DropWrites: true})
			op = change(target.AddEntitlement, "v:"+vendor+":drop")
			for i := 0; i < 4; i++ {
				e.run()
			}
			if got := e.op(op.ID); got.Status == provision.Verified {
				t.Errorf("a dropped write was counted as done: %+v", got)
			}
		})
	}
}
