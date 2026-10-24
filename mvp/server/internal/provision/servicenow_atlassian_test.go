package provision_test

import (
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/atlassian/atfake"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync/connsynctest"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/servicenow/snfake"
	"github.com/nischalravi/tessera/mvp/server/internal/provision"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/fake"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

const (
	snUserID = "6816f79cc0a8016401c5a33be04be441"
	snGroup  = "0000000000000000000000000000a001"
)

// A group membership and a deactivation in ServiceNow go through the engine like any other change (issue #559):
// not queued while write-back is off, then sent and re-read once it is on; a write the instance accepts and
// drops is not counted as done.
func TestEngine_ServiceNowTarget(t *testing.T) {
	e := setup(t, fake.Options{})
	fk := snfake.New("tessera.integration", "pw-1", "", "")
	fk.Set("sys_user", snfake.Row{"sys_id": snUserID, "user_name": "bob@acme.example", "active": "true"})
	fk.Set("sys_user_group", snfake.Row{"sys_id": snGroup, "name": "Network"})
	srv := connsynctest.New(t, fk)
	hc, err := safehttp.NewForTest(t, srv.Options(0))
	if err != nil {
		t.Fatal(err)
	}
	e.eng.HTTP, e.eng.Runtime = hc, connsynctest.Runtime
	id := store.NewID()
	set := func(writeBack bool, cred string) {
		e.inA(func(c *store.TenantTx) error {
			if old, err := c.ProvTarget(e.conn); err == nil {
				id = old.ID
			}
			enc, _ := provision.SealToken(e.sealer, e.f.A.ID, id, cred)
			return c.UpsertProvTarget(&store.ProvTarget{ID: id, ConnectionID: e.conn, Kind: provision.KindServiceNow, BaseURL: srv.URL, Settings: "{}",
				CredentialEnc: enc, WriteBack: writeBack, CreatedBy: "admin"}, e.now)
		})
	}
	submit := func(k string, g target.Group, key string) (op *store.ProvOp, routed bool) {
		e.inA(func(c *store.TenantTx) (err error) {
			op, routed, err = provision.Submit(c, e.now, provision.Change{System: e.system, Kind: k, Account: target.Account{Username: "bob@acme.example"},
				Group: g, Source: provision.SourceJML, Key: key})
			return
		})
		return
	}
	direct := `{"auth":"basic","username":"tessera.integration","password":"pw-1"}`

	set(false, direct)
	if _, routed := submit(target.AddEntitlement, target.Group{ExternalID: snGroup}, "sn:off"); routed {
		t.Fatal("a change was queued for a target with write-back off")
	}
	if _, _, w := fk.Counts(); w != 0 {
		t.Fatalf("writes with write-back off = %d", w)
	}

	set(true, direct)
	op, routed := submit(target.AddEntitlement, target.Group{ExternalID: snGroup}, "sn:add")
	if !routed {
		t.Fatal("not routed with write-back on")
	}
	if st := e.run(); st.Verified != 1 || len(fk.Rows("sys_user_grmember", "user", snUserID, "group", snGroup)) != 1 {
		t.Fatalf("add: stats %+v, op %+v", st, e.op(op.ID))
	}
	op, _ = submit(target.DisableAccount, target.Group{}, "sn:disable")
	if st := e.run(); st.Verified != 1 {
		t.Fatalf("disable: stats %+v, op %+v", st, e.op(op.ID))
	}
	if u := fk.Rows("sys_user", "sys_id", snUserID)[0]; u["active"] != "false" {
		t.Errorf("user = %v", u)
	}
	fk.SetFaults(snfake.Faults{DropWrites: true})
	op, _ = submit(target.RemoveEntitlement, target.Group{ExternalID: snGroup}, "sn:drop")
	for i := 0; i < 4; i++ {
		e.run()
	}
	if got := e.op(op.ID); got.Status == provision.Verified {
		t.Errorf("a dropped write was counted as done: %+v", got)
	}

	// ticket mode: one incident per change; the change is done when a person resolves the incident
	fk.SetFaults(snfake.Faults{})
	set(true, `{"auth":"basic","username":"tessera.integration","password":"pw-1","mode":"ticket"}`)
	op, _ = submit(target.AddEntitlement, target.Group{ExternalID: "0000000000000000000000000000a002", Name: "Apps"}, "sn:ticket")
	e.run()
	inc := fk.Rows("incident")
	if len(inc) != 1 {
		t.Fatalf("incidents = %d", len(inc))
	}
	if got := e.op(op.ID); got.Status == provision.Verified {
		t.Fatalf("an open ticket was counted as done: %+v", got)
	}
	inc[0]["state"] = "6"
	fk.Set("incident", inc[0])
	for i := 0; i < 4; i++ {
		e.run()
	}
	if got := e.op(op.ID); got.Status != provision.Verified {
		t.Errorf("a resolved ticket was not counted as done: %+v", got)
	}
	if len(fk.Rows("incident")) != 1 {
		t.Errorf("a retry raised another ticket: %d", len(fk.Rows("incident")))
	}
}

// Group membership in Atlassian Cloud goes through the engine: not queued while write-back is off, sent and
// re-read once it is on; the account lifecycle is refused with a pointer to the SCIM target.
func TestEngine_AtlassianTarget(t *testing.T) {
	const account = "5b10ac8d82e05b22cc7d4ef5"
	const group = "276f955c-63d7-42c8-9520-92d01dca0625"
	e := setup(t, fake.Options{})
	fk := atfake.New("tessera@acme.example", "tok-1", "", "")
	fk.Users = []atfake.User{{AccountID: account, Type: "atlassian", Email: "bob@acme.example", Name: "Bob", Active: true}}
	fk.Groups = []atfake.Group{{ID: group, Name: "developers"}}
	srv := connsynctest.New(t, fk)
	hc, err := safehttp.NewForTest(t, srv.Options(0))
	if err != nil {
		t.Fatal(err)
	}
	e.eng.HTTP, e.eng.Runtime = hc, connsynctest.Runtime
	id := store.NewID()
	set := func(writeBack bool) {
		e.inA(func(c *store.TenantTx) error {
			if old, err := c.ProvTarget(e.conn); err == nil {
				id = old.ID
			}
			enc, _ := provision.SealToken(e.sealer, e.f.A.ID, id, `{"email":"tessera@acme.example","api_token":"tok-1"}`)
			return c.UpsertProvTarget(&store.ProvTarget{ID: id, ConnectionID: e.conn, Kind: provision.KindAtlassian, BaseURL: srv.URL, Settings: "{}",
				CredentialEnc: enc, WriteBack: writeBack, CreatedBy: "admin"}, e.now)
		})
	}
	submit := func(k string, g target.Group, key string) (op *store.ProvOp, routed bool) {
		e.inA(func(c *store.TenantTx) (err error) {
			op, routed, err = provision.Submit(c, e.now, provision.Change{System: e.system, Kind: k, Account: target.Account{Username: "bob@acme.example", ExternalID: account},
				Group: g, Source: provision.SourceJML, Key: key})
			return
		})
		return
	}
	set(false)
	if _, routed := submit(target.AddEntitlement, target.Group{ExternalID: group}, "at:off"); routed {
		t.Fatal("a change was queued for a target with write-back off")
	}
	if _, w, _ := fk.Counts(); w != 0 {
		t.Fatalf("writes with write-back off = %d", w)
	}
	set(true)
	op, routed := submit(target.AddEntitlement, target.Group{ExternalID: group}, "at:add")
	if !routed {
		t.Fatal("not routed with write-back on")
	}
	if st := e.run(); st.Verified != 1 || len(fk.MembersOf(group)) != 1 {
		t.Fatalf("add: stats %+v, op %+v", st, e.op(op.ID))
	}
	op, _ = submit(target.DisableAccount, target.Group{}, "at:disable")
	for i := 0; i < 3; i++ {
		e.run()
	}
	got := e.op(op.ID)
	if got.Status != provision.Failed || got.LastError == nil || !strings.Contains(*got.LastError, "SCIM") {
		t.Errorf("an account lifecycle change was not refused with a pointer to SCIM: %+v", got)
	}
}
