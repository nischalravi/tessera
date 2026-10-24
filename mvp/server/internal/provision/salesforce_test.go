package provision_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync/connsynctest"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/salesforce/sffake"
	"github.com/nischalravi/tessera/mvp/server/internal/provision"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/fake"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// A permission-set assignment and a deactivation in Salesforce go through the engine like any other change
// (issue #555): not queued while write-back is off, then sent and re-read once it is on.
func TestEngine_SalesforceTarget(t *testing.T) {
	const (
		userID = "005000000000001AAA"
		psID   = "0PS000000000001AAA"
	)
	e := setup(t, fake.Options{})
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	cred, _ := json.Marshal(salesforceCred{ClientID: "3MVG9-key", Username: "tessera@acme.example", PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))})
	fk := sffake.New("3MVG9-key", "tessera@acme.example", &k.PublicKey)
	fk.Now = e.eng.Clock
	fk.Set("User", sffake.Row{"Id": userID, "Username": "bob@acme.example", "IsActive": true})
	fk.Set("UserLogin", sffake.Row{"Id": "0Yw000000000001AAA", "UserId": userID, "IsFrozen": false})
	fk.Set("PermissionSet", sffake.Row{"Id": psID, "Type": "Regular"})
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
			enc, _ := provision.SealToken(e.sealer, e.f.A.ID, id, string(cred))
			return c.UpsertProvTarget(&store.ProvTarget{ID: id, ConnectionID: e.conn, Kind: provision.KindSalesforce, BaseURL: srv.URL, Settings: "{}",
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

	set(false)
	if _, routed := submit(target.AddEntitlement, target.Group{ExternalID: psID}, "sf:off"); routed {
		t.Fatal("a change was queued for a target with write-back off")
	}
	if _, _, w := fk.Counts(); w != 0 {
		t.Fatalf("writes with write-back off = %d", w)
	}

	set(true)
	op, routed := submit(target.AddEntitlement, target.Group{ExternalID: psID}, "sf:add")
	if !routed {
		t.Fatal("not routed with write-back on")
	}
	if st := e.run(); st.Verified != 1 || len(fk.Rows("PermissionSetAssignment", "AssigneeId", userID)) != 1 {
		t.Fatalf("add: stats %+v, op %+v", st, e.op(op.ID))
	}
	op, _ = submit(target.DisableAccount, target.Group{}, "sf:disable")
	if st := e.run(); st.Verified != 1 {
		t.Fatalf("disable: stats %+v, op %+v", st, e.op(op.ID))
	}
	if u := fk.Rows("User", "Id", userID)[0]; u["IsActive"] != false {
		t.Errorf("user = %v", u)
	}
	// a org that accepts a write and drops it is not counted as done
	fk.SetFaults(sffake.Faults{DropWrites: true})
	op, _ = submit(target.RemoveEntitlement, target.Group{ExternalID: psID}, "sf:drop")
	for i := 0; i < 4; i++ {
		e.run()
	}
	if got := e.op(op.ID); got.Status == provision.Verified {
		t.Errorf("a dropped write was counted as done: %+v", got)
	}
}

type salesforceCred struct {
	ClientID   string `json:"client_id"`
	Username   string `json:"username"`
	PrivateKey string `json:"private_key"`
}
