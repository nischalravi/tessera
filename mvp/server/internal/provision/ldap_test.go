package provision_test

import (
	"encoding/json"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/ldapwrite"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/ldapwrite/ldapfake"
	"github.com/nischalravi/tessera/mvp/server/internal/provision"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/fake"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
	"github.com/nischalravi/tessera/mvp/server/internal/safedial"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// An LDAP account create and a group add go through the engine like any other change (issue #586):
// not queued while write-back is off, then sent over the guarded dialer and re-read once it is on.
func TestEngine_LDAPTarget(t *testing.T) {
	const base = "dc=acme,dc=example"
	e := setup(t, fake.Options{})
	fk := ldapfake.New(t)
	fk.BindUser("cn=svc,"+base, token)
	for _, dn := range []string{base, "ou=People," + base, "ou=Groups," + base} {
		fk.Put(dn, map[string][]string{"objectClass": {"organizationalUnit"}})
	}
	fk.Put("cn=staff,ou=Groups,"+base, map[string][]string{"objectClass": {"groupOfNames"}, "cn": {"staff"}, "member": {"uid=seed,ou=People," + base}})
	e.eng.LDAPDialer = func() (*safedial.Dialer, error) {
		return safedial.New(safedial.Options{Env: "dev", RootCAs: fk.CA(), Resolver: ldapfake.Resolver{}, TestDial: fk.DialFunc})
	}
	e.eng.Runtime.Env = "dev"
	cfg := ldapwrite.Config{Flavor: "ldap", Host: ldapfake.Host, BindDN: "cn=svc," + base, WriteScope: []string{"ou=People," + base, "ou=Groups," + base},
		UserBase: "ou=People," + base, UserDNTemplate: "uid=${account},ou=People," + base,
		UserAttrs: map[string]string{"uid": "${account}", "cn": "${user.display_name}", "sn": "${user.display_name}", "employeeNumber": "${user.external_id}"},
		MatchAttr: "employeeNumber", UniqueAttrs: []string{"uid"}, GroupBase: "ou=Groups," + base}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	id := store.NewID()
	set := func(writeBack bool) {
		e.inA(func(c *store.TenantTx) error {
			if old, err := c.ProvTarget(e.conn); err == nil {
				id = old.ID
			}
			enc, _ := provision.SealToken(e.sealer, e.f.A.ID, id, token)
			return c.UpsertProvTarget(&store.ProvTarget{ID: id, ConnectionID: e.conn, Kind: provision.KindLDAP, BaseURL: "ldaps://" + ldapfake.Host + ":636",
				Settings: mustJSON(provision.Settings{LDAP: &cfg}), CredentialEnc: enc, WriteBack: writeBack, CreatedBy: "admin"}, e.now)
		})
	}
	acct := target.Account{Username: "bob", DisplayName: "Bob Jones", ExternalID: "E100"}
	submit := func(k string, g target.Group, key string) (op *store.ProvOp, routed bool) {
		e.inA(func(c *store.TenantTx) (err error) {
			op, routed, err = provision.Submit(c, e.now, provision.Change{System: e.system, Kind: k, Account: acct, Group: g, Source: provision.SourceJML, Key: key})
			return
		})
		return
	}
	set(false)
	if _, routed := submit(target.CreateAccount, target.Group{}, "ldap:off"); routed || fk.Writes() != 0 {
		t.Fatal("a change was queued or sent for a target with write-back off")
	}
	set(true)
	op, routed := submit(target.CreateAccount, target.Group{}, "ldap:create")
	if !routed {
		t.Fatal("not routed with write-back on")
	}
	if st := e.run(); st.Verified != 1 {
		t.Fatalf("create: stats %+v, op %+v", st, e.op(op.ID))
	}
	if _, ok := fk.Get("uid=bob,ou=People," + base); !ok {
		t.Fatal("the account was not created")
	}
	op, _ = submit(target.AddEntitlement, target.Group{Name: "staff"}, "ldap:add")
	if st := e.run(); st.Verified != 1 {
		t.Fatalf("add: stats %+v, op %+v", st, e.op(op.ID))
	}
	if g, _ := fk.Get("cn=staff,ou=Groups," + base); len(g["member"]) != 2 {
		t.Errorf("members: %v", g["member"])
	}
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}
