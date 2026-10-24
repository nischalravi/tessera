package ldapwrite_test

import (
	"context"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/ldapwrite"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/ldapwrite/ldapfake"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
	"github.com/nischalravi/tessera/mvp/server/internal/safedial"
)

const (
	base     = "dc=acme,dc=example"
	people   = "ou=People," + base
	disabled = "ou=Disabled," + base
	groups   = "ou=Groups," + base
	bindDN   = "cn=svc-tessera," + base
	bindPW   = "bind-pw-Zx81"
)

func ldapConfig(port int) ldapwrite.Config {
	return ldapwrite.Config{
		Flavor: "ldap", Host: ldapfake.Host, Port: port, BindDN: bindDN,
		WriteScope: []string{people, groups, disabled}, UserBase: base,
		UserDNTemplate: "uid=${account},ou=People," + base,
		UserAttrs: map[string]string{"uid": "${account}", "cn": "${user.display_name}", "sn": "${user.last_name}",
			"mail": "${user.email}", "employeeNumber": "${user.external_id}"},
		MatchAttr:    "employeeNumber",
		AccountNames: []string{"${user.username}", "${user.username}${user.external_id}"},
		UniqueAttrs:  []string{"uid", "mail"},
		UpdateAttrs:  []string{"telephoneNumber", "title"},
		GroupBase:    groups, GroupMemberAttr: "uniqueMember",
		DisabledOU: disabled, EnabledOU: people,
		InitialPassword: true,
	}
}

func adConfig() ldapwrite.Config {
	c := ldapConfig(636)
	c.Flavor = "ad"
	c.DisableMode = ""
	c.GroupMemberAttr = "member"
	c.UserAttrs = map[string]string{"sAMAccountName": "${account}", "cn": "${user.display_name}", "mail": "${user.email}", "employeeID": "${user.external_id}"}
	c.MatchAttr, c.UniqueAttrs = "employeeID", []string{"sAMAccountName", "mail"}
	c.DisabledOU, c.EnabledOU = "", ""
	c.UserDNTemplate = "cn=${user.display_name},ou=People," + base
	return c
}

func dialer(t testing.TB, f *ldapfake.Server) *safedial.Dialer {
	t.Helper()
	d, err := safedial.New(safedial.Options{Env: "dev", RootCAs: f.CA(), Resolver: ldapfake.Resolver{}, TestDial: f.DialFunc})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

type rig struct {
	fake *ldapfake.Server
	tg   *ldapwrite.Target
	cfg  ldapwrite.Config
}

func newRig(t *testing.T, cfg ldapwrite.Config, ad bool) *rig {
	t.Helper()
	f := ldapfake.New(t)
	f.AD = ad
	f.BindUser(bindDN, bindPW)
	for _, ou := range []string{base, people, groups, disabled} {
		f.Put(ou, map[string][]string{"objectClass": {"organizationalUnit"}})
	}
	f.Put("cn=staff,"+groups, map[string][]string{"objectClass": {"groupOfUniqueNames", "group"}, "cn": {"staff"}, "uniqueMember": {"uid=seed," + people}, "member": {"uid=seed," + people}})
	tg, err := ldapwrite.NewTarget(cfg, connsync.NewSecret(bindPW), dialer(t, f))
	if err != nil {
		t.Fatal(err)
	}
	return &rig{f, tg, cfg}
}

func acct() target.Account {
	return target.Account{Username: "bob", Email: "bob@acme.example", DisplayName: "Bob Jones", ExternalID: "E100",
		Attrs: map[string]string{"last_name": "Jones"}}
}

func (r *rig) do(t *testing.T, kind string, a target.Account, g target.Group) error {
	t.Helper()
	req := target.Request{Kind: kind, Account: a, Group: g}
	if err := r.tg.Apply(context.Background(), req); err != nil {
		return err
	}
	v, err := r.tg.Verify(context.Background(), req)
	if err != nil {
		t.Fatalf("%s verify: %v", kind, err)
	}
	if !v.OK {
		t.Fatalf("%s did not verify: expected %q, saw %q", kind, v.Expected, v.Observed)
	}
	return nil
}

func TestLDAP_Lifecycle(t *testing.T) {
	r := newRig(t, ldapConfig(636), false)
	a, dn := acct(), "uid=bob,"+people
	if err := r.do(t, target.CreateAccount, a, target.Group{}); err != nil {
		t.Fatal(err)
	}
	e, ok := r.fake.Get(dn)
	if !ok || e["mail"][0] != "bob@acme.example" || e["employeenumber"][0] != "E100" {
		t.Fatalf("created entry: %v %v", e, ok)
	}
	if r.fake.Password(dn) == "" || len(r.fake.Password(dn)) < 16 {
		t.Error("no initial password was set from the policy")
	}
	// a repeat converges: nothing more is written
	w := r.fake.Writes()
	if err := r.do(t, target.CreateAccount, a, target.Group{}); err != nil || r.fake.Writes() != w {
		t.Fatalf("repeat create: %v, %d new writes", err, r.fake.Writes()-w)
	}
	// update: allow-listed attributes only
	up := a
	up.Attrs = map[string]string{"telephoneNumber": "+1 555 0100", "last_name": "x"}
	if err := r.do(t, target.UpdateAccount, up, target.Group{}); err == nil || !strings.Contains(err.Error(), "allow-list") {
		t.Fatalf("update of an attribute outside the allow-list: %v", err)
	}
	up.Attrs = map[string]string{"telephoneNumber": "+1 555 0100"}
	if err := r.do(t, target.UpdateAccount, up, target.Group{}); err != nil {
		t.Fatal(err)
	}
	if e, _ := r.fake.Get(dn); e["telephonenumber"][0] != "+1 555 0100" {
		t.Errorf("telephoneNumber: %v", e["telephonenumber"])
	}
	// groups
	g := target.Group{Name: "staff"}
	if err := r.do(t, target.AddEntitlement, a, g); err != nil {
		t.Fatal(err)
	}
	if e, _ := r.fake.Get("cn=staff," + groups); len(e["uniquemember"]) != 2 {
		t.Errorf("members after add: %v", e["uniquemember"])
	}
	if err := r.do(t, target.AddEntitlement, a, g); err != nil { // repeat
		t.Fatal(err)
	}
	if err := r.do(t, target.RemoveEntitlement, a, g); err != nil {
		t.Fatal(err)
	}
	if e, _ := r.fake.Get("cn=staff," + groups); len(e["uniquemember"]) != 1 {
		t.Errorf("members after remove: %v", e["uniquemember"])
	}
	// disable moves to the disabled OU, enable moves it back
	if err := r.do(t, target.DisableAccount, a, target.Group{}); err != nil {
		t.Fatal(err)
	}
	moved := "uid=bob," + disabled
	if e, ok := r.fake.Get(moved); !ok || e["nsaccountlock"][0] != "true" {
		t.Fatalf("disabled entry: %v %v", e, ok)
	}
	if _, ok := r.fake.Get(dn); ok {
		t.Error("the entry is still in the enabled OU")
	}
	en := a
	en.Attrs = map[string]string{ldapwrite.AttrEnabled: "true"}
	if err := r.do(t, target.UpdateAccount, en, target.Group{}); err != nil {
		t.Fatal(err)
	}
	if e, ok := r.fake.Get(dn); !ok || len(e["nsaccountlock"]) != 0 {
		t.Fatalf("enabled entry: %v %v", e, ok)
	}
	// delete
	if err := r.do(t, target.DeleteAccount, a, target.Group{}); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.fake.Get(dn); ok {
		t.Error("the entry was not deleted")
	}
	if err := r.do(t, target.DeleteAccount, a, target.Group{}); err != nil { // already gone
		t.Fatal(err)
	}
}

func TestLDAP_CandidateNamesAndUniqueness(t *testing.T) {
	r := newRig(t, ldapConfig(636), false)
	// "bob" belongs to somebody else (other employee number): the second candidate is used
	r.fake.Put("uid=bob,"+people, map[string][]string{"objectClass": {"inetOrgPerson"}, "uid": {"bob"}, "employeeNumber": {"E999"}, "mail": {"other@acme.example"}})
	if err := r.do(t, target.CreateAccount, acct(), target.Group{}); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.fake.Get("uid=bobE100," + people); !ok {
		t.Error("the second candidate name was not used")
	}
	// the mail address is taken by another account under any name: no candidate is unique
	r.fake.Put("uid=zed,"+people, map[string][]string{"objectClass": {"inetOrgPerson"}, "uid": {"zed"}, "employeeNumber": {"E5"}, "mail": {"carol@acme.example"}})
	c := acct()
	c.Username, c.Email, c.ExternalID = "carol", "carol@acme.example", "E200"
	w := r.fake.Writes()
	err := r.tg.Apply(context.Background(), target.Request{Kind: target.CreateAccount, Account: c})
	if err == nil || !strings.Contains(err.Error(), "unique") || r.fake.Writes() != w {
		t.Fatalf("no free name: %v, %d writes", err, r.fake.Writes()-w)
	}
}

func TestLDAP_WriteScopeAndInjection(t *testing.T) {
	r := newRig(t, ldapConfig(636), false)
	// an entry outside the named OUs matches by employee number: it is never written
	outside := "uid=eve,ou=Admins," + base
	r.fake.Put("ou=Admins,"+base, map[string][]string{"objectClass": {"organizationalUnit"}})
	r.fake.Put(outside, map[string][]string{"objectClass": {"inetOrgPerson"}, "uid": {"eve"}, "employeeNumber": {"E666"}})
	a := target.Account{Username: "eve", Email: "eve@acme.example", DisplayName: "Eve", ExternalID: "E666"}
	before := r.fake.Writes()
	_ = r.tg.Apply(context.Background(), target.Request{Kind: target.DeleteAccount, Account: a})
	if _, ok := r.fake.Get(outside); !ok || r.fake.Writes() != before {
		t.Error("an entry outside the write scope was changed")
	}
	// a username that tries to add an RDN or break the DN is refused before anything is sent
	for _, name := range []string{"x,ou=Admins," + "dc=acme", "a+uid=b", `a"b`, "a\nb", "a\x00b"} {
		bad := acct()
		bad.Username, bad.ExternalID, bad.Email = name, "E7"+strings.ToUpper(name[:1]), "z@acme.example"
		err := r.tg.Apply(context.Background(), target.Request{Kind: target.CreateAccount, Account: bad})
		if r.fake.Writes() != before {
			// escaping makes a harmless literal name; it must still be one RDN below People
			for _, op := range r.fake.Ops() {
				if op.Kind == "add" && !strings.HasSuffix(strings.ToLower(op.DN), ",ou=people,"+base) {
					t.Fatalf("name %q produced an add at %q", name, op.DN)
				}
			}
		}
		_ = err
	}
	// a filter metacharacter in a lookup value matches nothing instead of everything
	f := acct()
	f.ExternalID = "*)(uid=*"
	if err := r.tg.Apply(context.Background(), target.Request{Kind: target.DisableAccount, Account: f}); err == nil {
		t.Error("a wildcard employee number matched an account")
	}
	// the group outside the scope
	r.fake.Put("cn=wheel,ou=Admins,"+base, map[string][]string{"objectClass": {"groupOfUniqueNames"}, "uniqueMember": {"uid=x"}})
	if err := r.do(t, target.CreateAccount, acct(), target.Group{}); err != nil {
		t.Fatal(err)
	}
	w := r.fake.Writes()
	err := r.tg.Apply(context.Background(), target.Request{Kind: target.AddEntitlement, Account: acct(), Group: target.Group{ExternalID: "cn=wheel,ou=Admins," + base}})
	if err == nil || r.fake.Writes() != w {
		t.Errorf("a group outside the write scope: %v", err)
	}
}

func TestLDAP_ErrorsAreFixedText(t *testing.T) {
	r := newRig(t, ldapConfig(636), false)
	r.fake.DenyWrites = true
	a := acct()
	a.Username = "secret-user-name"
	a.DisplayName = "Secret Person"
	err := r.tg.Apply(context.Background(), target.Request{Kind: target.CreateAccount, Account: a})
	if err == nil || target.Retryable(err) {
		t.Fatalf("denied write: %v", err)
	}
	for _, leak := range []string{"secret-user-name", "Secret Person", bindPW, "E100"} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("the error carries %q: %v", leak, err)
		}
	}
}

func TestLDAP_StartTLSAndBind(t *testing.T) {
	r := newRig(t, ldapConfig(389), false) // StartTLS on 389
	if err := r.do(t, target.CreateAccount, acct(), target.Group{}); err != nil {
		t.Fatal(err)
	}
	tls := false
	for _, op := range r.fake.Ops() {
		if op.Kind == "starttls" {
			tls = true
		}
		if op.Kind == "bind" && !op.Secure {
			t.Fatal("a bind was sent on a clear connection")
		}
		if op.Kind == "bind" && !tls {
			t.Fatal("a bind came before StartTLS")
		}
	}
	// a wrong bind password is a permanent error with fixed text
	f := ldapfake.New(t)
	f.BindUser(bindDN, "another")
	tg, _ := ldapwrite.NewTarget(ldapConfig(636), connsync.NewSecret(bindPW), dialer(t, f))
	err := tg.Apply(context.Background(), target.Request{Kind: target.DisableAccount, Account: acct()})
	if err == nil || target.Retryable(err) || strings.Contains(err.Error(), bindPW) {
		t.Errorf("bad bind: %v", err)
	}
}

func TestAD_Lifecycle(t *testing.T) {
	r := newRig(t, adConfig(), true)
	a, dn := acct(), "cn=Bob Jones,"+people
	if err := r.do(t, target.CreateAccount, a, target.Group{}); err != nil {
		t.Fatal(err)
	}
	e, _ := r.fake.Get(dn)
	if e["useraccountcontrol"][0] != "512" || e["pwdlastset"][0] != "0" {
		t.Fatalf("created AD entry: %v", e)
	}
	pw := r.fake.Password(dn)
	if len(pw) < 16 {
		t.Fatalf("unicodePwd was not set from the policy (len %d)", len(pw))
	}
	if err := r.do(t, target.DisableAccount, a, target.Group{}); err != nil {
		t.Fatal(err)
	}
	if e, _ := r.fake.Get(dn); e["useraccountcontrol"][0] != "514" {
		t.Errorf("uac after disable: %v", e["useraccountcontrol"])
	}
	en := a
	en.Attrs = map[string]string{ldapwrite.AttrEnabled: "true"}
	if err := r.do(t, target.UpdateAccount, en, target.Group{}); err != nil {
		t.Fatal(err)
	}
	if e, _ := r.fake.Get(dn); e["useraccountcontrol"][0] != "512" {
		t.Errorf("uac after enable: %v", e["useraccountcontrol"])
	}
	// password reset is off unless the target allows it
	rs := a
	rs.Attrs = map[string]string{ldapwrite.AttrPassword: "reset"}
	if err := r.tg.Apply(context.Background(), target.Request{Kind: target.UpdateAccount, Account: rs}); err == nil {
		t.Fatal("a reset was sent although the target does not allow it")
	}
	cfg := adConfig()
	cfg.AllowPasswordReset = true
	r2 := newRig(t, cfg, true)
	if err := r2.do(t, target.CreateAccount, a, target.Group{}); err != nil {
		t.Fatal(err)
	}
	first := r2.fake.Password(dn)
	if err := r2.do(t, target.UpdateAccount, rs, target.Group{}); err != nil {
		t.Fatal(err)
	}
	if second := r2.fake.Password(dn); second == first || len(second) < 16 {
		t.Error("the password was not replaced")
	}
	// group membership by DN
	if err := r.do(t, target.AddEntitlement, a, target.Group{Name: "staff"}); err != nil {
		t.Fatal(err)
	}
	if e, _ := r.fake.Get("cn=staff," + groups); !contains(e["member"], dn) {
		t.Errorf("members: %v", e["member"])
	}
}

func contains(l []string, v string) bool {
	for _, x := range l {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}

func TestOtherModes(t *testing.T) {
	for _, tc := range []struct {
		mode, attr, value string
		check             func(map[string][]string) bool
	}{
		{"ppolicy", "", "", func(e map[string][]string) bool { return e["pwdaccountlockedtime"][0] == "000001010000Z" }},
		{"attribute", "carLicense", "OFF", func(e map[string][]string) bool { return e["carlicense"][0] == "OFF" }},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			cfg := ldapConfig(636)
			cfg.DisableMode, cfg.DisableAttr, cfg.DisableValue, cfg.DisabledOU, cfg.EnabledOU = tc.mode, tc.attr, tc.value, "", ""
			r := newRig(t, cfg, false)
			if err := r.do(t, target.CreateAccount, acct(), target.Group{}); err != nil {
				t.Fatal(err)
			}
			if err := r.do(t, target.DisableAccount, acct(), target.Group{}); err != nil {
				t.Fatal(err)
			}
			if e, _ := r.fake.Get("uid=bob," + people); !tc.check(e) {
				t.Errorf("entry: %v", e)
			}
		})
	}
}
