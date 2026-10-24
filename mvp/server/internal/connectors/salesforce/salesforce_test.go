package salesforce_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync/connsynctest"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/salesforce"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/salesforce/sffake"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

var t0 = time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)

const (
	consumerKey = "3MVG9-consumer-key"
	integration = "tessera@acme.example"
	profileStd  = "00e000000000001AAA"
	profileAdm  = "00e000000000002AAA"
	roleCEO     = "00E000000000001AAA"
	psReports   = "0PS000000000001AAA"
	psApex      = "0PS000000000002AAA"
	psOwned     = "0PS000000000003AAA"
	psGenGroup  = "0PS000000000004AAA"
	psgSales    = "0PG000000000001AAA"
	uAda        = "005000000000001AAA"
	uBo         = "005000000000002AAA"
	uSvc        = "005000000000003AAA"
)

func keyPEM(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustPKCS8(t, k)}))
}

func mustPKCS8(t *testing.T, k *rsa.PrivateKey) []byte {
	b, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type rig struct {
	fake *sffake.Fake
	srv  *connsynctest.Server
	c    *salesforce.Client
}

func newRig(t *testing.T) *rig {
	t.Helper()
	k, pemText := keyPEM(t)
	fk := sffake.New(consumerKey, integration, &k.PublicKey)
	fk.Now = func() time.Time { return t0 }
	fk.Set("Profile", sffake.Row{"Id": profileStd, "Name": "Standard User", "Description": "std"}, sffake.Row{"Id": profileAdm, "Name": "System Administrator"})
	fk.Set("UserRole", sffake.Row{"Id": roleCEO, "Name": "CEO"})
	fk.Set("PermissionSet",
		sffake.Row{"Id": "0PS0000000000AAAAA", "IsOwnedByProfile": true, "ProfileId": profileStd, "Type": "Profile", "PermissionsApiEnabled": true},
		sffake.Row{"Id": psOwned, "IsOwnedByProfile": true, "ProfileId": profileAdm, "Type": "Profile", "PermissionsModifyAllData": true, "PermissionsApiEnabled": true},
		sffake.Row{"Id": psReports, "Name": "Reports", "Label": "Run reports", "Type": "Regular", "PermissionsExportReport": true},
		sffake.Row{"Id": psApex, "Name": "Dev", "Label": "Apex author", "Type": "Regular", "PermissionsAuthorApex": true},
		sffake.Row{"Id": psGenGroup, "Type": "Group", "PermissionSetGroupId": psgSales})
	fk.Set("PermissionSetGroup", sffake.Row{"Id": psgSales, "DeveloperName": "Sales", "MasterLabel": "Sales team"})
	fk.Set("PermissionSetGroupComponent", sffake.Row{"PermissionSetGroupId": psgSales, "PermissionSetId": psReports})
	fk.Set("User",
		sffake.Row{"Id": uAda, "Username": "ada@acme.example", "Email": "Ada@Acme.example", "Name": "Ada A", "IsActive": true, "ProfileId": profileStd, "UserRoleId": roleCEO, "UserType": "Standard", "Title": "Rep", "LastLoginDate": "2026-10-01T08:00:00.000+0000", "CreatedDate": "2025-01-02T03:04:05.000+0000"},
		sffake.Row{"Id": uBo, "Username": "bo@acme.example", "Email": "bo@acme.example", "Name": "Bo B", "IsActive": true, "ProfileId": profileAdm, "UserType": "Standard"},
		sffake.Row{"Id": uSvc, "Username": "svc@acme.example", "Name": "Svc", "IsActive": false, "ProfileId": profileStd, "UserType": "AutomatedProcess"})
	fk.Set("UserLogin", sffake.Row{"Id": "0Yw000000000001AAA", "UserId": uAda, "IsFrozen": false}, sffake.Row{"Id": "0Yw000000000002AAA", "UserId": uBo, "IsFrozen": true})
	fk.Set("PermissionSetAssignment",
		sffake.Row{"Id": "0Pa000000000001AAA", "AssigneeId": uAda, "PermissionSetId": psReports},
		sffake.Row{"Id": "0Pa000000000002AAA", "AssigneeId": uAda, "PermissionSetId": psOwned},                                                 // profile's own set: skipped
		sffake.Row{"Id": "0Pa000000000003AAA", "AssigneeId": uBo, "PermissionSetId": psApex, "ExpirationDate": "2026-09-01T00:00:00.000+0000"}, // expired
		sffake.Row{"Id": "0Pa000000000004AAA", "AssigneeId": uBo, "PermissionSetId": psGenGroup, "PermissionSetGroupId": psgSales},
		sffake.Row{"Id": "0Pa000000000005AAA", "AssigneeId": uBo, "PermissionSetId": psReports, "PermissionSetGroupId": psgSales})
	srv := connsynctest.New(t, fk)
	hc, err := safehttp.NewForTest(t, srv.Options(0))
	if err != nil {
		t.Fatal(err)
	}
	c, err := salesforce.Open(salesforce.Config{BaseURL: srv.URL, ClientID: consumerKey, Username: integration, PrivateKey: connsync.NewSecret(pemText)},
		connsynctest.Runtime, hc, func() time.Time { return t0 })
	if err != nil {
		t.Fatal(err)
	}
	return &rig{fk, srv, c}
}

func edgeSet(res *connectors.DiscoveryResult, rel string) map[string]bool {
	out := map[string]bool{}
	for _, e := range res.Edges {
		if e.Relation == rel {
			out[e.Src.ExternalID+" -> "+e.Dst.ExternalID] = true
		}
	}
	return out
}

func TestDiscover(t *testing.T) {
	r := newRig(t)
	res, err := salesforce.NewConnector(r.c, func() time.Time { return t0 }).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	kind, priv := map[string]string{}, map[string]bool{}
	for _, g := range res.Groups {
		kind[g.ExternalID], priv[g.ExternalID] = g.Kind, g.Privileged
	}
	wantKind := map[string]string{profileStd: salesforce.KindProfile, profileAdm: salesforce.KindProfile, roleCEO: salesforce.KindRole,
		psReports: salesforce.KindPermSet, psApex: salesforce.KindPermSet, psgSales: salesforce.KindPSG}
	if len(kind) != len(wantKind) {
		t.Errorf("groups = %v (owned and generated sets must not be groups)", kind)
	}
	for id, k := range wantKind {
		if kind[id] != k {
			t.Errorf("group %s kind %q, want %q", id, kind[id], k)
		}
	}
	if !priv[profileAdm] || !priv[psApex] || priv[profileStd] || priv[psReports] || priv[psgSales] {
		t.Errorf("privileged = %v", priv)
	}
	grants := edgeSet(res, "grants")
	for _, want := range []string{profileAdm + " -> sf:ModifyAllData", profileAdm + " -> sf:ApiEnabled", psApex + " -> sf:AuthorApex", psReports + " -> sf:ExportReport"} {
		if !grants[want] {
			t.Errorf("missing grants %q in %v", want, grants)
		}
	}
	member := edgeSet(res, "member_of")
	for _, want := range []string{uAda + " -> " + profileStd, uAda + " -> " + roleCEO, uAda + " -> " + psReports, uBo + " -> " + profileAdm, uBo + " -> " + psgSales, psgSales + " -> " + psReports} {
		if !member[want] {
			t.Errorf("missing member_of %q in %v", want, member)
		}
	}
	if member[uBo+" -> "+psApex] || member[uAda+" -> "+psOwned] || member[uBo+" -> "+psReports] {
		t.Errorf("member_of = %v (expired, profile-owned and group-component assignments are not direct)", member)
	}
	acct := map[string]connectors.AccountRecord{}
	for _, a := range res.Accounts {
		acct[a.ExternalID] = a
	}
	if acct[uAda].Status != "active" || acct[uBo].Status != "disabled" || acct[uSvc].Status != "disabled" || acct[uSvc].Kind != "service" || acct[uAda].Kind != "user" {
		t.Errorf("accounts = %+v", acct)
	}
	if a := acct[uAda]; a.Identity == nil || a.Identity.Email != "ada@acme.example" || a.LastLoginAt == nil || a.Attributes["Title"] != "Rep" {
		t.Errorf("ada = %+v", a)
	}
	priv2 := map[string]bool{}
	for _, p := range res.Permissions {
		priv2[p.Action] = p.Privileged
		if p.ResourceExternalID != salesforce.ResOrg {
			t.Errorf("permission %+v", p)
		}
	}
	if !priv2["ModifyAllData"] || priv2["ApiEnabled"] || len(res.Permissions) != 4 {
		t.Errorf("permissions = %v", priv2)
	}
}

func TestAuthJWT(t *testing.T) {
	r := newRig(t)
	if _, err := salesforce.NewConnector(r.c, func() time.Time { return t0 }).Discover(context.Background()); err != nil {
		t.Fatal(err)
	}
	tokens, reads, _ := r.fake.Counts()
	if tokens != 1 || reads < 8 {
		t.Errorf("tokens %d reads %d: one assertion exchange serves the whole run", tokens, reads)
	}
	for _, q := range r.srv.Requests() {
		if q.Path == "/services/oauth2/token" {
			continue
		}
		if q.Authorization != "Bearer tok-sf-fake" {
			t.Errorf("%s sent %q", q.Path, q.Authorization)
		}
	}
	// the instance_url of the token response is another host: no request may go there (the fake would not see it, and safehttp would refuse it).
	// An expired session is renewed once.
	r.fake.SetFaults(sffake.Faults{Unauthorized: 1})
	if _, err := salesforce.NewConnector(r.c, nil).Discover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if tokens, _, _ := r.fake.Counts(); tokens != 2 {
		t.Errorf("tokens after a 401 = %d, want 2", tokens)
	}
}

func TestDiscoverFaults(t *testing.T) {
	for _, tc := range []struct {
		name string
		f    sffake.Faults
		page int
		want string
	}{
		{"token refused", sffake.Faults{TokenStatus: 401}, 0, "token request"},
		{"read error", sffake.Faults{ReadStatus: 403}, 0, "403"},
		{"malformed", sffake.Faults{Malformed: true}, 0, "malformed"},
		{"bad paging link", sffake.Faults{BadNext: true}, 1, "leaves the rest api"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t)
			r.fake.PageSize = tc.page
			r.fake.SetFaults(tc.f)
			_, err := salesforce.NewConnector(r.c, nil).Discover(context.Background())
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestDiscoverPages(t *testing.T) {
	r := newRig(t)
	r.fake.PageSize = 1
	res, err := salesforce.NewConnector(r.c, func() time.Time { return t0 }).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Accounts) != 3 || len(res.Groups) != 6 {
		t.Errorf("accounts %d groups %d with one row per page", len(res.Accounts), len(res.Groups))
	}
}

func TestOpenValidation(t *testing.T) {
	k, pemText := keyPEM(t)
	_ = k
	hc, _ := safehttp.NewForTest(t, connsynctest.New(t, sffake.New("a", "b", &k.PublicKey)).Options(0))
	good := salesforce.Config{BaseURL: "https://acme.my.salesforce.com", ClientID: "k", Username: "u@x.example", PrivateKey: connsync.NewSecret(pemText)}
	if _, err := salesforce.Open(good, connsynctest.Runtime, hc, nil); err != nil {
		t.Fatalf("good config: %v", err)
	}
	for name, mut := range map[string]func(*salesforce.Config){
		"no key":        func(c *salesforce.Config) { c.PrivateKey = connsync.Secret{} },
		"not pem":       func(c *salesforce.Config) { c.PrivateKey = connsync.NewSecret("hello") },
		"no client":     func(c *salesforce.Config) { c.ClientID = "" },
		"quote in user": func(c *salesforce.Config) { c.Username = "a'b" },
		"http":          func(c *salesforce.Config) { c.BaseURL = "http://acme.my.salesforce.com" },
		"path":          func(c *salesforce.Config) { c.BaseURL = "https://acme.my.salesforce.com/x" },
		"credentials":   func(c *salesforce.Config) { c.BaseURL = "https://u:p@acme.my.salesforce.com" },
		"bad login url": func(c *salesforce.Config) { c.LoginURL = "ftp://x" },
		"bad api":       func(c *salesforce.Config) { c.APIVersion = "61" },
		"api injection": func(c *salesforce.Config) { c.APIVersion = "v61.0/../../x" },
	} {
		c := good
		mut(&c)
		if _, err := salesforce.Open(c, connsync.Runtime{Env: "prod"}, hc, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := salesforce.Open(good, connsynctest.Runtime, nil, nil); err == nil {
		t.Error("no safehttp client: accepted")
	}
}

func TestSecretNeverPrints(t *testing.T) {
	_, pemText := keyPEM(t)
	s := connsync.NewSecret(pemText)
	if strings.Contains(strings.Join([]string{s.String()}, ""), "PRIVATE") {
		t.Fatal("secret prints")
	}
}

func TestFromEnv(t *testing.T) {
	r := newRig(t)
	_ = r
	env := map[string]string{"TESSERA_SALESFORCE_BASE_URL": "https://acme.my.salesforce.com", "TESSERA_SALESFORCE_CLIENT_ID": "k",
		"TESSERA_SALESFORCE_USERNAME": "u@x.example", "TESSERA_SALESFORCE_PRIVATE_KEY": "env:SF_KEY"}
	get := func(k string) string { return env[k] }
	hc, _ := safehttp.NewForTest(t, r.srv.Options(0))
	if _, err := salesforce.FromEnv(get, connsynctest.Runtime, hc, nil); err == nil || !strings.Contains(err.Error(), "PRIVATE_KEY") {
		t.Errorf("unset key: %v", err)
	}
	_, pemText := keyPEM(t)
	env["SF_KEY"] = pemText
	c, err := salesforce.FromEnv(get, connsynctest.Runtime, hc, nil)
	if err != nil || c.System() != "salesforce" || c.TypeName() != "SalesforceConnector" {
		t.Fatalf("FromEnv: %v %v", c, err)
	}
}

func apply(t *testing.T, tg *salesforce.Target, r target.Request) {
	t.Helper()
	if err := tg.Apply(context.Background(), r); err != nil {
		t.Fatalf("%s: %v", r.Kind, err)
	}
	v, err := tg.Verify(context.Background(), r)
	if err != nil || !v.OK {
		t.Fatalf("%s verify: %+v %v", r.Kind, v, err)
	}
}

func TestTargetLifecycle(t *testing.T) {
	r := newRig(t)
	tg := &salesforce.Target{C: r.c, DefaultProfileID: profileStd}
	ctx := context.Background()

	// create, then again: one user
	create := target.Request{Kind: target.CreateAccount, Account: target.Account{Username: "new@acme.example", Email: "new@acme.example", DisplayName: "Nia New", Attrs: map[string]string{"Title": "Rep"}}}
	apply(t, tg, create)
	apply(t, tg, create)
	rows := r.fake.Rows("User", "Username", "new@acme.example")
	if len(rows) != 1 || rows[0]["LastName"] != "New" || rows[0]["FirstName"] != "Nia" || rows[0]["ProfileId"] != profileStd || rows[0]["Title"] != "Rep" || rows[0]["Alias"] != "nianew" {
		t.Fatalf("created users = %v", rows)
	}
	newID := rows[0]["Id"].(string)

	// update
	upd := target.Request{Kind: target.UpdateAccount, Account: target.Account{Username: "new@acme.example", Attrs: map[string]string{"Department": "Sales", "UserRoleId": roleCEO}}}
	apply(t, tg, upd)
	if u := r.fake.Rows("User", "Id", newID)[0]; u["Department"] != "Sales" || u["UserRoleId"] != roleCEO {
		t.Errorf("updated user = %v", u)
	}
	_, _, w := r.fake.Counts()
	apply(t, tg, upd)
	if _, _, w2 := r.fake.Counts(); w2 != w {
		t.Error("an update that changes nothing wrote")
	}

	// permission set and group assignment, add twice, remove twice
	for _, g := range []string{psApex, psgSales} {
		add := target.Request{Kind: target.AddEntitlement, Account: target.Account{Username: "new@acme.example"}, Group: target.Group{ExternalID: g}}
		apply(t, tg, add)
		apply(t, tg, add)
	}
	if n := len(r.fake.Rows("PermissionSetAssignment", "AssigneeId", newID)); n != 3 { // apex, group set, component
		t.Errorf("assignments = %d, want 3", n)
	}
	for _, g := range []string{psApex, psgSales} {
		rm := target.Request{Kind: target.RemoveEntitlement, Account: target.Account{ExternalID: newID}, Group: target.Group{ExternalID: g}}
		apply(t, tg, rm)
		apply(t, tg, rm)
	}
	if n := len(r.fake.Rows("PermissionSetAssignment", "AssigneeId", newID)); n != 0 {
		t.Errorf("assignments left = %d", n)
	}

	// disable freezes and deactivates; delete does the same
	for _, k := range []string{target.DisableAccount, target.DeleteAccount} {
		apply(t, tg, target.Request{Kind: k, Account: target.Account{Username: "ada@acme.example"}})
	}
	if u := r.fake.Rows("User", "Id", uAda)[0]; u["IsActive"] != false {
		t.Errorf("ada = %v", u)
	}
	if l := r.fake.Rows("UserLogin", "UserId", uAda)[0]; l["IsFrozen"] != true {
		t.Errorf("login = %v", l)
	}
	// disabling a user the org does not have is done
	apply(t, tg, target.Request{Kind: target.DisableAccount, Account: target.Account{Username: "ghost@acme.example"}})
	_ = ctx
}

func TestTargetRefusals(t *testing.T) {
	r := newRig(t)
	tg := &salesforce.Target{C: r.c}
	ctx := context.Background()
	acct := target.Account{Username: "ada@acme.example"}
	for name, req := range map[string]target.Request{
		"no profile":          {Kind: target.CreateAccount, Account: target.Account{Username: "x@acme.example", Email: "x@acme.example"}},
		"no email":            {Kind: target.CreateAccount, Account: target.Account{Username: "x@acme.example", Attrs: map[string]string{"ProfileId": profileStd}}},
		"bad attribute":       {Kind: target.UpdateAccount, Account: target.Account{Username: acct.Username, Attrs: map[string]string{"IsActive": "false"}}},
		"bad profile id":      {Kind: target.UpdateAccount, Account: target.Account{Username: acct.Username, Attrs: map[string]string{"ProfileId": "x' OR '1"}}},
		"no attributes":       {Kind: target.UpdateAccount, Account: acct},
		"update missing user": {Kind: target.UpdateAccount, Account: target.Account{Username: "ghost@acme.example", Attrs: map[string]string{"Title": "x"}}},
		"profile as grant":    {Kind: target.AddEntitlement, Account: acct, Group: target.Group{ExternalID: profileAdm}},
		"role as grant":       {Kind: target.AddEntitlement, Account: acct, Group: target.Group{ExternalID: roleCEO}},
		"no group":            {Kind: target.AddEntitlement, Account: acct},
		"grant to missing":    {Kind: target.AddEntitlement, Account: target.Account{Username: "ghost@acme.example"}, Group: target.Group{ExternalID: psApex}},
		"injection":           {Kind: target.DisableAccount, Account: target.Account{Username: "a' OR Username != '"}},
		"no account":          {Kind: target.DisableAccount},
		"unknown kind":        {Kind: "rename", Account: acct},
	} {
		err := tg.Apply(ctx, req)
		if err == nil || target.Retryable(err) {
			t.Errorf("%s: want a permanent error, got %v", name, err)
		}
	}
	if _, _, w := r.fake.Counts(); w != 0 {
		t.Errorf("a refused request wrote %d times", w)
	}
}

func TestTargetWriteFaults(t *testing.T) {
	r := newRig(t)
	tg := &salesforce.Target{C: r.c, DefaultProfileID: profileStd}
	ctx := context.Background()
	add := target.Request{Kind: target.AddEntitlement, Account: target.Account{Username: "ada@acme.example"}, Group: target.Group{ExternalID: psApex}}

	r.fake.SetFaults(sffake.Faults{WriteStatus: 503})
	if err := tg.Apply(ctx, add); err == nil || !target.Retryable(err) {
		t.Errorf("503: want a retryable error, got %v", err)
	}
	r.fake.SetFaults(sffake.Faults{WriteStatus: 400})
	if err := tg.Apply(ctx, add); err == nil || target.Retryable(err) {
		t.Errorf("400: want a permanent error, got %v", err)
	}
	// a write the org accepts and drops is caught by the re-read
	r.fake.SetFaults(sffake.Faults{DropWrites: true})
	if err := tg.Apply(ctx, add); err != nil {
		t.Fatal(err)
	}
	if v, err := tg.Verify(ctx, add); err != nil || v.OK {
		t.Errorf("dropped write verified: %+v %v", v, err)
	}
	dis := target.Request{Kind: target.DisableAccount, Account: target.Account{Username: "ada@acme.example"}}
	if err := tg.Apply(ctx, dis); err != nil {
		t.Fatal(err)
	}
	if v, err := tg.Verify(ctx, dis); err != nil || v.OK {
		t.Errorf("dropped disable verified: %+v %v", v, err)
	}
}
