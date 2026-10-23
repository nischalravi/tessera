package perms_test

import (
	"context"
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/attrs"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/perms"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/pit"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// world is tenant B with roles app:payroll (Alice and Ivan are direct members)
// and app:staff (Pat is a direct member, and app:payroll is nested in it, so
// Alice and Ivan reach it by nesting), a permission definition app:perms with
// resources ledger (which implies entry) and entry and actions read and write
// (write implies read), and the limit definitions app:limits (strings) and
// app:limitsInt (integers).
type world struct {
	f                     *storetest.Fixture
	payroll, staff        store.GroupID
	alice, ivan, pat      int64
	perms, limits, limInt *store.GrpAttrDef
	ledger, entry         *store.GrpAttrName
	read, write           *store.GrpAttrAction
	ip, window, expr, amt *store.GrpAttrName
	aliceInPayroll        string // the membership row ids
	ivanInPayroll         string
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{f: storetest.TwoTenants(t)}
	w.tx(t, storetest.Now, func(c *store.TenantTx, e attrs.Env) {
		me := model.Env{Tx: c, Now: storetest.Now, TenantAdmin: true}
		app, err := me.CreateFolder(model.CreateFolderInput{Extension: "app"})
		must(t, err)
		group := func(ext string) store.GroupID {
			g, err := me.CreateGroup(model.CreateGroupInput{Folder: app.ID, Extension: ext})
			must(t, err)
			return g.ID
		}
		w.payroll, w.staff = group("payroll"), group("staff")
		ident := func(n string) int64 {
			id, err := c.InsertIdentity(&store.Identity{ExternalID: n, Name: n, Type: "person", Status: "active", CreatedAt: storetest.Now})
			must(t, err)
			return id
		}
		w.alice, w.ivan, w.pat = ident("Alice"), ident("Ivan"), ident("Pat")
		add := func(g store.GroupID, in model.MemberInput) string {
			r, err := me.AddMember(g, in)
			must(t, err)
			return r.Member.ID
		}
		w.aliceInPayroll = add(w.payroll, model.MemberInput{Identity: &w.alice})
		w.ivanInPayroll = add(w.payroll, model.MemberInput{Identity: &w.ivan})
		add(w.staff, model.MemberInput{Identity: &w.pat})
		add(w.staff, model.MemberInput{Group: w.payroll})

		mk := func(ext, typ, vt string, multi bool, to ...string) *store.GrpAttrDef {
			d, err := attrs.CreateDef(e, attrs.DefInput{Folder: app.ID, Extension: ext, AttrType: typ, ValueType: vt,
				MultiAssign: multi, MultiValued: vt != store.AttrValueMarker, AssignTo: to})
			must(t, err)
			return d
		}
		w.perms = mk("perms", store.AttrTypePerm, store.AttrValueMarker, true, store.AttrOwnerGroup, store.AttrOwnerMembership)
		w.limits = mk("limits", store.AttrTypeLimit, store.AttrValueString, true, store.AttrOwnerAssignment)
		w.limInt = mk("limitsInt", store.AttrTypeLimit, store.AttrValueInteger, true, store.AttrOwnerAssignment)
		nm := func(d *store.GrpAttrDef, ext string) *store.GrpAttrName {
			n, err := attrs.CreateName(e, attrs.NameInput{Def: d.ID, Extension: ext})
			must(t, err)
			return n
		}
		w.ledger, w.entry = nm(w.perms, "ledger"), nm(w.perms, "entry")
		w.ip, w.window, w.expr, w.amt = nm(w.limits, "ipOnNetwork"), nm(w.limits, "timeWindow"), nm(w.limits, "expression"), nm(w.limInt, "amountLessThan")
		_, err = attrs.SetNameImplies(e, w.ledger.ID, []string{w.entry.ID})
		must(t, err)
		w.read, err = attrs.CreateAction(e, w.perms.ID, "read", "")
		must(t, err)
		w.write, err = attrs.CreateAction(e, w.perms.ID, "write", "")
		must(t, err)
		_, err = attrs.SetActionImplies(e, w.write.ID, []string{w.read.ID})
		must(t, err)
	})
	return w
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func (w *world) tx(t *testing.T, now time.Time, fn func(c *store.TenantTx, e attrs.Env)) {
	t.Helper()
	err := w.f.DB.InTenant(context.Background(), w.f.B.ID, func(c *store.TenantTx) error {
		fn(c, attrs.Env{Tx: c, Now: now, TenantAdmin: true})
		return nil
	})
	must(t, err)
}

func raw(vs ...string) []json.RawMessage {
	out := make([]json.RawMessage, len(vs))
	for i, v := range vs {
		out[i] = json.RawMessage(v)
	}
	return out
}

func owner(typ, id string) attrs.Owner { return attrs.Owner{Type: typ, ID: id} }

// grant assigns a permission to an owner and returns the assignment id.
func (w *world) grant(t *testing.T, e attrs.Env, o attrs.Owner, res *store.GrpAttrName, act *store.GrpAttrAction, disallow bool) string {
	t.Helper()
	a, err := attrs.Assign(e, attrs.AssignInput{Name: res.ID, Action: act.ID, Owner: o, Disallowed: disallow})
	must(t, err)
	return a.Assign.ID
}

func (w *world) limit(t *testing.T, e attrs.Env, on string, name *store.GrpAttrName, values ...string) {
	t.Helper()
	vals := make([]string, len(values))
	for i, v := range values {
		vals[i] = v
		if name.DefID == w.limits.ID {
			vals[i] = strconv.Quote(v)
		}
	}
	_, err := attrs.Assign(e, attrs.AssignInput{Name: name.ID, Owner: owner(store.AttrOwnerAssignment, on), Values: raw(vals...)})
	must(t, err)
}

func decide(t *testing.T, c *store.TenantTx, identity int64, resource, action string, ctx perms.Context, now time.Time) *perms.Decision {
	t.Helper()
	s, err := perms.Load(c)
	must(t, err)
	sub, err := perms.SubjectOf(c, identity, now)
	must(t, err)
	q, err := s.Resolve(resource, action)
	must(t, err)
	d, err := s.Decide(sub, q, ctx, now)
	must(t, err)
	return d
}

// TestLimits_EvaluatedByPDP: limits on a permission assignment compile to Cedar
// `when` conditions over context, and the decision point answers with them: an
// assignment whose limits do not hold for the request's context does not apply.
func TestLimits_EvaluatedByPDP(t *testing.T) {
	w := newWorld(t)
	now := storetest.Now
	w.tx(t, now, func(c *store.TenantTx, e attrs.Env) {
		id := w.grant(t, e, owner(store.AttrOwnerGroup, string(w.payroll)), w.ledger, w.write, false)
		w.limit(t, e, id, w.amt, "1000")
		w.limit(t, e, id, w.ip, "10.0.0.0/8", "192.168.1.0/24")
		w.limit(t, e, id, w.window, "9-17")
		w.limit(t, e, id, w.expr, `region == "emea"`)
	})
	ok := perms.Context{"amount": int64(999), "ip": "192.168.1.20", "hour": int64(9), "region": "emea"}
	with := func(k string, v any) perms.Context {
		c := perms.Context{}
		for kk, vv := range ok {
			c[kk] = vv
		}
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
		return c
	}
	w.tx(t, now, func(c *store.TenantTx, _ attrs.Env) {
		for _, tc := range []struct {
			name string
			ctx  perms.Context
			want bool
		}{
			{"all limits hold", ok, true},
			{"amount at the limit", with("amount", int64(1000)), false},
			{"amount missing", with("amount", nil), false},
			{"amount of the wrong type", with("amount", "5"), false},
			{"other network", with("ip", "11.0.0.1"), false},
			{"second network", with("ip", "10.9.9.9"), true},
			{"ip missing", with("ip", nil), false},
			{"not an address", with("ip", "ten"), false},
			{"before the window", with("hour", int64(8)), false},
			{"window end is exclusive", with("hour", int64(17)), false},
			{"window start is inclusive", with("hour", int64(9)), true},
			{"other region", with("region", "apac"), false},
			{"region missing", with("region", nil), false},
		} {
			d := decide(t, c, w.alice, "app:perms:entry", "read", tc.ctx, now) // inherited down both axes
			if d.Allowed != tc.want {
				t.Errorf("%s: allowed = %v (%s), want %v", tc.name, d.Allowed, d.Reason, tc.want)
			}
			if !tc.want && len(d.LimitsFailed) != 1 {
				t.Errorf("%s: limits failed = %v, want the one assignment", tc.name, d.LimitsFailed)
			}
		}
		// without a context the allow stands but is reported as conditional
		if d := decide(t, c, w.alice, "app:perms:entry", "read", nil, now); !d.Allowed || !d.Conditional {
			t.Errorf("no context: %+v, want a conditional allow", d)
		}
		// the Cedar text carries the same conditions
		s, err := perms.Load(c)
		must(t, err)
		text := s.Policy(now)
		for _, want := range []string{
			`permit (`, `principal in Tessera::Group::"app:payroll"`, `action in Tessera::Action::"write"`,
			`resource in Tessera::Resource::"app:perms:ledger"`, `context has amount && context.amount < 1000`,
			`ip(context.ip).isInRange(ip("10.0.0.0/8"))`, `ip(context.ip).isInRange(ip("192.168.1.0/24"))`,
			`context.hour >= 9 && context.hour < 17`, `context.region == "emea"`,
		} {
			if !strings.Contains(text, want) {
				t.Errorf("policy lacks %q:\n%s", want, text)
			}
		}
	})
}

// TestPermissions_RolesPairsAndNesting: a permission on a role reaches its
// direct and nested members, a (role, identity) assignment only that identity,
// and a pair outranks the role's assignment either way.
func TestPermissions_RolesPairsAndNesting(t *testing.T) {
	w := newWorld(t)
	now := storetest.Now
	w.tx(t, now, func(c *store.TenantTx, e attrs.Env) {
		w.grant(t, e, owner(store.AttrOwnerGroup, string(w.staff)), w.ledger, w.read, false)     // Alice and Ivan by nesting, Pat directly
		w.grant(t, e, owner(store.AttrOwnerGroup, string(w.payroll)), w.entry, w.write, false)   // Alice and Ivan
		w.grant(t, e, owner(store.AttrOwnerMembership, w.ivanInPayroll), w.entry, w.write, true) // Ivan alone: no
		d := func(who int64, res, act string) string {
			return decide(t, c, who, res, act, nil, now).Reason
		}
		if got := d(w.alice, "app:perms:ledger", "read"); got != "allowed" {
			t.Errorf("alice ledger/read = %s", got)
		}
		if got := d(w.pat, "app:perms:entry", "read"); got != "allowed" {
			t.Errorf("pat entry/read (staff, inherited by resource) = %s", got)
		}
		if got := d(w.pat, "app:perms:entry", "write"); got != "no_permission" {
			t.Errorf("pat entry/write = %s", got)
		}
		if got := d(w.alice, "app:perms:entry", "write"); got != "allowed" {
			t.Errorf("alice entry/write = %s", got)
		}
		if got := d(w.ivan, "app:perms:entry", "write"); got != "disallowed" {
			t.Errorf("ivan entry/write (the pair's disallow beats the role's allow) = %s", got)
		}
		s, err := perms.Load(c)
		must(t, err)
		sub, err := perms.SubjectOf(c, w.ivan, now)
		must(t, err)
		eff, _, err := s.Effective(sub, now)
		must(t, err)
		type row struct {
			res, act string
			allowed  bool
		}
		var got []row
		for _, x := range eff {
			got = append(got, row{x.Resource, x.Action, x.Allowed})
		}
		want := []row{
			{"app:perms:entry", "read", false}, {"app:perms:entry", "write", false},
			{"app:perms:ledger", "read", true},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("ivan's effective permissions = %v, want %v", got, want)
		}
	})
}

// TestPermissions_PITView: the view as of an instant follows the history of the
// assignment and of the role membership.
func TestPermissions_PITView(t *testing.T) {
	w := newWorld(t)
	t1 := storetest.Now.Add(time.Hour)
	t2 := t1.Add(time.Hour)
	var id string
	w.tx(t, t1, func(c *store.TenantTx, e attrs.Env) {
		id = w.grant(t, e, owner(store.AttrOwnerGroup, string(w.payroll)), w.ledger, w.read, false)
		w.limit(t, e, id, w.amt, "50")
	})
	w.tx(t, t2, func(c *store.TenantTx, e attrs.Env) {
		_, err := attrs.Unassign(e, id)
		must(t, err)
	})
	w.tx(t, t2.Add(time.Hour), func(c *store.TenantTx, _ attrs.Env) {
		at := func(when time.Time, ctx perms.Context) bool {
			s, err := perms.LoadAt(c, when)
			must(t, err)
			sub, err := perms.SubjectAt(c, w.alice, when)
			must(t, err)
			q, err := s.Resolve("app:perms:entry", "read")
			must(t, err)
			d, err := s.Decide(sub, q, ctx, when)
			must(t, err)
			return d.Allowed
		}
		if at(t1.Add(-time.Minute), nil) {
			t.Error("before the grant: allowed")
		}
		if !at(t1.Add(time.Minute), perms.Context{"amount": int64(10)}) {
			t.Error("while granted, limit holds: denied")
		}
		if at(t1.Add(time.Minute), perms.Context{"amount": int64(60)}) {
			t.Error("while granted, limit fails: allowed")
		}
		if at(t2.Add(time.Minute), nil) {
			t.Error("after the removal: allowed")
		}
		// the live view agrees with the history's last state
		if d := decide(t, c, w.alice, "app:perms:entry", "read", nil, t2.Add(time.Hour)); d.Allowed {
			t.Error("live: allowed after the removal")
		}
		// the history survives a rebuild from the events
		cmp, err := pit.CompareRebuild(c, "")
		must(t, err)
		if !cmp.Equal || cmp.After.Assigns == 0 {
			t.Errorf("rebuilt history differs: %+v", cmp)
		}
	})
}

// TestGrouperImport_RoundTrip: an export imports into an empty tenant state to
// the same document, importing it again changes nothing, and a changed entry is
// replaced; a document with a wrong entry applies nothing.
func TestGrouperImport_RoundTrip(t *testing.T) {
	w := newWorld(t)
	now := storetest.Now
	var doc *perms.Doc
	w.tx(t, now, func(c *store.TenantTx, e attrs.Env) {
		a := w.grant(t, e, owner(store.AttrOwnerGroup, string(w.payroll)), w.ledger, w.write, false)
		w.limit(t, e, a, w.amt, "1000")
		w.limit(t, e, a, w.ip, "10.0.0.0/8", "172.16.0.0/12")
		w.grant(t, e, owner(store.AttrOwnerMembership, w.ivanInPayroll), w.entry, w.read, true)
		var err error
		doc, err = perms.Export(c)
		must(t, err)
		if len(doc.Permissions) != 2 {
			t.Fatalf("export = %+v", doc)
		}
		// remove everything, then import the document
		s, err := perms.Load(c)
		must(t, err)
		for _, x := range s.Assignments {
			if _, err := attrs.Unassign(e, x.ID); err != nil {
				t.Fatal(err)
			}
		}
		res, err := perms.Import(e, doc)
		must(t, err)
		if res.Created != 2 || res.Replaced != 0 || res.Unchanged != 0 || len(res.Errors) != 0 {
			t.Fatalf("import = %+v", res)
		}
		again, err := perms.Export(c)
		must(t, err)
		if !reflect.DeepEqual(doc, again) {
			t.Errorf("round trip changed the document:\n%+v\n%+v", doc, again)
		}
		// importing it again is a no-op
		if res, err = perms.Import(e, doc); err != nil || res.Unchanged != 2 || res.Created+res.Replaced != 0 {
			t.Fatalf("second import = %+v, %v", res, err)
		}
		// a changed entry replaces the held one
		changed := *doc
		changed.Permissions = append([]perms.Entry(nil), doc.Permissions...)
		for i := range changed.Permissions {
			if changed.Permissions[i].Subject == "" {
				changed.Permissions[i].Limits = []perms.Limit{{Name: "app:limitsInt:amountLessThan", Values: []string{"5"}}}
			}
		}
		if res, err = perms.Import(e, &changed); err != nil || res.Replaced != 1 || res.Unchanged != 1 {
			t.Fatalf("changed import = %+v, %v", res, err)
		}
		got, err := perms.Export(c)
		must(t, err)
		for _, x := range got.Permissions {
			if x.Subject == "" && (len(x.Limits) != 1 || x.Limits[0].Values[0] != "5") {
				t.Errorf("replaced entry = %+v", x)
			}
		}
		// a wrong entry refuses the whole document
		bad := perms.Doc{Permissions: []perms.Entry{
			{Role: "app:payroll", Resource: "app:perms:entry", Action: "read"},
			{Role: "app:nobody", Resource: "app:perms:entry", Action: "read"},
			{Role: "app:payroll", Resource: "app:perms:ledger", Action: "fly"},
			{Role: "app:payroll", Resource: "app:perms:ledger", Action: "read", Limits: []perms.Limit{{Name: "app:limits:timeWindow", Values: []string{"17-9"}}}},
			{Role: "app:payroll", Subject: "Pat", Resource: "app:perms:ledger", Action: "read"},
		}}
		before, err := perms.Export(c)
		must(t, err)
		res, err = perms.Import(e, &bad)
		must(t, err)
		if len(res.Errors) != 4 || res.Created != 0 {
			t.Errorf("bad import = %+v, want 4 errors and nothing created", res)
		}
		if after, _ := perms.Export(c); !reflect.DeepEqual(before, after) {
			t.Error("a refused import changed the assignments")
		}
	})
}
