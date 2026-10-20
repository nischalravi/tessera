package rules_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/privs"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/rules"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Rules and membership constraints (issue #56, GR-13; design §10.3).

type world struct {
	t  *testing.T
	f  *storetest.Fixture
	rt *rules.Runtime

	app, sub, other, one, oneSub  store.FolderID
	gA, gB, gC, gX, gOne, gOneB   store.GroupID
	alice, bob, carol, dave, ivan int64
	admin, author                 uuid.UUID

	mu    sync.Mutex
	notes []rules.Notification
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{t: t, f: storetest.TwoTenants(t)}
	w.rt = &rules.Runtime{Notify: func(_ context.Context, n rules.Notification) error {
		w.mu.Lock()
		defer w.mu.Unlock()
		w.notes = append(w.notes, n)
		return nil
	}}
	w.in(func(c *store.TenantTx) {
		e := model.Env{Tx: c, Now: storetest.Now}
		folder := func(parent store.FolderID, ext string) store.FolderID {
			f, err := e.CreateFolder(model.CreateFolderInput{Parent: parent, Extension: ext})
			if err != nil {
				t.Fatal(err)
			}
			return f.ID
		}
		group := func(folder store.FolderID, ext string) store.GroupID {
			g, err := e.CreateGroup(model.CreateGroupInput{Folder: folder, Extension: ext})
			if err != nil {
				t.Fatal(err)
			}
			return g.ID
		}
		w.app = folder("", "app")
		w.sub = folder(w.app, "sub")
		w.other = folder("", "other")
		w.one = folder("", "one")
		w.oneSub = folder(w.one, "sub")
		w.gA, w.gB, w.gC = group(w.app, "a"), group(w.app, "b"), group(w.sub, "c")
		w.gX = group(w.other, "x")
		w.gOne, w.gOneB = group(w.one, "first"), group(w.oneSub, "second")
		ident := func(name, dept string) int64 {
			email := strings.ToLower(name) + "@b.example"
			id, err := c.InsertIdentity(&store.Identity{ExternalID: name, Name: name, Type: "person", Status: "active", Email: &email,
				Department: &dept, CreatedAt: storetest.Now})
			if err != nil {
				t.Fatal(err)
			}
			return id
		}
		w.alice, w.bob, w.carol, w.dave, w.ivan = ident("Alice", "Eng"), ident("Bob", "Sales"), ident("Carol", "Eng"), ident("Dave", "Ops"),
			ident("Ivan", "Eng")
		user := func(name string, ident *int64) uuid.UUID {
			u := &store.PlatformUser{DisplayName: name, IdentityID: ident, CreatedAt: storetest.Now}
			if err := c.InsertPlatformUser(u); err != nil {
				t.Fatal(err)
			}
			return u.ID
		}
		w.admin, w.author = user("admin", nil), user("author", &w.ivan)
		if err := c.InsertRoleAssignment(&store.RoleAssignment{UserID: w.admin, Role: "tenant_admin", Source: "bootstrap", CreatedAt: storetest.Now}); err != nil {
			t.Fatal(err)
		}
	})
	w.drain()
	return w
}

func (w *world) in(fn func(c *store.TenantTx)) {
	w.t.Helper()
	if err := w.inErr(func(c *store.TenantTx) error { fn(c); return nil }); err != nil {
		w.t.Fatal(err)
	}
}

func (w *world) inErr(fn func(c *store.TenantTx) error) error {
	return w.f.DB.InTenant(context.Background(), w.f.B.ID, fn)
}

// drain reads every event so far, so a test's rules start from now.
func (w *world) drain() {
	w.t.Helper()
	w.in(func(c *store.TenantTx) {
		for {
			n, err := w.rt.Process(c, storetest.Now, 500)
			if err != nil {
				w.t.Fatal(err)
			}
			if n == 0 {
				return
			}
		}
	})
}

func (w *world) modelEnv(c *store.TenantTx, actor *int64) model.Env {
	return model.Env{Tx: c, Now: storetest.Now, ByIdentity: actor, Guard: w.rt.Guard(), TenantAdmin: true}
}

func (w *world) rulesEnv(c *store.TenantTx, user uuid.UUID) rules.Env {
	sub, err := rules.SubjectOf(c, user.String(), storetest.Now)
	if err != nil {
		w.t.Fatal(err)
	}
	return rules.Env{Tx: c, Now: storetest.Now, By: user.String(), Checker: privs.NewChecker(c, storetest.Now, nil, sub), RT: w.rt}
}

func (w *world) add(g store.GroupID, who int64, actor *int64) error {
	return w.inErr(func(c *store.TenantTx) error {
		_, err := w.modelEnv(c, actor).AddMember(g, model.MemberInput{Identity: &who})
		return err
	})
}

func (w *world) remove(g store.GroupID, who int64) {
	w.t.Helper()
	w.in(func(c *store.TenantTx) {
		if _, err := w.modelEnv(c, nil).RemoveMember(g, strconv.FormatInt(who, 10)); err != nil {
			w.t.Fatal(err)
		}
	})
}

func (w *world) has(g store.GroupID, who int64) bool {
	w.t.Helper()
	var ok bool
	w.in(func(c *store.TenantTx) {
		_, err := c.GrpDirectFind(g, store.MembersListID(c.Tenant()), store.MemberIdentity, strconv.FormatInt(who, 10))
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			w.t.Fatal(err)
		}
		ok = err == nil
	})
	return ok
}

func (w *world) grant(c *store.TenantTx, o privs.Object, p privs.Privilege, identity int64) *store.GrpPrivilege {
	w.t.Helper()
	row, _, err := privs.Grant(privs.Env{Tx: c, Now: storetest.Now, TenantAdmin: true}, privs.GrantInput{Object: o, Privilege: p,
		Holder: privs.IdentityHolder(identity)})
	if err != nil {
		w.t.Fatal(err)
	}
	return row
}

// create saves a rule as the user.
func (w *world) create(user uuid.UUID, s rules.Spec) (v *rules.View, secret string) {
	w.t.Helper()
	w.in(func(c *store.TenantTx) {
		var err error
		if v, secret, err = rules.Create(w.rulesEnv(c, user), s); err != nil {
			w.t.Fatalf("create %s: %v", s.Action, err)
		}
	})
	return v, secret
}

// fired returns the results of a rule's rule.fired events.
func (w *world) fired(rule string) (results, details []string) {
	w.t.Helper()
	w.in(func(c *store.TenantTx) {
		evs, err := c.GrpEventsOfObject(store.EventObjRule, rule, 0, 100)
		if err != nil {
			w.t.Fatal(err)
		}
		for _, ev := range evs {
			var d struct{ Result, Detail string }
			if err := json.Unmarshal(ev.Data, &d); err != nil {
				w.t.Fatal(err)
			}
			results, details = append(results, d.Result), append(details, d.Detail)
		}
	})
	return results, details
}

func spec(ownerType string, owner string, trigger, action string, p rules.Params, conds ...rules.Condition) rules.Spec {
	return rules.Spec{OwnerType: ownerType, OwnerID: owner, Name: action, Trigger: trigger, Action: action, Params: p, Conditions: conds, Enabled: true}
}

func onGroup(g store.GroupID, trigger, action string, p rules.Params, conds ...rules.Condition) rules.Spec {
	return spec(store.RuleOwnerGroup, string(g), trigger, action, p, conds...)
}

func onFolder(f store.FolderID, scope, trigger, action string, p rules.Params, conds ...rules.Condition) rules.Spec {
	s := spec(store.RuleOwnerFolder, string(f), trigger, action, p, conds...)
	s.Scope = scope
	return s
}

func wantVetoed(t *testing.T, err error, rule string) *model.Error {
	t.Helper()
	var me *model.Error
	if !errors.As(err, &me) || me.Code != "vetoed" || me.Kind != model.Conflict || me.Extra["rule"] != rule {
		t.Fatalf("err = %v, want a veto by rule %s", err, rule)
	}
	return me
}

// ---------------------------------------------------------------- authority

// TestRules_PrivilegeCheckedAtFireTime: a rule needs admin on its owner and on
// every group its action changes, when it is saved and again whenever it
// fires, with what its author holds then.
func TestRules_PrivilegeCheckedAtFireTime(t *testing.T) {
	w := newWorld(t)
	var onB, onC *store.GrpPrivilege
	w.in(func(c *store.TenantTx) {
		onB = w.grant(c, privs.GroupObject(w.gB), privs.Admin, w.ivan)
		onC = w.grant(c, privs.GroupObject(w.gC), privs.Admin, w.ivan)
	})
	add := onGroup(w.gB, rules.TrigDirectAdded, rules.ActAddToGroup, rules.Params{Group: string(w.gC)})

	// at save time: the author needs admin on the group the action changes
	wantDenied := func(err error, p privs.Privilege, id string) {
		t.Helper()
		var d *privs.DeniedError
		if !errors.As(err, &d) || d.Privilege != p || d.Object.ID != id {
			t.Fatalf("err = %v, want %s required on %s", err, p, id)
		}
	}
	err := w.inErr(func(c *store.TenantTx) error {
		bad := add
		bad.Params.Group = string(w.gA) // ivan holds nothing on it
		_, _, err := rules.Create(w.rulesEnv(c, w.author), bad)
		return err
	})
	wantDenied(err, privs.Admin, string(w.gA))
	err = w.inErr(func(c *store.TenantTx) error { // nor on an owner the author does not administer
		_, _, err := rules.Create(w.rulesEnv(c, w.author), onGroup(w.gA, rules.TrigDirectAdded, rules.ActAddToGroup, rules.Params{Group: string(w.gC)}))
		return err
	})
	wantDenied(err, privs.Admin, string(w.gA))
	// a machine client cannot save one at all
	err = w.inErr(func(c *store.TenantTx) error {
		e := w.rulesEnv(c, w.author)
		e.By = ""
		_, _, err := rules.Create(e, add)
		return err
	})
	var re *rules.Error
	if !errors.As(err, &re) || re.Code != "rule_needs_user" {
		t.Fatalf("a rule saved with no user: %v", err)
	}

	rule, _ := w.create(w.author, add)
	if err := w.add(w.gB, w.alice, nil); err != nil {
		t.Fatal(err)
	}
	w.drain()
	if !w.has(w.gC, w.alice) {
		t.Fatal("the rule did not add alice to c")
	}
	w.in(func(c *store.TenantTx) {
		m, err := c.GrpDirectFind(w.gC, store.MembersListID(c.Tenant()), store.MemberIdentity, strconv.FormatInt(w.alice, 10))
		if err != nil || m.Source != "rule" || m.SourceRef == nil || *m.SourceRef != rule.ID {
			t.Errorf("membership made by the rule = %+v, %v", m, err)
		}
	})

	// the author loses admin on c: the same rule now does nothing, and says why
	w.in(func(c *store.TenantTx) {
		if _, err := privs.Revoke(privs.Env{Tx: c, Now: storetest.Now, TenantAdmin: true}, onC.ID); err != nil {
			t.Fatal(err)
		}
	})
	if err := w.add(w.gB, w.bob, nil); err != nil {
		t.Fatal(err)
	}
	w.drain()
	if w.has(w.gC, w.bob) {
		t.Fatal("the rule acted although its author no longer administers c")
	}
	results, details := w.fired(rule.ID)
	if len(results) != 2 || results[0] != rules.ResultApplied || results[1] != rules.ResultDenied ||
		!strings.Contains(details[1], "privilege_required: admin on group "+string(w.gC)) {
		t.Fatalf("firings = %v %v", results, details)
	}

	// the privilege on the owner is checked at fire time too
	w.in(func(c *store.TenantTx) {
		w.grant(c, privs.GroupObject(w.gC), privs.Admin, w.ivan)
		if _, err := privs.Revoke(privs.Env{Tx: c, Now: storetest.Now, TenantAdmin: true}, onB.ID); err != nil {
			t.Fatal(err)
		}
	})
	if err := w.add(w.gB, w.carol, nil); err != nil {
		t.Fatal(err)
	}
	w.drain()
	if w.has(w.gC, w.carol) {
		t.Fatal("the rule acted although its author no longer administers its owner")
	}
	// a rule is not evaluated for a group it does not own
	if err := w.add(w.gA, w.dave, nil); err != nil {
		t.Fatal(err)
	}
	w.drain()
	if results, _ := w.fired(rule.ID); len(results) != 3 {
		t.Fatalf("firings = %v, want 3", results)
	}
}

// TestRules_ActOnNewEventsOnly: a rule saved now does not act on what happened
// before, and a disabled rule does not act.
func TestRules_ActOnNewEventsOnly(t *testing.T) {
	w := newWorld(t)
	if err := w.add(w.gB, w.alice, nil); err != nil { // before any rule exists
		t.Fatal(err)
	}
	rule, _ := w.create(w.admin, onGroup(w.gB, rules.TrigDirectAdded, rules.ActAddToGroup, rules.Params{Group: string(w.gC)}))
	w.drain()
	if w.has(w.gC, w.alice) {
		t.Fatal("a new rule acted on history")
	}
	off := onGroup(w.gB, rules.TrigDirectAdded, rules.ActAddToGroup, rules.Params{Group: string(w.gC)})
	off.Enabled = false
	w.in(func(c *store.TenantTx) {
		if _, _, err := rules.Update(w.rulesEnv(c, w.admin), rule.ID, off, false); err != nil {
			t.Fatal(err)
		}
	})
	if err := w.add(w.gB, w.bob, nil); err != nil {
		t.Fatal(err)
	}
	w.drain()
	if w.has(w.gC, w.bob) {
		t.Fatal("a disabled rule acted")
	}
}

// ---------------------------------------------------------------- constraints

// TestMembershipRequire_VetoAndRemove: to be in b one must be in a (G-28): an
// add is vetoed until then, and leaving a removes the member from b.
func TestMembershipRequire_VetoAndRemove(t *testing.T) {
	w := newWorld(t)
	rule, _ := w.create(w.admin, onGroup(w.gB, rules.TrigDirectAdded, rules.ActRequireMemberOf, rules.Params{Group: string(w.gA)}))
	if !rule.Veto {
		t.Error("a membership require does not say it can veto")
	}
	me := wantVetoed(t, w.add(w.gB, w.bob, nil), rule.ID)
	if !strings.Contains(me.Msg, "Bob") || !strings.Contains(me.Msg, "app:a") {
		t.Errorf("veto message = %q", me.Msg)
	}
	if w.has(w.gB, w.bob) {
		t.Fatal("a vetoed add left a row")
	}
	if err := w.add(w.gA, w.bob, nil); err != nil {
		t.Fatal(err)
	}
	if err := w.add(w.gB, w.bob, nil); err != nil {
		t.Fatalf("add of a member of a: %v", err)
	}
	// a member of b who is not in a is untouched by other changes: carol is only vetoed on add
	w.drain()
	if !w.has(w.gB, w.bob) {
		t.Fatal("bob left b without leaving a")
	}
	w.remove(w.gA, w.bob)
	w.drain()
	if w.has(w.gB, w.bob) {
		t.Fatal("bob left a but stayed in b")
	}
	results, details := w.fired(rule.ID)
	if len(results) != 1 || results[0] != rules.ResultApplied || !strings.Contains(details[0], "app:b") {
		t.Fatalf("firings = %v %v", results, details)
	}
	// a nested group is not an identity add: the rule leaves it to the engine
	// a condition narrows the rule: only Sales needs a
	w.in(func(c *store.TenantTx) {
		cond := rules.Condition{Type: rules.CondIdentityAttribute, Attribute: "department", Op: "equals", Values: []string{"Sales"}}
		s := onGroup(w.gC, rules.TrigDirectAdded, rules.ActRequireMemberOf, rules.Params{Group: string(w.gA)}, cond)
		if _, _, err := rules.Create(w.rulesEnv(c, w.admin), s); err != nil {
			t.Fatal(err)
		}
	})
	if err := w.add(w.gC, w.alice, nil); err != nil { // Eng: not covered
		t.Fatalf("a rule vetoed outside its condition: %v", err)
	}
	var se *model.Error
	if err := w.add(w.gC, w.bob, nil); !errors.As(err, &se) || se.Code != "vetoed" {
		t.Fatalf("a Sales add to c = %v, want a veto", err)
	}
}

// TestOneGroupOnly: an identity is in one group of a folder at most (G-29).
func TestOneGroupOnly(t *testing.T) {
	w := newWorld(t)
	rule, _ := w.create(w.admin, onFolder(w.app, "sub", rules.TrigDirectAdded, rules.ActOneGroupOnly, rules.Params{}))
	if err := w.add(w.gA, w.carol, nil); err != nil {
		t.Fatal(err)
	}
	me := wantVetoed(t, w.add(w.gC, w.carol, nil), rule.ID) // c is in app:sub
	if !strings.Contains(me.Msg, "app:a") {
		t.Errorf("veto message = %q", me.Msg)
	}
	wantVetoed(t, w.add(w.gB, w.carol, nil), rule.ID)
	if err := w.add(w.gX, w.carol, nil); err != nil { // another folder
		t.Fatalf("add outside the folder: %v", err)
	}
	if err := w.add(w.gC, w.dave, nil); err != nil { // someone else
		t.Fatal(err)
	}
	// a membership that has left is no longer counted
	w.remove(w.gA, w.carol)
	if err := w.add(w.gC, w.carol, nil); err != nil {
		t.Fatalf("add after leaving: %v", err)
	}
	// scope one covers the folder's own groups only
	w.create(w.admin, onFolder(w.one, "one", rules.TrigDirectAdded, rules.ActOneGroupOnly, rules.Params{}))
	if err := w.add(w.gOne, w.alice, nil); err != nil {
		t.Fatal(err)
	}
	if err := w.add(w.gOneB, w.alice, nil); err != nil {
		t.Fatalf("scope one vetoed a group of a subfolder: %v", err)
	}
	// the rule's own group is the one that is already there: re-adding is not a new row
	if _, err := newAdd(w, w.gOne, w.alice); err != nil {
		t.Fatalf("updating the dates of the one membership: %v", err)
	}
}

func newAdd(w *world, g store.GroupID, who int64) (*model.AddResult, error) {
	var res *model.AddResult
	err := w.inErr(func(c *store.TenantTx) error {
		var err error
		res, err = w.modelEnv(c, nil).AddMember(g, model.MemberInput{Identity: &who, Reason: "again"})
		return err
	})
	return res, err
}

// TestNoSelfAdd: nobody adds themselves to a group under the rule.
func TestNoSelfAdd(t *testing.T) {
	w := newWorld(t)
	rule, _ := w.create(w.admin, onGroup(w.gB, rules.TrigDirectAdded, rules.ActNoSelfAdd, rules.Params{}))
	wantVetoed(t, w.add(w.gB, w.alice, &w.alice), rule.ID)
	if err := w.add(w.gB, w.alice, &w.bob); err != nil {
		t.Fatalf("adding someone else: %v", err)
	}
	if err := w.add(w.gB, w.bob, nil); err != nil { // no identity behind the request
		t.Fatalf("a request with no identity: %v", err)
	}
}

// TestVeto_MessageAndOtherSources: a plain veto carries its message, and the
// rule's source condition decides which adds it covers.
func TestVeto_MessageAndOtherSources(t *testing.T) {
	w := newWorld(t)
	cond := rules.Condition{Type: rules.CondMembershipSource, Source: "api"}
	rule, _ := w.create(w.admin, onGroup(w.gB, rules.TrigDirectAdded, rules.ActVeto, rules.Params{Message: "b is closed"}, cond))
	if me := wantVetoed(t, w.add(w.gB, w.alice, nil), rule.ID); me.Msg != "b is closed" {
		t.Errorf("message = %q", me.Msg)
	}
	w.in(func(c *store.TenantTx) {
		_, err := w.modelEnv(c, nil).AddMember(w.gB, model.MemberInput{Identity: &w.bob, Source: "loader"})
		if err != nil {
			t.Errorf("a loader add under an api-only veto: %v", err)
		}
	})
}

// ---------------------------------------------------------------- actions

// TestRules_AddDisabledDateAndRemove: actions that change memberships, with
// conditions deciding whom they cover.
func TestRules_AddDisabledDateAndRemove(t *testing.T) {
	w := newWorld(t)
	eng := rules.Condition{Type: rules.CondIdentityAttribute, Attribute: "department", Op: "in", Values: []string{"Eng", "Ops"}}
	dateRule, _ := w.create(w.admin, onGroup(w.gB, rules.TrigDirectAdded, rules.ActAddDisabledDate, rules.Params{Days: 30}, eng))
	rm, _ := w.create(w.admin, onGroup(w.gB, rules.TrigDirectRemoved, rules.ActRemoveFromGroup, rules.Params{Group: string(w.gC)}))
	for _, who := range []int64{w.alice, w.bob, w.dave} {
		if err := w.add(w.gB, who, nil); err != nil {
			t.Fatal(err)
		}
	}
	w.drain()
	ends := func(who int64) *time.Time {
		var at *time.Time
		w.in(func(c *store.TenantTx) {
			m, err := c.GrpDirectFind(w.gB, store.MembersListID(c.Tenant()), store.MemberIdentity, strconv.FormatInt(who, 10))
			if err != nil {
				t.Fatal(err)
			}
			at = m.DisabledAt
		})
		return at
	}
	want := storetest.Now.AddDate(0, 0, 30)
	if at := ends(w.alice); at == nil || !at.Equal(want) {
		t.Errorf("alice (Eng) ends %v, want %v", at, want)
	}
	if at := ends(w.dave); at == nil || !at.Equal(want) {
		t.Errorf("dave (Ops) ends %v, want %v", at, want)
	}
	if at := ends(w.bob); at != nil {
		t.Errorf("bob (Sales) ends %v, but the condition excludes him", at)
	}
	// removing someone from b removes them from c
	if err := w.add(w.gC, w.alice, nil); err != nil {
		t.Fatal(err)
	}
	w.drain()
	w.remove(w.gB, w.alice)
	w.drain()
	if w.has(w.gC, w.alice) {
		t.Error("alice left b but not c")
	}
	if results, _ := w.fired(dateRule.ID); len(results) != 2 {
		t.Errorf("date rule fired %v, want twice", results)
	}
	if results, _ := w.fired(rm.ID); len(results) != 1 || results[0] != rules.ResultApplied {
		t.Errorf("remove rule fired %v", results)
	}
	// removing someone who is not in c is not an error
	w.remove(w.gB, w.dave)
	w.drain()
	if results, details := w.fired(rm.ID); len(results) != 2 || results[1] != rules.ResultSkipped || details[1] != "not_a_member" {
		t.Errorf("remove rule fired %v %v", results, details)
	}
}

// TestRules_AssignPrivilegeOnCreate: a folder's rule gives a privilege on what
// is created under it, and does not escape its scope.
func TestRules_AssignPrivilegeOnCreate(t *testing.T) {
	w := newWorld(t)
	rule, _ := w.create(w.admin, onFolder(w.app, "one", rules.TrigGroupCreated, rules.ActAssignPrivilege,
		rules.Params{Privilege: "read", HolderType: store.HolderIdentity, HolderIdentity: w.carol},
		rules.Condition{Type: rules.CondNameMatches, Pattern: "app:team-*"}))
	var matching, other, deeper store.GroupID
	w.in(func(c *store.TenantTx) {
		e := model.Env{Tx: c, Now: storetest.Now}
		mk := func(f store.FolderID, ext string) store.GroupID {
			g, err := e.CreateGroup(model.CreateGroupInput{Folder: f, Extension: ext})
			if err != nil {
				t.Fatal(err)
			}
			return g.ID
		}
		matching, other, deeper = mk(w.app, "team-red"), mk(w.app, "misc"), mk(w.sub, "team-blue")
	})
	w.drain()
	got := func(g store.GroupID) (n int) {
		w.in(func(c *store.TenantTx) {
			rows, err := c.GrpPrivilegesOf("group", string(g))
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range rows {
				if r.Privilege == "read" && r.HolderIdentity != nil && *r.HolderIdentity == w.carol && r.Source == store.PrivSourceTemplate {
					n++
				}
			}
		})
		return n
	}
	if got(matching) != 1 || got(other) != 0 || got(deeper) != 0 {
		t.Errorf("privileges: matching %d, other %d, deeper (outside scope one) %d; want 1 0 0", got(matching), got(other), got(deeper))
	}
	if results, _ := w.fired(rule.ID); len(results) != 1 || results[0] != rules.ResultApplied {
		t.Errorf("fired %v", results)
	}
}

// TestRules_FolderDeleteRemovesRules: a folder's rules end with it.
func TestRules_FolderDeleteRemovesRules(t *testing.T) {
	w := newWorld(t)
	var empty store.FolderID
	w.in(func(c *store.TenantTx) {
		f, err := model.Env{Tx: c, Now: storetest.Now}.CreateFolder(model.CreateFolderInput{Extension: "empty"})
		if err != nil {
			t.Fatal(err)
		}
		empty = f.ID
	})
	w.create(w.admin, onFolder(empty, "sub", rules.TrigDirectAdded, rules.ActNoSelfAdd, rules.Params{}))
	w.in(func(c *store.TenantTx) {
		if err := (model.Env{Tx: c, Now: storetest.Now}).DeleteFolder(empty); err != nil {
			t.Fatal(err)
		}
		if rs, err := c.GrpRulesOf("folder", string(empty)); err != nil || len(rs) != 0 {
			t.Errorf("rules of a deleted folder = %d, %v", len(rs), err)
		}
	})
}

// ---------------------------------------------------------------- email

// TestEmailRulesOffByDefault: a rule that sends email cannot be saved, and one
// that was saved does not send, until a tenant admin turns email rules on.
func TestEmailRulesOffByDefault(t *testing.T) {
	w := newWorld(t)
	notify := onGroup(w.gB, rules.TrigDirectAdded, rules.ActNotify, rules.Params{Subject: "Welcome", Message: "You joined {group}"})
	w.in(func(c *store.TenantTx) {
		if s, err := rules.LoadSettings(c); err != nil || s.EmailEnabled {
			t.Errorf("default settings = %+v, %v; want email off", s, err)
		}
	})
	err := w.inErr(func(c *store.TenantTx) error {
		_, _, err := rules.Create(w.rulesEnv(c, w.admin), notify)
		return err
	})
	var re *rules.Error
	if !errors.As(err, &re) || re.Kind != rules.Conflict || re.Code != "email_rules_disabled" {
		t.Fatalf("saving an email rule with the gate closed = %v", err)
	}
	setEmail := func(on bool) {
		w.in(func(c *store.TenantTx) {
			if _, err := rules.SaveSettings(w.rulesEnv(c, w.admin), rules.Settings{EmailEnabled: on}); err != nil {
				t.Fatal(err)
			}
		})
	}
	setEmail(true)
	rule, _ := w.create(w.admin, notify)
	setEmail(false) // closed again before the rule fires
	if err := w.add(w.gB, w.alice, nil); err != nil {
		t.Fatal(err)
	}
	w.drain()
	if len(w.notes) != 0 {
		t.Fatalf("an email went out with the gate closed: %+v", w.notes)
	}
	if results, details := w.fired(rule.ID); len(results) != 1 || results[0] != rules.ResultSkipped || details[0] != "email_rules_disabled" {
		t.Fatalf("firings = %v %v", results, details)
	}
	setEmail(true)
	if err := w.add(w.gB, w.bob, nil); err != nil {
		t.Fatal(err)
	}
	w.drain()
	if len(w.notes) != 1 || w.notes[0].Identity != w.bob || w.notes[0].Email != "bob@b.example" || w.notes[0].Body != "You joined app:b" {
		t.Fatalf("notifications = %+v", w.notes)
	}
}

// ---------------------------------------------------------------- webhooks

type hook struct {
	srv  *httptest.Server
	mu   sync.Mutex
	mode string // allow | deny | error | slow | garbage
	reqs []hookReq
}

type hookReq struct {
	header http.Header
	body   []byte
}

func newHook(t *testing.T) *hook {
	h := &hook{mode: "allow"}
	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		h.mu.Lock()
		h.reqs = append(h.reqs, hookReq{r.Header.Clone(), body})
		mode := h.mode
		h.mu.Unlock()
		switch mode {
		case "deny":
			_, _ = w.Write([]byte(`{"allow":false,"message":"the approver said no"}`))
		case "error":
			http.Error(w, "boom", http.StatusInternalServerError)
		case "slow":
			time.Sleep(600 * time.Millisecond)
			_, _ = w.Write([]byte(`{"allow":true}`))
		case "garbage":
			_, _ = w.Write([]byte(`<html>`))
		default:
			_, _ = w.Write([]byte(`{"allow":true}`))
		}
	}))
	t.Cleanup(h.srv.Close)
	return h
}

func (h *hook) set(mode string) { h.mu.Lock(); h.mode = mode; h.mu.Unlock() }

func (h *hook) calls() []hookReq {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]hookReq(nil), h.reqs...)
}

func (w *world) withHTTP() {
	w.t.Helper()
	hc, err := safehttp.NewForTest(w.t, safehttp.Options{Env: config.Dev, AllowLoopback: true})
	if err != nil {
		w.t.Fatal(err)
	}
	sealer, err := seal.New(seal.RandomBytes(seal.KeySize))
	if err != nil {
		w.t.Fatal(err)
	}
	w.rt.HTTP, w.rt.Sealer, w.rt.AllowHTTP, w.rt.Timeout = hc, sealer, true, 300*time.Millisecond
}

// TestVetoHookFailClosed: a webhook may veto an add synchronously. When it
// does not answer (error status, timeout, unreadable answer, unreachable) the
// add is refused, unless the rule says fail_open.
func TestVetoHookFailClosed(t *testing.T) {
	w := newWorld(t)
	h := newHook(t)

	// no outbound client: a webhook rule cannot be saved
	w.rt.AllowHTTP = true
	err := w.inErr(func(c *store.TenantTx) error {
		_, _, err := rules.Create(w.rulesEnv(c, w.admin), onGroup(w.gB, rules.TrigDirectAdded, rules.ActWebhook,
			rules.Params{URL: h.srv.URL, Veto: true}))
		return err
	})
	var re *rules.Error
	if !errors.As(err, &re) || re.Code != "webhooks_unavailable" {
		t.Fatalf("a webhook rule with no client = %v", err)
	}
	w.withHTTP()
	rule, secret := w.create(w.admin, onGroup(w.gB, rules.TrigDirectAdded, rules.ActWebhook, rules.Params{URL: h.srv.URL, Veto: true}))
	if secret == "" || !rule.HasSecret || !rule.Veto {
		t.Fatalf("rule = %+v, secret %q", rule, secret)
	}

	if err := w.add(w.gB, w.alice, nil); err != nil {
		t.Fatalf("an approving hook: %v", err)
	}
	// the call is signed with the secret shown at creation
	reqs := h.calls()
	if len(reqs) != 1 {
		t.Fatalf("hook calls = %d", len(reqs))
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(reqs[0].header.Get("Tessera-Timestamp") + "."))
	mac.Write(reqs[0].body)
	if got, want := reqs[0].header.Get("Tessera-Signature"), "sha256="+hex.EncodeToString(mac.Sum(nil)); got != want {
		t.Errorf("signature = %q, want %q", got, want)
	}
	var p struct {
		Rule     string
		Event    string
		Identity int64
		Veto     bool
		Group    struct{ Name string }
	}
	if err := json.Unmarshal(reqs[0].body, &p); err != nil || p.Rule != rule.ID || p.Event != rules.TrigDirectAdded || p.Identity != w.alice ||
		!p.Veto || p.Group.Name != "app:b" {
		t.Errorf("payload = %+v, %v", p, err)
	}

	h.set("deny")
	if me := wantVetoed(t, w.add(w.gB, w.bob, nil), rule.ID); me.Msg != "the approver said no" {
		t.Errorf("message = %q", me.Msg)
	}
	for _, mode := range []string{"error", "slow", "garbage"} {
		h.set(mode)
		me := wantVetoed(t, w.add(w.gB, w.bob, nil), rule.ID)
		if !strings.Contains(me.Msg, "did not answer") {
			t.Errorf("%s: message = %q", mode, me.Msg)
		}
	}
	if w.has(w.gB, w.bob) {
		t.Fatal("a vetoed add left a row")
	}
	h.srv.Close() // unreachable
	wantVetoed(t, w.add(w.gB, w.bob, nil), rule.ID)

	// fail open: the same failures let the add through
	open := onGroup(w.gB, rules.TrigDirectAdded, rules.ActWebhook, rules.Params{URL: h.srv.URL, Veto: true, FailOpen: true})
	w.in(func(c *store.TenantTx) {
		if _, _, err := rules.Update(w.rulesEnv(c, w.admin), rule.ID, open, false); err != nil {
			t.Fatal(err)
		}
	})
	if err := w.add(w.gB, w.bob, nil); err != nil {
		t.Fatalf("fail_open with an unreachable hook: %v", err)
	}
}

// TestHook_NonVetoDeliveredAfterTheChange: a hook that cannot veto is told
// after the change, and its failure does not undo it.
func TestHook_NonVetoDeliveredAfterTheChange(t *testing.T) {
	w := newWorld(t)
	w.withHTTP()
	h := newHook(t)
	rule, _ := w.create(w.admin, onGroup(w.gB, rules.TrigDirectAdded, rules.ActWebhook, rules.Params{URL: h.srv.URL}))
	h.set("error")
	if err := w.add(w.gB, w.alice, nil); err != nil {
		t.Fatalf("a failing notification hook blocked the add: %v", err)
	}
	if len(h.calls()) != 0 {
		t.Fatal("the hook was called inside the request")
	}
	w.drain()
	results, details := w.fired(rule.ID)
	if len(h.calls()) != 1 || len(results) != 1 || results[0] != rules.ResultFailed || details[0] != "hook_status_500" {
		t.Fatalf("calls %d, firings %v %v", len(h.calls()), results, details)
	}
	h.set("allow")
	if err := w.add(w.gB, w.bob, nil); err != nil {
		t.Fatal(err)
	}
	w.drain()
	if results, _ := w.fired(rule.ID); len(results) != 2 || results[1] != rules.ResultApplied {
		t.Fatalf("firings %v", results)
	}
}

// TestHook_SecretRotatesAndStaysHidden: the secret is shown when made and when
// rotated, never in a read, and a saved rule that is not a hook has none.
func TestHook_SecretRotatesAndStaysHidden(t *testing.T) {
	w := newWorld(t)
	w.withHTTP()
	h := newHook(t)
	s := onGroup(w.gB, rules.TrigDirectAdded, rules.ActWebhook, rules.Params{URL: h.srv.URL, Veto: true})
	rule, first := w.create(w.admin, s)
	var second, third string
	w.in(func(c *store.TenantTx) {
		var err error
		if _, second, err = rules.Update(w.rulesEnv(c, w.admin), rule.ID, s, false); err != nil || second != "" {
			t.Errorf("update without rotate gave a secret %q, %v", second, err)
		}
		if _, third, err = rules.Update(w.rulesEnv(c, w.admin), rule.ID, s, true); err != nil || third == "" || third == first {
			t.Errorf("rotate gave %q (was %q), %v", third, first, err)
		}
		views, err := rules.List(c, store.RuleOwnerGroup, string(w.gB))
		if err != nil || len(views) != 1 || !views[0].HasSecret {
			t.Fatalf("list = %+v, %v", views, err)
		}
		if b, _ := json.Marshal(views[0]); strings.Contains(string(b), third) {
			t.Error("a read shows the secret")
		}
		plain := onGroup(w.gB, rules.TrigDirectAdded, rules.ActNoSelfAdd, rules.Params{})
		if v, sec, err := rules.Update(w.rulesEnv(c, w.admin), rule.ID, plain, false); err != nil || sec != "" || v.HasSecret {
			t.Errorf("a rule that is no longer a hook keeps a secret: %+v %q %v", v, sec, err)
		}
	})
}

// ---------------------------------------------------------------- vocabulary

func TestSpec_Validate(t *testing.T) {
	g := uuid.NewString()
	ok := rules.Params{Group: g}
	cases := []struct {
		name string
		spec rules.Spec
		code string // "" = valid
	}{
		{"add to group", onGroup("00000000-0000-4000-8000-000000000001", rules.TrigDirectAdded, rules.ActAddToGroup, ok), ""},
		{"folder rule defaults to sub", onFolder("f", "", rules.TrigDirectAdded, rules.ActNoSelfAdd, rules.Params{}), ""},
		{"unknown trigger", onGroup("x", "membership.sideways", rules.ActNoSelfAdd, rules.Params{}), "invalid_trigger"},
		{"unknown action", onGroup("x", rules.TrigDirectAdded, "run_script", rules.Params{}), "invalid_action"},
		{"a planned action", onGroup("x", rules.TrigDirectAdded, "open_inbox_task", rules.Params{}), "action_unavailable"},
		{"group rule with a scope", func() rules.Spec {
			s := onGroup("x", rules.TrigDirectAdded, rules.ActNoSelfAdd, rules.Params{})
			s.Scope = "sub"
			return s
		}(), "invalid_scope"},
		{"folder rule with scope self", onFolder("f", "self", rules.TrigDirectAdded, rules.ActNoSelfAdd, rules.Params{}), "invalid_scope"},
		{"creation trigger on a group", onGroup("x", rules.TrigGroupCreated, rules.ActAssignPrivilege, rules.Params{}), "invalid_trigger"},
		{"veto needs a message", onGroup("x", rules.TrigDirectAdded, rules.ActVeto, rules.Params{}), "invalid_message"},
		{"veto on a removal", onGroup("x", rules.TrigDirectRemoved, rules.ActVeto, rules.Params{Message: "no"}), "invalid_trigger"},
		{"params of another action", onGroup("x", rules.TrigDirectAdded, rules.ActNoSelfAdd, rules.Params{Message: "hi"}), "invalid_params"},
		{"require needs a group id", onGroup("x", rules.TrigDirectAdded, rules.ActRequireMemberOf, rules.Params{Group: "app:a"}), "invalid_group"},
		{"one group only on a group", onGroup("x", rules.TrigDirectAdded, rules.ActOneGroupOnly, rules.Params{}), "invalid_owner"},
		{"days out of range", onGroup("x", rules.TrigDirectAdded, rules.ActAddDisabledDate, rules.Params{Days: 0}), "invalid_days"},
		{"a condition of another trigger", onFolder("f", "sub", rules.TrigGroupCreated, rules.ActAssignPrivilege,
			rules.Params{Privilege: "read", HolderType: "identity", HolderIdentity: 1}, rules.Condition{Type: rules.CondMembershipSource, Source: "api"}), "invalid_conditions"},
		{"unknown condition", onGroup("x", rules.TrigDirectAdded, rules.ActNoSelfAdd, rules.Params{}, rules.Condition{Type: "jexl"}), "invalid_conditions"},
		{"unknown attribute", onGroup("x", rules.TrigDirectAdded, rules.ActNoSelfAdd, rules.Params{},
			rules.Condition{Type: rules.CondIdentityAttribute, Attribute: "salary", Op: "equals", Values: []string{"1"}}), "invalid_conditions"},
		{"equals with two values", onGroup("x", rules.TrigDirectAdded, rules.ActNoSelfAdd, rules.Params{},
			rules.Condition{Type: rules.CondIdentityAttribute, Attribute: "title", Op: "equals", Values: []string{"a", "b"}}), "invalid_conditions"},
		{"a condition with a stray field", onGroup("x", rules.TrigDirectAdded, rules.ActNoSelfAdd, rules.Params{},
			rules.Condition{Type: rules.CondIdentityInGroup, Group: g, Pattern: "*"}), "invalid_conditions"},
		{"privilege to everyone", onFolder("f", "sub", rules.TrigGroupCreated, rules.ActAssignPrivilege,
			rules.Params{Privilege: "read", HolderType: "everyone"}), "invalid_holder"},
		{"folder privilege on a new group", onFolder("f", "sub", rules.TrigGroupCreated, rules.ActAssignPrivilege,
			rules.Params{Privilege: "create", HolderType: "identity", HolderIdentity: 1}), "invalid_privilege"},
		{"hook url with user info", onGroup("x", rules.TrigDirectAdded, rules.ActWebhook, rules.Params{URL: "https://u:p@h.example/x"}), "invalid_url"},
		{"hook url that is not http", onGroup("x", rules.TrigDirectAdded, rules.ActWebhook, rules.Params{URL: "file:///etc/passwd"}), "invalid_url"},
		{"a veto hook on a removal", onGroup("x", rules.TrigDirectRemoved, rules.ActWebhook, rules.Params{URL: "https://h.example/x", Veto: true}), "invalid_veto"},
		{"fail_open without a veto", onGroup("x", rules.TrigDirectAdded, rules.ActWebhook, rules.Params{URL: "https://h.example/x", FailOpen: true}), "invalid_fail_open"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := c.spec
			err := s.Validate()
			var re *rules.Error
			switch {
			case c.code == "" && err != nil:
				t.Fatalf("Validate = %v", err)
			case c.code != "" && (!errors.As(err, &re) || re.Kind != rules.Invalid || re.Code != c.code):
				t.Fatalf("Validate = %v, want %s", err, c.code)
			}
		})
	}
}
