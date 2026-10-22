package svcaccounts_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/provision"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/fake"
	"github.com/nischalravi/tessera/mvp/server/internal/requests"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/svcaccounts"
	"github.com/nischalravi/tessera/mvp/server/internal/workflow"
)

// The fixture is tenant A of the two-tenant world: alice, bob and carol are active people,
// dave is terminated, svc-etl is a service identity. pat decides; zed is a user who is nobody.

type env struct {
	t   *testing.T
	f   *storetest.Fixture
	ids map[string]int64
	now time.Time

	alice, bob, carol, zed, pat requests.Actor
}

func setup(t *testing.T) *env {
	t.Helper()
	f := storetest.TwoTenants(t)
	e := &env{t: t, f: f, ids: f.A.IDs, now: storetest.Now}
	e.tx(func(c *store.TenantTx) error {
		// a decider with no linked identity is refused (approver_unlinked, issue #443)
		patID, err := c.InsertIdentity(&store.Identity{TenantID: c.Tenant(), ExternalID: "pat", Name: "Pat", Type: "human", Status: "active", CreatedAt: e.now})
		if err != nil {
			return err
		}
		e.ids["pat"] = patID
		for _, u := range []struct {
			a     *requests.Actor
			name  string
			ident string
		}{{&e.alice, "Alice", "alice"}, {&e.bob, "Bob", "bob"}, {&e.carol, "Carol", "carol"}, {&e.zed, "Zed", ""}, {&e.pat, "Pat", "pat"}} {
			pu := &store.PlatformUser{DisplayName: u.name, CreatedAt: e.now}
			if u.ident != "" {
				id := e.ids[u.ident]
				pu.IdentityID = &id
			}
			if err := c.InsertPlatformUser(pu); err != nil {
				return err
			}
			*u.a = requests.Actor{UserID: pu.ID, Display: u.name, IdentityID: pu.IdentityID}
		}
		e.pat.Decider = true
		return nil
	})
	return e
}

func (e *env) tx(fn func(c *store.TenantTx) error) {
	e.t.Helper()
	if err := e.f.DB.InTenant(context.Background(), e.f.A.ID, fn); err != nil {
		e.t.Fatal(err)
	}
}

func code(err error) string {
	var re *requests.Error
	if errors.As(err, &re) {
		return re.Code
	}
	if err != nil {
		return "error: " + err.Error()
	}
	return ""
}

func p64(v int64) *int64 { return &v }

func (e *env) file(by requests.Actor, in svcaccounts.Input) (*store.ServiceAccountRequest, error) {
	var q *store.ServiceAccountRequest
	var ferr error
	e.tx(func(c *store.TenantTx) error {
		q, ferr = svcaccounts.File(c, in, by, e.now)
		return nil
	})
	return q, ferr
}

func (e *env) approve(by requests.Actor, id string, at time.Time) (*store.ServiceAccountRequest, error) {
	var q *store.ServiceAccountRequest
	var aerr error
	e.tx(func(c *store.TenantTx) error {
		q, aerr = svcaccounts.Approve(c, id, by, "", at)
		return nil
	})
	return q, aerr
}

func (e *env) get(id string) *store.ServiceAccountRequest {
	e.t.Helper()
	var q *store.ServiceAccountRequest
	e.tx(func(c *store.TenantTx) (err error) { q, err = c.ServiceAccountRequest(id); return })
	return q
}

func (e *env) stages(id string) []*store.RequestStage {
	e.t.Helper()
	var ss []*store.RequestStage
	e.tx(func(c *store.TenantTx) (err error) { ss, err = c.WorkflowStages(id); return })
	return ss
}

func (e *env) create(name string) *store.ServiceAccountRequest {
	return e.createBy(e.zed, name)
}

func (e *env) createBy(by requests.Actor, name string) *store.ServiceAccountRequest {
	e.t.Helper()
	q, err := e.file(by, svcaccounts.Input{Kind: store.SAKindCreate, Name: name, System: "okta", Username: name, Purpose: "nightly sync",
		PrimaryOwnerID: p64(e.ids["bob"]), BackupOwnerID: p64(e.ids["carol"]), Justification: "new pipeline"})
	if err != nil {
		e.t.Fatal(err)
	}
	return q
}

// made files and approves a create, returning the new account's identity id.
func (e *env) made(name string) int64 {
	e.t.Helper()
	q := e.create(name)
	if _, err := e.approve(e.bob, q.ID, e.now); err != nil {
		e.t.Fatal(err)
	}
	if got, err := e.approve(e.pat, q.ID, e.now); err != nil || got.Status != store.SAFulfilled || got.IdentityID == nil {
		e.t.Fatalf("approve: %+v %v", got, err)
	}
	return *e.get(q.ID).IdentityID
}

func TestCreate_DefaultRouting(t *testing.T) {
	e := setup(t)
	q := e.create("svc-sync")
	st := e.stages(q.ID)
	if len(st) != 2 || st[0].Kind != store.StageOwner || st[0].AssigneeID == nil || *st[0].AssigneeID != e.ids["bob"] || st[1].Kind != store.StageDecider {
		t.Fatalf("stages = %+v", st)
	}
	// only the new owner may decide the first stage; the requester never
	if _, err := e.approve(e.zed, q.ID, e.now); code(err) != "self_approval" {
		t.Errorf("requester: %v", err)
	}
	if _, err := e.approve(e.carol, q.ID, e.now); code(err) != "not_an_approver" {
		t.Errorf("another person: %v", err)
	}
	if _, err := e.approve(e.pat, q.ID, e.now); code(err) != "not_an_approver" {
		t.Errorf("decider before escalation: %v", err)
	}
	var pend []*store.ServiceAccountRequest
	e.tx(func(c *store.TenantTx) (err error) { pend, err = svcaccounts.Pending(c, e.bob, e.now); return })
	if len(pend) != 1 || pend[0].ID != q.ID {
		t.Errorf("bob's pending = %v", pend)
	}
	if got, err := e.approve(e.bob, q.ID, e.now); err != nil || got.Status != store.SAPending {
		t.Fatalf("new owner approves: %+v %v", got, err)
	}
	if _, err := e.approve(e.bob, q.ID, e.now); code(err) == "" {
		t.Error("the owner approved twice")
	}
	got, err := e.approve(e.pat, q.ID, e.now)
	if err != nil || got.Status != store.SAFulfilled || got.IdentityID == nil || got.FulfilledAt == nil {
		t.Fatalf("decider approves: %+v %v", got, err)
	}
	e.tx(func(c *store.TenantTx) error {
		i, err := c.Identity(*got.IdentityID)
		if err != nil || i.Type != "service" || i.Status != "active" || i.OwnerID == nil || *i.OwnerID != e.ids["bob"] {
			t.Errorf("identity = %+v, %v", i, err)
		}
		o, err := c.Ownership(store.OwnedIdentity, strconv.FormatInt(i.ID, 10))
		if err != nil || o.PrimaryID == nil || *o.PrimaryID != e.ids["bob"] || o.BackupID == nil || *o.BackupID != e.ids["carol"] || o.Purpose != "nightly sync" {
			t.Errorf("ownership = %+v, %v", o, err)
		}
		a, err := c.AccountByXID("okta", "svc-sync")
		if err != nil || a.Kind != "service" || a.Status != "active" || *a.IdentityID != i.ID {
			t.Errorf("account = %+v, %v", a, err)
		}
		return nil
	})
	if _, err := e.approve(e.pat, q.ID, e.now); code(err) != "not_pending" {
		t.Errorf("approving a fulfilled request: %v", err)
	}
}

func TestCreate_OwnersAreMandatory(t *testing.T) {
	e := setup(t)
	base := svcaccounts.Input{Kind: store.SAKindCreate, Name: "svc-x", System: "okta", Username: "svc-x", PrimaryOwnerID: p64(e.ids["bob"]),
		BackupOwnerID: p64(e.ids["carol"]), Justification: "why"}
	with := func(f func(in *svcaccounts.Input)) svcaccounts.Input { in := base; f(&in); return in }
	cases := []struct {
		name string
		in   svcaccounts.Input
		want string
	}{
		{"valid", base, ""},
		{"no primary", with(func(in *svcaccounts.Input) { in.PrimaryOwnerID = nil }), "primary_owner_required"},
		{"no backup", with(func(in *svcaccounts.Input) { in.BackupOwnerID = nil }), "backup_owner_required"},
		{"same owner twice", with(func(in *svcaccounts.Input) { in.BackupOwnerID = in.PrimaryOwnerID }), "same_owner"},
		{"terminated owner", with(func(in *svcaccounts.Input) { in.BackupOwnerID = p64(e.ids["dave"]) }), "backup_owner_not_active"},
		{"a service as owner", with(func(in *svcaccounts.Input) { in.PrimaryOwnerID = p64(e.ids["svc-etl"]) }), "primary_owner_not_active"},
		{"unknown owner", with(func(in *svcaccounts.Input) { in.PrimaryOwnerID = p64(99999) }), "primary_owner_not_found"},
		{"no justification", with(func(in *svcaccounts.Input) { in.Justification = " " }), "justification_required"},
		{"no name", with(func(in *svcaccounts.Input) { in.Name = "" }), "invalid_name"},
		{"bad username", with(func(in *svcaccounts.Input) { in.Username = "a b" }), "invalid_username"},
		{"unknown system", with(func(in *svcaccounts.Input) { in.System = "nowhere" }), "unknown_system"},
		{"account exists", with(func(in *svcaccounts.Input) { in.Username = "alice@larkspur.example" }), ""},
		{"unknown kind", with(func(in *svcaccounts.Input) { in.Kind = "delete" }), "invalid_kind"},
		{"an existing account for a create", with(func(in *svcaccounts.Input) { in.IdentityID = p64(e.ids["svc-etl"]) }), "invalid_account"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := e.file(e.zed, c.in)
			if c.name == "account exists" {
				return // depends on the fixture's account names; covered by TestCreate_Conflicts
			}
			if got := code(err); got != c.want {
				t.Errorf("code = %q (%v), want %q", got, err, c.want)
			}
			if c.want != "" {
				e.tx(func(c2 *store.TenantTx) error {
					qs, _ := c2.ServiceAccountRequests(store.SARequestFilter{})
					for _, q := range qs {
						if q.Name == c.in.Name && c.in.Name != "svc-x" {
							t.Errorf("a refused request was kept: %+v", q)
						}
					}
					return nil
				})
			}
		})
	}
}

func TestCreate_Conflicts(t *testing.T) {
	e := setup(t)
	e.create("svc-one")
	if _, err := e.file(e.zed, svcaccounts.Input{Kind: store.SAKindCreate, Name: "svc-one", System: "okta", Username: "svc-two",
		PrimaryOwnerID: p64(e.ids["bob"]), BackupOwnerID: p64(e.ids["carol"]), Justification: "x"}); code(err) != "request_open" {
		t.Errorf("the same name twice: %v", err)
	}
	e.made("svc-three")
	if _, err := e.file(e.zed, svcaccounts.Input{Kind: store.SAKindCreate, Name: "other", System: "okta", Username: "svc-three",
		PrimaryOwnerID: p64(e.ids["bob"]), BackupOwnerID: p64(e.ids["carol"]), Justification: "x"}); code(err) != "account_exists" {
		t.Errorf("an account that exists: %v", err)
	}
}

func TestTransfer_NeedsOldAndNewOwner(t *testing.T) {
	e := setup(t)
	id := e.made("svc-move")
	q, err := e.file(e.zed, svcaccounts.Input{Kind: store.SAKindTransfer, IdentityID: &id, PrimaryOwnerID: p64(e.ids["alice"]), Justification: "bob left the team"})
	if err != nil {
		t.Fatal(err)
	}
	st := e.stages(q.ID)
	if len(st) != 3 || *st[0].AssigneeID != e.ids["bob"] || *st[1].AssigneeID != e.ids["alice"] || st[2].Kind != store.StageDecider {
		t.Fatalf("stages = %+v", st)
	}
	if q.PreviousPrimaryID == nil || *q.PreviousPrimaryID != e.ids["bob"] || q.BackupOwnerID == nil || *q.BackupOwnerID != e.ids["carol"] {
		t.Errorf("snapshot / backup = %+v", q)
	}
	// a second open request about the account is refused
	if _, err := e.file(e.zed, svcaccounts.Input{Kind: store.SAKindChange, IdentityID: &id, Purpose: "x", Justification: "x"}); code(err) != "request_open" {
		t.Errorf("a second request: %v", err)
	}
	// the new owner cannot go first; the old owner does, then the new owner, then a decider
	if _, err := e.approve(e.alice, q.ID, e.now); code(err) != "not_an_approver" {
		t.Errorf("the new owner on the old owner's stage: %v", err)
	}
	if _, err := e.approve(e.bob, q.ID, e.now); err != nil {
		t.Fatal(err)
	}
	if _, err := e.approve(e.pat, q.ID, e.now); code(err) != "not_an_approver" {
		t.Errorf("a decider before the new owner: %v", err)
	}
	if got, err := e.approve(e.alice, q.ID, e.now); err != nil || got.Status != store.SAPending {
		t.Fatalf("new owner: %+v %v", got, err)
	}
	if got, err := e.approve(e.pat, q.ID, e.now); err != nil || got.Status != store.SAFulfilled {
		t.Fatalf("decider: %+v %v", got, err)
	}
	e.tx(func(c *store.TenantTx) error {
		o, err := c.Ownership(store.OwnedIdentity, strconv.FormatInt(id, 10))
		if err != nil || *o.PrimaryID != e.ids["alice"] || *o.BackupID != e.ids["carol"] || o.Purpose != "nightly sync" {
			t.Errorf("ownership = %+v, %v", o, err)
		}
		i, _ := c.Identity(id)
		if i.OwnerID == nil || *i.OwnerID != e.ids["alice"] {
			t.Errorf("owner of the identity = %v", i.OwnerID)
		}
		return nil
	})
}

func TestTransfer_RequesterIsTheOldOwner(t *testing.T) {
	e := setup(t)
	id := e.made("svc-handover")
	q, err := e.file(e.bob, svcaccounts.Input{Kind: store.SAKindTransfer, IdentityID: &id, PrimaryOwnerID: p64(e.ids["alice"]), Justification: "moving teams"})
	if err != nil {
		t.Fatal(err)
	}
	st := e.stages(q.ID)
	if st[0].Status != store.StageApproved || st[0].DecidedBy == nil || *st[0].DecidedBy != e.bob.UserID.String() || st[1].Status != store.StageWaiting {
		t.Fatalf("the owner's own request did not stand for their approval: %+v", st)
	}
	// still two more approvals: the new owner and a decider; the requester decides neither
	if _, err := e.approve(e.bob, q.ID, e.now); code(err) != "self_approval" {
		t.Errorf("requester approves: %v", err)
	}
	if _, err := e.approve(e.alice, q.ID, e.now); err != nil {
		t.Fatal(err)
	}
	if got, err := e.approve(e.pat, q.ID, e.now); err != nil || got.Status != store.SAFulfilled {
		t.Fatalf("decider: %+v %v", got, err)
	}
}

func TestTransfer_Refusals(t *testing.T) {
	e := setup(t)
	id := e.made("svc-refuse")
	cases := []struct {
		name string
		in   svcaccounts.Input
		want string
	}{
		{"same owner", svcaccounts.Input{Kind: store.SAKindTransfer, IdentityID: &id, PrimaryOwnerID: p64(e.ids["bob"])}, "same_owner"},
		{"no new owner", svcaccounts.Input{Kind: store.SAKindTransfer, IdentityID: &id}, "primary_owner_required"},
		{"new owner is the backup", svcaccounts.Input{Kind: store.SAKindTransfer, IdentityID: &id, PrimaryOwnerID: p64(e.ids["carol"])}, "same_owner"},
		{"not a service account", svcaccounts.Input{Kind: store.SAKindTransfer, IdentityID: p64(e.ids["alice"]), PrimaryOwnerID: p64(e.ids["carol"])}, "account_not_found"},
		{"no account", svcaccounts.Input{Kind: store.SAKindTransfer, PrimaryOwnerID: p64(e.ids["carol"])}, "account_required"},
		{"terminated new owner", svcaccounts.Input{Kind: store.SAKindTransfer, IdentityID: &id, PrimaryOwnerID: p64(e.ids["dave"])}, "primary_owner_not_active"},
	}
	for _, c := range cases {
		c.in.Justification = "because"
		if _, err := e.file(e.zed, c.in); code(err) != c.want {
			t.Errorf("%s: %v, want %s", c.name, err, c.want)
		}
	}
}

func TestChange_PurposeAndBackup(t *testing.T) {
	e := setup(t)
	id := e.made("svc-change")
	for name, in := range map[string]svcaccounts.Input{
		"nothing changes":   {Kind: store.SAKindChange, IdentityID: &id, Justification: "x"},
		"the primary":       {Kind: store.SAKindChange, IdentityID: &id, PrimaryOwnerID: p64(e.ids["alice"]), Purpose: "y", Justification: "x"},
		"backup is primary": {Kind: store.SAKindChange, IdentityID: &id, BackupOwnerID: p64(e.ids["bob"]), Justification: "x"},
	} {
		if _, err := e.file(e.zed, in); code(err) == "" {
			t.Errorf("%s: accepted", name)
		}
	}
	q, err := e.file(e.zed, svcaccounts.Input{Kind: store.SAKindChange, IdentityID: &id, BackupOwnerID: p64(e.ids["alice"]), Purpose: "weekly export", Justification: "scope moved"})
	if err != nil {
		t.Fatal(err)
	}
	if st := e.stages(q.ID); len(st) != 2 || *st[0].AssigneeID != e.ids["bob"] {
		t.Fatalf("stages = %+v", st)
	}
	if _, err := e.approve(e.bob, q.ID, e.now); err != nil {
		t.Fatal(err)
	}
	if got, err := e.approve(e.pat, q.ID, e.now); err != nil || got.Status != store.SAFulfilled {
		t.Fatalf("approve: %+v %v", got, err)
	}
	e.tx(func(c *store.TenantTx) error {
		o, _ := c.Ownership(store.OwnedIdentity, strconv.FormatInt(id, 10))
		if *o.PrimaryID != e.ids["bob"] || *o.BackupID != e.ids["alice"] || o.Purpose != "weekly export" {
			t.Errorf("ownership = %+v", o)
		}
		return nil
	})
}

func TestDenyAndCancel(t *testing.T) {
	e := setup(t)
	q := e.create("svc-deny")
	e.tx(func(c *store.TenantTx) error {
		if _, err := svcaccounts.Deny(c, q.ID, e.bob, " ", e.now); code(err) != "reason_required" {
			t.Errorf("deny without a reason: %v", err)
		}
		got, err := svcaccounts.Deny(c, q.ID, e.bob, "not ours", e.now)
		if err != nil || got.Status != store.SADenied || got.ClosedAt == nil {
			t.Errorf("deny: %+v %v", got, err)
		}
		ss, _ := c.WorkflowStages(q.ID)
		if ss[0].Status != store.StageDenied || ss[1].Status != store.StageClosed {
			t.Errorf("stages after a denial = %+v", ss)
		}
		return nil
	})
	if _, err := e.approve(e.pat, q.ID, e.now); code(err) != "not_pending" {
		t.Errorf("approve a denied request: %v", err)
	}
	q = e.create("svc-cancel")
	e.tx(func(c *store.TenantTx) error {
		if _, err := svcaccounts.Cancel(c, q.ID, e.bob, e.now); code(err) != "request_not_found" {
			t.Errorf("someone else cancels: %v", err)
		}
		got, err := svcaccounts.Cancel(c, q.ID, e.zed, e.now)
		if err != nil || got.Status != store.SACancelled {
			t.Errorf("cancel: %+v %v", got, err)
		}
		if _, err := svcaccounts.Cancel(c, q.ID, e.zed, e.now); code(err) != "not_pending" {
			t.Errorf("cancel twice: %v", err)
		}
		return nil
	})
	// after a cancel the name is free again
	e.create("svc-cancel")
}

func TestWorkflowRoutesServiceAccountRequests(t *testing.T) {
	e := setup(t)
	var wf *workflow.View
	assign := func(name, requestType string, steps []workflow.Step) error {
		var aerr error
		e.tx(func(c *store.TenantTx) error {
			v, err := workflow.Create(c, workflow.Spec{Name: name, Scope: store.WorkflowScopeServiceAccount, Steps: steps}, "Pat", e.now)
			if err != nil {
				aerr = err
				return nil
			}
			wf = v
			_, aerr = workflow.SetTargets(c, v.ID, []workflow.Target{{Kind: store.WFTargetRequestType, TargetID: requestType}}, "Pat", e.now)
			return nil
		})
		return aerr
	}
	appr := func(id, a string) workflow.Step {
		return workflow.Step{ID: id, Type: workflow.TypeApproval, Approver: a}
	}
	// a transfer workflow must ask both owners on every path
	if err := assign("bad", workflow.RequestSATransfer, []workflow.Step{appr("o", workflow.ApproverOldOwner), appr("d", workflow.ApproverDecider)}); err == nil {
		t.Fatal("a transfer workflow without the new owner was assigned")
	} else {
		var we *workflow.Error
		if !errors.As(err, &we) || we.Code != "transfer_needs_both_owners" {
			t.Errorf("error = %v", err)
		}
	}
	// a create has no old owner
	if err := assign("bad-create", workflow.RequestSACreate, []workflow.Step{appr("o", workflow.ApproverOldOwner), appr("d", workflow.ApproverDecider)}); err == nil {
		t.Error("a create workflow with an old owner was assigned")
	}
	// a create workflow: the decider alone, then a notice
	if err := assign("create-fast", workflow.RequestSACreate, []workflow.Step{appr("d", workflow.ApproverDecider),
		{ID: "n", Type: workflow.TypeNotify, Notify: workflow.NotifyRequester}}); err != nil {
		t.Fatal(err)
	}
	q := e.create("svc-fast")
	if st := e.stages(q.ID); len(st) != 1 || st[0].Kind != store.StageDecider {
		t.Fatalf("stages = %+v", st)
	}
	e.tx(func(c *store.TenantTx) error {
		run, err := c.WorkflowRunFor(store.WFSubjectServiceAccount, q.ID)
		if err != nil || run.WorkflowID != wf.ID || run.Status != store.WFRunRunning {
			t.Errorf("run = %+v, %v", run, err)
		}
		return nil
	})
	if got, err := e.approve(e.pat, q.ID, e.now); err != nil || got.Status != store.SAFulfilled {
		t.Fatalf("approve: %+v %v", got, err)
	}
	e.tx(func(c *store.TenantTx) error {
		run, _ := c.WorkflowRunFor(store.WFSubjectServiceAccount, q.ID)
		if run.Status != store.WFRunCompleted {
			t.Errorf("run after approval = %+v", run)
		}
		return nil
	})
}

func TestRequesterCannotApproveEverything(t *testing.T) {
	e := setup(t)
	e.tx(func(c *store.TenantTx) error {
		v, err := workflow.Create(c, workflow.Spec{Name: "owner-only", Scope: store.WorkflowScopeServiceAccount,
			Steps: []workflow.Step{{ID: "n", Type: workflow.TypeApproval, Approver: workflow.ApproverNewOwner}}}, "Pat", e.now)
		if err != nil {
			return err
		}
		_, err = workflow.SetTargets(c, v.ID, []workflow.Target{{Kind: store.WFTargetRequestType, TargetID: workflow.RequestSACreate}}, "Pat", e.now)
		return err
	})
	// the new owner files the request: their consent is the only approval, so it needs another person
	if _, err := e.file(e.bob, svcaccounts.Input{Kind: store.SAKindCreate, Name: "svc-self", System: "okta", Username: "svc-self",
		PrimaryOwnerID: p64(e.ids["bob"]), BackupOwnerID: p64(e.ids["carol"]), Justification: "x"}); code(err) != "needs_another_approver" {
		t.Errorf("a request that approves itself: %v", err)
	}
	e.tx(func(c *store.TenantTx) error {
		if _, err := c.OpenServiceAccountCreate("svc-self"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("the refused request was kept: %v", err)
		}
		return nil
	})
}

func TestStagesHeldByWait(t *testing.T) {
	e := setup(t)
	e.tx(func(c *store.TenantTx) error {
		v, err := workflow.Create(c, workflow.Spec{Name: "cool-off", Scope: store.WorkflowScopeServiceAccount, Steps: []workflow.Step{
			{ID: "n", Type: workflow.TypeApproval, Approver: workflow.ApproverNewOwner}, {ID: "w", Type: workflow.TypeWait, Hours: 4},
			{ID: "d", Type: workflow.TypeApproval, Approver: workflow.ApproverDecider}}}, "Pat", e.now)
		if err != nil {
			return err
		}
		_, err = workflow.SetTargets(c, v.ID, []workflow.Target{{Kind: store.WFTargetRequestType, TargetID: workflow.RequestSACreate}}, "Pat", e.now)
		return err
	})
	q := e.create("svc-wait")
	if _, err := e.approve(e.bob, q.ID, e.now); err != nil {
		t.Fatal(err)
	}
	if _, err := e.approve(e.pat, q.ID, e.now.Add(time.Hour)); code(err) != "stage_not_open" {
		t.Errorf("held stage: %v", err)
	}
	if got, err := e.approve(e.pat, q.ID, e.now.Add(4*time.Hour)); err != nil || got.Status != store.SAFulfilled {
		t.Fatalf("after the wait: %+v %v", got, err)
	}
}

// A create routed to a target with write-back waits for the target to confirm the account.
func TestCreate_ProvisionedThroughTheEngine(t *testing.T) {
	e := setup(t)
	fk := fake.New(fake.Options{Token: "tok"})
	srv := httptest.NewServer(fk.Handler())
	t.Cleanup(srv.Close)
	hc, err := safehttp.NewForTest(t, safehttp.Options{Env: config.Dev, AllowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := seal.New(seal.RandomBytes(seal.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	eng := &provision.Engine{DB: e.f.DB, Sealer: sealer, HTTP: hc, Clock: func() time.Time { return e.now },
		MaxAttempts: 3, MaxVerifies: 3, Backoff: func(int) time.Duration { return 0 }}
	conn := e.f.A.Refs["connection:ad"]
	var system string
	e.tx(func(c *store.TenantTx) error {
		cn, err := c.Connection(conn)
		if err != nil {
			return err
		}
		system = cn.System
		id := store.NewID()
		enc, err := provision.SealToken(sealer, e.f.A.ID, id, "tok")
		if err != nil {
			return err
		}
		settings, _ := json.Marshal(provision.Settings{})
		return c.UpsertProvTarget(&store.ProvTarget{ID: id, ConnectionID: conn, Kind: provision.KindSCIM, BaseURL: srv.URL + "/scim/v2",
			Settings: string(settings), CredentialEnc: enc, WriteBack: true, CreatedBy: "admin"}, e.now)
	})
	e.tx(func(c *store.TenantTx) error { // the connection's system has an account, so it is an application
		_, err := c.InsertAccount(&store.Account{System: system, ExternalID: "seed", Username: "seed", Kind: "user", Status: "active", CreatedAt: &e.now})
		return err
	})
	q, err := e.file(e.zed, svcaccounts.Input{Kind: store.SAKindCreate, Name: "svc-prov", System: system, Username: "svc-prov",
		PrimaryOwnerID: p64(e.ids["bob"]), BackupOwnerID: p64(e.ids["carol"]), Justification: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.approve(e.bob, q.ID, e.now); err != nil {
		t.Fatal(err)
	}
	got, err := e.approve(e.pat, q.ID, e.now)
	if err != nil || got.Status != store.SAApproved || got.OpID == nil {
		t.Fatalf("approve: %+v %v", got, err)
	}
	e.tx(func(c *store.TenantTx) error {
		if _, err := c.AccountByXID(system, "svc-prov"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("the account exists before the target confirmed it: %v", err)
		}
		return nil
	})
	if _, err := eng.RunTenant(context.Background(), e.f.A.ID); err != nil {
		t.Fatal(err)
	}
	if done := e.get(q.ID); done.Status != store.SAFulfilled || done.FulfilledAt == nil {
		t.Errorf("after the engine ran: %+v", done)
	}
	e.tx(func(c *store.TenantTx) error {
		if a, err := c.AccountByXID(system, "svc-prov"); err != nil || a.Kind != "service" {
			t.Errorf("account = %+v, %v", a, err)
		}
		return nil
	})
}
