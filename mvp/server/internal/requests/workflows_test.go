package requests_test

import (
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/questionnaires"
	"github.com/nischalravi/tessera/mvp/server/internal/requests"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/workflow"
)

// Workflows on access requests (issue #298): a workflow assigned to the item routes its lines
// through the same stages, and an item with none keeps the approval policy.

func (r *routed) workflow(name string, steps []workflow.Step, targets ...workflow.Target) *workflow.View {
	r.t.Helper()
	var v *workflow.View
	r.tx(func(c *store.TenantTx) error {
		var err error
		if v, err = workflow.Create(c, workflow.Spec{Name: name, Scope: store.WorkflowScopeAccess, Steps: steps}, "Pat", r.now); err != nil {
			return err
		}
		v, err = workflow.SetTargets(c, v.ID, targets, "Pat", r.now)
		return err
	})
	return v
}

func (r *routed) itemTarget() workflow.Target {
	return workflow.Target{Kind: store.WFTargetCatalogItem, TargetID: r.item}
}

func (r *routed) submitPlatform(answers map[string]map[string]any) ([]*store.RequestLine, error) {
	var lines []*store.RequestLine
	var err error
	r.tx(func(c *store.TenantTx) error {
		_, lines, err = requests.Submit(c, requests.Submission{Beneficiaries: []int64{r.ids["alice"]}, Items: []string{r.item},
			Justification: "project Atlas", Answers: answers}, r.alice, false, r.now)
		return nil
	})
	return lines, err
}

func approval(id, approver string) workflow.Step {
	return workflow.Step{ID: id, Type: workflow.TypeApproval, Approver: approver}
}

func TestWorkflow_RoutesLineByCondition(t *testing.T) {
	r := newRouted(t)
	cond := workflow.Step{ID: "c", Type: workflow.TypeCondition, When: &workflow.Cond{Attribute: "risk", Op: workflow.OpEq, Values: []string{"medium"}},
		Then: "m", Else: "d"}
	steps := []workflow.Step{cond, approval("m", workflow.ApproverOwner), approval("d", workflow.ApproverDecider)}
	v := r.workflow("platform", steps, r.itemTarget())

	// medium risk: owner (bob), then a decider; the manager stage of the item's policy is not asked
	lines, err := r.submitPlatform(nil)
	if err != nil {
		t.Fatal(err)
	}
	id := lines[0].ID
	if got := r.inbox(r.carol, r.now); len(got) != 0 {
		t.Errorf("the policy's manager stage was asked: %v", got)
	}
	if got := r.inbox(r.bob, r.now); len(got) != 1 || got[0] != id {
		t.Fatalf("bob's inbox = %v", got)
	}
	st := r.stages(id)
	if len(st) != 2 || st[0].Kind != store.StageOwner || st[1].Kind != store.StageDecider {
		t.Fatalf("stages = %+v", st)
	}
	if _, err := r.approve(r.pat, id, r.now); code(err) != "not_an_approver" {
		t.Errorf("decider on the owner stage: %v", err)
	}
	if l, err := r.approve(r.bob, id, r.now); err != nil || l.Status != store.RequestPending {
		t.Fatalf("owner approves: %v %v", l, err)
	}
	if l, err := r.approve(r.pat, id, r.now); err != nil || l.Status != store.RequestApproved {
		t.Fatalf("decider approves: %v %v", l, err)
	}
	r.tx(func(c *store.TenantTx) error {
		run, err := c.WorkflowRunFor(store.WFSubjectAccessLine, id)
		if err != nil || run.WorkflowID != v.ID || run.Version != 1 || run.Status != store.WFRunCompleted || run.FinishedAt == nil {
			t.Errorf("run = %+v, %v", run, err)
		}
		return nil
	})
	if r.edge("acct:okta:alice", "group:okta:platform") == nil {
		t.Error("no grant after the last stage")
	}

	// a high-risk item takes the other branch: the decider alone
	r2 := newRouted(t)
	r2.workflow("platform", steps, r2.itemTarget())
	r2.tx(func(c *store.TenantTx) error {
		bob := r2.ids["bob"]
		_, err := requests.PutItem(c, r2.ids["group:okta:platform"], requests.ItemSpec{Requestable: true, Risk: "high", OwnerIdentityID: &bob}, r2.pat, r2.now)
		return err
	})
	lines, err = r2.submitPlatform(nil)
	if err != nil {
		t.Fatal(err)
	}
	if st := r2.stages(lines[0].ID); len(st) != 1 || st[0].Kind != store.StageDecider {
		t.Errorf("high-risk stages = %+v", st)
	}
}

func TestWorkflow_ItemWithoutOneKeepsPolicy(t *testing.T) {
	r := newRouted(t)
	// a workflow routes another item; this one keeps manager, owner, decider
	other := workflow.Target{Kind: store.WFTargetCatalogItem, TargetID: r.items["group:okta:eng"]}
	r.workflow("eng", []workflow.Step{approval("d", workflow.ApproverDecider)}, other)
	lines, err := r.submitPlatform(nil)
	if err != nil {
		t.Fatal(err)
	}
	st := r.stages(lines[0].ID)
	if len(st) != 3 || st[0].Kind != store.StageManager || st[1].Kind != store.StageOwner || st[2].Kind != store.StageDecider {
		t.Fatalf("stages = %+v", st)
	}
	r.tx(func(c *store.TenantTx) error {
		if _, err := c.WorkflowRunFor(store.WFSubjectAccessLine, lines[0].ID); err == nil {
			t.Error("a line no workflow routed has a run")
		}
		return nil
	})
}

func TestWorkflow_RequestTypeAssignment(t *testing.T) {
	r := newRouted(t)
	// the access request type routes every item without its own workflow
	r.workflow("all", []workflow.Step{approval("d", workflow.ApproverDecider)},
		workflow.Target{Kind: store.WFTargetRequestType, TargetID: workflow.RequestAccess})
	lines, err := r.submitPlatform(nil)
	if err != nil {
		t.Fatal(err)
	}
	if st := r.stages(lines[0].ID); len(st) != 1 || st[0].Kind != store.StageDecider {
		t.Fatalf("stages = %+v", st)
	}
	// an item's own workflow wins
	r.workflow("own", []workflow.Step{approval("o", workflow.ApproverOwner), approval("d", workflow.ApproverDecider)}, r.itemTarget())
	lines, err = r.submitPlatformFor("bob")
	if err != nil {
		t.Fatal(err)
	}
	if st := r.stages(lines[0].ID); len(st) != 2 || st[0].Kind != store.StageOwner {
		t.Fatalf("stages under the item's own workflow = %+v", st)
	}
}

func TestWorkflow_WaitHoldsNextStage(t *testing.T) {
	r := newRouted(t)
	r.workflow("held", []workflow.Step{approval("o", workflow.ApproverOwner), {ID: "w", Type: workflow.TypeWait, Hours: 2},
		approval("d", workflow.ApproverDecider)}, r.itemTarget())
	lines, err := r.submitPlatform(nil)
	if err != nil {
		t.Fatal(err)
	}
	id := lines[0].ID
	if _, err := r.approve(r.bob, id, r.now); err != nil {
		t.Fatal(err)
	}
	if got := r.inbox(r.pat, r.now.Add(time.Hour)); len(got) != 0 {
		t.Errorf("a held stage is in the inbox: %v", got)
	}
	if _, err := r.approve(r.pat, id, r.now.Add(time.Hour)); code(err) != "stage_not_open" {
		t.Errorf("deciding a held stage: %v", err)
	}
	if got := r.inbox(r.pat, r.now.Add(2*time.Hour)); len(got) != 1 {
		t.Errorf("the opened stage is not in the inbox: %v", got)
	}
	if l, err := r.approve(r.pat, id, r.now.Add(2*time.Hour)); err != nil || l.Status != store.RequestApproved {
		t.Fatalf("decider after the wait: %v %v", l, err)
	}
}

func TestWorkflow_GroupStage(t *testing.T) {
	r := newRouted(t)
	var group string
	r.tx(func(c *store.TenantTx) error {
		root := &store.Folder{CreatedAt: r.now}
		if err := c.InsertGrpFolder(root); err != nil {
			return err
		}
		g := &store.NativeGroup{FolderID: root.ID, Extension: "approvers", DisplayExtension: "approvers", Name: "approvers", DisplayName: "approvers", CreatedAt: r.now}
		if err := c.InsertGrpGroup(g); err != nil {
			return err
		}
		l, err := c.EnsureGrpMembersList()
		if err != nil {
			return err
		}
		group = string(g.ID)
		return c.SetGrpEffective(g.ID, l, r.ids["carol"], 1, r.now)
	})
	r.workflow("grp", []workflow.Step{{ID: "g", Type: workflow.TypeApproval, Approver: workflow.ApproverGroup, GroupID: group},
		approval("d", workflow.ApproverDecider)}, r.itemTarget())
	lines, err := r.submitPlatform(nil)
	if err != nil {
		t.Fatal(err)
	}
	id := lines[0].ID
	if got := r.inbox(r.carol, r.now); len(got) != 1 {
		t.Errorf("a member's inbox = %v", got)
	}
	if got := r.inbox(r.bob, r.now); len(got) != 0 {
		t.Errorf("a non-member's inbox = %v", got)
	}
	if _, err := r.approve(r.bob, id, r.now); code(err) != "not_an_approver" {
		t.Errorf("a non-member approves: %v", err)
	}
	if _, err := r.approve(r.pat, id, r.now); code(err) != "not_an_approver" {
		t.Errorf("a decider before escalation: %v", err)
	}
	if l, err := r.approve(r.carol, id, r.now); err != nil || l.Status != store.RequestPending {
		t.Fatalf("member approves: %v %v", l, err)
	}
	if l, err := r.approve(r.pat, id, r.now); err != nil || l.Status != store.RequestApproved {
		t.Fatalf("decider approves: %v %v", l, err)
	}
}

func TestWorkflow_GroupStageEscalates(t *testing.T) {
	r := newRouted(t)
	// a group nobody is in: the stage is due at once and a decider may act
	r.tx(func(c *store.TenantTx) error {
		root := &store.Folder{CreatedAt: r.now}
		if err := c.InsertGrpFolder(root); err != nil {
			return err
		}
		g := &store.NativeGroup{FolderID: root.ID, Extension: "empty", DisplayExtension: "empty", Name: "empty", DisplayName: "empty", CreatedAt: r.now}
		if err := c.InsertGrpGroup(g); err != nil {
			return err
		}
		v, err := workflow.Create(c, workflow.Spec{Name: "empty", Scope: store.WorkflowScopeAccess,
			Steps: []workflow.Step{{ID: "g", Type: workflow.TypeApproval, Approver: workflow.ApproverGroup, GroupID: string(g.ID)}}}, "Pat", r.now)
		if err != nil {
			return err
		}
		_, err = workflow.SetTargets(c, v.ID, []workflow.Target{r.itemTarget()}, "Pat", r.now)
		return err
	})
	lines, err := r.submitPlatform(nil)
	if err != nil {
		t.Fatal(err)
	}
	if l, err := r.approve(r.pat, lines[0].ID, r.now); err != nil || l.Status != store.RequestApproved {
		t.Fatalf("decider on an unreachable group stage: %v %v", l, err)
	}
}

func (r *routed) submitPlatformFor(who string) ([]*store.RequestLine, error) {
	var lines []*store.RequestLine
	var err error
	r.tx(func(c *store.TenantTx) error {
		_, lines, err = requests.Submit(c, requests.Submission{Beneficiaries: []int64{r.ids[who]}, Items: []string{r.item},
			Justification: "x"}, r.pat, true, r.now)
		return nil
	})
	return lines, err
}

func TestWorkflow_QuestionnaireStep(t *testing.T) {
	r := newRouted(t)
	var qid string
	r.tx(func(c *store.TenantTx) error {
		d, err := questionnaires.Create(c, questionnaires.Spec{Title: "Why", Questions: []questionnaires.Question{
			{ID: "why", Type: questionnaires.ShortText, Text: "Why do you need it?", Required: true}}}, "Pat", r.now)
		qid = d.ID
		return err
	})
	r.workflow("asks", []workflow.Step{{ID: "q", Type: workflow.TypeQuestionnaire, QuestionnaireID: qid}, approval("d", workflow.ApproverDecider)}, r.itemTarget())
	if _, err := r.submitPlatform(nil); code(err) == "" || code(err) == "error: <nil>" {
		t.Errorf("submitted without the workflow's questionnaire answered: %v", err)
	}
	lines, err := r.submitPlatform(map[string]map[string]any{qid: {"why": "to rotate keys"}})
	if err != nil {
		t.Fatal(err)
	}
	r.tx(func(c *store.TenantTx) error {
		as, err := questionnaires.AnswersFor(c, store.QSubjectRequestLine, lines[0].ID)
		if err != nil || len(as) != 1 || as[0].QuestionnaireID != qid {
			t.Errorf("answers = %+v, %v", as, err)
		}
		return nil
	})
}

func TestWorkflow_DenyAndCancelEndTheRun(t *testing.T) {
	r := newRouted(t)
	r.workflow("d", []workflow.Step{approval("d", workflow.ApproverDecider),
		{ID: "p", Type: workflow.TypeProvisioning}}, r.itemTarget())
	lines, err := r.submitPlatform(nil)
	if err != nil {
		t.Fatal(err)
	}
	r.tx(func(c *store.TenantTx) error {
		if _, err := requests.Deny(c, lines[0].ID, r.pat, "no", r.now); err != nil {
			return err
		}
		run, err := c.WorkflowRunFor(store.WFSubjectAccessLine, lines[0].ID)
		if err != nil || run.Status != store.WFRunDenied {
			t.Errorf("run = %+v, %v", run, err)
		}
		return nil
	})
	lines, err = r.submitPlatform(nil)
	if err != nil {
		t.Fatal(err)
	}
	r.tx(func(c *store.TenantTx) error {
		if _, err := requests.Cancel(c, lines[0].ID, r.alice, r.now); err != nil {
			return err
		}
		run, err := c.WorkflowRunFor(store.WFSubjectAccessLine, lines[0].ID)
		if err != nil || run.Status != store.WFRunCancelled {
			t.Errorf("run = %+v, %v", run, err)
		}
		return nil
	})
	// a provisioning step with no write-back leaves the grant in Tessera, as for any line
	lines, err = r.submitPlatform(nil)
	if err != nil {
		t.Fatal(err)
	}
	if l, err := r.approve(r.pat, lines[0].ID, r.now); err != nil || l.Status != store.RequestApproved {
		t.Fatalf("approve: %v %v", l, err)
	}
}
