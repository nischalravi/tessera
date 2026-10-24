package workflow

import (
	"slices"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

func appr(id, approver string) Step { return Step{ID: id, Type: TypeApproval, Approver: approver} }

func cond(id, attr, then, els string, values ...string) Step {
	return Step{ID: id, Type: TypeCondition, When: &Cond{Attribute: attr, Op: OpEq, Values: values}, Then: then, Else: els}
}

func codes(is []Issue) []string {
	var out []string
	for _, i := range is {
		out = append(out, i.Code)
	}
	slices.Sort(out)
	return out
}

func TestValidate(t *testing.T) {
	access, sa := store.WorkflowScopeAccess, store.WorkflowScopeServiceAccount
	long := make([]Step, MaxSteps+1)
	for i := range long {
		long[i] = appr("s"+string(rune('a'+i%26))+string(rune('a'+i/26)), ApproverDecider)
	}
	cases := []struct {
		name  string
		scope string
		steps []Step
		want  []string // issue codes; none: valid
	}{
		{"one decider", access, []Step{appr("a", ApproverDecider)}, nil},
		{"manager owner decider", access, []Step{appr("a", ApproverManager), appr("b", ApproverOwner), appr("c", ApproverDecider)}, nil},
		{"branch converges", access, []Step{cond("c", "risk", "h", "d", "high"), appr("h", ApproverOwner), appr("d", ApproverDecider)}, nil},
		{"empty", access, nil, []string{"invalid_steps"}},
		{"too many steps", access, long, []string{"invalid_steps"}},
		{"bad scope", "x", []Step{appr("a", ApproverDecider)}, []string{"invalid_scope"}},
		{"bad id", access, []Step{appr("A b", ApproverDecider)}, []string{"invalid_id"}},
		{"end as an id", access, []Step{appr("end", ApproverDecider)}, []string{"invalid_id"}},
		{"duplicate id", access, []Step{appr("a", ApproverDecider), appr("a", ApproverManager)}, []string{"duplicate_id"}},
		{"unknown type", access, []Step{{ID: "a", Type: "teleport"}}, []string{"invalid_type"}},
		{"old owner outside service accounts", access, []Step{appr("a", ApproverOldOwner)}, []string{"invalid_approver"}},
		{"owner is not a service-account approver", sa, []Step{appr("a", ApproverOwner)}, []string{"invalid_approver"}},
		{"service account transfer approvers", sa, []Step{appr("a", ApproverOldOwner), appr("b", ApproverNewOwner), appr("c", ApproverDecider)}, nil},
		{"group needs a group", access, []Step{appr("a", ApproverGroup)}, []string{"group_required"}},
		{"stray group", access, []Step{{ID: "a", Type: TypeApproval, Approver: ApproverDecider, GroupID: "g"}}, []string{"stray_field"}},
		{"stray hours", access, []Step{{ID: "a", Type: TypeApproval, Approver: ApproverDecider, Hours: 3}}, []string{"stray_field"}},
		{"escalation out of range", access, []Step{{ID: "a", Type: TypeApproval, Approver: ApproverDecider, EscalateAfterHours: MaxHours + 1}}, []string{"invalid_escalation"}},
		{"next to nowhere", access, []Step{{ID: "a", Type: TypeApproval, Approver: ApproverDecider, Next: "zz"}}, []string{"unknown_step"}},
		{"next to itself", access, []Step{{ID: "a", Type: TypeApproval, Approver: ApproverDecider, Next: "a"}}, []string{"self_reference"}},
		{"cycle", access, []Step{appr("a", ApproverManager), {ID: "b", Type: TypeApproval, Approver: ApproverDecider, Next: "a"}}, []string{"cycle"}},
		{"cycle through a condition", access, []Step{cond("c", "risk", "a", "end", "high"), {ID: "a", Type: TypeApproval, Approver: ApproverDecider, Next: "c"}}, []string{"cycle"}},
		{"unreachable step", access, []Step{{ID: "a", Type: TypeApproval, Approver: ApproverDecider, Next: "end"}, appr("b", ApproverManager)}, []string{"unreachable"}},
		{"a path with no approval", access, []Step{cond("c", "risk", "a", "end", "low"), appr("a", ApproverDecider)}, []string{"no_approval"}},
		{"notify only", access, []Step{{ID: "n", Type: TypeNotify, Notify: NotifyRequester}}, []string{"no_approval"}},
		{"provisioning before approval", access, []Step{{ID: "p", Type: TypeProvisioning}, appr("a", ApproverDecider)}, []string{"provisioning_before_approval", "after_provisioning"}},
		{"provisioning on a path with no approval before", access, []Step{cond("c", "risk", "a", "p", "high"), appr("a", ApproverDecider), {ID: "p", Type: TypeProvisioning}},
			[]string{"provisioning_before_approval", "no_approval"}},
		{"provisioning after approval", access, []Step{appr("a", ApproverDecider), {ID: "p", Type: TypeProvisioning}, {ID: "n", Type: TypeNotify, Notify: NotifyRequester}}, nil},
		{"approval after provisioning", access, []Step{appr("a", ApproverDecider), {ID: "p", Type: TypeProvisioning}, appr("b", ApproverManager)}, []string{"after_provisioning"}},
		{"questionnaire first", access, []Step{{ID: "q", Type: TypeQuestionnaire, QuestionnaireID: "x"}, appr("a", ApproverDecider)}, nil},
		{"questionnaire after an approval", access, []Step{appr("a", ApproverDecider), {ID: "q", Type: TypeQuestionnaire, QuestionnaireID: "x"}}, []string{"questionnaire_late"}},
		{"questionnaire without id", access, []Step{{ID: "q", Type: TypeQuestionnaire}, appr("a", ApproverDecider)}, []string{"questionnaire_required"}},
		{"wait before approval", access, []Step{{ID: "w", Type: TypeWait, Hours: 4}, appr("a", ApproverDecider)}, nil},
		{"wait at the end", access, []Step{appr("a", ApproverDecider), {ID: "w", Type: TypeWait, Hours: 4}}, []string{"wait_without_approval"}},
		{"wait of no time", access, []Step{{ID: "w", Type: TypeWait}, appr("a", ApproverDecider)}, []string{"invalid_hours"}},
		{"notify a group without one", access, []Step{{ID: "n", Type: TypeNotify, Notify: NotifyGroup}, appr("a", ApproverDecider)}, []string{"group_required"}},
		{"notify nobody", access, []Step{{ID: "n", Type: TypeNotify}, appr("a", ApproverDecider)}, []string{"invalid_notify"}},
		{"condition without a test", access, []Step{{ID: "c", Type: TypeCondition, Then: "a", Else: "a"}, appr("a", ApproverDecider)}, []string{"condition_required", "condition_same_branch"}},
		{"condition unknown attribute", access, []Step{cond("c", "mood", "a", "end", "x"), appr("a", ApproverDecider)}, []string{"invalid_attribute"}},
		{"condition unknown value", access, []Step{cond("c", "risk", "a", "end", "extreme"), appr("a", ApproverDecider)}, []string{"invalid_values"}},
		{"condition both branches the same", access, []Step{cond("c", "risk", "a", "a", "high"), appr("a", ApproverDecider)}, []string{"condition_same_branch"}},
		{"condition missing branch", access, []Step{{ID: "c", Type: TypeCondition, When: &Cond{Attribute: "risk", Op: OpEq, Values: []string{"high"}}, Then: "a"}, appr("a", ApproverDecider)},
			[]string{"branch_required", "unknown_step"}},
		{"condition eq with two values", access, []Step{cond("c", "item", "a", "end", "x", "y"), appr("a", ApproverDecider)}, []string{"invalid_values"}},
		{"service-account attribute on access", access, []Step{cond("c", "kind", "a", "end", "create"), appr("a", ApproverDecider)}, []string{"invalid_attribute"}},
		{"service-account kind", sa, []Step{cond("c", "kind", "a", "end", "create"), appr("a", ApproverDecider)}, []string{"no_approval"}},
		{"approvals per path", access, func() []Step {
			var s []Step
			for i := 0; i <= MaxApprovalsPerPath; i++ {
				s = append(s, appr("s"+string(rune('a'+i)), ApproverDecider))
			}
			return s
		}(), []string{"too_many_approvals"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := codes(Definition{Steps: c.steps}.Validate(c.scope))
			want := slices.Clone(c.want)
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Errorf("issues = %v, want %v", got, want)
			}
		})
	}
}

func TestCompile(t *testing.T) {
	d := Definition{Steps: []Step{
		{ID: "q", Type: TypeQuestionnaire, QuestionnaireID: "qq"},
		{ID: "n0", Type: TypeNotify, Notify: NotifyRequester},
		cond("c", "risk", "g", "m", "high"),
		{ID: "m", Type: TypeApproval, Approver: ApproverManager, Name: "Line manager", Next: "n1"},
		{ID: "g", Type: TypeApproval, Approver: ApproverGroup, GroupID: "grp", EscalateAfterHours: 12},
		{ID: "w", Type: TypeWait, Hours: 2},
		{ID: "d", Type: TypeApproval, Approver: ApproverDecider},
		{ID: "p", Type: TypeProvisioning},
		{ID: "n1", Type: TypeNotify, Notify: NotifyOwner, Message: "done"},
	}}
	if is := d.Validate(store.WorkflowScopeAccess); len(is) != 0 {
		t.Fatalf("invalid: %v", is)
	}
	high, err := d.Compile("w1", 3, map[string]string{"risk": "high"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(high.Path, []string{"q", "n0", "c", "g", "w", "d", "p", "n1"}) {
		t.Errorf("high path = %v", high.Path)
	}
	if len(high.Stages) != 2 || high.Stages[0].Approver != ApproverGroup || high.Stages[0].EscalateAfterHours != 12 ||
		high.Stages[1].HoldHours != 2 || high.Stages[1].EscalateAfterHours != DefaultEscalateHours {
		t.Errorf("high stages = %+v", high.Stages)
	}
	if !high.Provision || !slices.Equal(high.Questionnaires, []string{"qq"}) || high.Workflow != "w1" || high.Version != 3 {
		t.Errorf("high plan = %+v", high)
	}
	if len(high.Actions) != 2 || high.Actions[0].After != -1 || high.Actions[1].After != 1 {
		t.Errorf("high actions = %+v", high.Actions)
	}
	// anything but high (and an unknown attribute) takes the else branch
	for _, attrs := range []map[string]string{{"risk": "low"}, {}} {
		low, err := d.Compile("w1", 3, attrs)
		if err != nil {
			t.Fatal(err)
		}
		if len(low.Stages) != 1 || low.Stages[0].Label != "Line manager" || low.Stages[0].Kind() != store.StageManager || low.Provision {
			t.Errorf("low plan (%v) = %+v", attrs, low)
		}
	}
}

func TestCondEval(t *testing.T) {
	cases := []struct {
		c     Cond
		attrs map[string]string
		want  bool
	}{
		{Cond{Attribute: "risk", Op: OpEq, Values: []string{"high"}}, map[string]string{"risk": "high"}, true},
		{Cond{Attribute: "risk", Op: OpEq, Values: []string{"high"}}, map[string]string{"risk": "low"}, false},
		{Cond{Attribute: "risk", Op: OpNe, Values: []string{"high"}}, map[string]string{"risk": "low"}, true},
		{Cond{Attribute: "risk", Op: OpIn, Values: []string{"medium", "high"}}, map[string]string{"risk": "medium"}, true},
		{Cond{Attribute: "risk", Op: OpNotIn, Values: []string{"medium", "high"}}, map[string]string{"risk": "low"}, true},
		{Cond{Attribute: "requester_org", Op: OpNe, Values: []string{"Finance"}}, map[string]string{}, false}, // missing: never matches
		{Cond{Attribute: "requester_org", Op: OpNotIn, Values: []string{"Finance"}}, map[string]string{"requester_org": ""}, false},
	}
	for _, c := range cases {
		if got := c.c.Eval(c.attrs); got != c.want {
			t.Errorf("%+v on %v = %v", c.c, c.attrs, got)
		}
	}
}

func TestMinOnEveryPath(t *testing.T) {
	d := Definition{Steps: []Step{cond("c", "kind", "a", "b", "create"), appr("a", ApproverOldOwner), {ID: "a2", Type: TypeApproval, Approver: ApproverDecider, Next: "end"}, appr("b", ApproverNewOwner)}}
	old := func(s Step) bool { return s.Type == TypeApproval && s.Approver == ApproverOldOwner }
	if n := d.MinOnEveryPath(old); n != 0 {
		t.Errorf("min old-owner approvals = %d, want 0 (the else branch skips it)", n)
	}
	any := func(s Step) bool { return s.Type == TypeApproval }
	if n := d.MinOnEveryPath(any); n != 1 {
		t.Errorf("min approvals = %d, want 1", n)
	}
}

// A condition may test membership in a dataset (issue #588) instead of listing values.
func TestDatasetCondition(t *testing.T) {
	dc := func(op string, values ...string) Step {
		return Step{ID: "c", Type: TypeCondition, When: &Cond{Attribute: "system", Op: op, Values: values, Dataset: "Restricted"}, Then: "g", Else: "m"}
	}
	steps := func(c Step) []Step {
		return []Step{c, {ID: "m", Type: TypeApproval, Approver: ApproverManager, Next: "end"}, {ID: "g", Type: TypeApproval, Approver: ApproverDecider}}
	}
	if is := (Definition{Steps: steps(dc(OpIn))}).Validate(store.WorkflowScopeAccess); len(is) != 0 {
		t.Fatalf("a dataset test is valid: %v", is)
	}
	for name, c := range map[string]Step{"op eq": dc(OpEq), "own values": dc(OpIn, "x"), "long name": func() Step {
		s := dc(OpIn)
		s.When.Dataset = strings.Repeat("a", MaxName+1)
		return s
	}()} {
		if is := (Definition{Steps: steps(c)}).Validate(store.WorkflowScopeAccess); len(is) == 0 {
			t.Errorf("%s: accepted", name)
		}
	}
	d := Definition{Steps: steps(dc(OpIn))}
	sets := Sets{"Restricted": {"okta": true}}
	for _, tc := range []struct {
		attrs map[string]string
		sets  Sets
		want  string // the approver of the one stage
	}{
		{map[string]string{"system": "okta"}, sets, ApproverDecider},
		{map[string]string{"system": "aws"}, sets, ApproverManager},
		{map[string]string{}, sets, ApproverManager},
		{map[string]string{"system": "okta"}, nil, ApproverManager}, // a dataset that is gone holds nothing
	} {
		p, err := d.compile("w", 1, tc.attrs, tc.sets)
		if err != nil || len(p.Stages) != 1 || p.Stages[0].Approver != tc.want {
			t.Errorf("%v: %+v %v, want %s", tc.attrs, p, err, tc.want)
		}
	}
	notIn := Definition{Steps: steps(dc(OpNotIn))}
	if p, _ := notIn.compile("w", 1, map[string]string{"system": "aws"}, sets); p.Stages[0].Approver != ApproverDecider {
		t.Errorf("not_in: %+v", p)
	}
}
