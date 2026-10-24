// Package workflow is the workflow designer (issue #298): configurable, versioned definitions
// of how a request is routed, and the resolver that turns a definition into the approval
// stages of one request.
//
// A definition is an ordered list of steps. Each step names its own id and, unless it ends the
// workflow, runs the next step in the list; "next" (any step but a condition) and a condition's
// "then" and "else" jump to another step id, or to "end". Step types:
//
//	approval       manager, owner, group (a named native group), decider, or for a
//	               service-account request old_owner or new_owner
//	questionnaire  the requester answers a questionnaire (internal/questionnaires) when filing
//	notify         tell the requester, the beneficiary, the owner or a group
//	wait           hold the next approval for some hours before it opens
//	condition      branch on request attributes (risk, item, requester org, ...)
//	provisioning   push the grant to the target system through the provisioning engine
//
// A definition is checked when it is saved (Validate): ids are unique, every reference
// resolves, there is no cycle, every step is reachable, every path reaches the end, and four
// eyes are kept: every path approves at least once, a provisioning step comes after an
// approval, and nothing but notices follows it. The conditions are evaluated once, when a
// request is filed, against its attributes (Compile); the path they select becomes the
// request's approval stages (internal/requests, #165), so a later edit never reroutes a request
// in flight. Who may decide a stage, and that nobody decides a request they made or
// two stages of one request, is the existing approval routing's rule, not repeated here.
package workflow

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Step types.
const (
	TypeApproval      = "approval"
	TypeQuestionnaire = "questionnaire"
	TypeNotify        = "notify"
	TypeWait          = "wait"
	TypeCondition     = "condition"
	TypeProvisioning  = "provisioning"
)

// Types lists the step types in the order the editor offers them.
var Types = []string{TypeApproval, TypeQuestionnaire, TypeNotify, TypeWait, TypeCondition, TypeProvisioning}

// Approvers of an approval step.
const (
	ApproverManager  = "manager"
	ApproverOwner    = "owner"
	ApproverGroup    = "group"
	ApproverDecider  = "decider"
	ApproverOldOwner = "old_owner"
	ApproverNewOwner = "new_owner"
)

// Notify targets of a notify step.
const (
	NotifyRequester   = "requester"
	NotifyBeneficiary = "beneficiary"
	NotifyOwner       = "owner"
	NotifyGroup       = "group"
)

// Condition operators.
const (
	OpEq    = "eq"
	OpNe    = "ne"
	OpIn    = "in"
	OpNotIn = "not_in"
)

// Ops lists the condition operators.
var Ops = []string{OpEq, OpNe, OpIn, OpNotIn}

// End is the step id that ends the workflow.
const End = "end"

// Limits.
const (
	MaxSteps            = 20
	MaxApprovalsPerPath = 8
	MaxName             = 80
	MaxDescription      = 500
	MaxMessage          = 500
	MaxHours            = 24 * 30
	MaxValues           = 20
	MaxValueLen         = 100
	// DefaultEscalateHours is how long an approval stage waits before deciders may act.
	DefaultEscalateHours = 48.0
)

// Attributes a condition may test, by scope.
var (
	AccessAttributes         = []string{"risk", "item", "privileged", "system", "requester_org", "beneficiary_org"}
	ServiceAccountAttributes = []string{"kind", "system", "requester_org", "owner_org"}
)

// Approvers a scope offers.
var (
	AccessApprovers         = []string{ApproverManager, ApproverOwner, ApproverGroup, ApproverDecider}
	ServiceAccountApprovers = []string{ApproverManager, ApproverGroup, ApproverDecider, ApproverOldOwner, ApproverNewOwner}
)

// Attributes returns the attributes a scope's conditions may test.
func Attributes(scope string) []string {
	if scope == store.WorkflowScopeServiceAccount {
		return ServiceAccountAttributes
	}
	return AccessAttributes
}

// Approvers returns the approvers a scope's approval steps may name.
func Approvers(scope string) []string {
	if scope == store.WorkflowScopeServiceAccount {
		return ServiceAccountApprovers
	}
	return AccessApprovers
}

// Cond is a condition's test. Missing attributes never match, whatever the operator, so a
// request that lacks the attribute takes the "else" branch.
//
// With Dataset set (the name of a tenant dataset, issue #588) the test is membership of the
// attribute's value in that dataset instead of in Values: the op is in or not_in and Values is empty.
// A dataset that no longer exists holds nothing.
type Cond struct {
	Attribute string   `json:"attribute"`
	Op        string   `json:"op"`
	Values    []string `json:"values"`
	Dataset   string   `json:"dataset,omitempty"`
}

// Sets are dataset contents by name, loaded when a definition is resolved for a request.
type Sets map[string]map[string]bool

// Step is one step of a definition. Fields that do not belong to its type must be empty.
type Step struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	Name string `json:"name,omitempty"`
	// Next is the step that runs after this one (default: the following step; "end" ends).
	Next string `json:"next,omitempty"`
	// approval
	Approver           string  `json:"approver,omitempty"`
	GroupID            string  `json:"group_id,omitempty"` // approval (group) and notify (group): a native group
	EscalateAfterHours float64 `json:"escalate_after_hours,omitempty"`
	// questionnaire
	QuestionnaireID string `json:"questionnaire_id,omitempty"`
	// notify
	Notify  string `json:"notify,omitempty"`
	Message string `json:"message,omitempty"`
	// wait
	Hours float64 `json:"hours,omitempty"`
	// condition
	When *Cond  `json:"when,omitempty"`
	Then string `json:"then,omitempty"`
	Else string `json:"else,omitempty"`
}

// Definition is a workflow's steps.
type Definition struct {
	Steps []Step `json:"steps"`
}

// Issue is one problem found in a definition.
type Issue struct {
	Step string `json:"step,omitempty"`
	Code string `json:"code"`
	Msg  string `json:"message"`
}

func (i Issue) String() string {
	if i.Step != "" {
		return "step " + i.Step + ": " + i.Msg
	}
	return i.Msg
}

var stepIDRE = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

// Validate checks a definition for a scope (store.WorkflowScopeAccess or ...ServiceAccount) and
// returns every problem it finds; none means it can be saved. It reads no database: the
// questionnaires and groups it names are checked by the service.
func (d Definition) Validate(scope string) []Issue {
	var out []Issue
	add := func(step, code, format string, args ...any) {
		out = append(out, Issue{Step: step, Code: code, Msg: fmt.Sprintf(format, args...)})
	}
	if scope != store.WorkflowScopeAccess && scope != store.WorkflowScopeServiceAccount {
		add("", "invalid_scope", "scope is access or service_account")
		return out
	}
	if len(d.Steps) == 0 || len(d.Steps) > MaxSteps {
		add("", "invalid_steps", "a workflow has 1 to %d steps", MaxSteps)
		return out
	}
	ids := map[string]int{}
	for i, s := range d.Steps {
		switch {
		case !stepIDRE.MatchString(s.ID) || s.ID == End:
			add(s.ID, "invalid_id", "step ids are 1 to 32 lowercase letters, digits, - or _, starting with a letter, and not %q", End)
		default:
			if _, dup := ids[s.ID]; dup {
				add(s.ID, "duplicate_id", "two steps have the id %q", s.ID)
			}
			ids[s.ID] = i
		}
	}
	if len(out) > 0 {
		return out
	}
	for _, s := range d.Steps {
		out = append(out, s.check(scope)...)
	}
	// references
	ref := func(step, field, to string) {
		if to == End {
			return
		}
		if _, ok := ids[to]; !ok {
			add(step, "unknown_step", "%s names the step %q, which does not exist", field, to)
		} else if to == step {
			add(step, "self_reference", "%s names the step itself", field)
		}
	}
	for _, s := range d.Steps {
		switch {
		case s.Type == TypeCondition:
			ref(s.ID, "then", s.Then)
			ref(s.ID, "else", s.Else)
			if s.Then == s.Else && s.Then != "" {
				add(s.ID, "condition_same_branch", "a condition's then and else go to the same step")
			}
		case s.Next != "":
			ref(s.ID, "next", s.Next)
		}
	}
	if len(out) > 0 {
		return out
	}
	g := d.graph()
	if cyc := g.cycle(); cyc != "" {
		add(cyc, "cycle", "the workflow loops back through this step")
		return out
	}
	reach := g.reachable()
	for i, s := range d.Steps {
		if !reach[i] {
			add(s.ID, "unreachable", "no path from the first step reaches this step")
		}
	}
	if !reach[g.end] {
		add("", "no_end", "no path reaches the end")
		return out
	}
	// four eyes: every path approves, and provisioning waits for an approval
	approvals := func(s Step) bool { return s.Type == TypeApproval }
	minA, maxA := g.count(approvals)
	if minA < 1 {
		add("", "no_approval", "a path from the first step to the end has no approval; every request needs one")
	}
	if maxA > MaxApprovalsPerPath {
		add("", "too_many_approvals", "a path has %d approvals; at most %d", maxA, MaxApprovalsPerPath)
	}
	if _, maxP := g.count(func(s Step) bool { return s.Type == TypeProvisioning }); maxP > 1 {
		add("", "provisioning_twice", "a path has more than one provisioning step")
	}
	beforeMin, beforeMax := g.countBefore(approvals)
	for i, s := range d.Steps {
		if !reach[i] {
			continue
		}
		switch s.Type {
		case TypeProvisioning:
			if beforeMin[i] < 1 {
				add(s.ID, "provisioning_before_approval", "provisioning can run on a path with no approval before it")
			}
			for _, j := range g.after(i) {
				if t := d.Steps[j].Type; t != TypeNotify {
					add(d.Steps[j].ID, "after_provisioning", "only notify steps may follow a provisioning step")
				}
			}
		case TypeQuestionnaire:
			if beforeMax[i] > 0 {
				add(s.ID, "questionnaire_late", "a questionnaire is answered when the request is filed, so no approval may come before it")
			}
		case TypeWait:
			if minAfter := g.minAfter(i, approvals); minAfter < 1 {
				add(s.ID, "wait_without_approval", "a wait holds the next approval, but a path from here reaches the end without one")
			}
		}
	}
	return out
}

// check validates one step's own fields.
func (s Step) check(scope string) []Issue {
	var out []Issue
	add := func(code, format string, args ...any) {
		out = append(out, Issue{Step: s.ID, Code: code, Msg: fmt.Sprintf(format, args...)})
	}
	if len(s.Name) > MaxName {
		add("invalid_name", "a step name is at most %d characters", MaxName)
	}
	// fields that belong to another type are refused, so a saved definition is canonical
	stray := func(field string, set bool) {
		if set {
			add("stray_field", "%s does not apply to a %s step", field, s.Type)
		}
	}
	isApproval, isNotify := s.Type == TypeApproval, s.Type == TypeNotify
	stray("approver", s.Approver != "" && !isApproval)
	stray("group_id", s.GroupID != "" && !isApproval && !isNotify)
	stray("escalate_after_hours", s.EscalateAfterHours != 0 && !isApproval)
	stray("questionnaire_id", s.QuestionnaireID != "" && s.Type != TypeQuestionnaire)
	stray("notify", s.Notify != "" && !isNotify)
	stray("message", s.Message != "" && !isNotify)
	stray("hours", s.Hours != 0 && s.Type != TypeWait)
	stray("when", s.When != nil && s.Type != TypeCondition)
	stray("then", s.Then != "" && s.Type != TypeCondition)
	stray("else", s.Else != "" && s.Type != TypeCondition)
	stray("next", s.Next != "" && s.Type == TypeCondition)
	switch s.Type {
	case TypeApproval:
		switch {
		case !slices.Contains(Approvers(scope), s.Approver):
			add("invalid_approver", "approver is one of %s", strings.Join(Approvers(scope), ", "))
		case s.Approver == ApproverGroup && (s.GroupID == "" || len(s.GroupID) > 64):
			add("group_required", "a group approval names the group")
		case s.Approver != ApproverGroup && s.GroupID != "":
			add("stray_field", "group_id applies only to a group approval")
		}
		if s.EscalateAfterHours < 0 || s.EscalateAfterHours > MaxHours {
			add("invalid_escalation", "escalation is after 0 to %d hours (0: the default, %g)", MaxHours, DefaultEscalateHours)
		}
	case TypeQuestionnaire:
		if s.QuestionnaireID == "" || len(s.QuestionnaireID) > 64 {
			add("questionnaire_required", "a questionnaire step names the questionnaire")
		}
	case TypeNotify:
		switch {
		case !slices.Contains([]string{NotifyRequester, NotifyBeneficiary, NotifyOwner, NotifyGroup}, s.Notify):
			add("invalid_notify", "notify is requester, beneficiary, owner or group")
		case s.Notify == NotifyGroup && (s.GroupID == "" || len(s.GroupID) > 64):
			add("group_required", "a group notice names the group")
		case s.Notify != NotifyGroup && s.GroupID != "":
			add("stray_field", "group_id applies only to a notice to a group")
		}
		if len(s.Message) > MaxMessage {
			add("invalid_message", "a message is at most %d characters", MaxMessage)
		}
	case TypeWait:
		if !(s.Hours > 0 && s.Hours <= MaxHours) {
			add("invalid_hours", "a wait is 0 to %d hours, more than 0", MaxHours)
		}
	case TypeCondition:
		out = append(out, s.checkCondition(scope)...)
	case TypeProvisioning:
	default:
		add("invalid_type", "type is one of %s", strings.Join(Types, ", "))
	}
	return out
}

var (
	riskValues = []string{"low", "medium", "high"}
	kindValues = []string{store.SAKindCreate, store.SAKindChange, store.SAKindTransfer}
	boolValues = []string{"true", "false"}
)

func (s Step) checkCondition(scope string) []Issue {
	var out []Issue
	add := func(code, format string, args ...any) {
		out = append(out, Issue{Step: s.ID, Code: code, Msg: fmt.Sprintf(format, args...)})
	}
	c := s.When
	if c == nil {
		add("condition_required", "a condition needs a test")
		return out
	}
	if s.Then == "" || s.Else == "" {
		add("branch_required", "a condition names the steps to run when it holds (then) and when it does not (else)")
	}
	if !slices.Contains(Attributes(scope), c.Attribute) {
		add("invalid_attribute", "attribute is one of %s", strings.Join(Attributes(scope), ", "))
		return out
	}
	switch {
	case !slices.Contains(Ops, c.Op):
		add("invalid_op", "operator is one of %s", strings.Join(Ops, ", "))
		return out
	case c.Dataset != "":
		if c.Op != OpIn && c.Op != OpNotIn {
			add("invalid_op", "a dataset test uses %s or %s", OpIn, OpNotIn)
		}
		if len(c.Values) != 0 {
			add("invalid_values", "a dataset test has no values of its own")
		}
		if len(c.Dataset) > MaxName {
			add("invalid_dataset", "the dataset name is at most %d characters", MaxName)
		}
		return out
	case (c.Op == OpEq || c.Op == OpNe) && len(c.Values) != 1:
		add("invalid_values", "%s tests exactly one value", c.Op)
	case len(c.Values) == 0 || len(c.Values) > MaxValues:
		add("invalid_values", "a test has 1 to %d values", MaxValues)
	}
	var allowed []string
	switch c.Attribute {
	case "risk":
		allowed = riskValues
	case "kind":
		allowed = kindValues
	case "privileged":
		allowed = boolValues
	}
	for _, v := range c.Values {
		switch {
		case strings.TrimSpace(v) == "" || len(v) > MaxValueLen:
			add("invalid_values", "a value is 1 to %d characters", MaxValueLen)
		case allowed != nil && !slices.Contains(allowed, v):
			add("invalid_values", "%s is one of %s", c.Attribute, strings.Join(allowed, ", "))
		}
	}
	return out
}

// Eval reports whether the condition holds for the attributes.
func (c Cond) Eval(attrs map[string]string) bool { return c.eval(attrs, nil) }

func (c Cond) eval(attrs map[string]string, sets Sets) bool {
	v, ok := attrs[c.Attribute]
	if !ok || v == "" {
		return false
	}
	in := slices.Contains(c.Values, v)
	if c.Dataset != "" {
		in = sets[c.Dataset][v]
	}
	switch c.Op {
	case OpEq, OpIn:
		return in
	case OpNe, OpNotIn:
		return !in
	}
	return false
}

// ---------------------------------------------------------------- graph

// graph is the definition's steps (nodes 0..n-1) and the end (node n); edges are the steps a
// step may run next.
type graph struct {
	steps []Step
	succ  [][]int
	end   int
}

func (d Definition) graph() *graph {
	idx := map[string]int{}
	for i, s := range d.Steps {
		idx[s.ID] = i
	}
	n := len(d.Steps)
	at := func(id string) int {
		if id == End {
			return n
		}
		return idx[id]
	}
	g := &graph{steps: d.Steps, succ: make([][]int, n+1), end: n}
	for i, s := range d.Steps {
		switch {
		case s.Type == TypeCondition:
			g.succ[i] = []int{at(s.Then), at(s.Else)}
		case s.Next != "":
			g.succ[i] = []int{at(s.Next)}
		case i+1 < n:
			g.succ[i] = []int{i + 1}
		default:
			g.succ[i] = []int{n}
		}
	}
	return g
}

// cycle returns the id of a step on a cycle, or "".
func (g *graph) cycle() string {
	const white, grey, black = 0, 1, 2
	color := make([]int, len(g.succ))
	var found string
	var visit func(int)
	visit = func(u int) {
		color[u] = grey
		for _, v := range g.succ[u] {
			if found != "" {
				return
			}
			switch color[v] {
			case grey:
				found = g.steps[v].ID
				return
			case white:
				visit(v)
			}
		}
		color[u] = black
	}
	for i := range g.steps {
		if color[i] == white && found == "" {
			visit(i)
		}
	}
	return found
}

func (g *graph) reachable() []bool {
	seen := make([]bool, len(g.succ))
	var visit func(int)
	visit = func(u int) {
		if seen[u] {
			return
		}
		seen[u] = true
		for _, v := range g.succ[u] {
			visit(v)
		}
	}
	visit(0)
	return seen
}

// after lists the steps reachable after step i (not i itself, not the end).
func (g *graph) after(i int) []int {
	seen := make([]bool, len(g.succ))
	var visit func(int)
	visit = func(u int) {
		for _, v := range g.succ[u] {
			if !seen[v] {
				seen[v] = true
				visit(v)
			}
		}
	}
	visit(i)
	var out []int
	for j := range g.steps {
		if seen[j] {
			out = append(out, j)
		}
	}
	return out
}

// count returns the fewest and the most steps satisfying pred on a path from the first step to
// the end. The graph must be acyclic.
func (g *graph) count(pred func(Step) bool) (minC, maxC int) {
	return g.span(0, pred)
}

// minAfter is the fewest steps satisfying pred on a path from step i's successors to the end.
func (g *graph) minAfter(i int, pred func(Step) bool) int {
	best := -1
	for _, v := range g.succ[i] {
		lo, _ := g.span(v, pred)
		if best < 0 || lo < best {
			best = lo
		}
	}
	return best
}

func (g *graph) span(from int, pred func(Step) bool) (int, int) {
	type mm struct{ lo, hi int }
	memo := map[int]mm{}
	var f func(int) mm
	f = func(u int) mm {
		if u == g.end {
			return mm{}
		}
		if r, ok := memo[u]; ok {
			return r
		}
		r := mm{lo: 1 << 30}
		for _, v := range g.succ[u] {
			s := f(v)
			r.lo, r.hi = min(r.lo, s.lo), max(r.hi, s.hi)
		}
		if pred(g.steps[u]) {
			r.lo, r.hi = r.lo+1, r.hi+1
		}
		memo[u] = r
		return r
	}
	r := f(from)
	return r.lo, r.hi
}

// countBefore returns, for each step, the fewest and the most steps satisfying pred on a path
// from the first step to it (not counting the step itself).
func (g *graph) countBefore(pred func(Step) bool) (minB, maxB []int) {
	n := len(g.succ)
	minB, maxB = make([]int, n), make([]int, n)
	for i := range minB {
		minB[i] = 1 << 30
	}
	minB[0], maxB[0] = 0, 0
	// topological order: reverse of a depth-first post-order
	var order []int
	seen := make([]bool, n)
	var visit func(int)
	visit = func(u int) {
		seen[u] = true
		for _, v := range g.succ[u] {
			if !seen[v] {
				visit(v)
			}
		}
		order = append(order, u)
	}
	visit(0)
	for k := len(order) - 1; k >= 0; k-- {
		u := order[k]
		if u == g.end {
			continue
		}
		add := 0
		if pred(g.steps[u]) {
			add = 1
		}
		for _, v := range g.succ[u] {
			minB[v] = min(minB[v], minB[u]+add)
			maxB[v] = max(maxB[v], maxB[u]+add)
		}
	}
	return minB, maxB
}

// MinOnEveryPath is the fewest steps satisfying pred on any path through a valid definition.
func (d Definition) MinOnEveryPath(pred func(Step) bool) int {
	lo, _ := d.graph().count(pred)
	return lo
}
