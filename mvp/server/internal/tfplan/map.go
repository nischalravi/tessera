package tfplan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/snapshot"
	"github.com/nischalravi/tessera/mvp/server/internal/blast"
)

// Finding statuses.
const (
	// StatusUnsupported: the resource type is not mapped to an AWS operation, so its effect on access is not in the
	// answer.
	StatusUnsupported = "unsupported"
	// StatusConditional: a value the mapping needs is not known until apply. The change is not applied, and the answer is
	// conditional on it: it is neither assumed to allow nor to deny.
	StatusConditional = "conditional"
	// StatusUnresolved: the change names something the snapshot does not hold (a role the plan creates, a policy no
	// principal uses, a bucket that was not collected) or a value the mapping cannot use.
	StatusUnresolved = "unresolved"
	// StatusNoEffect: the change does not alter what the snapshot evaluates.
	StatusNoEffect = "no_effect"
)

// Finding is a resource change the plan makes that is not (fully) turned into operations. It carries the resource's
// address and a fixed reason, never a value from the plan.
type Finding struct {
	Address string   `json:"address"`
	Type    string   `json:"type"`
	Actions []string `json:"actions"`
	Status  string   `json:"status"`
	Reason  string   `json:"reason"`
	// AccessRelevant marks an unsupported change that can alter who has access (an IAM or Organizations resource, a policy
	// or permission of any service): it makes the answer conditional.
	AccessRelevant bool `json:"access_relevant,omitempty"`
}

// Result is what a plan does to the estate.
type Result struct {
	// Operations are in the order they must be applied: policy documents first, then detaches, then the policies of
	// roles and buckets, then attaches; within a phase sorted by source.
	Operations []blast.Operation
	// Findings are sorted by address.
	Findings []Finding
	// Resources is how many managed resource changes the plan makes; Mapped how many of them produced operations;
	// Ignored the data sources, reads and no-ops.
	Resources int
	Mapped    int
	Ignored   int
	// Exceeded: the plan made more operations than the limit given to Map; the result is partial.
	Exceeded bool
}

// Conditional reports whether the answer rests on something the plan leaves unknown or the snapshot lacks.
func (r *Result) Conditional() bool {
	for _, f := range r.Findings {
		if f.Status == StatusConditional || f.Status == StatusUnresolved || (f.Status == StatusUnsupported && f.AccessRelevant) {
			return true
		}
	}
	return false
}

// Count is how many findings have the status.
func (r *Result) Count(status string) int {
	n := 0
	for _, f := range r.Findings {
		if f.Status == status {
			n++
		}
	}
	return n
}

type issue struct{ status, reason string }

type mapper struct {
	p   *Plan
	e   *Estate
	res *Result
	ops []mop

	byBase  map[string][]*Change // module path and type.name, no index
	orgByID map[string]*Change   // organization policies the plan knows by id
	acct    *string
	polARN  map[string]string
	created map[string]bool // policy ARNs (with their kind) the plan puts
	pairs   map[string]bool // "<target>|<policy ARN>" the plan attaches
	touched map[string]bool // addresses that have a finding
	seen    map[string]bool

	refCache     map[string]*Change // "<resource>|<attribute>" -> what its expression refers to (nil: nothing usable)
	groupsMoving bool               // the plan creates a group or changes who belongs to one
}

// mop is an operation with the resource that causes it and its phase.
type mop struct {
	op blast.Operation
	ph int
	c  *Change
}

// Map turns the changes of a plan into operations against the estate, and reports what it cannot turn into one. It
// stops, with Result.Exceeded set, once the plan has made more than maxOps operations (0 is no limit), so a plan
// cannot make it do unbounded work.
func Map(p *Plan, e *Estate, maxOps int) *Result {
	m := &mapper{p: p, e: e, res: &Result{}, byBase: map[string][]*Change{}, orgByID: map[string]*Change{}, polARN: map[string]string{},
		created: map[string]bool{}, pairs: map[string]bool{}, touched: map[string]bool{}, seen: map[string]bool{}, refCache: map[string]*Change{}}
	for _, c := range p.Changes {
		if c.Mode != "managed" {
			continue
		}
		if !ignored(c) {
			switch c.Type {
			case "aws_iam_group", "aws_iam_group_membership", "aws_iam_user_group_membership":
				m.groupsMoving = true
			}
		}
		m.byBase[m.baseKey(c)] = append(m.byBase[m.baseKey(c)], c)
		if c.Type == "aws_organizations_policy" {
			for _, after := range []bool{false, true} {
				if v := c.get(after, "id"); v.st == stOK {
					if s, ok := v.v.(string); ok {
						m.orgByID[s] = c
					}
				}
			}
		}
	}
	// the policies a plan creates are processed before what refers to them
	order := append([]*Change(nil), p.Changes...)
	sort.SliceStable(order, func(i, j int) bool {
		pi, pj := priority(order[i].Type), priority(order[j].Type)
		if pi != pj {
			return pi < pj
		}
		return order[i].Address < order[j].Address
	})
	for _, c := range order {
		if c.Mode != "managed" || ignored(c) {
			m.res.Ignored++
			continue
		}
		m.res.Resources++
		before := len(m.ops)
		m.dispatch(c)
		if len(m.ops) > before {
			m.res.Mapped++
		} else if !m.touched[c.Address] {
			m.note(c, StatusNoEffect, "no attribute the preview evaluates changes")
		}
		if maxOps > 0 && len(m.ops) > maxOps {
			m.res.Exceeded = true
			break
		}
	}
	sortOperations(m.ops)
	m.conflicts()
	m.res.Operations = make([]blast.Operation, len(m.ops))
	for i, o := range m.ops {
		m.res.Operations[i] = o.op
	}
	sort.Slice(m.res.Findings, func(i, j int) bool {
		a, b := m.res.Findings[i], m.res.Findings[j]
		if a.Address != b.Address {
			return a.Address < b.Address
		}
		if a.Status != b.Status {
			return a.Status < b.Status
		}
		return a.Reason < b.Reason
	})
	return m.res
}

func priority(t string) int {
	if t == "aws_iam_policy" || t == "aws_organizations_policy" {
		return 0
	}
	return 1
}

// ignored are the changes that change nothing: reads, no-ops and resources Terraform only forgets.
func ignored(c *Change) bool {
	for _, a := range c.Actions {
		switch a {
		case "no-op", "read", "forget":
		default:
			return false
		}
	}
	return true
}

func (m *mapper) dispatch(c *Change) {
	switch c.Type {
	case "aws_iam_policy":
		m.iamPolicy(c)
	case "aws_iam_user_policy":
		m.inlinePolicy(c, "user")
	case "aws_iam_role_policy":
		m.inlinePolicy(c, "role")
	case "aws_iam_group_policy":
		m.inlinePolicy(c, "group")
	case "aws_iam_user_policy_attachment":
		m.attachment(c, "user")
	case "aws_iam_role_policy_attachment":
		m.attachment(c, "role")
	case "aws_iam_group_policy_attachment":
		m.attachment(c, "group")
	case "aws_iam_policy_attachment":
		m.exclusiveAttachment(c)
	case "aws_iam_role":
		m.iamRole(c)
	case "aws_s3_bucket_policy":
		m.bucketPolicy(c)
	case "aws_organizations_policy":
		m.orgPolicy(c)
	case "aws_organizations_policy_attachment":
		m.orgAttachment(c)
	default:
		m.noteUnsupported(c, "the resource type is not mapped to an AWS operation; its effect on access is not in this preview", accessRelevant(c.Type))
	}
}

// ---------------------------------------------------------------- reporting

// accessRelevant reports whether a resource type that is not mapped can change who has access: an IAM or Organizations
// resource, a policy of any service, a KMS, Lambda permission or S3 resource.
func accessRelevant(t string) bool {
	for _, p := range []string{"aws_iam_", "aws_organizations_", "aws_kms_", "aws_lambda_permission", "aws_s3_", "aws_ssoadmin_", "aws_sts_", "aws_ram_"} {
		if strings.HasPrefix(t, p) {
			return true
		}
	}
	return strings.HasSuffix(t, "_policy") || strings.Contains(t, "_policy_") || strings.Contains(t, "_permission")
}

func (m *mapper) noteUnsupported(c *Change, reason string, relevant bool) {
	m.noteF(c, StatusUnsupported, reason, relevant)
}

func (m *mapper) note(c *Change, status, reason string) { m.noteF(c, status, reason, false) }

func (m *mapper) noteF(c *Change, status, reason string, relevant bool) {
	m.touched[c.Address] = true
	f := Finding{Address: c.Address, Type: c.Type, Actions: append([]string(nil), c.Actions...), Status: status, Reason: reason, AccessRelevant: relevant}
	key := c.Address + "|" + status + "|" + reason
	if m.seen[key] {
		return
	}
	m.seen[key] = true
	m.res.Findings = append(m.res.Findings, f)
}

func (m *mapper) report(c *Change, i *issue) { m.note(c, i.status, i.reason) }

func conditional(key string) *issue {
	return &issue{StatusConditional, key + " is not known until apply, so the answer is conditional on it"}
}

func unresolved(reason string) *issue { return &issue{StatusUnresolved, reason} }

// op adds an operation, labelled with the resource that causes it.
func (m *mapper) op(c *Change, ch snapshot.PolicyChange) {
	m.opPhase(c, ch, phase(ch.Op))
}

func (m *mapper) opPhase(c *Change, ch snapshot.PolicyChange, ph int) {
	m.ops = append(m.ops, mop{op: blast.Operation{PolicyChange: ch, Source: "terraform:" + clipRunes(c.Address, 180)}, ph: ph, c: c})
}

func (m *mapper) put(c *Change, op snapshot.PolicyChangeOp, target, doc string) {
	m.op(c, snapshot.PolicyChange{Op: op, TargetARN: target, Document: &doc})
}

func clipRunes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// phase orders operations so that what a later one needs exists: documents, detaches, entity policies, attaches.
func phase(op snapshot.PolicyChangeOp) int {
	switch op {
	case snapshot.OpPutPolicyVersion, snapshot.OpPutSCP, snapshot.OpPutRCP:
		return 0
	case snapshot.OpDetach, snapshot.OpDetachSCP, snapshot.OpDetachRCP, snapshot.OpDeleteInline, snapshot.OpDeleteBoundary:
		return 1
	case snapshot.OpAttach, snapshot.OpAttachSCP, snapshot.OpAttachRCP:
		return 3
	}
	return 2
}

// conflictKey names the thing an operation sets: two resources that set the same thing leave the result to the apply order.
func conflictKey(o blast.Operation) string {
	name := deref(o.PolicyARN)
	switch o.Op {
	case snapshot.OpPutPolicyVersion:
		return "policy|" + o.TargetARN
	case snapshot.OpPutSCP, snapshot.OpPutRCP:
		return "orgpolicy|" + o.TargetARN
	case snapshot.OpPutResourcePolicy:
		return "resource|" + o.TargetARN
	case snapshot.OpPutTrustPolicy:
		return "trust|" + o.TargetARN
	case snapshot.OpPutBoundary, snapshot.OpDeleteBoundary:
		return "boundary|" + o.TargetARN
	case snapshot.OpPutInline, snapshot.OpDeleteInline:
		return "inline|" + o.TargetARN + "|" + name
	case snapshot.OpAttach, snapshot.OpDetach:
		return "attach|" + o.TargetARN + "|" + name
	case snapshot.OpAttachSCP, snapshot.OpDetachSCP:
		return "scp|" + o.TargetARN + "|" + name
	case snapshot.OpAttachRCP, snapshot.OpDetachRCP:
		return "rcp|" + o.TargetARN + "|" + name
	}
	return ""
}

// conflicts reports, as conditional, the resources whose operations set the same thing as another resource's: a
// bucket policy that moves between modules is a delete in one and a create in the other, and which wins is not
// something the plan says.
func (m *mapper) conflicts() {
	by := map[string]map[*Change]bool{}
	for _, o := range m.ops {
		k := conflictKey(o.op)
		if k == "" {
			continue
		}
		if by[k] == nil {
			by[k] = map[*Change]bool{}
		}
		by[k][o.c] = true
	}
	for _, cs := range by {
		if len(cs) < 2 {
			continue
		}
		for c := range cs {
			m.note(c, StatusConditional, "another resource of the plan changes the same policy, attachment or document, so the result depends on the order Terraform applies them")
		}
	}
}

func sortOperations(ops []mop) {
	sort.SliceStable(ops, func(i, j int) bool {
		a, b := ops[i].op, ops[j].op
		if pa, pb := ops[i].ph, ops[j].ph; pa != pb {
			return pa < pb
		}
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		if a.Op != b.Op {
			return a.Op < b.Op
		}
		if a.TargetARN != b.TargetARN {
			return a.TargetARN < b.TargetARN
		}
		return deref(a.PolicyARN) < deref(b.PolicyARN)
	})
}

func strPtr(s string) *string { return &s }

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// ---------------------------------------------------------------- values

type state int

const (
	stOK state = iota
	stUnknown
	stNull
	stSensitive
)

type value struct {
	v  any
	st state
}

// get reads an attribute of the resource before or after the change, with whether the plan leaves it unknown or
// marks it sensitive.
func (c *Change) get(after bool, key string) value {
	obj, unk, sens := c.Before, any(nil), c.BeforeSens
	if after {
		obj, unk, sens = c.After, c.AfterUnknown, c.AfterSens
	}
	if hit(unk, key) {
		return value{st: stUnknown}
	}
	v, ok := obj[key]
	if !ok || v == nil {
		return value{st: stNull}
	}
	if hit(sens, key) {
		return value{v: v, st: stSensitive}
	}
	return value{v: v}
}

// hit reports whether a marker tree (after_unknown, after_sensitive) flags the key.
func hit(tree any, key string) bool {
	switch t := tree.(type) {
	case bool:
		return t
	case map[string]any:
		return anyTrue(t[key])
	}
	return false
}

func anyTrue(n any) bool {
	switch t := n.(type) {
	case bool:
		return t
	case []any:
		for _, x := range t {
			if anyTrue(x) {
				return true
			}
		}
	case map[string]any:
		for _, x := range t {
			if anyTrue(x) {
				return true
			}
		}
	}
	return false
}

// idStr reads an attribute that names an AWS entity. A sensitive value is not used to name one (it would reach the
// answer as a target), and an unknown one makes the answer conditional.
func (m *mapper) idStr(c *Change, after bool, key string) (string, *issue) {
	v := c.get(after, key)
	switch v.st {
	case stUnknown:
		return "", conditional(key)
	case stNull:
		return "", unresolved(key + " is not set")
	case stSensitive:
		return "", unresolved(key + " is marked sensitive in the plan, so it is not used to name an AWS entity")
	}
	s, ok := v.v.(string)
	if !ok || s == "" || len(s) > 2048 || !utf8.ValidString(s) {
		return "", unresolved(key + " is not a text value the preview can use")
	}
	return s, nil
}

// plain is a string attribute for comparing two sides ("" when absent or not text).
func plain(c *Change, after bool, key string) string {
	if v := c.get(after, key); v.st != stUnknown {
		s, _ := v.v.(string)
		return s
	}
	return ""
}

// differs reports whether any of the string attributes differs between the two sides, or is unknown after.
func differs(c *Change, keys ...string) bool {
	for _, k := range keys {
		if c.get(true, k).st == stUnknown || plain(c, false, k) != plain(c, true, k) {
			return true
		}
	}
	return false
}

// doc reads a policy document of the resource after the change. A sensitive document is used (it is evaluated, never
// echoed).
func (m *mapper) doc(c *Change, key string) (string, *issue) {
	v := c.get(true, key)
	switch v.st {
	case stUnknown:
		return "", conditional(key)
	case stNull:
		return "", unresolved(key + " is not set")
	}
	s, ok := docText(v.v)
	if !ok {
		return "", unresolved(key + " is not a JSON policy document")
	}
	return s, nil
}

func docText(v any) (string, bool) {
	s, ok := v.(string)
	if !ok || len(s) > maxDocument || !json.Valid([]byte(s)) {
		return "", false
	}
	var obj map[string]any
	if json.Unmarshal([]byte(s), &obj) != nil || obj == nil {
		return "", false
	}
	return s, true
}

func jsonEqual(a, b string) bool {
	var x, y any
	if json.Unmarshal([]byte(a), &x) != nil || json.Unmarshal([]byte(b), &y) != nil {
		return false
	}
	return reflect.DeepEqual(x, y)
}

// sameDoc reports whether the document before the change is the same policy as after it.
func sameDoc(c *Change, key, after string) bool {
	if c.Before == nil {
		return false
	}
	b, ok := c.Before[key].(string)
	return ok && jsonEqual(b, after)
}

// strSet reads a set or list of strings. unknown is true when any of it is unknown after the change.
// The set is deduplicated and sorted; dropped counts the entries that are not usable (not text, empty, over 2,048
// bytes) and those past maxSetEntries, which the caller reports.
func strSet(c *Change, after bool, key string) (vals []string, unknown bool, dropped int) {
	v := c.get(after, key)
	if v.st == stUnknown {
		return nil, true, 0
	}
	list, _ := v.v.([]any)
	seen := map[string]bool{}
	for _, x := range list {
		s, ok := x.(string)
		switch {
		case !ok || s == "" || len(s) > 2048:
			dropped++
		case seen[s]:
		case len(seen) >= maxSetEntries:
			dropped++
		default:
			seen[s] = true
			vals = append(vals, s)
		}
	}
	sort.Strings(vals)
	return vals, false, dropped
}

// maxSetEntries bounds one set of names or ARNs of a resource.
const maxSetEntries = 1000

// droppedFinding reports entries of a list that the preview could not use, so none is silently ignored.
func (m *mapper) droppedFinding(c *Change, key string, n int) {
	if n > 0 {
		m.note(c, StatusUnresolved, key+" has entries that are not usable (not text, empty, too long, or past the limit of 1,000) and were not applied")
	}
}

func minus(a, b []string) []string {
	in := map[string]bool{}
	for _, s := range b {
		in[s] = true
	}
	var out []string
	for _, s := range a {
		if !in[s] {
			out = append(out, s)
		}
	}
	return out
}

// ---------------------------------------------------------------- names and references

func (m *mapper) baseKey(c *Change) string {
	k := c.Type + "." + stripIndex(c.Name)
	if mod := stripIndex(c.ModuleAddress); mod != "" {
		return mod + "." + k
	}
	return k
}

var notResource = map[string]bool{"var": true, "local": true, "data": true, "module": true, "each": true, "count": true, "path": true, "self": true, "terraform": true}

// refTarget finds the one resource of the plan that an unknown attribute is computed from, by the references of its
// expression in the configuration (policy_arn = aws_iam_policy.deploy.arn). An expression that refers to anything
// else (a variable, a condition between two resources) is not resolved.
//
// Only a reference to one of the attributes the caller expects (or to the whole resource) counts, and each
// (resource, attribute) is worked out once. Terraform lists the same references for aws_iam_policy.x.arn and for
// replace(aws_iam_policy.x.arn, ...), so a resolution is never certain: it always adds a conditional finding that
// says the expression is assumed to be the bare attribute.
func (m *mapper) refTarget(c *Change, key string, attrs ...string) *Change {
	ck := m.baseKey(c) + "|" + key
	t, done := m.refCache[ck]
	if !done {
		t = m.resolveRef(c, key, attrs)
		m.refCache[ck] = t
	}
	if t != nil {
		m.note(c, StatusConditional, key+" is resolved by reference to "+t.Address+"; this assumes the expression is that attribute unchanged")
	}
	return t
}

func (m *mapper) resolveRef(c *Change, key string, attrs []string) *Change {
	refs := m.p.refs[m.baseKey(c)][key]
	prefix := ""
	if mod := stripIndex(c.ModuleAddress); mod != "" {
		prefix = mod + "."
	}
	found := ""
	for _, r := range refs {
		segs := strings.SplitN(stripIndex(r), ".", 3)
		if len(segs) < 2 || notResource[segs[0]] || !strings.HasPrefix(segs[0], "aws_") {
			return nil
		}
		if len(segs) == 3 && !slices.Contains(attrs, strings.SplitN(segs[2], ".", 2)[0]) {
			return nil
		}
		k := prefix + segs[0] + "." + segs[1]
		if found != "" && found != k {
			return nil
		}
		found = k
	}
	if cands := m.byBase[found]; len(cands) == 1 {
		return cands[0]
	}
	return nil
}

var accountRE = regexp.MustCompile(`^[0-9]{12}$`)

// account is the AWS account the plan's IAM resources belong to: the one their known ARNs name, else the one account
// of the estate. "" when it cannot be told.
func (m *mapper) account() string {
	if m.acct != nil {
		return *m.acct
	}
	set := map[string]bool{}
	for _, c := range m.p.Changes {
		if !strings.HasPrefix(c.Type, "aws_iam_") {
			continue
		}
		for _, after := range []bool{false, true} {
			if s, ok := c.get(after, "arn").v.(string); ok && strings.HasPrefix(s, "arn:") && accountRE.MatchString(accountOf(s)) {
				set[accountOf(s)] = true
			}
		}
	}
	out := ""
	switch {
	case len(set) == 1:
		for a := range set {
			out = a
		}
	case len(set) == 0 && len(m.e.accounts) == 1:
		out = m.e.accounts[0]
	}
	m.acct = &out
	return out
}

func slug(address string) string {
	var b strings.Builder
	for _, r := range address {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	s := clipRunes(b.String(), 60)
	sum := sha256.Sum256([]byte(address))
	return s + "-" + hex.EncodeToString(sum[:4])
}

// policyARNOf is the ARN of a managed IAM policy or an organization policy the plan changes: the one the plan
// knows, else (for an IAM policy) the one its account, path and name give, else a placeholder ARN that no real
// policy has, so the policy still takes effect where the plan attaches it by reference.
func (m *mapper) policyARNOf(c *Change) string {
	if a, ok := m.polARN[c.Address]; ok {
		return a
	}
	arn := ""
	// the ARN after the change; a deleted resource has only the one before. A replaced resource's old ARN is not its new one.
	if v := c.get(c.After != nil, "arn"); v.st == stOK {
		if s, ok := v.v.(string); ok && strings.HasPrefix(s, "arn:") && len(s) <= 2048 {
			arn = s
		}
	}
	if arn == "" && c.Type == "aws_iam_policy" {
		name, path := plain(c, true, "name"), plain(c, true, "path")
		if name == "" {
			name = plain(c, false, "name")
		}
		if path == "" {
			path = "/"
		}
		if acct := m.account(); acct != "" && name != "" && c.get(true, "name").st == stOK && strings.HasPrefix(path, "/") && strings.HasSuffix(path, "/") {
			arn = fmt.Sprintf("arn:%s:iam::%s:policy%s%s", m.e.partition, acct, path, name)
		}
	}
	if arn == "" {
		if c.Type == "aws_organizations_policy" {
			kind := "service_control_policy"
			if k, _ := m.orgKind(c, true); k == model.PolicyRCP {
				kind = "resource_control_policy"
			}
			arn = fmt.Sprintf("arn:%s:organizations::000000000000:policy/o-tessera-plan/%s/p-%s", m.e.partition, kind, slug(c.Address))
		} else {
			arn = fmt.Sprintf("arn:%s:iam::000000000000:policy/tessera-plan/%s", m.e.partition, slug(c.Address))
		}
	}
	m.polARN[c.Address] = arn
	return arn
}

// lookup finds a user, role or group of the snapshot by name.
func (m *mapper) lookup(kind, name string) (string, *issue) {
	// With the account known, only that account's entity counts. With it unknown and several accounts in the estate, a
	// name is used only when one entity has it and the plan uses one provider configuration.
	acct := m.account()
	arn, n := m.e.find(kind, name, acct)
	if acct == "" && n == 1 && len(m.e.accounts) > 1 && len(m.p.providers) > 1 {
		return "", unresolved("the plan uses several provider configurations and does not say which account holds this " + kind)
	}
	switch {
	case n == 1:
		return arn, nil
	case n > 1:
		return "", unresolved("more than one " + kind + " of the snapshot has this name and the plan does not say which account")
	case kind == "group" && !m.groupsMoving:
		return "", &issue{StatusNoEffect, "no user of the snapshot is a member of this group, so the change reaches no principal"}
	case kind == "group":
		return "", unresolved("the plan creates a group or changes group membership, so who belongs to this group after it is not known")
	}
	return "", unresolved("the " + kind + " is not in the snapshot; the preview edits users and roles the snapshot holds, so one the plan creates is not evaluated")
}

// entity resolves the user, role or group an attribute names, following a reference to a resource of the plan when
// the name is not known until apply.
func (m *mapper) entity(c *Change, after bool, kind, key string) (string, *issue) {
	if v := c.get(after, key); v.st == stUnknown {
		t := m.refTarget(c, key, "name", "id")
		if t == nil || t.Type != "aws_iam_"+kind {
			return "", conditional(key)
		}
		name, iss := m.idStr(t, t.After != nil, "name")
		if iss != nil {
			return "", iss
		}
		return m.lookup(kind, name)
	}
	name, iss := m.idStr(c, after, key)
	if iss != nil {
		return "", iss
	}
	return m.lookup(kind, name)
}

// policyArg resolves a managed policy ARN attribute, following a reference to a policy of the plan.
func (m *mapper) policyArg(c *Change, after bool, key string) (string, *issue) {
	if v := c.get(after, key); v.st == stUnknown {
		if t := m.refTarget(c, key, "arn", "id"); t != nil && t.Type == "aws_iam_policy" && t.After != nil {
			return m.policyARNOf(t), nil
		}
		return "", conditional(key)
	}
	s, iss := m.idStr(c, after, key)
	if iss != nil {
		return "", iss
	}
	if !strings.HasPrefix(s, "arn:") {
		return "", unresolved(key + " is not an ARN")
	}
	return s, nil
}

func (m *mapper) policyKnown(arn string) bool { return m.e.hasManaged(arn) || m.created["iam|"+arn] }

// ---------------------------------------------------------------- IAM

func (m *mapper) iamPolicy(c *Change) {
	if c.After == nil {
		m.note(c, StatusNoEffect, "deleting a managed policy is not an operation; the plan's attachment changes carry its effect")
		return
	}
	doc, iss := m.doc(c, "policy")
	if iss != nil {
		m.report(c, iss)
		return
	}
	arn := m.policyARNOf(c)
	if before, ok := c.get(false, "arn").v.(string); ok && before == arn && sameDoc(c, "policy", doc) {
		m.created["iam|"+arn] = true
		m.note(c, StatusNoEffect, "the policy document is unchanged")
		return
	}
	m.created["iam|"+arn] = true
	m.put(c, snapshot.OpPutPolicyVersion, arn, doc)
}

var inlineNameRE = regexp.MustCompile(`^[\w+=,.@-]{1,128}$`)

func (m *mapper) inlinePolicy(c *Change, kind string) {
	if c.Before != nil && (c.After == nil || differs(c, kind, "name")) {
		m.deleteInline(c, kind)
	}
	if c.After == nil {
		return
	}
	target, iss := m.entity(c, true, kind, kind)
	if iss != nil {
		m.report(c, iss)
		return
	}
	name, iss := m.idStr(c, true, "name")
	if iss != nil {
		m.report(c, iss)
		return
	}
	doc, iss := m.doc(c, "policy")
	if iss != nil {
		m.report(c, iss)
		return
	}
	if !inlineNameRE.MatchString(name) {
		m.report(c, unresolved("name is not a valid inline policy name"))
		return
	}
	if c.Before != nil && !differs(c, kind, "name") && sameDoc(c, "policy", doc) {
		m.note(c, StatusNoEffect, "the policy document is unchanged")
		return
	}
	m.op(c, snapshot.PolicyChange{Op: snapshot.OpPutInline, TargetARN: target, PolicyARN: &name, Document: &doc})
}

func (m *mapper) deleteInline(c *Change, kind string) {
	target, iss := m.entity(c, false, kind, kind)
	if iss != nil {
		m.report(c, iss)
		return
	}
	name, iss := m.idStr(c, false, "name")
	if iss != nil {
		m.report(c, iss)
		return
	}
	if !m.e.hasInline(target, name) {
		m.report(c, unresolved("the inline policy that the plan removes is not in the snapshot"))
		return
	}
	m.op(c, snapshot.PolicyChange{Op: snapshot.OpDeleteInline, TargetARN: target, PolicyARN: &name})
}

func (m *mapper) attachment(c *Change, kind string) {
	if c.Before != nil && (c.After == nil || differs(c, kind, "policy_arn")) {
		if target, iss := m.entity(c, false, kind, kind); iss != nil {
			m.report(c, iss)
		} else if arn, iss := m.policyArg(c, false, "policy_arn"); iss != nil {
			m.report(c, iss)
		} else {
			m.detach(c, target, arn)
		}
	}
	if c.After == nil {
		return
	}
	if c.Before != nil && !differs(c, kind, "policy_arn") {
		m.note(c, StatusNoEffect, "the attachment is unchanged")
		return
	}
	target, iss := m.entity(c, true, kind, kind)
	if iss != nil {
		m.report(c, iss)
		return
	}
	arn, iss := m.policyArg(c, true, "policy_arn")
	if iss != nil {
		m.report(c, iss)
		return
	}
	m.attach(c, target, arn)
}

func (m *mapper) attach(c *Change, target, arn string) {
	if !m.policyKnown(arn) {
		m.report(c, unresolved("the managed policy is not in the snapshot, so its permissions are not known (the snapshot holds the policies something uses)"))
		return
	}
	m.pairs[target+"|"+arn] = true
	m.op(c, snapshot.PolicyChange{Op: snapshot.OpAttach, TargetARN: target, PolicyARN: &arn})
}

func (m *mapper) detach(c *Change, target, arn string) {
	if !m.e.attached(target, arn) {
		if m.pairs[target+"|"+arn] {
			// attached by one resource of the plan and detached by another: not an operation that can apply (the pair is
			// not in the snapshot), and which comes last is not in the plan
			m.note(c, StatusConditional, "the plan attaches this policy to the same target with another resource, so whether it ends attached depends on the order Terraform applies them")
			return
		}
		m.report(c, unresolved("the policy that the plan detaches is not attached in the snapshot"))
		return
	}
	m.op(c, snapshot.PolicyChange{Op: snapshot.OpDetach, TargetARN: target, PolicyARN: &arn})
}

// exclusiveAttachment is aws_iam_policy_attachment: one policy for sets of users, roles and groups.
func (m *mapper) exclusiveAttachment(c *Change) {
	var bPol, aPol string
	if c.Before != nil {
		bPol = plain(c, false, "policy_arn")
	}
	if c.After != nil {
		var iss *issue
		if aPol, iss = m.policyArg(c, true, "policy_arn"); iss != nil {
			m.report(c, iss)
			return
		}
	}
	for _, k := range []struct{ key, kind string }{{"users", "user"}, {"roles", "role"}, {"groups", "group"}} {
		var bset, aset []string
		if c.Before != nil {
			var dropped int
			bset, _, dropped = strSet(c, false, k.key)
			m.droppedFinding(c, k.key, dropped)
		}
		if c.After != nil {
			var unk bool
			var dropped int
			if aset, unk, dropped = strSet(c, true, k.key); unk {
				m.report(c, conditional(k.key))
				continue
			}
			m.droppedFinding(c, k.key, dropped)
		}
		toDetach, toAttach := minus(bset, aset), minus(aset, bset)
		if bPol != aPol { // a different policy: every pair changes
			toDetach, toAttach = bset, aset
		}
		for _, n := range toDetach {
			if arn, iss := m.lookup(k.kind, n); iss != nil {
				m.report(c, iss)
			} else {
				m.detach(c, arn, bPol)
			}
		}
		for _, n := range toAttach {
			if arn, iss := m.lookup(k.kind, n); iss != nil {
				m.report(c, iss)
			} else {
				m.attach(c, arn, aPol)
			}
		}
	}
}

func (m *mapper) iamRole(c *Change) {
	if c.After == nil {
		m.noteUnsupported(c, "deleting a role is not an AWS operation this preview models", true)
		return
	}
	var arn string
	if v := c.get(true, "arn"); v.st == stOK {
		if s, ok := v.v.(string); ok && m.e.hasPrincipal(s) {
			arn = s
		}
	}
	if arn == "" {
		name, iss := m.idStr(c, true, "name")
		if iss == nil {
			arn, iss = m.lookup("role", name)
		}
		if iss != nil {
			m.report(c, iss)
			return
		}
	}

	// the trust policy
	if doc, iss := m.doc(c, "assume_role_policy"); iss != nil {
		m.report(c, iss)
	} else if !sameDoc(c, "assume_role_policy", doc) {
		m.put(c, snapshot.OpPutTrustPolicy, arn, doc)
	}

	// managed policies attached through the role's own attribute
	bset, _, bdrop := strSet(c, false, "managed_policy_arns")
	m.droppedFinding(c, "managed_policy_arns", bdrop)
	if aset, unk, adrop := strSet(c, true, "managed_policy_arns"); unk {
		m.report(c, conditional("managed_policy_arns"))
	} else {
		m.droppedFinding(c, "managed_policy_arns", adrop)
		for _, p := range minus(bset, aset) {
			m.detach(c, arn, p)
		}
		for _, p := range minus(aset, bset) {
			m.attach(c, arn, p)
		}
	}

	m.roleInline(c, arn)
	m.roleBoundary(c, arn)
}

// inlineSet reads the inline_policy blocks of a role: name to document ("" when the document is not usable).
// dropped counts the blocks that are not usable (not an object, a bad name, past the limit).
func inlineSet(c *Change, after bool) (out map[string]string, unknown bool, dropped int) {
	v := c.get(after, "inline_policy")
	if v.st == stUnknown {
		return nil, true, 0
	}
	out = map[string]string{}
	list, _ := v.v.([]any)
	for _, x := range list {
		o, ok := x.(map[string]any)
		name, _ := o["name"].(string)
		switch {
		case !ok || !inlineNameRE.MatchString(name) || len(out) >= maxSetEntries:
			dropped++
		default:
			doc, _ := docText(o["policy"])
			out[name] = doc
		}
	}
	return out, false, dropped
}

func (m *mapper) roleInline(c *Change, arn string) {
	after, unk, adrop := inlineSet(c, true)
	if unk {
		m.report(c, conditional("inline_policy"))
		return
	}
	before, _, bdrop := inlineSet(c, false)
	m.droppedFinding(c, "inline_policy", adrop+bdrop)
	for _, n := range sortedKeys(after) {
		d := after[n]
		switch {
		case d == "":
			m.report(c, unresolved("an inline policy of the role is not a JSON policy document"))
		case before[n] == "" || !jsonEqual(before[n], d):
			name := n
			m.op(c, snapshot.PolicyChange{Op: snapshot.OpPutInline, TargetARN: arn, PolicyARN: &name, Document: &d})
		}
	}
	for _, n := range sortedKeys(before) {
		if _, ok := after[n]; ok {
			continue
		}
		if !m.e.hasInline(arn, n) {
			m.report(c, unresolved("the inline policy that the plan removes is not in the snapshot"))
			continue
		}
		name := n
		m.op(c, snapshot.PolicyChange{Op: snapshot.OpDeleteInline, TargetARN: arn, PolicyARN: &name})
	}
}

func (m *mapper) roleBoundary(c *Change, arn string) {
	if !differs(c, "permissions_boundary") {
		return
	}
	b, iss := m.policyArg(c, true, "permissions_boundary")
	switch {
	case c.get(true, "permissions_boundary").st == stNull:
		if p := m.e.principal(arn); p != nil && p.BoundaryPolicyID != "" {
			m.op(c, snapshot.PolicyChange{Op: snapshot.OpDeleteBoundary, TargetARN: arn})
		}
	case iss != nil:
		m.report(c, iss)
	case !m.policyKnown(b):
		m.report(c, unresolved("the permissions boundary policy is not in the snapshot, so its permissions are not known"))
	default:
		m.op(c, snapshot.PolicyChange{Op: snapshot.OpPutBoundary, TargetARN: arn, PolicyARN: &b})
	}
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------- S3

var policyTypeRE = regexp.MustCompile(`^[A-Z_]{1,64}$`)

var bucketRE = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

const emptyPolicy = `{"Version":"2012-10-17","Statement":[]}`

func (m *mapper) bucketARN(c *Change, after bool) (string, *issue) {
	var name string
	if c.get(after, "bucket").st == stUnknown {
		t := m.refTarget(c, "bucket", "bucket", "id")
		if t == nil || t.Type != "aws_s3_bucket" {
			return "", conditional("bucket")
		}
		var iss *issue
		if name, iss = m.idStr(t, t.After != nil, "bucket"); iss != nil {
			return "", iss
		}
	} else {
		var iss *issue
		if name, iss = m.idStr(c, after, "bucket"); iss != nil {
			return "", iss
		}
	}
	if !bucketRE.MatchString(name) {
		return "", unresolved("bucket is not a valid bucket name")
	}
	return "arn:" + m.e.partition + ":s3:::" + name, nil
}

func (m *mapper) bucketPolicy(c *Change) {
	oldARN, oiss := "", (*issue)(nil)
	if c.Before != nil {
		oldARN, oiss = m.bucketARN(c, false)
	}
	newARN, niss := "", (*issue)(nil)
	var doc string
	if c.After != nil {
		if newARN, niss = m.bucketARN(c, true); niss == nil {
			doc, niss = m.doc(c, "policy")
		}
	}
	// a policy the plan removes (or moves to another bucket) leaves its bucket with none
	if c.Before != nil && (c.After == nil || (niss == nil && oldARN != newARN)) {
		switch {
		case oiss != nil:
			m.report(c, oiss)
		case !m.e.hasResource(oldARN):
			m.report(c, unresolved("the bucket is not in the snapshot"))
		case m.e.hasResourcePolicy(oldARN):
			// a removal is applied with the detaches, before any document: when the same plan puts a policy on this bucket
			// from another resource (a move between modules), the new document must be the one that is left
			m.opPhase(c, snapshot.PolicyChange{Op: snapshot.OpPutResourcePolicy, TargetARN: oldARN, Document: strPtr(emptyPolicy)}, 1)
		default:
			m.note(c, StatusNoEffect, "the bucket has no policy in the snapshot to remove")
		}
	}
	if c.After == nil {
		return
	}
	switch {
	case niss != nil:
		m.report(c, niss)
	case !m.e.hasResource(newARN):
		m.report(c, unresolved("the bucket is not in the snapshot"))
	case c.Before != nil && oiss == nil && oldARN == newARN && sameDoc(c, "policy", doc):
		m.note(c, StatusNoEffect, "the policy document is unchanged")
	default:
		m.put(c, snapshot.OpPutResourcePolicy, newARN, doc)
	}
}

// ---------------------------------------------------------------- Organizations

// orgKind is the kind of an organization policy: SERVICE_CONTROL_POLICY (the default) or RESOURCE_CONTROL_POLICY.
func (m *mapper) orgKind(c *Change, after bool) (model.PolicyKind, *issue) {
	v := c.get(after, "type")
	switch v.st {
	case stUnknown:
		return 0, conditional("type")
	case stNull:
		return model.PolicySCP, nil
	}
	s, _ := v.v.(string)
	switch s {
	case "SERVICE_CONTROL_POLICY":
		return model.PolicySCP, nil
	case "RESOURCE_CONTROL_POLICY":
		return model.PolicyRCP, nil
	}
	if policyTypeRE.MatchString(s) {
		return 0, &issue{StatusUnsupported, "an organization policy of type " + s + " does not change the access the preview evaluates"}
	}
	return 0, &issue{StatusUnsupported, "an organization policy of this type does not change the access the preview evaluates"}
}

func (m *mapper) orgPolicy(c *Change) {
	if c.After == nil {
		m.note(c, StatusNoEffect, "deleting an organization policy is not an operation; the plan's detachments carry its effect")
		return
	}
	kind, iss := m.orgKind(c, true)
	if iss != nil {
		m.report(c, iss)
		return
	}
	doc, iss := m.doc(c, "content")
	if iss != nil {
		m.report(c, iss)
		return
	}
	if !m.e.orgEnabled(kind) {
		m.report(c, unresolved("the snapshot's organization does not have this policy type enabled"))
		return
	}
	arn := m.policyARNOf(c)
	m.created[kind.String()+"|"+arn] = true
	if before, ok := c.get(false, "arn").v.(string); ok && before == arn && sameDoc(c, "content", doc) {
		m.note(c, StatusNoEffect, "the policy content is unchanged")
		return
	}
	op := snapshot.OpPutSCP
	if kind == model.PolicyRCP {
		op = snapshot.OpPutRCP
	}
	m.put(c, op, arn, doc)
}

// orgPolicyArg resolves the policy of an attachment: the kind and ARN of the SCP or RCP its policy_id names.
func (m *mapper) orgPolicyArg(c *Change, after bool) (model.PolicyKind, string, *issue) {
	if c.get(after, "policy_id").st == stUnknown {
		t := m.refTarget(c, "policy_id", "id")
		if t == nil || t.Type != "aws_organizations_policy" || t.After == nil {
			return 0, "", conditional("policy_id")
		}
		kind, iss := m.orgKind(t, true)
		if iss != nil {
			return 0, "", iss
		}
		return kind, m.policyARNOf(t), nil
	}
	id, iss := m.idStr(c, after, "policy_id")
	if iss != nil {
		return 0, "", iss
	}
	// a policy the plan replaces has a new ARN: what is attached now (the before side) is the one the snapshot holds
	if t := m.orgByID[id]; t != nil && after && t.After != nil {
		kind, iss := m.orgKind(t, true)
		if iss != nil {
			return 0, "", iss
		}
		return kind, m.policyARNOf(t), nil
	}
	if kind, arn, ok := m.e.orgPolicyByID(id); ok {
		return kind, arn, nil
	}
	return 0, "", unresolved("the organization policy is not in the snapshot")
}

func (m *mapper) orgAttachment(c *Change) {
	if c.Before != nil && (c.After == nil || differs(c, "policy_id", "target_id")) {
		m.orgAttach(c, false)
	}
	if c.After == nil {
		return
	}
	if c.Before != nil && !differs(c, "policy_id", "target_id") {
		m.note(c, StatusNoEffect, "the attachment is unchanged")
		return
	}
	m.orgAttach(c, true)
}

func (m *mapper) orgAttach(c *Change, attach bool) {
	kind, arn, iss := m.orgPolicyArg(c, attach)
	if iss != nil {
		m.report(c, iss)
		return
	}
	node, iss := m.idStr(c, attach, "target_id")
	if iss != nil {
		m.report(c, iss)
		return
	}
	if !m.e.orgEnabled(kind) {
		m.report(c, unresolved("the snapshot's organization does not have this policy type enabled"))
		return
	}
	if m.e.orgNode(node) == nil {
		m.report(c, unresolved("the target is not an account, OU or root of the snapshot's organization"))
		return
	}
	var op snapshot.PolicyChangeOp
	switch {
	case attach && kind == model.PolicySCP:
		op = snapshot.OpAttachSCP
	case attach:
		op = snapshot.OpAttachRCP
	case kind == model.PolicySCP:
		op = snapshot.OpDetachSCP
	default:
		op = snapshot.OpDetachRCP
	}
	switch {
	case attach && !m.created[kind.String()+"|"+arn] && !m.e.hasOrgPolicy(kind, arn):
		m.report(c, unresolved("the organization policy is not in the snapshot"))
		return
	case !attach && !m.e.orgAttached(kind, node, arn):
		if m.pairs[node+"|"+arn] {
			m.note(c, StatusConditional, "the plan attaches this policy to the same target with another resource, so whether it ends attached depends on the order Terraform applies them")
		} else {
			m.report(c, unresolved("the policy that the plan detaches is not attached there in the snapshot"))
		}
		return
	case attach:
		m.pairs[node+"|"+arn] = true
	}
	m.op(c, snapshot.PolicyChange{Op: op, TargetARN: node, PolicyARN: &arn})
}
