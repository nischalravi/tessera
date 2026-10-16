// Package policy is the policy-as-code engine.
//
// Policies are YAML files. Each has an id, name, severity, type and
// type-specific fields. Supported types:
//
//   - separation_of_duties: an identity must not hold permissions matching both
//     conflict.a and conflict.b (each a list of action names).
//   - no_standing_access: permissions matching `match` (privileged / environment /
//     systems / tags_any) must only be reachable through JIT grants.
//   - forbidden_access: identities matching `subjects` (identity_types) must not
//     reach resources matching `resources` (tags_any / environment / systems).
//   - secret_max_age: secrets older than max_age_days since creation/rotation.
//   - nhi_ownership: service accounts and AI agents need an active human owner.
//   - terminated_with_access: terminated identities must not retain effective access.
//   - mfa_required: privileged identities need a registered method of at least
//     the `require` class (default phishing_resistant; see internal/mfa).
//
// Graph-based policies are evaluated against a graph.Snapshot, so the same
// code evaluates the live graph and simulated (what-if) graphs.
package policy

import (
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/mfa"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// SeverityRank orders severities (unknown severities rank 0).
var SeverityRank = map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}

// Policy is one parsed policy document.
type Policy struct {
	ID          string
	Name        string
	Type        string
	Severity    string
	Description string
	Spec        map[string]any
	Source      string
	Enabled     bool
}

// Violation is one policy finding.
type Violation struct {
	PolicyID     string     `json:"policy_id"`
	PolicyName   string     `json:"policy_name"`
	Severity     string     `json:"severity"`
	IdentityID   *int64     `json:"identity_id"`
	IdentityName string     `json:"identity_name"`
	Key          string     `json:"key"`
	Message      string     `json:"message"`
	Evidence     []string   `json:"evidence"`
	Edges        [][]string `json:"edges"` // grant edges (src, dst) implicated
}

func newViolation(p *Policy, iid int64, name, key, msg string, evidence []string, edges [][]string) Violation {
	if evidence == nil {
		evidence = []string{}
	}
	if edges == nil {
		edges = [][]string{}
	}
	id := iid
	return Violation{p.ID, p.Name, p.Severity, &id, name, key, msg, evidence, edges}
}

// ------------------------------------------------------------------ loading

// Loader reads policies from a file system and caches them until a file changes.
type Loader struct {
	fsys fs.FS
	mu   sync.Mutex
	sig  string
	pols []*Policy
}

// NewLoader returns a loader over fsys (e.g. os.DirFS(dir) or policies.FS).
func NewLoader(fsys fs.FS) *Loader { return &Loader{fsys: fsys} }

func isPolicyFile(name string) bool {
	ext := path.Ext(name)
	return strings.HasPrefix(ext, ".y") && strings.HasSuffix(ext, "ml")
}

// Load returns the policies in file-name order, re-reading files that changed.
func (l *Loader) Load() ([]*Policy, error) {
	entries, err := fs.ReadDir(l.fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("policy: read dir: %w", err)
	}
	var names []string
	var sig strings.Builder
	for _, e := range entries {
		if e.IsDir() || !isPolicyFile(e.Name()) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			return nil, err
		}
		names = append(names, e.Name())
		fmt.Fprintf(&sig, "%s|%d|%d;", e.Name(), info.Size(), info.ModTime().UnixNano())
	}
	sort.Strings(names)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.pols != nil && sig.String() == l.sig {
		return l.pols, nil
	}
	var out []*Policy
	for _, n := range names {
		text, err := fs.ReadFile(l.fsys, n)
		if err != nil {
			return nil, err
		}
		var doc any
		if err := yaml.Unmarshal(text, &doc); err != nil {
			return nil, fmt.Errorf("policy: %s: %w", n, err)
		}
		docs, ok := doc.([]any)
		if !ok {
			docs = []any{doc}
		}
		for _, d := range docs {
			m, ok := d.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("policy: %s: document is not a mapping", n)
			}
			p, err := Parse(m, string(text))
			if err != nil {
				return nil, fmt.Errorf("policy: %s: %w", n, err)
			}
			out = append(out, p)
		}
	}
	l.sig, l.pols = sig.String(), out
	return out, nil
}

// Parse builds a Policy from a decoded YAML mapping.
func Parse(d map[string]any, source string) (*Policy, error) {
	str := func(k, def string) string {
		if v, ok := d[k]; ok && v != nil {
			return fmt.Sprint(v)
		}
		return def
	}
	id, typ := str("id", ""), str("type", "")
	if id == "" || typ == "" {
		return nil, fmt.Errorf("policy needs id and type")
	}
	p := &Policy{ID: id, Name: str("name", id), Type: typ, Severity: str("severity", "medium"),
		Description: str("description", ""), Spec: map[string]any{}, Source: source, Enabled: true}
	if v, ok := d["enabled"].(bool); ok {
		p.Enabled = v
	}
	for k, v := range d {
		switch k {
		case "id", "name", "type", "severity", "description", "enabled":
		default:
			p.Spec[k] = v
		}
	}
	return p, nil
}

// ------------------------------------------------------------------ context

// Context is what evaluators see: a graph plus, optionally, the database for
// policies that need non-graph data (secrets, ownership).
type Context struct {
	Graph *graph.Snapshot
	Conn  *store.TenantTx
	Now   time.Time

	idents []*graph.Node
	byID   map[int64]*graph.Node
}

// NewContext builds an evaluation context; conn may be nil.
func NewContext(g *graph.Snapshot, conn *store.TenantTx, now time.Time) *Context {
	ctx := &Context{Graph: g, Conn: conn, Now: now, byID: map[int64]*graph.Node{}}
	for _, n := range g.Nodes() {
		if n.Kind == "identity" {
			ctx.idents = append(ctx.idents, n)
			ctx.byID[n.ID] = n
		}
	}
	return ctx
}

func (c *Context) eff(iid int64) *graph.Eff { return c.Graph.EffectivePermissions(iid) }

// ------------------------------------------------------------------ matchers

func asList(v any) []any {
	switch x := v.(type) {
	case []any:
		return x
	case []string:
		out := make([]any, len(x))
		for i, s := range x {
			out[i] = s
		}
		return out
	}
	return nil
}

// contains mirrors Python's `x in container` for lists and strings.
func contains(container any, x string) bool {
	if s, ok := container.(string); ok {
		return strings.Contains(s, x)
	}
	for _, v := range asList(container) {
		if s, ok := v.(string); ok && s == x {
			return true
		}
	}
	return false
}

func boolEq(b bool, v any) bool {
	switch x := v.(type) {
	case bool:
		return x == b
	case int:
		return (x == 1 && b) || (x == 0 && !b)
	}
	return false
}

func permMatches(ep *graph.EffectivePermission, m map[string]any) bool {
	if v, ok := m["actions"]; ok && !contains(v, ep.Action) {
		return false
	}
	if v, ok := m["privileged"]; ok && !boolEq(ep.Privileged, v) {
		return false
	}
	if v, ok := m["environment"]; ok {
		if v == nil {
			if ep.Environment != nil {
				return false
			}
		} else if s, isStr := v.(string); !isStr || ep.Environment == nil || *ep.Environment != s {
			return false
		}
	}
	if v, ok := m["systems"]; ok && !contains(v, ep.System) {
		return false
	}
	if v, ok := m["tags_any"]; ok {
		hit := false
		for _, t := range ep.Tags {
			if contains(asList(v), t) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	return true
}

func mapOf(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func (c *Context) evidence(ep *graph.EffectivePermission, onlyStanding bool) ([]string, [][]string) {
	var paths [][]string
	for _, p := range ep.Paths {
		if !(onlyStanding && c.Graph.PathHasJIT(p)) {
			paths = append(paths, p)
		}
	}
	if len(paths) > 3 {
		paths = paths[:3]
	}
	texts := []string{}
	edges := [][]string{}
	for _, p := range paths {
		texts = append(texts, c.Graph.PathText(p))
	}
	for _, p := range paths {
		if fh, ok := graph.FirstHopEdge(p); ok {
			dup := false
			for _, e := range edges {
				if e[0] == fh[0] && e[1] == fh[1] {
					dup = true
					break
				}
			}
			if !dup {
				edges = append(edges, []string{fh[0], fh[1]})
			}
		}
	}
	return texts, edges
}

func (c *Context) subjects(spec map[string]any) []int64 {
	subj := mapOf(spec["subjects"])
	types := asList(subj["identity_types"])
	statuses := []any{"active"}
	if v, ok := subj["statuses"]; ok {
		statuses = asList(v)
	}
	var out []int64
	for _, n := range c.idents {
		if (len(types) == 0 || contains(types, n.Type)) && contains(statuses, n.Status) {
			out = append(out, n.ID)
		}
	}
	return out
}

// ---------------------------------------------------------------- evaluators

func evalSoD(p *Policy, c *Context) ([]Violation, error) {
	conflict := mapOf(p.Spec["conflict"])
	aActs, bActs := asList(conflict["a"]), asList(conflict["b"])
	var out []Violation
	for _, iid := range c.subjects(p.Spec) {
		var a, b []*graph.EffectivePermission
		for _, ep := range c.eff(iid).Values() {
			if contains(aActs, ep.Action) {
				a = append(a, ep)
			}
			if contains(bActs, ep.Action) {
				b = append(b, ep)
			}
		}
		if len(a) > 0 && len(b) > 0 {
			evA, edA := c.evidence(a[0], false)
			evB, edB := c.evidence(b[0], false)
			name := c.byID[iid].Label
			out = append(out, newViolation(p, iid, name, fmt.Sprintf("%s:%d", p.ID, iid),
				fmt.Sprintf("%s can both %s and %s on %s", name, a[0].Action, b[0].Action, a[0].ResourceName),
				append(evA, evB...), append(edA, edB...)))
		}
	}
	return out, nil
}

type grantHit struct {
	ep   *graph.EffectivePermission
	path []string
}

func evalNoStanding(p *Policy, c *Context) ([]Violation, error) {
	m := mapOf(p.Spec["match"])
	if m == nil {
		m = map[string]any{}
	}
	var out []Violation
	for _, iid := range c.subjects(p.Spec) {
		// one violation per standing grant (first hop from the account), listing what it exposes
		var order [][2]string
		byGrant := map[[2]string][]grantHit{}
		for _, ep := range c.eff(iid).Values() {
			if !(permMatches(ep, m) && ep.Standing) {
				continue
			}
			for _, path := range ep.Paths {
				if c.Graph.PathHasJIT(path) {
					continue
				}
				fh, _ := graph.FirstHopEdge(path)
				if _, ok := byGrant[fh]; !ok {
					order = append(order, fh)
				}
				byGrant[fh] = append(byGrant[fh], grantHit{ep, path})
			}
		}
		if len(order) == 0 {
			continue
		}
		name := c.byID[iid].Label
		for _, fh := range order {
			hits := byGrant[fh]
			set := map[string]bool{}
			var actions []string
			var evidence []string
			for _, h := range hits {
				a := h.ep.Action + " on " + h.ep.ResourceName
				if !set[a] {
					set[a] = true
					actions = append(actions, a)
				}
			}
			sort.Strings(actions)
			for _, h := range hits {
				t := c.Graph.PathText(h.path)
				if !contains(toAny(evidence), t) {
					evidence = append(evidence, t)
				}
			}
			shown, more := actions, ""
			if len(actions) > 3 {
				shown, more = actions[:3], " …"
			}
			if len(evidence) > 4 {
				evidence = evidence[:4]
			}
			out = append(out, newViolation(p, iid, name, fmt.Sprintf("%s:%d:%s->%s", p.ID, iid, fh[0], fh[1]),
				fmt.Sprintf("%s has standing privileged prod access via %s: %s%s", name, c.Graph.Label(fh[1]),
					strings.Join(shown, ", "), more),
				evidence, [][]string{{fh[0], fh[1]}}))
		}
	}
	return out, nil
}

func toAny(s []string) []any {
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}

func evalForbidden(p *Policy, c *Context) ([]Violation, error) {
	m := mapOf(p.Spec["resources"])
	if m == nil {
		m = map[string]any{}
	}
	var out []Violation
	for _, iid := range c.subjects(p.Spec) {
		for _, ep := range c.eff(iid).Values() {
			if !permMatches(ep, m) {
				continue
			}
			n := c.byID[iid]
			ev, edges := c.evidence(ep, false)
			out = append(out, newViolation(p, iid, n.Label, fmt.Sprintf("%s:%d:%s", p.ID, iid, ep.PermKey),
				fmt.Sprintf("%s (%s) can %s on %s [%s]", n.Label, n.Type, ep.Action, ep.ResourceName, strings.Join(ep.Tags, ", ")),
				ev, edges))
		}
	}
	return out, nil
}

func evalTerminated(p *Policy, c *Context) ([]Violation, error) {
	var out []Violation
	for _, n := range c.idents {
		if n.Status != "terminated" {
			continue
		}
		eff := c.eff(n.ID)
		if eff.Len() == 0 {
			continue
		}
		acctSet, edgeSet := map[string]bool{}, map[[2]string]bool{}
		for _, ep := range eff.Values() {
			for _, path := range ep.Paths {
				acctSet[c.Graph.Label(path[1])] = true
				fh, _ := graph.FirstHopEdge(path)
				edgeSet[fh] = true
			}
		}
		accts := make([]string, 0, len(acctSet))
		for a := range acctSet {
			accts = append(accts, a)
		}
		sort.Strings(accts)
		keys := make([][2]string, 0, len(edgeSet))
		for e := range edgeSet {
			keys = append(keys, e)
		}
		sort.Slice(keys, func(i, j int) bool {
			if keys[i][0] != keys[j][0] {
				return keys[i][0] < keys[j][0]
			}
			return keys[i][1] < keys[j][1]
		})
		evidence := make([]string, len(accts))
		for i, a := range accts {
			evidence[i] = "active account: " + a
		}
		edges := make([][]string, len(keys))
		for i, k := range keys {
			edges[i] = []string{k[0], k[1]}
		}
		out = append(out, newViolation(p, n.ID, n.Label, fmt.Sprintf("%s:%d", p.ID, n.ID),
			fmt.Sprintf("%s is terminated but retains %d effective permissions via %d active account(s)", n.Label, eff.Len(), len(accts)),
			evidence, edges))
	}
	return out, nil
}

func evalSecretAge(p *Policy, c *Context) ([]Violation, error) {
	if c.Conn == nil {
		return nil, nil
	}
	maxAge := any(90)
	if v, ok := p.Spec["max_age_days"]; ok {
		maxAge = v
	}
	limit, ok := toFloat(maxAge)
	if !ok {
		return nil, fmt.Errorf("policy %s: max_age_days must be a number", p.ID)
	}
	rows, err := c.Conn.SecretsWithAccounts()
	if err != nil {
		return nil, err
	}
	var out []Violation
	for _, r := range rows {
		if r.Secret.Status != "active" {
			continue
		}
		ref := r.Secret.CreatedAt
		if r.Secret.LastRotatedAt != nil {
			ref = *r.Secret.LastRotatedAt
		}
		age := timeutil.Days(c.Now, ref)
		if float64(age) <= limit || r.Account.IdentityID == nil {
			continue
		}
		n, ok := c.byID[*r.Account.IdentityID]
		if !ok || n.Status != "active" {
			continue
		}
		rotated := "never"
		if r.Secret.LastRotatedAt != nil {
			rotated = timeutil.Date(*r.Secret.LastRotatedAt)
		}
		out = append(out, newViolation(p, n.ID, n.Label, fmt.Sprintf("%s:%d", p.ID, r.Secret.ID),
			fmt.Sprintf("%s '%s' on %s:%s is %d days old (max %v)", r.Secret.Kind, r.Secret.Name, r.Account.System,
				r.Account.Username, age, maxAge),
			[]string{"created " + timeutil.Date(r.Secret.CreatedAt), "last rotated " + rotated}, nil))
	}
	return out, nil
}

func toFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case float64:
		return x, true
	}
	return 0, false
}

func evalNHIOwnership(p *Policy, c *Context) ([]Violation, error) {
	if c.Conn == nil {
		return nil, nil
	}
	people, all, err := c.Conn.IdentityMap()
	if err != nil {
		return nil, err
	}
	var out []Violation
	for _, i := range all {
		if (i.Type != "service" && i.Type != "ai_agent") || i.Status != "active" {
			continue
		}
		var owner *store.Identity
		if i.OwnerID != nil {
			owner = people[*i.OwnerID]
		}
		var msg string
		switch {
		case owner == nil:
			msg = i.Name + " has no owner"
		case owner.Status != "active":
			msg = fmt.Sprintf("%s is owned by %s, who is %s", i.Name, owner.Name, owner.Status)
		default:
			continue
		}
		out = append(out, newViolation(p, i.ID, i.Name, fmt.Sprintf("%s:%d", p.ID, i.ID), msg,
			[]string{fmt.Sprintf("%d effective permissions", c.eff(i.ID).Len())}, nil))
	}
	return out, nil
}

// evalMFARequired flags privileged people whose strongest registered method is
// weaker than the policy's `require` class (default phishing_resistant). A
// person is privileged when they are in a privileged group or hold a
// privileged permission (internal/mfa). A person none of whose accounts is in
// a system that reported its methods is skipped: unknown is not a violation.
func evalMFARequired(p *Policy, c *Context) ([]Violation, error) {
	if c.Conn == nil {
		return nil, nil
	}
	required := mfa.PhishingResistant
	if v, ok := p.Spec["require"]; ok {
		required = mfa.Strength(fmt.Sprint(v))
		if !required.Valid() {
			return nil, fmt.Errorf("policy %s: require must be one of %v", p.ID, mfa.Strengths)
		}
	}
	data, err := mfa.Load(c.Conn, c.Now)
	if err != nil {
		return nil, err
	}
	byID := map[int64]*mfa.Identity{}
	for _, v := range data.Identities {
		byID[v.ID] = v
	}
	var out []Violation
	for _, iid := range c.subjects(p.Spec) {
		v := byID[iid]
		if v == nil || !v.Privileged || v.Best == mfa.Unknown || v.Best.Rank() >= required.Rank() {
			continue
		}
		name := c.byID[iid].Label
		state := "has no MFA method registered"
		if v.Best != mfa.None {
			state = "their strongest MFA method is " + strings.ToLower(v.Best.Label())
		}
		msg := fmt.Sprintf("%s has privileged access (%s) but %s; policy requires %s MFA", name, v.PrivilegedVia[0], state,
			strings.ToLower(required.Label()))
		evidence := []string{}
		for _, m := range v.Methods {
			evidence = append(evidence, fmt.Sprintf("%s: %s (%s)", m.System, m.Kind, m.Strength.Label()))
		}
		if len(evidence) == 0 {
			evidence = append(evidence, "no registered authentication method in "+strings.Join(v.Systems, ", "))
		}
		out = append(out, newViolation(p, iid, name, fmt.Sprintf("%s:%d", p.ID, iid), msg, evidence, nil))
	}
	return out, nil
}

// Evaluators maps policy types to evaluator functions.
var Evaluators = map[string]func(*Policy, *Context) ([]Violation, error){
	"mfa_required":           evalMFARequired,
	"separation_of_duties":   evalSoD,
	"no_standing_access":     evalNoStanding,
	"forbidden_access":       evalForbidden,
	"terminated_with_access": evalTerminated,
	"secret_max_age":         evalSecretAge,
	"nhi_ownership":          evalNHIOwnership,
}

// Evaluate runs every enabled policy and sorts findings by severity, policy id
// and identity name.
func Evaluate(policies []*Policy, c *Context) ([]Violation, error) {
	out := []Violation{}
	for _, p := range policies {
		if !p.Enabled {
			continue
		}
		fn, ok := Evaluators[p.Type]
		if !ok {
			return nil, fmt.Errorf("unknown policy type %q in policy %s", p.Type, p.ID)
		}
		vs, err := fn(p, c)
		if err != nil {
			return nil, err
		}
		out = append(out, vs...)
	}
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := SeverityRank[out[i].Severity], SeverityRank[out[j].Severity]
		if ri != rj {
			return ri > rj
		}
		if out[i].PolicyID != out[j].PolicyID {
			return out[i].PolicyID < out[j].PolicyID
		}
		return out[i].IdentityName < out[j].IdentityName
	})
	return out, nil
}

// Diff is the change in violations between two evaluations.
type Diff struct {
	Resolved   []Violation `json:"resolved"`
	Introduced []Violation `json:"introduced"`
}

// DiffViolations compares two evaluations by violation key. Both lists are
// sorted by key so the result is deterministic.
func DiffViolations(before, after []Violation) Diff {
	b, a := map[string]Violation{}, map[string]Violation{}
	for _, v := range before {
		b[v.Key] = v
	}
	for _, v := range after {
		a[v.Key] = v
	}
	d := Diff{Resolved: []Violation{}, Introduced: []Violation{}}
	for k, v := range b {
		if _, ok := a[k]; !ok {
			d.Resolved = append(d.Resolved, v)
		}
	}
	for k, v := range a {
		if _, ok := b[k]; !ok {
			d.Introduced = append(d.Introduced, v)
		}
	}
	sort.Slice(d.Resolved, func(i, j int) bool { return d.Resolved[i].Key < d.Resolved[j].Key })
	sort.Slice(d.Introduced, func(i, j int) bool { return d.Introduced[i].Key < d.Introduced[j].Key })
	return d
}
