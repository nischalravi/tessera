package policy

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"sync"

	"github.com/nischalravi/tessera/mvp/server/internal/cedarx"
	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/mfa"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// Cedar invariants (access-as-code design section 3.6, issue #649).
//
// An invariant is a Cedar forbid over a fact, evaluated with an implicit
// permit of everything: a fact for which a forbid is satisfied is a violation.
// The facts are built from the graph, never authored:
//
//	reach            one row of the effective permissions of an identity
//	                 (principal Identity, resource Resource, context action,
//	                 action_class, system, standing, via_jit, fidelity)
//	exist            an identity; its owner, mfa_strength (the strongest known
//	                 method) and membership of Group "privileged" are set
//	hold_credential  an active secret (principal = the holder)
//
// Which findings exist is Cedar's decision; how a finding is worded (key,
// message, evidence, edges) stays the evaluator's, chosen by the @type
// annotation, so a ported invariant reports exactly what its YAML did. A
// finding whose every basis is an approximate, unsupported or conditional
// permission is flagged LowFidelity: reported, never blocking.

// Fact shapes: the actions of the schema.
const (
	FactReach          = "reach"
	FactExist          = "exist"
	FactHoldCredential = "hold_credential"
)

// TypeInvariant is the Type of a Cedar invariant without a @type annotation.
const TypeInvariant = "invariant"

// invariantShapes maps the @type values (the YAML types that are ported) to
// the fact shape each is evaluated over.
var invariantShapes = map[string]string{
	"forbidden_access":       FactReach,
	"no_standing_access":     FactReach,
	"terminated_with_access": FactReach,
	"nhi_ownership":          FactExist,
	"mfa_required":           FactExist,
	"secret_max_age":         FactHoldCredential,
}

// CedarSpec is the Cedar half of a Policy.
type CedarSpec struct {
	Text    string           // the source file the invariant came from
	Set     *cedarx.Policies // just this invariant
	Fact    string           // FactReach, FactExist or FactHoldCredential
	Shape   string           // the @type: how findings are worded; "" for the generic wording
	Require string           // @require: the MFA strength mfa_required words its findings with
	MaxAge  string           // @max_age_days: the limit secret_max_age words its findings with
	Message string           // @message: the generic wording of an exist or credential finding
}

var idRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`)

var (
	permitAllOnce sync.Once
	permitAllSet  *cedarx.Policies
	schemaOnce    sync.Once
	invSchema     *cedarx.Schema
	invSchemaErr  error
)

// permitAll is the implicit permit of everything the forbids are evaluated with.
func permitAll() *cedarx.Policies {
	permitAllOnce.Do(func() {
		p, err := cedarx.ParsePolicies("permit-all", []byte("permit (principal, action, resource);"))
		if err != nil {
			panic("policy: permit-all does not parse: " + err.Error())
		}
		permitAllSet = p
	})
	return permitAllSet
}

// InvariantSchema is the Cedar schema invariants are checked against: the
// generated schema of cedarx for a graph with no identity attributes (the
// facts built here carry none).
func InvariantSchema() (*cedarx.Schema, error) {
	schemaOnce.Do(func() { invSchema, invSchemaErr = cedarx.Generate(cedarx.Facts{}) })
	return invSchema, invSchemaErr
}

// ParseInvariants reads the Cedar source of one invariant file: every policy is
// a forbid with an @id, scoped to exactly one fact shape, valid against the
// schema, and within the cedarx limits. Annotations give the Policy fields:
// @id, @name, @severity (critical, high, medium or low; default medium),
// @description, @enabled("false"), @type (see invariantShapes), @require,
// @max_age_days and @message.
func ParseInvariants(name string, src []byte) ([]*Policy, error) {
	schema, err := InvariantSchema()
	if err != nil {
		return nil, err
	}
	ps, err := schema.Check(name, src)
	if err != nil {
		return nil, err
	}
	var out []*Policy
	seen := map[string]bool{}
	for _, cid := range ps.IDs() {
		line := ps.Line(cid)
		bad := func(format string, args ...any) error {
			return fmt.Errorf("policy: %s: line %d: %s", name, line, fmt.Sprintf(format, args...))
		}
		if ps.Effect(cid) != "forbid" {
			return nil, bad("an invariant is a forbid")
		}
		ann := func(k string) string { v, _ := ps.Annotation(cid, k); return v }
		id := ann("id")
		if !idRE.MatchString(id) {
			return nil, bad("an invariant needs @id(\"...\") of 1 to 64 letters, digits and . _ : -")
		}
		if seen[id] {
			return nil, bad("@id %q is used twice", id)
		}
		seen[id] = true
		sev := ann("severity")
		if sev == "" {
			sev = "medium"
		}
		if SeverityRank[sev] == 0 {
			return nil, bad("@severity is one of critical, high, medium, low")
		}
		actions, all := ps.ActionScope(cid)
		if all || len(actions) != 1 || actions[0].Type != "Tessera::Action" {
			return nil, bad("an invariant is scoped to exactly one fact: action == Tessera::Action::\"reach\", \"exist\" or \"hold_credential\"")
		}
		fact := actions[0].ID
		shape := ann("type")
		if shape != "" && invariantShapes[shape] != fact {
			return nil, bad("@type %q is evaluated over %q facts, not %q", shape, invariantShapes[shape], fact)
		}
		typ := shape
		if typ == "" {
			typ = TypeInvariant
		}
		if r := ann("require"); r != "" && !mfa.Strength(r).Valid() {
			return nil, bad("@require is one of %v", mfa.Strengths)
		}
		out = append(out, &Policy{
			ID: id, Name: orDefault(ann("name"), id), Type: typ, Severity: sev, Description: ann("description"),
			Spec: map[string]any{}, Source: string(src), Enabled: ann("enabled") != "false",
			Cedar: &CedarSpec{Text: string(src), Set: ps.Only(cid), Fact: fact, Shape: shape, Require: ann("require"),
				MaxAge: ann("max_age_days"), Message: ann("message")},
		})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("policy: %s: no policy", name)
	}
	return out, nil
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// ------------------------------------------------------------------ facts

// cedarFacts caches what the Cedar facts of one Context share.
type cedarFacts struct {
	loaded    bool
	people    map[int64]*store.Identity
	all       []*store.Identity
	mfaLoaded bool
	mfaByID   map[int64]*mfa.Identity
	reach     map[int64]*cedarx.Entities
	exist     map[int64]*cedarx.Entities
}

func (c *Context) facts() *cedarFacts {
	if c.cf == nil {
		c.cf = &cedarFacts{reach: map[int64]*cedarx.Entities{}, exist: map[int64]*cedarx.Entities{}}
	}
	return c.cf
}

func (c *Context) people() (map[int64]*store.Identity, []*store.Identity, error) {
	f := c.facts()
	if !f.loaded {
		if c.Conn != nil {
			var err error
			if f.people, f.all, err = c.Conn.IdentityMap(); err != nil {
				return nil, nil, err
			}
		}
		f.loaded = true
	}
	return f.people, f.all, nil
}

func (c *Context) mfaIdentities() (map[int64]*mfa.Identity, error) {
	f := c.facts()
	if !f.mfaLoaded {
		data, err := mfa.Load(c.Conn, c.Now)
		if err != nil {
			return nil, err
		}
		f.mfaByID = map[int64]*mfa.Identity{}
		for _, v := range data.Identities {
			f.mfaByID[v.ID] = v
		}
		f.mfaLoaded = true
	}
	return f.mfaByID, nil
}

const (
	typeIdentity   = "Tessera::Identity"
	typeResource   = "Tessera::Resource"
	typeCredential = "Tessera::Credential"
	typeGroup      = "Tessera::Group"
	typeAction     = "Tessera::Action"
)

func identUID(id int64) cedarx.UID {
	return cedarx.UID{Type: typeIdentity, ID: strconv.FormatInt(id, 10)}
}

// identityAttrs are the schema attributes of an Identity from the graph node and, when there is a
// database, the stored identity.
func (c *Context) identityAttrs(n *graph.Node, i *store.Identity) map[string]any {
	a := map[string]any{"type": n.Type, "status": n.Status, "attrs": map[string]any{}, "created_days": 0}
	if n.Department != nil && *n.Department != "" {
		a["department"] = *n.Department
	}
	if i != nil {
		if i.Title != nil && *i.Title != "" {
			a["title"] = *i.Title
		}
		if d := timeutil.Days(c.Now, i.CreatedAt); d > 0 {
			a["created_days"] = d
		}
	}
	return a
}

// principal is the entity set of an identity: the identity, its owner when
// that is known, and for exist facts its mfa_strength and the privileged group.
func (c *Context) principal(n *graph.Node, exist bool) (*cedarx.Entities, error) {
	f := c.facts()
	cache := f.reach
	if exist {
		cache = f.exist
	}
	if e, ok := cache[n.ID]; ok {
		return e, nil
	}
	people, _, err := c.people()
	if err != nil {
		return nil, err
	}
	i := people[n.ID]
	attrs := c.identityAttrs(n, i)
	ents := cedarx.NewEntities()
	if i != nil && i.OwnerID != nil {
		if o := people[*i.OwnerID]; o != nil {
			on := &graph.Node{ID: o.ID, Type: o.Type, Status: o.Status, Department: o.Department}
			if err := ents.Add(identUID(o.ID), c.identityAttrs(on, o)); err != nil {
				return nil, err
			}
			attrs["owner"] = cedarx.Ref(identUID(o.ID))
		}
	}
	var parents []cedarx.UID
	if exist && c.Conn != nil {
		byID, err := c.mfaIdentities()
		if err != nil {
			return nil, err
		}
		if v := byID[n.ID]; v != nil {
			if v.Best != mfa.Unknown {
				attrs["mfa_strength"] = string(v.Best)
			}
			if v.Privileged {
				g := cedarx.UID{Type: typeGroup, ID: "privileged"}
				parents = append(parents, g)
				if err := ents.Add(g, map[string]any{"system": "tessera", "name": "privileged", "privileged": true, "requestable": false}); err != nil {
					return nil, err
				}
			}
		}
	}
	if err := ents.Add(identUID(n.ID), attrs, parents...); err != nil {
		return nil, err
	}
	cache[n.ID] = ents
	return ents, nil
}

// fidelity is the Cedar fidelity of an effective permission.
func fidelity(ep *graph.EffectivePermission) string {
	switch {
	case ep.Fidelity == graph.FidelityUnsupp:
		return "UNSUPPORTED"
	case ep.Fidelity == graph.FidelityApprox || ep.Conditional:
		return "APPROXIMATE"
	}
	return "EXACT"
}

type reachContext struct {
	Action      string `json:"action"`
	ActionClass string `json:"action_class"`
	System      string `json:"system"`
	Standing    bool   `json:"standing"`
	ViaJIT      bool   `json:"via_jit"`
	Fidelity    string `json:"fidelity"`
}

func (c *Context) reachContext(ep *graph.EffectivePermission) ([]byte, error) {
	rc := reachContext{Action: ep.Action, ActionClass: "unclassified", System: ep.System, Standing: ep.Standing,
		Fidelity: fidelity(ep)}
	if ep.Privileged {
		rc.ActionClass = "admin"
	}
	for _, p := range ep.Paths {
		if c.Graph.PathHasJIT(p) {
			rc.ViaJIT = true
			break
		}
	}
	return json.Marshal(rc)
}

func resourceAttrs(system string, env *string, tags []string, privileged bool) map[string]any {
	if tags == nil {
		tags = []string{}
	}
	a := map[string]any{"system": system, "tags": tags, "privileged": privileged}
	if env != nil {
		a["environment"] = *env
	}
	return a
}

// violates asks Cedar: is a forbid of the invariant satisfied by the fact?
func violates(sp *CedarSpec, principal, resource *cedarx.Entities, pu cedarx.UID, action string, ru cedarx.UID, ctx []byte) (bool, error) {
	ents := cedarx.NewEntities()
	if err := ents.Merge(principal); err != nil {
		return false, err
	}
	if err := ents.Merge(resource); err != nil {
		return false, err
	}
	d, err := cedarx.Decide(ents, cedarx.Request{Principal: pu, Action: cedarx.UID{Type: typeAction, ID: action}, Resource: ru, Context: ctx},
		permitAll(), sp.Set)
	if err != nil {
		return false, err
	}
	return !d.Allow, nil // an evaluation error leaves a forbid unsatisfied, as in Cedar
}

// ------------------------------------------------------------------ evaluation

// evalCedar evaluates one Cedar invariant over the facts of its shape.
func evalCedar(p *Policy, c *Context) ([]Violation, error) {
	switch p.Cedar.Fact {
	case FactReach:
		return c.cedarReach(p)
	case FactExist:
		return c.cedarExist(p)
	case FactHoldCredential:
		return c.cedarCredential(p)
	}
	return nil, fmt.Errorf("policy %s: unknown fact %q", p.ID, p.Cedar.Fact)
}

func (c *Context) cedarReach(p *Policy) ([]Violation, error) {
	sp := p.Cedar
	var out []Violation
	for _, n := range c.idents {
		eff := c.eff(n.ID)
		if eff.Len() == 0 {
			continue
		}
		pe, err := c.principal(n, false)
		if err != nil {
			return nil, err
		}
		var hits []*graph.EffectivePermission
		for _, ep := range eff.Values() {
			ctx, err := c.reachContext(ep)
			if err != nil {
				return nil, err
			}
			res := cedarx.NewEntities()
			ru := cedarx.UID{Type: typeResource, ID: strconv.FormatInt(ep.ResourceID, 10)}
			if err := res.Add(ru, resourceAttrs(ep.System, ep.Environment, ep.Tags, ep.Privileged)); err != nil {
				return nil, err
			}
			bad, err := violates(sp, pe, res, identUID(n.ID), FactReach, ru, ctx)
			if err != nil {
				return nil, err
			}
			if bad {
				hits = append(hits, ep)
			}
		}
		if len(hits) == 0 {
			continue
		}
		switch sp.Shape {
		case "no_standing_access":
			out = append(out, noStandingViolations(p, c, n.ID, hits, true)...)
		case "terminated_with_access":
			out = append(out, terminatedViolation(p, c, n, hits, true))
		default:
			for _, ep := range hits {
				v := forbiddenViolation(p, c, n, ep)
				v.LowFidelity = ep.Weak()
				out = append(out, v)
			}
		}
	}
	return out, nil
}

func (c *Context) cedarExist(p *Policy) ([]Violation, error) {
	if c.Conn == nil {
		return nil, nil // the facts need the database
	}
	sp := p.Cedar
	people, all, err := c.people()
	if err != nil {
		return nil, err
	}
	res := cedarx.NewEntities()
	ru := cedarx.UID{Type: typeResource, ID: "tessera"}
	if err := res.Add(ru, resourceAttrs("tessera", nil, nil, false)); err != nil {
		return nil, err
	}
	required := mfa.PhishingResistant
	if sp.Require != "" {
		required = mfa.Strength(sp.Require)
	}
	var out []Violation
	for _, i := range all {
		n := c.byID[i.ID]
		if n == nil {
			continue
		}
		pe, err := c.principal(n, true)
		if err != nil {
			return nil, err
		}
		bad, err := violates(sp, pe, res, identUID(i.ID), FactExist, ru, nil)
		if err != nil {
			return nil, err
		}
		if !bad {
			continue
		}
		switch sp.Shape {
		case "nhi_ownership":
			var owner *store.Identity
			if i.OwnerID != nil {
				owner = people[*i.OwnerID]
			}
			msg := i.Name + " violates " + p.Name
			switch {
			case owner == nil:
				msg = i.Name + " has no owner"
			case owner.Status != "active":
				msg = fmt.Sprintf("%s is owned by %s, who is %s", i.Name, owner.Name, owner.Status)
			}
			out = append(out, nhiViolation(p, c, i, msg))
			continue
		case "mfa_required":
			byID, err := c.mfaIdentities()
			if err != nil {
				return nil, err
			}
			if v := byID[i.ID]; v != nil && len(v.PrivilegedVia) > 0 {
				out = append(out, mfaViolation(p, n.Label, i.ID, v, required))
				continue
			}
		}
		out = append(out, newViolation(p, i.ID, n.Label, fmt.Sprintf("%s:%d", p.ID, i.ID),
			orDefault(sp.Message, n.Label+" violates "+p.Name), nil, nil))
	}
	return out, nil
}

func (c *Context) cedarCredential(p *Policy) ([]Violation, error) {
	if c.Conn == nil {
		return nil, nil // the facts need the database
	}
	sp := p.Cedar
	rows, err := c.Conn.SecretsWithAccounts()
	if err != nil {
		return nil, err
	}
	var out []Violation
	for _, r := range rows {
		if r.Secret.Status != "active" || r.Account.IdentityID == nil {
			continue
		}
		n, ok := c.byID[*r.Account.IdentityID]
		if !ok {
			continue
		}
		ref := r.Secret.CreatedAt
		if r.Secret.LastRotatedAt != nil {
			ref = *r.Secret.LastRotatedAt
		}
		age := timeutil.Days(c.Now, ref)
		pe, err := c.principal(n, false)
		if err != nil {
			return nil, err
		}
		res := cedarx.NewEntities()
		ru := cedarx.UID{Type: typeCredential, ID: strconv.FormatInt(r.Secret.ID, 10)}
		if err := res.Add(ru, map[string]any{"kind": r.Secret.Kind, "age_days": age, "holder": cedarx.Ref(identUID(n.ID))}); err != nil {
			return nil, err
		}
		bad, err := violates(sp, pe, res, identUID(n.ID), FactHoldCredential, ru, nil)
		if err != nil {
			return nil, err
		}
		if !bad {
			continue
		}
		if sp.Shape == "secret_max_age" {
			out = append(out, secretViolation(p, n, r, age, orDefault(sp.MaxAge, "?")))
			continue
		}
		out = append(out, newViolation(p, n.ID, n.Label, fmt.Sprintf("%s:%d", p.ID, r.Secret.ID),
			orDefault(sp.Message, fmt.Sprintf("%s '%s' on %s:%s violates %s", r.Secret.Kind, r.Secret.Name, r.Account.System,
				r.Account.Username, p.Name)),
			[]string{"created " + timeutil.Date(r.Secret.CreatedAt)}, nil))
	}
	return out, nil
}

// Blocking is the violations that may fail a gate: those a Cedar invariant
// found on exact facts, and every YAML finding. A low-fidelity finding is a
// report (design section 10, decision 6).
func Blocking(vs []Violation) []Violation {
	out := []Violation{}
	for _, v := range vs {
		if !v.LowFidelity {
			out = append(out, v)
		}
	}
	return out
}
