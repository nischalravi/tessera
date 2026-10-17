package awsorg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/authz"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/eval"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/index"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/query"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/ingest"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Evaluator-confirmed records (issue #30, PR-11; design §11.1, §11.2, §11.4).
//
// Materialize runs the evaluator over a collected snapshot and returns the
// MVP's normalized records, so the existing graph, least-privilege, review and
// NHI code works unchanged on AWS and its output simply becomes correct:
//
//   - an AccountRecord for each IAM user (kind user) and each role (kind
//     service); a GroupRecord for each IAM group and for each role seen as a
//     group (kind role, so a maps_to edge from an identity provider's group
//     still has somewhere to land);
//   - a ResourceRecord for each resource a permission names;
//   - PermissionRecords for only the tuples the engine confirmed ALLOW or
//     CONDITIONAL, at the granularity of an action atom by a resource atom,
//     named by the atoms' representative members;
//   - EdgeRecords "grants" from the user or role to each permission, carrying
//     the explanation id, the outcome and the fidelity (stored with source
//     "evaluator"), and "can_assume" edges for the trust edges the engine
//     found, evaluated symbolically.
//
// Fail closed (§3.3): a finding of the collection that could change a cell
// makes its edge UNSUPPORTED, so least privilege never acts on it.

// EvalConfig says how to evaluate a snapshot.
type EvalConfig struct {
	// Index returns the index configuration for a snapshot (the catalog, the
	// action universe and the cells that exist).
	Index func(*model.Snapshot) index.Config
	// Privileged says whether an action is a permission-management action
	// (the catalog's access level). Nil: none is.
	Privileged func(action string) bool
	// MaxCellsPerPrincipal bounds the permissions materialized for one
	// principal (default 5000); MaxTrustEvaluations the trust questions asked
	// of the engine (default 20000). A cut is reported in Materialized.Notes.
	MaxCellsPerPrincipal int
	MaxTrustEvaluations  int
	// Workers is the number of goroutines that evaluate cells (default 4).
	Workers int
}

func (c *EvalConfig) cells() int {
	if c.MaxCellsPerPrincipal > 0 {
		return c.MaxCellsPerPrincipal
	}
	return 5000
}

func (c *EvalConfig) trustEvals() int {
	if c.MaxTrustEvaluations > 0 {
		return c.MaxTrustEvaluations
	}
	return 20000
}

// Materialized is what an evaluation of a snapshot produces.
type Materialized struct {
	Result       *connectors.DiscoveryResult
	Trust        []*store.AWSTrustEdge
	Explanations []*store.AWSExplanation
	// Cells counts the permissions materialized; Notes says what was cut.
	Cells int
	Notes []string
}

const (
	systemAWS = "aws"
	// trustOutside is the From of a trust fact taken from the trust policy
	// itself, naming a principal that is not in the snapshot.
	trustOutsidePrefix = "trust-policy:"
)

func acctRef(arn string) connectors.Ref {
	return connectors.Ref{Kind: "account", System: systemAWS, ExternalID: arn}
}
func groupRef(arn string) connectors.Ref {
	return connectors.Ref{Kind: "group", System: systemAWS, ExternalID: arn}
}
func permRef(xid string) connectors.Ref {
	return connectors.Ref{Kind: "perm", System: systemAWS, ExternalID: xid}
}

func entityName(arn string) string {
	if i := strings.LastIndexByte(arn, '/'); i >= 0 {
		return arn[i+1:]
	}
	return arn
}

// Materialize evaluates snap through q (a symbolic querier with the default
// profile) and returns the records. It does no I/O of its own.
func Materialize(ctx context.Context, snap *model.Snapshot, findings Findings, q *query.Querier, cfg *EvalConfig) (*Materialized, error) {
	if snap == nil || q == nil || cfg == nil {
		return nil, errors.New("awsorg: Materialize needs a snapshot, a querier and a config")
	}
	m := &Materialized{Result: &connectors.DiscoveryResult{}}
	res := m.Result
	ix := q.Idx

	arns := make([]string, 0, len(snap.Principals))
	for arn, p := range snap.Principals {
		if p.Kind == model.IAMUser || p.Kind == model.IAMRole {
			arns = append(arns, arn)
		}
	}
	sort.Strings(arns)

	groups := map[string]bool{}
	resources := map[string]bool{}
	perms := map[string]connectors.PermissionRecord{}
	explained := map[string]bool{}
	explain := func(d *authz.Decision) (string, error) {
		id, err := eval.ExplanationID(d)
		if err != nil {
			return "", err
		}
		if !explained[id] {
			explained[id] = true
			trace, err := json.Marshal(d)
			if err != nil {
				return "", err
			}
			m.Explanations = append(m.Explanations, &store.AWSExplanation{ID: id, Trace: trace})
		}
		return id, nil
	}
	gapsFor := func(principal, resource string) []authz.FidelityReason {
		if len(findings) == 0 {
			return nil
		}
		return findings.Unsupported(findingRequest(snap, principal, resource))
	}

	for _, arn := range arns {
		p := snap.Principals[arn]
		kind := "user"
		if p.Kind == model.IAMRole {
			kind = "service"
		}
		res.Accounts = append(res.Accounts, connectors.AccountRecord{System: systemAWS, ExternalID: arn, Username: entityName(arn), Kind: kind, Status: "active"})
		granter := acctRef(arn)
		if p.Kind == model.IAMRole {
			res.Groups = append(res.Groups, connectors.GroupRecord{System: systemAWS, ExternalID: arn, Name: entityName(arn), Kind: "role"})
			res.Edges = append(res.Edges, connectors.EdgeRecord{Src: acctRef(arn), Dst: groupRef(arn), Relation: "member_of"})
			granter = groupRef(arn)
		}
		for _, g := range p.GroupARNs {
			if !groups[g] {
				groups[g] = true
				res.Groups = append(res.Groups, connectors.GroupRecord{System: systemAWS, ExternalID: g, Name: entityName(g), Kind: "group"})
			}
			res.Edges = append(res.Edges, connectors.EdgeRecord{Src: acctRef(arn), Dst: groupRef(g), Relation: "member_of"})
		}

		eff, err := q.EffectivePermissions(ctx, arn)
		if err != nil {
			return nil, fmt.Errorf("awsorg: effective permissions of %s: %w", arn, err)
		}
		n := 0
		for _, row := range eff.Rows {
			c := row.Cell
			if c.Outcome != authz.Allow && c.Outcome != authz.Conditional {
				continue // only what the engine confirmed
			}
			if n >= cfg.cells() {
				m.Notes = append(m.Notes, fmt.Sprintf("%s: more than %d permissions; the rest are not materialized", arn, cfg.cells()))
				break
			}
			n++
			action, resource := ix.Actions.RepName(row.Action), ix.Resources.RepARN(row.Resource)
			reqResource := resource
			if reqResource == "*" {
				reqResource = ""
			}
			d, err := q.Can(ctx, arn, action, reqResource)
			if err != nil {
				return nil, fmt.Errorf("awsorg: trace of %s %s %s: %w", arn, action, resource, err)
			}
			if gaps := gapsFor(arn, resource); len(gaps) > 0 {
				d.Fidelity = authz.Unsupported
				d.FidelityReasons = append(d.FidelityReasons, gaps...)
			}
			id, err := explain(d)
			if err != nil {
				return nil, err
			}
			xid := action + "|" + resource
			if _, ok := perms[xid]; !ok {
				priv := cfg.Privileged != nil && cfg.Privileged(action)
				perms[xid] = connectors.PermissionRecord{System: systemAWS, ExternalID: xid, Action: action, ResourceExternalID: resource, Privileged: priv}
			}
			resources[resource] = true
			res.Edges = append(res.Edges, connectors.EdgeRecord{Src: granter, Dst: permRef(xid), Relation: "grants",
				Evaluation: &connectors.EdgeEvaluation{ExplanationID: id, Outcome: d.Outcome.String(), Fidelity: d.Fidelity.String()}})
		}
		m.Cells += n
	}

	for _, xid := range sortedKeys(perms) {
		res.Permissions = append(res.Permissions, perms[xid])
	}
	for _, arn := range sortedKeys(resources) {
		res.Resources = append(res.Resources, resourceRecord(snap, arn))
	}
	if err := m.addTrust(ctx, snap, q, cfg, explain); err != nil {
		return nil, err
	}
	return m, nil
}

func findingRequest(snap *model.Snapshot, principal, resource string) Request {
	r := Request{PrincipalARN: principal, ResourceARN: resource}
	if p := snap.Principals[principal]; p != nil {
		r.PrincipalAccount = p.AccountID
	} else {
		r.PrincipalAccount = arnAccountID(principal)
	}
	if x := snap.Resources[resource]; x != nil {
		r.ResourceAccount = x.AccountID
	} else {
		r.ResourceAccount = arnAccountID(resource)
	}
	return r
}

func arnAccountID(arn string) string {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 5 || parts[0] != "arn" {
		return ""
	}
	return parts[4]
}

// classificationKeys are the resource tag keys whose values become the tags
// the policies and recommendations look at ("pii", "payments", ...).
var classificationKeys = []string{"data-classification", "data_classification", "classification", "sensitivity"}

func resourceRecord(snap *model.Snapshot, arn string) connectors.ResourceRecord {
	rec := connectors.ResourceRecord{System: systemAWS, ExternalID: arn, Name: arn, Kind: "resource"}
	if x := snap.Resources[arn]; x != nil {
		if x.Type != "" {
			rec.Kind = x.Type
		}
		for _, k := range sortedKeys(x.Tags) {
			switch lk := strings.ToLower(k); {
			case lk == "environment" || lk == "env":
				v := x.Tags[k]
				rec.Environment = &v
			case slices.Contains(classificationKeys, lk):
				rec.Tags = append(rec.Tags, strings.ToLower(x.Tags[k]))
			}
		}
	}
	return rec
}

// ---------------------------------------------------------------- trust

type trustCandidate struct {
	caller    string
	action    string
	mechanism model.TrustMechanism
}

// trustStatements are the Allow statements of a role's trust policy.
func trustStatements(snap *model.Snapshot, role string) []model.Statement {
	var out []model.Statement
	for _, rp := range snap.ResourcePolicies[role] {
		if rp.Kind != model.PolicyTrust {
			continue
		}
		if d := snap.Policies[rp.PolicyID]; d != nil {
			for _, st := range d.Statements {
				if st.Effect == model.EffectAllow {
					out = append(out, st)
				}
			}
		}
	}
	return out
}

func stmtMentions(st *model.Statement, action string) bool {
	if st.Actions == nil {
		return true // NotAction: evaluated for every mechanism, the engine decides
	}
	for _, p := range st.Actions.Patterns {
		l := strings.ToLower(p)
		if l == "*" || l == "sts:*" || l == strings.ToLower(action) {
			return true
		}
	}
	return false
}

// candidates are the callers a role's trust policy could admit (§11.4): the
// principals it names, every principal of an account it names, and, for "*",
// every principal of the snapshot.
func candidates(snap *model.Snapshot, role string, entities []string) []trustCandidate {
	seen := map[trustCandidate]bool{}
	var out []trustCandidate
	add := func(c trustCandidate) {
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	const assume = "sts:AssumeRole"
	for _, st := range trustStatements(snap, role) {
		st := st
		if st.Principals == nil {
			continue
		}
		for _, e := range st.Principals.Entries {
			switch e.Kind {
			case model.PrincipalWildcard:
				for _, c := range entities {
					add(trustCandidate{c, assume, model.AssumeRole})
				}
			case model.PrincipalAccount:
				for _, c := range entities {
					if snap.Principals[c].AccountID == e.AccountID {
						add(trustCandidate{c, assume, model.AssumeRole})
					}
				}
			case model.PrincipalIAMUser, model.PrincipalIAMRole:
				if snap.Principals[e.Value] != nil && stmtMentions(&st, assume) {
					add(trustCandidate{e.Value, assume, model.AssumeRole})
				}
			case model.PrincipalService:
				if stmtMentions(&st, assume) {
					add(trustCandidate{e.Value, assume, model.ServiceTrust})
				}
			case model.PrincipalFederated:
				if !strings.HasPrefix(e.Value, "arn:") {
					continue
				}
				if stmtMentions(&st, "sts:AssumeRoleWithWebIdentity") && strings.Contains(e.Value, ":oidc-provider/") {
					add(trustCandidate{e.Value, "sts:AssumeRoleWithWebIdentity", model.AssumeRoleWithWebIdentity})
				}
				if stmtMentions(&st, "sts:AssumeRoleWithSAML") && strings.Contains(e.Value, ":saml-provider/") {
					add(trustCandidate{e.Value, "sts:AssumeRoleWithSAML", model.AssumeRoleWithSAML})
				}
			}
		}
	}
	slices.SortFunc(out, func(a, b trustCandidate) int {
		return strings.Compare(a.caller+"|"+a.action, b.caller+"|"+b.action)
	})
	return out
}

// trustResidual is the JSON of a trust edge's residual column: the condition
// in words, and the risks the trust shows (design §11.4), which the NHI
// inventory reads.
type trustResidual struct {
	Text  string   `json:"text"`
	Flags []string `json:"flags"`
}

// The NHI flags a trust can raise.
const (
	FlagWildcardOIDCTrust = "wildcard_oidc_trust"
	FlagMissingExternalID = "missing_external_id"
	FlagPublicTrust       = "public_trust"
)

func (m *Materialized) addTrust(ctx context.Context, snap *model.Snapshot, q *query.Querier, cfg *EvalConfig,
	explain func(*authz.Decision) (string, error)) error {
	var roles, entities []string
	for arn, p := range snap.Principals {
		switch p.Kind {
		case model.IAMRole:
			roles = append(roles, arn)
			entities = append(entities, arn)
		case model.IAMUser:
			entities = append(entities, arn)
		}
	}
	sort.Strings(roles)
	sort.Strings(entities)
	budget := cfg.trustEvals()
	for _, role := range roles {
		flags := map[string]bool{}
		for _, c := range candidates(snap, role, entities) {
			if budget--; budget < 0 {
				m.Notes = append(m.Notes, fmt.Sprintf("more than %d trust evaluations; the remaining roles have no can_assume edges", cfg.trustEvals()))
				return nil
			}
			d, err := q.Can(ctx, c.caller, c.action, role)
			if err != nil {
				if errors.Is(err, eval.ErrUnknownPrincipal) || errors.Is(err, eval.ErrInvalidRequest) {
					continue // a caller the engine cannot place (a provider it has no entity for)
				}
				return fmt.Errorf("awsorg: trust of %s by %s: %w", role, c.caller, err)
			}
			if d.Outcome != authz.Allow && d.Outcome != authz.Conditional {
				continue
			}
			id, err := explain(d)
			if err != nil {
				return err
			}
			tr := trustResidual{Text: authz.Render(d.Residual, authz.RenderOptions{}), Flags: []string{}}
			if c.mechanism == model.AssumeRoleWithWebIdentity && wildcardSubject(d.Residual) {
				tr.Flags = append(tr.Flags, FlagWildcardOIDCTrust)
				flags[FlagWildcardOIDCTrust] = true
			}
			rb, err := json.Marshal(tr)
			if err != nil {
				return err
			}
			m.Trust = append(m.Trust, &store.AWSTrustEdge{FromARN: c.caller, ToRoleARN: role, Mechanism: c.mechanism.String(),
				Outcome: d.Outcome.String(), Residual: rb, ExplanationID: id})
			if snap.Principals[c.caller] != nil && c.mechanism == model.AssumeRole {
				m.Result.Edges = append(m.Result.Edges, connectors.EdgeRecord{Src: acctRef(c.caller), Dst: acctRef(role), Relation: "can_assume",
					Evaluation: &connectors.EdgeEvaluation{ExplanationID: id, Outcome: d.Outcome.String(), Fidelity: d.Fidelity.String()}})
			}
		}
		if err := m.statementFlags(snap, role); err != nil {
			return err
		}
	}
	return nil
}

// statementFlags records the risks a trust policy shows in its own text: a
// cross-account trust with no external id, and a trust of "*" that nothing
// narrows. The principals involved are not in the snapshot (an account that is
// not ours, or anyone), so no engine question names them; each is a trust fact
// from the policy, with an empty explanation id.
func (m *Materialized) statementFlags(snap *model.Snapshot, role string) error {
	roleAccount := arnAccountID(role)
	for _, st := range trustStatements(snap, role) {
		if st.Principals == nil {
			continue
		}
		pinned := hasKey(st.Condition, pinningKeys...)
		for _, e := range st.Principals.Entries {
			var flag, from string
			switch {
			case e.Kind == model.PrincipalWildcard && !pinned:
				flag, from = FlagPublicTrust, "*"
			case (e.Kind == model.PrincipalAccount || e.Kind == model.PrincipalIAMUser || e.Kind == model.PrincipalIAMRole) &&
				e.AccountID != "" && e.AccountID != roleAccount && !inOrganization(snap, e.AccountID) && !hasKey(st.Condition, "sts:externalid"):
				flag, from = FlagMissingExternalID, e.Value
			default:
				continue
			}
			text := "trust policy " + stmtLabel(&st)
			rb, err := json.Marshal(trustResidual{Text: text, Flags: []string{flag}})
			if err != nil {
				return err
			}
			outcome := authz.Allow.String()
			if len(st.Condition) > 0 {
				outcome = authz.Conditional.String()
			}
			m.Trust = append(m.Trust, &store.AWSTrustEdge{FromARN: trustOutsidePrefix + from, ToRoleARN: role,
				Mechanism: model.AssumeRole.String(), Outcome: outcome, Residual: rb})
		}
	}
	return nil
}

func stmtLabel(st *model.Statement) string {
	if st.Sid != "" {
		return "statement " + st.Sid
	}
	return fmt.Sprintf("statement %d", st.Index)
}

// pinningKeys are the condition keys that narrow a trust of "*" to something.
var pinningKeys = []string{"aws:principalorgid", "aws:principalaccount", "aws:principalarn", "aws:sourceaccount",
	"aws:sourcearn", "aws:sourceowner", "aws:sourceorgid", "sts:externalid", "aws:principalorgpaths"}

func hasKey(atoms []authz.Atom, keys ...string) bool {
	for _, a := range atoms {
		if slices.Contains(keys, strings.ToLower(a.Key)) {
			return true
		}
	}
	return false
}

func inOrganization(snap *model.Snapshot, account string) bool {
	if snap.Org == nil {
		return false
	}
	n := snap.Org.Nodes[account]
	return n != nil && n.Kind == model.OrgAccount
}

// wildcardSubject: an OIDC trust is wildcarded when nothing in its residual
// pins the token's subject (":sub") to a fixed value: an unconditional allow, a
// condition on other keys only, or a StringLike on ":sub" with a wildcard.
func wildcardSubject(r authz.Residual) bool {
	atoms := atomsOf(r)
	sub := false
	for _, a := range atoms {
		if !strings.HasSuffix(strings.ToLower(a.Key), ":sub") {
			continue
		}
		sub = true
		for _, v := range a.Values {
			if strings.ContainsAny(v, "*?") {
				return true
			}
		}
	}
	return !sub
}

func atomsOf(r authz.Residual) []authz.Atom {
	switch t := r.(type) {
	case authz.Atom:
		return []authz.Atom{t}
	case *authz.Atom:
		return []authz.Atom{*t}
	case authz.And:
		return atomsOfAll(t.Terms)
	case authz.Or:
		return atomsOfAll(t.Terms)
	case authz.Not:
		return atomsOf(t.Term)
	}
	return nil
}

func atomsOfAll(ts []authz.Residual) []authz.Atom {
	var out []authz.Atom
	for _, t := range ts {
		out = append(out, atomsOf(t)...)
	}
	return out
}

// ---------------------------------------------------------------- persisting

// Persist stores the trust edges and explanations of an evaluation of snapshot
// id (idempotent: a trust edge row is replaced by the same facts only once per
// snapshot, since the rows are keyed by the snapshot's content).
func (m *Materialized) Persist(tx *store.TenantTx, snapshotID string) error {
	existing, err := tx.AWSTrustEdges(snapshotID)
	if err != nil {
		return err
	}
	if len(existing) > 0 {
		return nil // this snapshot was evaluated before: the same snapshot, catalog and engine give the same rows
	}
	for _, x := range m.Explanations {
		if err := tx.PutAWSExplanation(x); err != nil {
			return err
		}
	}
	for _, e := range m.Trust {
		e.SnapshotID = snapshotID
		if err := tx.AddAWSTrustEdge(e); err != nil {
			return err
		}
	}
	return nil
}

// Materialize evaluates a stored snapshot and brings the MVP's graph up to
// date with it: the records of Materialize are ingested (edges the evaluator
// no longer confirms are removed), the trust edges and explanations are
// stored, and the run is audited, in one transaction. The evaluation itself
// holds no transaction.
func (s *Service) Materialize(ctx context.Context, db *store.DB, tenant tenancy.ID, snapshotID, actor string) (*MaterializeStats, error) {
	if s.Eval == nil {
		return nil, errors.New("awsorg: no evaluator is configured")
	}
	var col *Collection
	if err := db.ReadTenant(ctx, tenant, func(c *store.TenantTx) (err error) {
		col, err = Load(c, snapshotID)
		return err
	}); err != nil {
		return nil, err
	}
	cfg := s.Eval
	ix, err := index.Build(col.Snapshot, cfg.Index(col.Snapshot))
	if err != nil {
		return nil, err
	}
	workers := cfg.Workers
	if workers <= 0 {
		workers = 4
	}
	hour := s.now().UTC().Truncate(time.Hour)
	q, err := query.New(ix, nil, query.Options{Mode: eval.Symbolic, Profile: eval.DefaultProfile(hour), Workers: workers})
	if err != nil {
		return nil, err
	}
	m, err := Materialize(ctx, col.Snapshot, col.Findings, q, cfg)
	if err != nil {
		return nil, err
	}
	stats := &MaterializeStats{Cells: m.Cells, Trust: len(m.Trust), Notes: m.Notes}
	err = db.InTenant(ctx, tenant, func(c *store.TenantTx) error {
		now := s.now()
		if err := m.Persist(c, snapshotID); err != nil {
			return err
		}
		if err := keepIdentityLinks(c, m.Result); err != nil {
			return err
		}
		st, err := ingest.Discovery(c, now, []*connectors.DiscoveryResult{m.Result}, false)
		if err != nil {
			return err
		}
		stats.Ingested = st
		if stats.Pruned, err = pruneEvaluatorEdges(c, m.Result); err != nil {
			return err
		}
		return c.Audit(now, actor, "aws.snapshot.materialized", ojson.Object{{Key: "snapshot_id", Value: snapshotID},
			{Key: "permissions", Value: m.Cells}, {Key: "trust_edges", Value: len(m.Trust)}, {Key: "pruned_edges", Value: stats.Pruned},
			{Key: "notes", Value: len(m.Notes)}})
	})
	if err != nil {
		return nil, err
	}
	return stats, nil
}

// keepIdentityLinks gives each account the identity it already has. The
// evaluator knows nothing of people, and an account upsert takes the identity
// from the record: without this, evaluating again would unlink an account that
// a mapping (Identity Center, SAML, correlation) had linked to a person.
func keepIdentityLinks(c *store.TenantTx, r *connectors.DiscoveryResult) error {
	idents, err := c.Identities()
	if err != nil {
		return err
	}
	xid := map[int64]string{}
	for _, i := range idents {
		xid[i.ID] = i.ExternalID
	}
	accts, err := c.Accounts()
	if err != nil {
		return err
	}
	linked := map[string]string{}
	for _, a := range accts {
		if a.System == systemAWS && a.IdentityID != nil {
			linked[a.ExternalID] = xid[*a.IdentityID]
		}
	}
	for i := range r.Accounts {
		if x := linked[r.Accounts[i].ExternalID]; x != "" && r.Accounts[i].Identity == nil {
			r.Accounts[i].Identity = &connectors.IdentityRef{ExternalID: x}
		}
	}
	return nil
}

// MaterializeStats says what Service.Materialize did.
type MaterializeStats struct {
	Cells    int
	Trust    int
	Pruned   int
	Ingested ingest.DiscoveryStats
	Notes    []string
}

// pruneEvaluatorEdges removes the evaluator's edges that this evaluation did
// not produce: a permission the engine no longer confirms is not kept.
func pruneEvaluatorEdges(c *store.TenantTx, r *connectors.DiscoveryResult) (int, error) {
	keep := map[[2]string]bool{}
	nodes, err := nodeKeys(c)
	if err != nil {
		return 0, err
	}
	for _, e := range r.Edges {
		if e.Evaluation != nil {
			keep[[2]string{nodes[e.Src], nodes[e.Dst]}] = true
		}
	}
	edges, err := c.Edges()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range edges {
		if e.Source == store.EdgeSourceEvaluator && !keep[[2]string{e.Src, e.Dst}] {
			if err := c.DeleteEdge(e.ID); err != nil {
				return n, err
			}
			n++
		}
	}
	return n, nil
}

// nodeKeys maps the AWS records of a result to graph node keys ("account:7").
func nodeKeys(c *store.TenantTx) (map[connectors.Ref]string, error) {
	out := map[connectors.Ref]string{}
	accts, err := c.Accounts()
	if err != nil {
		return nil, err
	}
	for _, a := range accts {
		if a.System == systemAWS {
			out[acctRef(a.ExternalID)] = fmt.Sprintf("account:%d", a.ID)
		}
	}
	groups, err := c.Groups()
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		if g.System == systemAWS {
			out[groupRef(g.ExternalID)] = fmt.Sprintf("group:%d", g.ID)
		}
	}
	perms, err := c.Permissions()
	if err != nil {
		return nil, err
	}
	for _, p := range perms {
		if p.System == systemAWS {
			out[permRef(p.ExternalID)] = fmt.Sprintf("perm:%d", p.ID)
		}
	}
	return out, nil
}
