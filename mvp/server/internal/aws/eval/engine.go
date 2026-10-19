package eval

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/authz"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
)

// trustActions are the actions whose resource is the target role and whose
// resource policy is the role's trust policy (§7.4.1).
var trustActions = map[string]bool{
	"sts:assumerole": true, "sts:assumerolewithwebidentity": true, "sts:assumerolewithsaml": true,
	"sts:tagsession": true, "sts:setsourceidentity": true,
}

// evaluator holds the state of one Evaluate call. It never writes the snapshot.
type evaluator struct {
	rctx context.Context
	snap *model.Snapshot
	cat  Catalog
	req  *EvaluationRequest
	opts Options

	action string // canonical, or lower-cased after a catalog miss
	prefix string // lower-cased service prefix
	p      *model.Principal
	class  principalClass
	res    resolvedResource
	ctx    *Context

	id, pb, sp, rbp, vpce []*docEntry
	hasBoundary           bool
	scp, rcp, shadowRCP   []*level // nil: not applicable
	scpNA, rcpNA          string
	denies, shadowDenies  []*stmtEval
	allStmts              []*stmtEval

	rbpAllowed       bool // some resource-policy Allow applies to the request
	isTrust          bool
	requiresExplicit bool
	rbpUnverified    bool
	cross            bool
	crossAssumed     bool
	vpceUnknown      bool
	rootDefault      bool

	spec special

	reasons map[string]*authz.FidelityReason
}

// special holds the SPECIAL terms of §7.2 step 4 (KMS grants, S3 ACLs) and the
// S3 guardrail inputs for one request. They depend on the request, not on the
// reading of an ambiguity, so they are computed once in prepare.
type special struct {
	// KMS (§7.6.1): grants to the requester, to its parent, and to its account
	// root (a delegation).
	kmsSelf, kmsParent, kmsRoot authz.Tri
	kmsSteps                    []authz.ExplanationStep

	// S3 (§7.6.2).
	isS3       bool
	eff        model.BPA // most restrictive setting across org, account and bucket
	aclsOn     bool      // Object Ownership is not BucketOwnerEnforced
	aclPublic  authz.Tri // a public-group ACL grant covers the request, after IgnorePublicAcls
	aclAccount authz.Tri // an ACL grant to the requester's account covers the request
	aclIgnored bool      // a public ACL grant was dropped by IgnorePublicAcls
	aclSteps   []authz.ExplanationStep
	// objCtx is the object-context requirement: true unless the object owner is
	// another account. objCtxAlt is the reading that assumes it is, used when
	// the owner is unknown (objFlag).
	objCtx, objCtxAlt authz.Tri
	objFlag           bool
	bpa               authz.Tri // the BPA guardrail
	bpaWhy            string
}

// Evaluate answers one request against an immutable snapshot (§7.2). It is
// pure: no I/O, no clock, no writes to snap. rctx only carries a deadline or
// cancellation; when it ends, Evaluate returns its error.
func Evaluate(rctx context.Context, snap *model.Snapshot, cat Catalog, req *EvaluationRequest, opts Options) (*authz.Decision, error) {
	if snap == nil {
		return nil, ErrNoSnapshot
	}
	if cat == nil {
		return nil, ErrNoCatalog
	}
	if req == nil || req.Action == "" {
		return nil, fmt.Errorf("%w: an action is required", ErrInvalidRequest)
	}
	if rctx == nil {
		rctx = context.Background()
	}
	e := &evaluator{rctx: rctx, snap: snap, cat: cat, req: req, opts: opts, reasons: map[string]*authz.FidelityReason{}}
	if err := e.prepare(); err != nil {
		return nil, err
	}
	base := e.combine(&altSet{})
	if !opts.Fast {
		if err := e.assess(base); err != nil {
			return nil, err
		}
	}
	return e.finish(base), nil
}

func (e *evaluator) addReason(code, detail string, sensitive bool) {
	k := code + "|" + detail
	if r, ok := e.reasons[k]; ok {
		r.OutcomeSensitive = r.OutcomeSensitive || sensitive
		return
	}
	e.reasons[k] = &authz.FidelityReason{Code: authz.ReasonCode(code), Detail: detail, OutcomeSensitive: sensitive}
}

// prepare is §7.2 steps 0 and 1: normalize, build the context, collect the
// applicable policy sets and evaluate every statement.
func (e *evaluator) prepare() error {
	if a, ok := e.cat.CanonicalAction(e.req.Action); ok {
		e.action = a
	} else {
		e.addReason(string(authz.ReasonCatalogMiss), "action "+clip(e.req.Action)+" is not in the catalog", true)
		e.action = asciiLower(e.req.Action)
	}
	e.prefix, _, _ = strings.Cut(asciiLower(e.action), ":")

	p, class, err := resolvePrincipal(e.snap, e.req.PrincipalARN)
	if err != nil {
		return err
	}
	e.p, e.class = effectivePrincipal(e.snap, p, e.req.Session), class
	e.res = resolveResource(e.snap, e.req.ResourceARN)

	e.cross = e.class == classIAM && !e.res.none && e.res.accountKnown && e.p.AccountID != e.res.account
	e.crossAssumed = e.class == classIAM && !e.res.none && !e.res.accountKnown
	e.rootDefault = e.p.Kind == model.Root && (e.res.none || e.res.account == e.p.AccountID)

	e.buildContext()
	if err := e.rctx.Err(); err != nil {
		return err
	}
	if err := e.gather(); err != nil {
		return err
	}
	e.kmsTerms()
	e.s3Terms()
	return nil
}

func (e *evaluator) buildContext() {
	in := DeriveInput{
		Mode:                e.req.Mode,
		Principal:           e.p,
		LongTermCredentials: e.p.Kind == model.IAMUser || e.p.Kind == model.Root,
		DirectCall:          !e.req.ViaAWSService,
		Profile:             e.req.Profile,
		Supplied:            map[string]ContextValue{},
	}
	if e.p.Kind == model.Service {
		in.ServiceName = e.p.ARN
	}
	if e.snap.Org != nil && e.p.AccountID != "" {
		in.PrincipalOrgID, in.PrincipalOrgPaths = orgFacts(e.snap.Org, e.p.AccountID)
	}
	if !e.res.none {
		ri := &ResourceInfo{Account: e.res.account, Tags: e.res.tags, TagsSupported: e.cat.ResourceTagsSupported(e.action)}
		if e.snap.Org != nil && e.res.account != "" {
			ri.OrgID, ri.OrgPaths = orgFacts(e.snap.Org, e.res.account)
		}
		in.Resource = ri
	}
	for k, v := range e.req.Context {
		in.Supplied[k] = v
	}
	if e.req.ViaVPCE != "" {
		in.Supplied["aws:sourcevpce"] = PresentValues(e.req.ViaVPCE)
	}
	e.ctx = DeriveContext(in)
	e.ctx.Multivalued = e.cat.MultivaluedKey
}

// docFor wraps a snapshot document. A policy the snapshot references but does
// not hold is treated as unparseable: it is never skipped silently (§3.3).
func (e *evaluator) docFor(id string, path []string) *docEntry {
	d := e.snap.Policies[id]
	if d == nil {
		d = &model.PolicyDoc{ID: id, Unparseable: "policy is referenced but not in the snapshot"}
	}
	return &docEntry{doc: d, path: path}
}

func (e *evaluator) attachmentPath(id string, targets ...string) []string {
	for _, a := range e.snap.Attachments {
		if a.PolicyID != id {
			continue
		}
		for _, t := range targets {
			if t != "" && a.TargetARN == t {
				path := append([]string(nil), a.Via...)
				src := ""
				if d := e.snap.Policies[id]; d != nil {
					src = d.SourceARN
				}
				return append(path, a.AttachmentType.String()+":"+src)
			}
		}
	}
	return nil
}

func (e *evaluator) addDocs(ids []string, targets ...string) ([]*docEntry, error) {
	var out []*docEntry
	for _, id := range sortedPolicyIDs(e.snap, ids) {
		// The attachment path is provenance for the explanation. It costs a scan
		// of every attachment, so the bulk (Fast) mode of internal/aws/query,
		// which keeps no trace, leaves it out.
		var path []string
		if !e.opts.Fast {
			path = e.attachmentPath(id, targets...)
		}
		d := e.docFor(id, path)
		if err := e.evalDoc(d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}

// gather is §7.2 step 1: the applicable policy sets, each statement evaluated.
func (e *evaluator) gather() error {
	var err error
	iamRequester := e.class == classIAM && (e.p.Kind == model.IAMUser || e.p.Kind == model.RoleSession || e.p.Kind == model.FederatedUserSession)
	if iamRequester {
		targets := append([]string{e.p.ARN, e.p.EntityARN}, e.p.GroupARNs...)
		if e.id, err = e.addDocs(e.p.IdentityPolicyIDs, targets...); err != nil {
			return err
		}
		if e.p.BoundaryPolicyID != "" {
			e.hasBoundary = true
			if e.pb, err = e.addDocs([]string{e.p.BoundaryPolicyID}, e.p.ARN, e.p.EntityARN); err != nil {
				return err
			}
		}
		if e.sp, err = e.addDocs(e.p.SessionPolicyIDs, e.p.ARN); err != nil {
			return err
		}
	}
	if err = e.gatherOrg(); err != nil {
		return err
	}
	if err = e.gatherResourcePolicies(); err != nil {
		return err
	}
	e.collectStatements()
	return nil
}

func (e *evaluator) gatherOrg() error {
	org := e.snap.Org
	if org == nil {
		return nil
	}
	// SCPs (§7.5).
	if na := scpGate(org, e.class, e.p); na != "" {
		e.scpNA = na
	} else {
		ls, err := e.orgLevels(e.p.AccountID, false, false)
		if err != nil {
			return err
		}
		e.scp = ls
	}
	// RCPs (§7.5).
	shadow := false
	switch {
	case !org.RCPEnabled:
		e.rcpNA = "RCPs are not enabled in the organization"
	case e.res.none:
		e.rcpNA = "the action has no resource, so RCPs do not apply"
	case org.PathTo(e.res.account) == nil:
		e.rcpNA = "the resource's account is outside the organization, so RCPs do not apply"
	case e.res.account == org.ManagementAccountID:
		e.rcpNA = "RCPs do not apply to resources in the management account"
	case e.p.IsServiceLinked:
		e.rcpNA = "RCPs do not apply to service-linked roles"
	case e.action == "kms:retiregrant":
		e.rcpNA = "RCPs do not apply to kms:RetireGrant"
	case !e.cat.RCPSupportedService(e.prefix):
		e.rcpNA = "RCPs do not cover " + e.prefix
		shadow = true // A14: evaluated for the alternative reading only
	default:
		ls, err := e.orgLevels(e.res.account, true, false)
		if err != nil {
			return err
		}
		e.rcp = ls
	}
	if shadow {
		ls, err := e.orgLevels(e.res.account, true, true)
		if err != nil {
			return err
		}
		e.shadowRCP = ls
	}
	return nil
}

// orgLevels builds the chain root → OUs → account for an account.
func (e *evaluator) orgLevels(account string, rcp, shadow bool) ([]*level, error) {
	var out []*level
	for _, n := range e.snap.Org.PathTo(account) {
		l := &level{node: n}
		ids := n.SCPIDs
		if rcp {
			ids = n.RCPIDs
		}
		for _, id := range sortedPolicyIDs(e.snap, ids) {
			d := e.docFor(id, []string{n.Kind.String() + "/" + n.ID})
			d.level = l
			if shadow {
				d.notApplicable = e.rcpNA
			}
			if err := e.evalDoc(d); err != nil {
				return nil, err
			}
			l.docs = append(l.docs, d)
		}
		out = append(out, l)
	}
	return out, nil
}

func (e *evaluator) gatherResourcePolicies() error {
	if e.res.none {
		return nil
	}
	trust := trustActions[asciiLower(e.action)]
	var ids []string
	explicit := false
	for _, key := range e.res.policyKeys {
		for _, rp := range e.snap.ResourcePolicies[key] {
			switch {
			case rp.Kind == model.PolicyVPCE:
				continue
			case rp.Kind == model.PolicyTrust && !trust:
				continue // a trust policy answers only the sts:AssumeRole family
			}
			ids = append(ids, rp.PolicyID)
			if rp.Kind == model.PolicyTrust {
				e.isTrust = true
			}
			explicit = explicit || rp.RequiresExplicitAllow || rp.Kind == model.PolicyTrust || rp.Kind == model.PolicyKMSKey
		}
	}
	var err error
	if e.rbp, err = e.addDocs(ids, e.res.arn+"#policy"); err != nil {
		return err
	}
	if len(e.rbp) > 0 && !explicit && !e.isTrust {
		x, verified := e.cat.RequiresExplicitRBP(e.prefix)
		explicit = x
		e.rbpUnverified = !x && !verified
	}
	e.requiresExplicit = explicit

	if v := e.ctx.Lookup("aws:sourcevpce"); v.State == Present && len(v.Values) > 0 {
		if id, ok := e.snap.VPCEPolicies[v.Values[0]]; ok {
			if e.vpce, err = e.addDocs([]string{id}); err != nil {
				return err
			}
		} else {
			e.vpceUnknown = true
		}
	}
	return nil
}

// collectStatements lists every statement in the order of §7.10: SCP, RCP,
// VPCE, resource, boundary, session, identity; then document order.
func (e *evaluator) collectStatements() {
	add := func(ds []*docEntry, shadow bool) {
		for _, d := range ds {
			for _, se := range d.stmts {
				if shadow {
					e.shadowDenies = appendIf(e.shadowDenies, se, se.effect == model.EffectDeny)
					continue
				}
				e.allStmts = append(e.allStmts, se)
				e.denies = appendIf(e.denies, se, se.effect == model.EffectDeny)
			}
		}
	}
	levelDocs := func(ls []*level) []*docEntry {
		var out []*docEntry
		for _, l := range ls {
			out = append(out, l.docs...)
		}
		return out
	}
	add(levelDocs(e.scp), false)
	add(levelDocs(e.rcp), false)
	add(levelDocs(e.shadowRCP), true)
	add(e.vpce, false)
	add(e.rbp, false)
	add(e.pb, false)
	add(e.sp, false)
	add(e.id, false)
	for _, d := range e.rbp {
		for _, se := range d.stmts {
			if se.effect == model.EffectAllow && !se.match.IsFalse() {
				e.rbpAllowed = true
			}
		}
	}
}

func appendIf(s []*stmtEval, se *stmtEval, ok bool) []*stmtEval {
	if ok {
		return append(s, se)
	}
	return s
}

func sortStrings(s []string) { sort.Strings(s) }
