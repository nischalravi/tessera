package snapshot

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/policy"
)

// PolicyChangeOp is one kind of hypothetical change (design §11.3). The set is
// closed: a request that names another op is refused when it is decoded.
type PolicyChangeOp string

// The ops. For the ops that take no policy ARN as such, PolicyARN carries
// their one extra argument, as noted:
//
//	put_inline, delete_inline  the inline policy's name
//	move_account               the id of the new parent (a root or an OU)
//	retire_grant               the grant id
const (
	OpPutPolicyVersion    PolicyChangeOp = "put_policy_version"
	OpAttach              PolicyChangeOp = "attach"
	OpDetach              PolicyChangeOp = "detach"
	OpPutInline           PolicyChangeOp = "put_inline"
	OpDeleteInline        PolicyChangeOp = "delete_inline"
	OpPutBoundary         PolicyChangeOp = "put_boundary"
	OpDeleteBoundary      PolicyChangeOp = "delete_boundary"
	OpPutResourcePolicy   PolicyChangeOp = "put_resource_policy"
	OpPutTrustPolicy      PolicyChangeOp = "put_trust_policy"
	OpAttachSCP           PolicyChangeOp = "attach_scp"
	OpDetachSCP           PolicyChangeOp = "detach_scp"
	OpPutSCP              PolicyChangeOp = "put_scp"
	OpAttachRCP           PolicyChangeOp = "attach_rcp"
	OpDetachRCP           PolicyChangeOp = "detach_rcp"
	OpPutRCP              PolicyChangeOp = "put_rcp"
	OpMoveAccount         PolicyChangeOp = "move_account"
	OpCreateGrant         PolicyChangeOp = "create_grant"
	OpRetireGrant         PolicyChangeOp = "retire_grant"
	OpPutBPA              PolicyChangeOp = "put_bpa"
	OpPutOwnershipControl PolicyChangeOp = "put_ownership_controls"
)

var policyChangeOps = []PolicyChangeOp{OpPutPolicyVersion, OpAttach, OpDetach, OpPutInline, OpDeleteInline, OpPutBoundary,
	OpDeleteBoundary, OpPutResourcePolicy, OpPutTrustPolicy, OpAttachSCP, OpDetachSCP, OpPutSCP, OpAttachRCP, OpDetachRCP,
	OpPutRCP, OpMoveAccount, OpCreateGrant, OpRetireGrant, OpPutBPA, OpPutOwnershipControl}

// PolicyChangeOps lists the valid ops.
func PolicyChangeOps() []PolicyChangeOp { return slices.Clone(policyChangeOps) }

// Valid reports whether o is one of the ops.
func (o PolicyChangeOp) Valid() bool { return slices.Contains(policyChangeOps, o) }

// UnmarshalText validates the op against the closed set, so a JSON request is
// refused at decode time.
func (o *PolicyChangeOp) UnmarshalText(b []byte) error {
	v := PolicyChangeOp(b)
	if !v.Valid() {
		return fmt.Errorf("unknown policy change op %q", clip(string(b), 40))
	}
	*o = v
	return nil
}

// PolicyChange is one hypothetical change to the estate.
type PolicyChange struct {
	Op        PolicyChangeOp `json:"op"`
	TargetARN string         `json:"target_arn"`
	Document  *string        `json:"document"`   // raw JSON for puts; nil otherwise
	PolicyARN *string        `json:"policy_arn"` // nil if not applicable
}

// ApplyOptions are the values Apply needs and must not read from the world.
type ApplyOptions struct {
	// FetchedAt stamps the documents the changes add.
	FetchedAt time.Time
	// MultivaluedKey is policy.Options.MultivaluedKey (the catalog's).
	MultivaluedKey func(lowerKey string) bool
}

// ChangeError says which change of the list cannot be applied and why. It is a
// problem with the request (an unknown target, a missing document), not with
// the estate.
type ChangeError struct {
	Index int
	Op    PolicyChangeOp
	Msg   string
}

func (e *ChangeError) Error() string { return fmt.Sprintf("change %d (%s): %s", e.Index, e.Op, e.Msg) }

// simulatedVersion is the version id of a document a change puts.
const simulatedVersion = "simulated"

var inlineNameRE = regexp.MustCompile(`^[\w+=,.@-]{1,128}$`)

// Apply returns the snapshot that results from applying the changes, in order,
// to base (design §11.3 step 1). base is not modified: the result shares only
// immutable values with it (policy documents are copied by value, and a
// document that a change replaces is a new one, with its own id). A document
// that does not parse is stored as unparseable, never skipped, so the
// decisions it could affect are UNSUPPORTED (§3.3). Applying no changes
// returns a snapshot with the content of base.
//
// Group ARNs: the snapshot has no group entities; a group is the GroupARNs of
// its member users, so attach, detach and the inline ops on a group reach its
// members (and their sessions), and a group with no member changes nothing.
//
// PolicyIsPublic of a bucket is not recomputed (the collector does not set it;
// the engine derives it from the document when it evaluates).
func Apply(base *model.Snapshot, changes []PolicyChange, opts ApplyOptions) (*model.Snapshot, error) {
	if base == nil {
		return nil, errors.New("snapshot: Apply of a nil snapshot")
	}
	e := newEditor(base, opts)
	for i, ch := range changes {
		if err := e.apply(ch); err != nil {
			return nil, &ChangeError{Index: i, Op: ch.Op, Msg: err.Error()}
		}
	}
	e.prune()
	return e.b.Build()
}

type editor struct {
	b    *Builder
	opts ApplyOptions
	// latest is the document the changes put last for a (kind, source): a
	// later attach finds that one, not an older version still in the map.
	latest map[string]string
}

func newEditor(base *model.Snapshot, opts ApplyOptions) *editor {
	b := NewBuilder()
	b.takenAt = base.TakenAt
	b.org = cloneOrg(base.Org)
	for k, p := range base.Principals {
		c := *p
		c.IdentityPolicyIDs = slices.Clone(p.IdentityPolicyIDs)
		c.SessionPolicyIDs = slices.Clone(p.SessionPolicyIDs)
		c.GroupARNs = slices.Clone(p.GroupARNs)
		c.TransitiveTagKeys = slices.Clone(p.TransitiveTagKeys)
		b.principals[k] = &c
	}
	for k, d := range base.Policies {
		b.policies[k] = d // documents are immutable
	}
	b.attachments = slices.Clone(base.Attachments)
	for k, v := range base.ResourcePolicies {
		b.resPolicies[k] = slices.Clone(v)
	}
	for k, v := range base.KMSGrants {
		b.grants[k] = slices.Clone(v)
	}
	for k, v := range base.S3 {
		c := *v
		b.s3[k] = &c
	}
	for k, v := range base.Resources {
		b.resources[k] = v
	}
	for k, v := range base.VPCEPolicies {
		b.vpce[k] = v
	}
	for k, v := range base.CanonicalIDs {
		b.canonicalIDs[k] = v
	}
	return &editor{b: b, opts: opts, latest: map[string]string{}}
}

// ---------------------------------------------------------------- documents

func (e *editor) addDoc(kind model.PolicyKind, source, raw string) *model.PolicyDoc {
	d := e.b.AddPolicy(policy.Options{Kind: kind, SourceARN: source, VersionID: simulatedVersion, FetchedAt: e.opts.FetchedAt,
		MultivaluedKey: e.opts.MultivaluedKey}, []byte(raw))
	e.latest[kind.String()+"|"+source] = d.ID
	return d
}

// current is the document a policy source has now: the one the changes put
// last, else the one in the snapshot.
func (e *editor) current(kind model.PolicyKind, source string) *model.PolicyDoc {
	if d := e.b.policies[e.latest[kind.String()+"|"+source]]; d != nil {
		return d
	}
	if ds := e.docsBySource(kind, source); len(ds) > 0 {
		return ds[0]
	}
	return nil
}

// docsBySource lists the documents of a kind with a source ARN, sorted by id.
func (e *editor) docsBySource(kind model.PolicyKind, source string) []*model.PolicyDoc {
	var out []*model.PolicyDoc
	for _, d := range e.b.policies {
		if d.Kind == kind && d.SourceARN == source {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// docFor finds the document of a managed policy for a use. A managed policy
// is parsed once per use (identity, boundary), so a policy known only as an
// identity policy is parsed again, from its own bytes, as a boundary.
func (e *editor) docFor(kind model.PolicyKind, policyARN string) (*model.PolicyDoc, error) {
	if d := e.current(kind, policyARN); d != nil {
		return d, nil
	}
	for _, k := range []model.PolicyKind{model.PolicyIdentity, model.PolicyBoundary} {
		if d := e.current(k, policyARN); d != nil {
			return e.addDoc(kind, policyARN, string(d.RawJSON)), nil
		}
	}
	return nil, fmt.Errorf("policy %s is not in the snapshot; put it with put_policy_version first", clip(policyARN, 200))
}

func (e *editor) refs() map[string]bool {
	used := map[string]bool{"": true}
	for _, a := range e.b.attachments {
		used[a.PolicyID] = true
	}
	for _, rps := range e.b.resPolicies {
		for _, rp := range rps {
			used[rp.PolicyID] = true
		}
	}
	for _, id := range e.b.vpce {
		used[id] = true
	}
	for _, p := range e.b.principals {
		for _, id := range p.IdentityPolicyIDs {
			used[id] = true
		}
		for _, id := range p.SessionPolicyIDs {
			used[id] = true
		}
		used[p.BoundaryPolicyID] = true
	}
	if o := e.b.org; o != nil {
		for _, n := range o.Nodes {
			for _, id := range n.SCPIDs {
				used[id] = true
			}
			for _, id := range n.RCPIDs {
				used[id] = true
			}
		}
	}
	return used
}

// prune drops the documents nothing refers to any more (the connector does the
// same), so a replaced document leaves no atoms behind.
func (e *editor) prune() {
	used := e.refs()
	for id := range e.b.policies {
		if !used[id] {
			delete(e.b.policies, id)
		}
	}
}

// replaceDoc swaps a document id for another everywhere it is referenced.
func (e *editor) replaceDoc(oldID, newID string) {
	if oldID == newID {
		return
	}
	for _, p := range e.b.principals {
		for i, id := range p.IdentityPolicyIDs {
			if id == oldID {
				p.IdentityPolicyIDs[i] = newID
			}
		}
		for i, id := range p.SessionPolicyIDs {
			if id == oldID {
				p.SessionPolicyIDs[i] = newID
			}
		}
		if p.BoundaryPolicyID == oldID {
			p.BoundaryPolicyID = newID
		}
	}
	for i := range e.b.attachments {
		if e.b.attachments[i].PolicyID == oldID {
			e.b.attachments[i].PolicyID = newID
		}
	}
	for k, rps := range e.b.resPolicies {
		for i := range rps {
			if rps[i].PolicyID == oldID {
				rps[i].PolicyID = newID
			}
		}
		e.b.resPolicies[k] = rps
	}
	for k, id := range e.b.vpce {
		if id == oldID {
			e.b.vpce[k] = newID
		}
	}
	if o := e.b.org; o != nil {
		for _, n := range o.Nodes {
			for i, id := range n.SCPIDs {
				if id == oldID {
					n.SCPIDs[i] = newID
				}
			}
			for i, id := range n.RCPIDs {
				if id == oldID {
					n.RCPIDs[i] = newID
				}
			}
		}
	}
}

// ---------------------------------------------------------------- targets

// affected lists the principals a change to an entity reaches: the principal
// itself, the sessions of a role or user (EntityARN), and, when the target is
// a group, its member users and their sessions. The result is sorted.
func (e *editor) affected(target string) (principals []*model.Principal, viaGroup string, err error) {
	entities := map[string]bool{target: true}
	if _, ok := e.b.principals[target]; !ok && isGroupARN(target) {
		viaGroup = "group/" + groupName(target)
		entities = map[string]bool{}
		for _, p := range e.b.principals {
			if slices.Contains(p.GroupARNs, target) {
				entities[p.ARN] = true
			}
		}
	}
	for _, p := range e.b.principals {
		if entities[p.ARN] || entities[p.EntityARN] {
			principals = append(principals, p)
		}
	}
	sort.Slice(principals, func(i, j int) bool { return principals[i].ARN < principals[j].ARN })
	if len(principals) == 0 && viaGroup == "" {
		return nil, "", fmt.Errorf("no principal %s in the snapshot", clip(target, 200))
	}
	return principals, viaGroup, nil
}

func isGroupARN(arn string) bool {
	parts := strings.SplitN(arn, ":", 6)
	return len(parts) == 6 && parts[0] == "arn" && parts[2] == "iam" && strings.HasPrefix(parts[5], "group/")
}

func groupName(arn string) string {
	i := strings.LastIndexByte(arn, '/')
	return arn[i+1:]
}

func accountOf(arn string) string {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 5 {
		return ""
	}
	return parts[4]
}

var accountIDRE = regexp.MustCompile(`^[0-9]{12}$`)

func (e *editor) attach(p *model.Principal, docID string, typ model.AttachmentType, via string) {
	if !slices.Contains(p.IdentityPolicyIDs, docID) {
		p.IdentityPolicyIDs = append(p.IdentityPolicyIDs, docID)
	}
	var v []string
	if via != "" {
		v = []string{via}
	}
	a := model.PolicyAttachment{PolicyID: docID, TargetARN: p.ARN, Via: v, AttachmentType: typ}
	if !slices.ContainsFunc(e.b.attachments, func(x model.PolicyAttachment) bool {
		return x.PolicyID == docID && x.TargetARN == p.ARN && x.AttachmentType == typ && slices.Equal(x.Via, v)
	}) {
		e.b.attachments = append(e.b.attachments, a)
	}
}

// detach removes a document from a principal's identity policies and
// attachments (of the types given), and reports whether it was attached.
func (e *editor) detach(p *model.Principal, match func(*model.PolicyDoc) bool, types ...model.AttachmentType) bool {
	found := false
	keep := p.IdentityPolicyIDs[:0]
	for _, id := range p.IdentityPolicyIDs {
		if d := e.b.policies[id]; d != nil && match(d) {
			found = true
			continue
		}
		keep = append(keep, id)
	}
	p.IdentityPolicyIDs = keep
	e.b.attachments = slices.DeleteFunc(e.b.attachments, func(a model.PolicyAttachment) bool {
		d := e.b.policies[a.PolicyID]
		return a.TargetARN == p.ARN && slices.Contains(types, a.AttachmentType) && d != nil && match(d)
	})
	return found
}

// ---------------------------------------------------------------- the ops

func (e *editor) apply(ch PolicyChange) error {
	if !ch.Op.Valid() {
		return fmt.Errorf("unknown op %q", clip(string(ch.Op), 40))
	}
	if ch.TargetARN == "" || len(ch.TargetARN) > 2048 {
		return errors.New("target_arn is required (at most 2048 bytes)")
	}
	doc, pol := "", ""
	if ch.Document != nil {
		doc = *ch.Document
	}
	if ch.PolicyARN != nil {
		pol = *ch.PolicyARN
	}
	needDoc := map[PolicyChangeOp]bool{OpPutPolicyVersion: true, OpPutInline: true, OpPutResourcePolicy: true, OpPutTrustPolicy: true,
		OpPutSCP: true, OpPutRCP: true, OpCreateGrant: true, OpPutBPA: true, OpPutOwnershipControl: true}
	if needDoc[ch.Op] && doc == "" {
		return errors.New("document is required")
	}
	needPolicy := map[PolicyChangeOp]bool{OpAttach: true, OpDetach: true, OpPutInline: true, OpDeleteInline: true, OpAttachSCP: true,
		OpDetachSCP: true, OpAttachRCP: true, OpDetachRCP: true, OpMoveAccount: true, OpRetireGrant: true}
	if needPolicy[ch.Op] && pol == "" {
		return errors.New("policy_arn is required")
	}
	if len(pol) > 2048 {
		return errors.New("policy_arn is too long")
	}
	switch ch.Op {
	case OpPutPolicyVersion:
		return e.putPolicyVersion(ch.TargetARN, doc)
	case OpAttach, OpDetach:
		return e.attachDetach(ch.Op == OpAttach, ch.TargetARN, pol)
	case OpPutInline:
		return e.putInline(ch.TargetARN, pol, doc)
	case OpDeleteInline:
		return e.deleteInline(ch.TargetARN, pol)
	case OpPutBoundary:
		return e.putBoundary(ch.TargetARN, pol, doc)
	case OpDeleteBoundary:
		return e.deleteBoundary(ch.TargetARN)
	case OpPutResourcePolicy:
		return e.putResourcePolicy(ch.TargetARN, doc, false)
	case OpPutTrustPolicy:
		return e.putResourcePolicy(ch.TargetARN, doc, true)
	case OpAttachSCP, OpDetachSCP, OpAttachRCP, OpDetachRCP:
		kind, typ := model.PolicySCP, model.AttachSCP
		if ch.Op == OpAttachRCP || ch.Op == OpDetachRCP {
			kind, typ = model.PolicyRCP, model.AttachRCP
		}
		return e.attachOrg(kind, typ, ch.Op == OpAttachSCP || ch.Op == OpAttachRCP, ch.TargetARN, pol)
	case OpPutSCP:
		return e.putOrgPolicy(model.PolicySCP, ch.TargetARN, doc)
	case OpPutRCP:
		return e.putOrgPolicy(model.PolicyRCP, ch.TargetARN, doc)
	case OpMoveAccount:
		return e.moveAccount(ch.TargetARN, pol)
	case OpCreateGrant:
		return e.createGrant(ch.TargetARN, doc)
	case OpRetireGrant:
		return e.retireGrant(ch.TargetARN, pol)
	case OpPutBPA:
		return e.putBPA(ch.TargetARN, doc)
	case OpPutOwnershipControl:
		return e.putOwnership(ch.TargetARN, doc)
	}
	return fmt.Errorf("unhandled op %q", ch.Op)
}

// putPolicyVersion makes doc the default version of a managed policy: every
// use of it (identity or boundary) now has the new document. A policy no
// principal uses is added as an identity policy, so a later attach finds it.
func (e *editor) putPolicyVersion(policyARN, raw string) error {
	found := false
	for _, kind := range []model.PolicyKind{model.PolicyIdentity, model.PolicyBoundary} {
		for _, old := range e.docsBySource(kind, policyARN) {
			found = true
			nd := e.addDoc(kind, policyARN, raw)
			e.replaceDoc(old.ID, nd.ID)
		}
	}
	if !found {
		e.addDoc(model.PolicyIdentity, policyARN, raw)
	}
	return nil
}

func (e *editor) attachDetach(attach bool, target, policyARN string) error {
	ps, via, err := e.affected(target)
	if err != nil {
		return err
	}
	if attach {
		d, err := e.docFor(model.PolicyIdentity, policyARN)
		if err != nil {
			return err
		}
		for _, p := range ps {
			e.attach(p, d.ID, model.AttachManaged, via)
		}
		return nil
	}
	match := func(d *model.PolicyDoc) bool { return d.Kind == model.PolicyIdentity && d.SourceARN == policyARN }
	found := len(ps) == 0 // a group with no member
	for _, p := range ps {
		if e.detach(p, match, model.AttachManaged) {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("policy %s is not attached to %s", clip(policyARN, 200), clip(target, 200))
	}
	return nil
}

func inlineSource(target, name string) string { return target + "#inline/" + name }

func (e *editor) putInline(target, name, raw string) error {
	if !inlineNameRE.MatchString(name) {
		return errors.New("policy_arn must be the inline policy's name (1 to 128 characters of letters, digits and +=,.@_-)")
	}
	ps, via, err := e.affected(target)
	if err != nil {
		return err
	}
	src := inlineSource(target, name)
	d := e.addDoc(model.PolicyIdentity, src, raw)
	match := func(x *model.PolicyDoc) bool {
		return x.Kind == model.PolicyIdentity && x.SourceARN == src && x.ID != d.ID
	}
	for _, p := range ps {
		e.detach(p, match, model.AttachInline)
		e.attach(p, d.ID, model.AttachInline, via)
	}
	return nil
}

func (e *editor) deleteInline(target, name string) error {
	ps, _, err := e.affected(target)
	if err != nil {
		return err
	}
	src := inlineSource(target, name)
	match := func(d *model.PolicyDoc) bool { return d.Kind == model.PolicyIdentity && d.SourceARN == src }
	found := len(ps) == 0
	for _, p := range ps {
		if e.detach(p, match, model.AttachInline) {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("%s has no inline policy %q", clip(target, 200), clip(name, 128))
	}
	return nil
}

// entities lists the principals a boundary change reaches: the entity and its
// sessions. A group has no boundary.
func (e *editor) entities(target string) ([]*model.Principal, error) {
	if _, ok := e.b.principals[target]; !ok {
		return nil, fmt.Errorf("no user or role %s in the snapshot", clip(target, 200))
	}
	ps, _, err := e.affected(target)
	return ps, err
}

func (e *editor) putBoundary(target, policyARN, raw string) error {
	ps, err := e.entities(target)
	if err != nil {
		return err
	}
	var d *model.PolicyDoc
	switch {
	case raw != "" && policyARN != "":
		d = e.addDoc(model.PolicyBoundary, policyARN, raw)
	case raw != "":
		d = e.addDoc(model.PolicyBoundary, target+"#boundary", raw)
	case policyARN != "":
		if d, err = e.docFor(model.PolicyBoundary, policyARN); err != nil {
			return err
		}
	default:
		return errors.New("a boundary needs a document or a policy_arn")
	}
	for _, p := range ps {
		e.clearBoundary(p)
		p.BoundaryPolicyID = d.ID
		e.b.attachments = append(e.b.attachments, model.PolicyAttachment{PolicyID: d.ID, TargetARN: p.ARN, AttachmentType: model.AttachBoundary})
	}
	return nil
}

func (e *editor) clearBoundary(p *model.Principal) {
	p.BoundaryPolicyID = ""
	e.b.attachments = slices.DeleteFunc(e.b.attachments, func(a model.PolicyAttachment) bool {
		return a.TargetARN == p.ARN && a.AttachmentType == model.AttachBoundary
	})
}

func (e *editor) deleteBoundary(target string) error {
	ps, err := e.entities(target)
	if err != nil {
		return err
	}
	for _, p := range ps {
		e.clearBoundary(p)
	}
	return nil
}

// resourceKind picks the kind of a resource's policy: that of the policy it
// has, else by the kind of resource.
func (e *editor) resourceKind(arn string) model.PolicyKind {
	for _, rp := range e.b.resPolicies[arn] {
		if rp.Kind != model.PolicyTrust {
			return rp.Kind
		}
	}
	parts := strings.SplitN(arn, ":", 6)
	switch {
	case len(parts) == 6 && parts[2] == "kms" && strings.HasPrefix(parts[5], "key/"):
		return model.PolicyKMSKey
	case len(parts) == 6 && parts[2] == "s3" && strings.HasPrefix(parts[5], "accesspoint/"):
		return model.PolicyS3AccessPoint
	case len(parts) == 6 && parts[2] == "s3-outposts":
		return model.PolicyS3AccessPoint
	}
	return model.PolicyResource
}

// putResourcePolicy replaces a resource's policy, or a role's trust policy.
func (e *editor) putResourcePolicy(target, raw string, trust bool) error {
	kind := model.PolicyTrust
	if trust {
		if p := e.b.principals[target]; p == nil || p.Kind != model.IAMRole {
			return fmt.Errorf("no role %s in the snapshot", clip(target, 200))
		}
	} else {
		if e.b.resources[target] == nil {
			return fmt.Errorf("no resource %s in the snapshot", clip(target, 200))
		}
		kind = e.resourceKind(target)
	}
	src := target + "#policy"
	if trust {
		src = target + "#trust"
	}
	d := e.addDoc(kind, src, raw)
	rps := e.b.resPolicies[target][:0:0]
	for _, rp := range e.b.resPolicies[target] {
		if rp.Kind != kind {
			rps = append(rps, rp)
		}
	}
	e.b.resPolicies[target] = append(rps, model.ResourcePolicy{ResourceARN: target, Kind: kind, PolicyID: d.ID,
		RequiresExplicitAllow: trust || kind == model.PolicyKMSKey})
	typ := model.AttachResource
	if trust {
		typ = model.AttachTrust
	}
	e.b.attachments = slices.DeleteFunc(e.b.attachments, func(a model.PolicyAttachment) bool {
		x := e.b.policies[a.PolicyID]
		return a.TargetARN == target && a.AttachmentType == typ && x != nil && x.Kind == kind
	})
	e.b.attachments = append(e.b.attachments, model.PolicyAttachment{PolicyID: d.ID, TargetARN: target, AttachmentType: typ})
	return nil
}

// ---------------------------------------------------------------- organization

func (e *editor) org(kind model.PolicyKind) (*model.Organization, error) {
	o := e.b.org
	if o == nil {
		return nil, errors.New("the snapshot has no organization")
	}
	if kind == model.PolicySCP && !o.SCPEnabled {
		return nil, errors.New("service control policies are not enabled in the organization")
	}
	if kind == model.PolicyRCP && !o.RCPEnabled {
		return nil, errors.New("resource control policies are not enabled in the organization")
	}
	return o, nil
}

func nodeIDs(n *model.OrgNode, kind model.PolicyKind) *[]string {
	if kind == model.PolicyRCP {
		return &n.RCPIDs
	}
	return &n.SCPIDs
}

func (e *editor) attachOrg(kind model.PolicyKind, typ model.AttachmentType, attach bool, nodeID, policyARN string) error {
	o, err := e.org(kind)
	if err != nil {
		return err
	}
	n := o.Nodes[nodeID]
	if n == nil {
		return fmt.Errorf("no organization node %s in the snapshot", clip(nodeID, 100))
	}
	ids := nodeIDs(n, kind)
	if attach {
		d := e.current(kind, policyARN)
		if d == nil {
			return fmt.Errorf("policy %s is not in the snapshot; put it first", clip(policyARN, 200))
		}
		if !slices.Contains(*ids, d.ID) {
			*ids = append(*ids, d.ID)
			e.b.attachments = append(e.b.attachments, model.PolicyAttachment{PolicyID: d.ID, TargetARN: nodeID, AttachmentType: typ})
		}
		return nil
	}
	found := false
	*ids = slices.DeleteFunc(*ids, func(id string) bool {
		d := e.b.policies[id]
		if d != nil && d.SourceARN == policyARN {
			found = true
			return true
		}
		return false
	})
	if !found {
		return fmt.Errorf("policy %s is not attached to %s", clip(policyARN, 200), clip(nodeID, 100))
	}
	e.b.attachments = slices.DeleteFunc(e.b.attachments, func(a model.PolicyAttachment) bool {
		d := e.b.policies[a.PolicyID]
		return a.TargetARN == nodeID && a.AttachmentType == typ && d != nil && d.SourceARN == policyARN
	})
	return nil
}

// putOrgPolicy gives an SCP or RCP new content, wherever it is attached. A
// policy attached nowhere is added, for a later attach.
func (e *editor) putOrgPolicy(kind model.PolicyKind, policyARN, raw string) error {
	if _, err := e.org(kind); err != nil {
		return err
	}
	old := e.docsBySource(kind, policyARN)
	nd := e.addDoc(kind, policyARN, raw)
	for _, d := range old {
		e.replaceDoc(d.ID, nd.ID)
	}
	return nil
}

func (e *editor) moveAccount(accountID, parentID string) error {
	o := e.b.org
	if o == nil {
		return errors.New("the snapshot has no organization")
	}
	n := o.Nodes[accountID]
	if n == nil || n.Kind != model.OrgAccount {
		return fmt.Errorf("no account %s in the organization", clip(accountID, 40))
	}
	p := o.Nodes[parentID]
	if p == nil || (p.Kind != model.OrgRoot && p.Kind != model.OrgOU) {
		return fmt.Errorf("no root or OU %s in the organization", clip(parentID, 40))
	}
	n.ParentID = parentID
	return nil
}

// ---------------------------------------------------------------- KMS and S3

func decodeStrict(raw string, into any) error {
	dec := json.NewDecoder(bytes.NewReader([]byte(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return fmt.Errorf("document: %v", err)
	}
	if dec.More() {
		return errors.New("document: trailing data")
	}
	return nil
}

func (e *editor) createGrant(keyARN, raw string) error {
	if e.b.resources[keyARN] == nil {
		return fmt.Errorf("no key %s in the snapshot", clip(keyARN, 200))
	}
	var g model.KMSGrant
	if err := decodeStrict(raw, &g); err != nil {
		return err
	}
	if g.GrantID == "" || len(g.GrantID) > 128 {
		return errors.New("document: grant_id is required (at most 128 bytes)")
	}
	if g.GranteePrincipal == "" && g.GranteeServicePrincipal == "" {
		return errors.New("document: a grant needs a grantee_principal or a grantee_service_principal")
	}
	g.KeyARN = keyARN
	g.CreatedAt = e.opts.FetchedAt
	sort.Strings(g.Operations)
	gs := slices.DeleteFunc(slices.Clone(e.b.grants[keyARN]), func(x model.KMSGrant) bool { return x.GrantID == g.GrantID })
	e.b.grants[keyARN] = append(gs, g)
	return nil
}

func (e *editor) retireGrant(keyARN, grantID string) error {
	n := len(e.b.grants[keyARN])
	e.b.grants[keyARN] = slices.DeleteFunc(slices.Clone(e.b.grants[keyARN]), func(x model.KMSGrant) bool { return x.GrantID == grantID })
	if len(e.b.grants[keyARN]) == n {
		return fmt.Errorf("key %s has no grant %s", clip(keyARN, 200), clip(grantID, 128))
	}
	if len(e.b.grants[keyARN]) == 0 {
		delete(e.b.grants, keyARN)
	}
	return nil
}

// putBPA sets the Block Public Access settings of one bucket (the target is a
// bucket ARN) or of an account (a 12-digit id: every bucket the account owns).
func (e *editor) putBPA(target, raw string) error {
	var bpa model.BPA
	if err := decodeStrict(raw, &bpa); err != nil {
		return err
	}
	if accountIDRE.MatchString(target) {
		n := 0
		for _, s := range e.b.s3 {
			if s.OwnerAccount == target {
				s.BPAAccount = bpa
				n++
			}
		}
		if n == 0 {
			return fmt.Errorf("account %s owns no bucket in the snapshot", target)
		}
		return nil
	}
	s := e.b.s3[target]
	if s == nil {
		return fmt.Errorf("no bucket %s in the snapshot", clip(target, 200))
	}
	s.BPABucket = bpa
	return nil
}

var ownershipModes = []string{"BucketOwnerEnforced", "BucketOwnerPreferred", "ObjectWriter"}

// putOwnership sets a bucket's object ownership; the document is the JSON
// string of the mode, for example "BucketOwnerEnforced".
func (e *editor) putOwnership(bucketARN, raw string) error {
	var mode string
	if err := decodeStrict(raw, &mode); err != nil {
		return err
	}
	if !slices.Contains(ownershipModes, mode) {
		return fmt.Errorf("document: object ownership must be one of %s", strings.Join(ownershipModes, ", "))
	}
	s := e.b.s3[bucketARN]
	if s == nil {
		return fmt.Errorf("no bucket %s in the snapshot", clip(bucketARN, 200))
	}
	s.ObjectOwnership = mode
	return nil
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
