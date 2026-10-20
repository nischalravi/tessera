package awsorg

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// builder accumulates a model.Snapshot and the findings of one run. The
// design (§6.1) has snapshot.Builder (PR-5) build snapshots; until it lands the
// connector builds the value itself and never changes it after finish.
type builder struct {
	now  time.Time
	snap *model.Snapshot
	// findings holds every Finding; a policy that fails to parse gets its
	// scope filled in as its attachments are found.
	findings Findings
	// managed caches the parse of a managed policy per (ARN, kind).
	managed  map[string]polRef
	accounts []string
	sso      []SSOAssignment
}

func newBuilder(now time.Time) *builder {
	return &builder{now: now, managed: map[string]polRef{}, snap: &model.Snapshot{
		Principals:       map[string]*model.Principal{},
		Policies:         map[string]*model.PolicyDoc{},
		ResourcePolicies: map[string][]model.ResourcePolicy{},
		KMSGrants:        map[string][]model.KMSGrant{},
		S3:               map[string]*model.S3BucketState{},
		Resources:        map[string]*model.Resource{},
		VPCEPolicies:     map[string]string{},
		CanonicalIDs:     map[string]string{},
	}}
}

// polRef is the outcome of parsing one stored policy: its document id, or the
// index of the finding that records why there is none.
type polRef struct {
	id   string
	fail int // index into builder.findings; -1 when id is set
	// drops are the findings of statements dropped as ingest anomalies: the
	// document is kept, and what it governs is still not exactly known.
	drops []int
}

// ok reports whether the policy parsed.
func (r polRef) ok() bool { return r.fail < 0 }

// addFinding records a finding and returns its index.
func (b *builder) addFinding(f Finding) int {
	b.findings = append(b.findings, f)
	return len(b.findings) - 1
}

// gap records a read that failed, with the decisions it could affect.
func (b *builder) gap(source, code, detail string, scope Scope) {
	b.addFinding(Finding{Kind: store.AWSFindingAccountError, SourceARN: source, Code: code, Detail: detail, Scope: scope})
}

// errCode is the AWS error code of err, or a short description of other errors.
func errCode(err error) string {
	var ae *Error
	if errors.As(err, &ae) {
		return ae.Code
	}
	return "error"
}

func errDetail(err error) string { return clip(err.Error(), 300) }

// parseDoc parses one stored policy. A policy that does not parse, or that
// parses with a statement dropped as an ingest anomaly, is never skipped
// silently (design §3.3): the failure becomes a finding whose scope the caller
// completes (target principals) or sets. The returned ref carries the finding
// index for a parse failure. A dropped statement does not make the document
// unusable, so the document is still returned (ok) and the finding stands.
func (b *builder) parseDoc(kind model.PolicyKind, source, version, raw string, awsManaged bool, scope Scope) polRef {
	res, err := policy.Parse([]byte(raw), policy.Options{Kind: kind, SourceARN: source, VersionID: version,
		AWSManaged: awsManaged, FetchedAt: b.now})
	if err != nil {
		code := "unparseable"
		var pe *policy.ParseError
		if errors.As(err, &pe) {
			code = pe.Code
		}
		i := b.addFinding(Finding{Kind: store.AWSFindingPolicyUnparseable, SourceARN: source, PolicyKind: kind.String(),
			Code: code, Detail: clip(err.Error(), 300), Scope: scope})
		return polRef{fail: i}
	}
	ref := polRef{id: res.Doc.ID, fail: -1}
	for _, a := range res.Anomalies {
		if a.Dropped {
			ref.drops = append(ref.drops, b.addFinding(Finding{Kind: store.AWSFindingStatementDropped, SourceARN: source,
				PolicyKind: kind.String(), Code: string(a.Code),
				Detail: fmt.Sprintf("statement %d: %s", a.StatementIndex, clip(a.Detail, 200)), Scope: scope}))
		}
	}
	if _, dup := b.snap.Policies[res.Doc.ID]; !dup {
		b.snap.Policies[res.Doc.ID] = res.Doc
	}
	return ref
}

// addTargets widens the findings of a policy (its parse failure, or its dropped
// statements) to cover target.
func (b *builder) addTargets(ref polRef, target string) {
	if !ref.ok() {
		b.addTarget(ref.fail, target)
	}
	for _, i := range ref.drops {
		b.addTarget(i, target)
	}
}

// attach links a parsed policy to a principal, or, when the policy did not
// parse, widens the finding's scope to include the principal.
func (b *builder) attach(ref polRef, principal *model.Principal, typ model.AttachmentType, via []string) {
	b.addTargets(ref, principal.ARN)
	if !ref.ok() {
		return
	}
	b.snap.Attachments = append(b.snap.Attachments, model.PolicyAttachment{PolicyID: ref.id, TargetARN: principal.ARN,
		Via: via, AttachmentType: typ})
	if typ == model.AttachInline || typ == model.AttachManaged {
		principal.IdentityPolicyIDs = append(principal.IdentityPolicyIDs, ref.id)
	}
}

func (b *builder) addTarget(finding int, target string) {
	f := &b.findings[finding]
	if !slices.Contains(f.Scope.Targets, target) {
		f.Scope.Targets = append(f.Scope.Targets, target)
	}
}

// finish sorts everything that is accumulated in append order, so equal input
// gives an equal snapshot, and computes the content hash. The snapshot must
// not be changed afterwards.
func (b *builder) finish(accounts []string) (*Collection, error) {
	s := b.snap
	for i := range b.findings {
		sort.Strings(b.findings[i].Scope.Targets)
		b.findings[i].Scope.Targets = slices.Compact(b.findings[i].Scope.Targets)
		if b.findings[i].Scope.Targets == nil {
			b.findings[i].Scope.Targets = []string{}
		}
	}
	sort.SliceStable(b.findings, func(i, j int) bool {
		x, y := b.findings[i], b.findings[j]
		if x.Kind != y.Kind {
			return x.Kind < y.Kind
		}
		if x.SourceARN != y.SourceARN {
			return x.SourceARN < y.SourceARN
		}
		return x.Code < y.Code
	})
	slices.SortFunc(s.Attachments, func(x, y model.PolicyAttachment) int {
		if c := strings.Compare(x.TargetARN, y.TargetARN); c != 0 {
			return c
		}
		if c := strings.Compare(x.AttachmentType.String(), y.AttachmentType.String()); c != 0 {
			return c
		}
		if c := strings.Compare(x.PolicyID, y.PolicyID); c != 0 {
			return c
		}
		return strings.Compare(strings.Join(x.Via, "/"), strings.Join(y.Via, "/"))
	})
	for _, p := range s.Principals {
		p.IdentityPolicyIDs = slices.Compact(p.IdentityPolicyIDs)
	}
	if s.Org != nil {
		for _, n := range s.Org.Nodes {
			slices.Sort(n.SCPIDs)
			slices.Sort(n.RCPIDs)
		}
	}
	b.pruneUnreferenced()
	slices.SortFunc(b.sso, func(x, y SSOAssignment) int {
		return strings.Compare(x.AccountID+x.PermissionSetARN+x.PrincipalID, y.AccountID+y.PermissionSetARN+y.PrincipalID)
	})
	slices.Sort(accounts)
	c := &Collection{Snapshot: s, Findings: b.findings, IdentityCenter: b.sso, AccountIDs: accounts}
	id, err := ContentID(c)
	if err != nil {
		return nil, err
	}
	s.ID, s.TakenAt = id, b.now.UTC()
	return c, nil
}

// pruneUnreferenced drops parsed documents nothing refers to (an SCP attached
// to no node): they cannot change a decision, and a persisted snapshot can
// only bring back what an attachment, a resource, an endpoint or a principal
// names.
func (b *builder) pruneUnreferenced() {
	s := b.snap
	used := map[string]bool{}
	for _, a := range s.Attachments {
		used[a.PolicyID] = true
	}
	for _, rps := range s.ResourcePolicies {
		for _, rp := range rps {
			used[rp.PolicyID] = true
		}
	}
	for _, id := range s.VPCEPolicies {
		used[id] = true
	}
	for _, p := range s.Principals {
		for _, id := range p.IdentityPolicyIDs {
			used[id] = true
		}
		used[p.BoundaryPolicyID] = true
	}
	for id := range s.Policies {
		if !used[id] {
			delete(s.Policies, id)
		}
	}
}

// Collection is what one run produced: the snapshot, and what the evaluator
// must know about its limits.
type Collection struct {
	Snapshot *model.Snapshot
	// Findings are the policies and reads that could not be taken at face
	// value; see Findings.Unsupported.
	Findings Findings
	// IdentityCenter holds the Identity Center assignments of the accounts read.
	IdentityCenter []SSOAssignment
	// AccountIDs are the accounts that were read, sorted.
	AccountIDs []string
}

// ContentID is the content hash of a collection: the snapshot id. It covers
// everything the evaluator reads and the findings, and not the time it was
// taken or the time policies were fetched, so two runs over an unchanged
// estate give the same id. Maps marshal in key order and every slice is sorted
// by finish.
func ContentID(c *Collection) (string, error) {
	s := c.Snapshot
	ids := make([]string, 0, len(s.Policies))
	for id := range s.Policies {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	view := struct {
		Org              *model.Organization               `json:"org"`
		Principals       map[string]*model.Principal       `json:"principals"`
		PolicyIDs        []string                          `json:"policy_ids"`
		Attachments      []model.PolicyAttachment          `json:"attachments"`
		ResourcePolicies map[string][]model.ResourcePolicy `json:"resource_policies"`
		KMSGrants        map[string][]model.KMSGrant       `json:"kms_grants"`
		S3               map[string]*model.S3BucketState   `json:"s3"`
		Resources        map[string]*model.Resource        `json:"resources"`
		VPCEPolicies     map[string]string                 `json:"vpce_policies"`
		CanonicalIDs     map[string]string                 `json:"canonical_ids"`
		Findings         Findings                          `json:"findings"`
		IdentityCenter   []SSOAssignment                   `json:"identity_center"`
		Accounts         []string                          `json:"accounts"`
	}{s.Org, s.Principals, ids, s.Attachments, s.ResourcePolicies, s.KMSGrants, s.S3, s.Resources, s.VPCEPolicies,
		s.CanonicalIDs, c.Findings, c.IdentityCenter, c.AccountIDs}
	b, err := json.Marshal(view)
	if err != nil {
		return "", err
	}
	return sha256Hex(b), nil
}
