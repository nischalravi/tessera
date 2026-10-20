// Package snapshot assembles the immutable model.Snapshot the evaluator reads
// (design §5, §6.1). Build() normalizes every ordering so the snapshot, its
// content hash and the traces computed from it do not depend on the order in
// which facts were added. The package does no I/O and reads no clock: times
// come in as values.
package snapshot

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/policy"
)

// Builder collects the facts of one snapshot. It is not safe for concurrent use.
type Builder struct {
	takenAt      time.Time
	org          *model.Organization
	principals   map[string]*model.Principal
	policies     map[string]*model.PolicyDoc
	attachments  []model.PolicyAttachment
	resPolicies  map[string][]model.ResourcePolicy
	grants       map[string][]model.KMSGrant
	s3           map[string]*model.S3BucketState
	resources    map[string]*model.Resource
	vpce         map[string]string
	canonicalIDs map[string]string
	errs         []error
}

// NewBuilder returns an empty builder.
func NewBuilder() *Builder {
	return &Builder{
		principals:   map[string]*model.Principal{},
		policies:     map[string]*model.PolicyDoc{},
		resPolicies:  map[string][]model.ResourcePolicy{},
		grants:       map[string][]model.KMSGrant{},
		s3:           map[string]*model.S3BucketState{},
		resources:    map[string]*model.Resource{},
		vpce:         map[string]string{},
		canonicalIDs: map[string]string{},
	}
}

// SetTakenAt records when the snapshot was taken (passed in; never read from a clock).
func (b *Builder) SetTakenAt(t time.Time) { b.takenAt = t }

// SetOrg sets the organization.
func (b *Builder) SetOrg(o *model.Organization) { b.org = o }

// AddPrincipal adds an entity or session template, keyed by ARN.
func (b *Builder) AddPrincipal(p *model.Principal) { b.principals[p.ARN] = p }

// AddPolicy parses raw and adds the document. A document that fails to parse,
// or that has an ingest anomaly which dropped a statement, is stored with
// PolicyDoc.Unparseable set, never skipped (§3.3): the engine then answers
// every decision it could affect with UNSUPPORTED. The returned document is
// always usable as a reference target.
func (b *Builder) AddPolicy(opts policy.Options, raw []byte) *model.PolicyDoc {
	res, err := policy.Parse(raw, opts)
	var doc *model.PolicyDoc
	if err != nil {
		doc = &model.PolicyDoc{
			ID: policy.DocumentID(opts.Kind, opts.SourceARN, opts.VersionID, raw), Kind: opts.Kind,
			SourceARN: opts.SourceARN, VersionID: opts.VersionID, AWSManaged: opts.AWSManaged,
			FetchedAt: opts.FetchedAt, RawJSON: append([]byte(nil), raw...), Unparseable: err.Error(),
		}
	} else {
		doc = res.Doc
		for _, a := range res.Anomalies {
			if a.Dropped {
				doc.Unparseable = fmt.Sprintf("statement %d dropped: %s", a.StatementIndex, a.Code)
				break
			}
		}
	}
	b.policies[doc.ID] = doc
	return doc
}

// Attach records a policy attachment.
func (b *Builder) Attach(a model.PolicyAttachment) { b.attachments = append(b.attachments, a) }

// AddResourcePolicy attaches a resource-based policy to a resource ARN.
func (b *Builder) AddResourcePolicy(rp model.ResourcePolicy) {
	b.resPolicies[rp.ResourceARN] = append(b.resPolicies[rp.ResourceARN], rp)
}

// AddKMSGrant records a KMS grant.
func (b *Builder) AddKMSGrant(g model.KMSGrant) { b.grants[g.KeyARN] = append(b.grants[g.KeyARN], g) }

// AddS3Bucket records a bucket's S3 state.
func (b *Builder) AddS3Bucket(s *model.S3BucketState) { b.s3[s.BucketARN] = s }

// AddResource records a resource.
func (b *Builder) AddResource(r *model.Resource) { b.resources[r.ARN] = r }

// SetVPCEPolicy maps a VPC endpoint id to a policy document id.
func (b *Builder) SetVPCEPolicy(endpointID, policyID string) { b.vpce[endpointID] = policyID }

// SetCanonicalID maps an S3 canonical user id to an account id.
func (b *Builder) SetCanonicalID(canonical, account string) { b.canonicalIDs[canonical] = account }

// Build returns the snapshot. Every list is sorted, so any insertion order
// gives the same snapshot and the same ID. The builder can be reused, but
// shares no mutable state with a returned snapshot.
func (b *Builder) Build() (*model.Snapshot, error) {
	if len(b.errs) > 0 {
		return nil, errors.Join(b.errs...)
	}
	s := &model.Snapshot{
		TakenAt:          b.takenAt,
		Org:              cloneOrg(b.org),
		Principals:       map[string]*model.Principal{},
		Policies:         map[string]*model.PolicyDoc{},
		ResourcePolicies: map[string][]model.ResourcePolicy{},
		KMSGrants:        map[string][]model.KMSGrant{},
		S3:               map[string]*model.S3BucketState{},
		Resources:        map[string]*model.Resource{},
		VPCEPolicies:     map[string]string{},
		CanonicalIDs:     map[string]string{},
	}
	for k, d := range b.policies {
		c := *d
		s.Policies[k] = &c
	}
	policyOrder := func(ids []string) []string {
		out := append([]string(nil), ids...)
		sort.Slice(out, func(i, j int) bool {
			var si, sj string
			if d := s.Policies[out[i]]; d != nil {
				si = d.SourceARN
			}
			if d := s.Policies[out[j]]; d != nil {
				sj = d.SourceARN
			}
			if si != sj {
				return si < sj
			}
			return out[i] < out[j]
		})
		return out
	}
	for k, p := range b.principals {
		c := *p
		c.IdentityPolicyIDs = policyOrder(p.IdentityPolicyIDs)
		c.SessionPolicyIDs = policyOrder(p.SessionPolicyIDs)
		c.GroupARNs = sortedCopy(p.GroupARNs)
		c.TransitiveTagKeys = sortedCopy(p.TransitiveTagKeys)
		s.Principals[k] = &c
	}
	s.Attachments = append([]model.PolicyAttachment(nil), b.attachments...)
	sort.Slice(s.Attachments, func(i, j int) bool {
		x, y := s.Attachments[i], s.Attachments[j]
		if x.TargetARN != y.TargetARN {
			return x.TargetARN < y.TargetARN
		}
		if x.PolicyID != y.PolicyID {
			return x.PolicyID < y.PolicyID
		}
		return fmt.Sprint(x.Via) < fmt.Sprint(y.Via)
	})
	for k, rps := range b.resPolicies {
		c := append([]model.ResourcePolicy(nil), rps...)
		sort.Slice(c, func(i, j int) bool { return c[i].PolicyID < c[j].PolicyID })
		s.ResourcePolicies[k] = c
	}
	for k, gs := range b.grants {
		c := append([]model.KMSGrant(nil), gs...)
		sort.Slice(c, func(i, j int) bool { return c[i].GrantID < c[j].GrantID })
		s.KMSGrants[k] = c
	}
	for k, v := range b.s3 {
		c := *v
		s.S3[k] = &c
	}
	for k, v := range b.resources {
		c := *v
		s.Resources[k] = &c
	}
	for k, v := range b.vpce {
		s.VPCEPolicies[k] = v
	}
	for k, v := range b.canonicalIDs {
		s.CanonicalIDs[k] = v
	}
	id, err := Hash(s)
	if err != nil {
		return nil, err
	}
	s.ID = id
	return s, nil
}

func sortedCopy(in []string) []string {
	if in == nil {
		return nil
	}
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func cloneOrg(o *model.Organization) *model.Organization {
	if o == nil {
		return nil
	}
	c := *o
	c.Nodes = map[string]*model.OrgNode{}
	for k, n := range o.Nodes {
		nc := *n
		nc.SCPIDs, nc.RCPIDs = sortedCopy(n.SCPIDs), sortedCopy(n.RCPIDs)
		c.Nodes[k] = &nc
	}
	return &c
}
