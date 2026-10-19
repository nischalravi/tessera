package awstest

import (
	"fmt"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/snapshot"
)

// ScaleConfig sizes a synthetic tenant (§12.1).
type ScaleConfig struct {
	Seed               uint64
	Accounts           int
	Principals         int
	ManagedDocs        int // shared identity policies
	StatementsPerDoc   int
	Resources          int
	ResourcePolicyDocs int
	Services           int // service prefixes besides the eight real ones
	ActionsPerService  int
	PermissionSets     int // distinct combinations of managed policies
}

// TargetScale is the design's "large tenant": 500 accounts, 50,000 principals,
// about 30,000 documents and 400,000 statements, 2,000,000 resources of which
// 50,000 have a resource policy, and a catalog of about 18,000 actions.
func TargetScale() ScaleConfig {
	return ScaleConfig{Seed: 1, Accounts: 500, Principals: 50000, ManagedDocs: 20000, StatementsPerDoc: 13, Resources: 2000000,
		ResourcePolicyDocs: 50000, Services: 442, ActionsPerService: 40, PermissionSets: 1500}
}

// Times scales the tenant dimensions (not the catalog) by n.
func (c ScaleConfig) Times(n int) ScaleConfig {
	c.Accounts *= n
	c.Principals *= n
	c.ManagedDocs *= n
	c.Resources *= n
	c.ResourcePolicyDocs *= n
	c.PermissionSets *= n
	return c
}

// Scaled is a synthetic tenant and what the performance tests need to sample it.
type Scaled struct {
	Cfg         ScaleConfig
	Snap        *model.Snapshot
	Actions     []string
	Principals  []string // principal ARNs
	Buckets     []string // S3 bucket ARNs
	Keys        []string // KMS key ARNs
	Managed     []string // source ARNs of the managed identity policies
	UsedManaged []int    // indexes into Managed of the policies some permission set attaches
	RPSources   []string // source ARNs of resource policies
	OUs         []string
}

var realServices = []string{"s3", "kms", "sts", "iam", "sqs", "sns", "lambda", "ec2"}
var verbs = []string{"Get", "List", "Put", "Delete", "Describe", "Create", "Update", "Tag", "Untag", "Start", "Stop", "Invoke", "Send", "Receive", "Publish", "Subscribe",
	"Attach", "Detach", "Enable", "Disable", "Read", "Write", "Copy", "Move", "Restore", "Export", "Import", "Run", "Cancel", "Check", "Query", "Scan", "Batch", "Set", "Reset", "Validate", "Associate", "Disassociate", "Register", "Deregister"}

// Account returns the id of account i.
func Account(i int) string { return fmt.Sprintf("%012d", 100000000000+i) }

func (c ScaleConfig) service(k int) string {
	if k < len(realServices) {
		return realServices[k]
	}
	return fmt.Sprintf("svc%03d", k-len(realServices))
}

// ScaleActions is the action universe of a scale config.
func (c ScaleConfig) ScaleActions() []string {
	n := len(realServices) + c.Services
	out := make([]string, 0, n*c.ActionsPerService)
	for k := 0; k < n; k++ {
		for v := 0; v < c.ActionsPerService; v++ {
			out = append(out, fmt.Sprintf("%s:%s%s", c.service(k), verbs[v%len(verbs)], strings.Repeat("X", v/len(verbs))))
		}
	}
	return out
}

func (g *Rand) scaleStatement(c ScaleConfig, acct string) string {
	svc := c.service(g.Intn(len(realServices) + c.Services))
	var action string
	switch g.Intn(6) {
	case 0:
		action = fmt.Sprintf(`"%s:*"`, svc)
	case 1:
		action = fmt.Sprintf(`["%s:Get*","%s:List*","%s:Describe*"]`, svc, svc, svc)
	case 2:
		action = fmt.Sprintf(`"%s:Put*"`, svc)
	default:
		// Exact actions cluster on a few services and verbs, as real policies do;
		// if every action were named somewhere no two would share an atom.
		action = fmt.Sprintf(`"%s:%s"`, c.service(g.Intn(30)), verbs[g.Intn(8)])
	}
	var res string
	switch n := g.Intn(20); {
	case n < 3:
		res = `"*"`
	case n < 6:
		res = fmt.Sprintf(`"arn:aws:%s:*:*:*"`, svc)
	case n < 16:
		res = fmt.Sprintf(`"arn:aws:%s:*:%s:*"`, svc, acct)
	default:
		res = fmt.Sprintf(`"arn:aws:s3:::a%s-*"`, acct[6:])
	}
	cond := ""
	switch g.Intn(8) {
	case 0:
		cond = fmt.Sprintf(`,"Condition":{"StringEquals":{"aws:PrincipalTag/team":"t%d"}}`, g.Intn(10))
	case 1:
		cond = `,"Condition":{"Bool":{"aws:SecureTransport":"true"}}`
	}
	effect := "Allow"
	if g.Intn(40) == 0 {
		effect = "Deny"
	}
	return fmt.Sprintf(`{"Effect":"%s","Action":%s,"Resource":%s%s}`, effect, action, res, cond)
}

// GenerateScale builds a tenant of the given size. The same config gives the
// same snapshot.
func GenerateScale(c ScaleConfig) (*Scaled, error) {
	g := NewRand(c.Seed)
	s := &Scaled{Cfg: c, Actions: c.ScaleActions()}
	b := snapshot.NewBuilder()
	opts := func(kind model.PolicyKind, src string) policy.Options {
		return policy.Options{Kind: kind, SourceARN: src}
	}

	// Organization: a root, 20 OUs and the accounts under them.
	org := &model.Organization{OrgID: "o-scale", ManagementAccountID: "999999999999", SCPEnabled: true, RCPEnabled: true, Nodes: map[string]*model.OrgNode{}}
	org.Nodes["r-1"] = &model.OrgNode{ID: "r-1", Kind: model.OrgRoot}
	b.AddPolicy(opts(model.PolicySCP, "scp/full"), []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`))
	b.AddPolicy(opts(model.PolicyRCP, "rcp/baseline"), []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"}]}`))
	full := policy.DocumentID(model.PolicySCP, "scp/full", "", []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`))
	rcp := policy.DocumentID(model.PolicyRCP, "rcp/baseline", "", []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"}]}`))
	org.Nodes["r-1"].SCPIDs = []string{full}
	org.Nodes["r-1"].RCPIDs = []string{rcp}
	for i := 0; i < 20; i++ {
		id := fmt.Sprintf("ou-%02d", i)
		s.OUs = append(s.OUs, id)
		deny := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"svc%03d:*","Resource":"*"}]}`, i)
		d := b.AddPolicy(opts(model.PolicySCP, "scp/ou"+id), []byte(deny))
		org.Nodes[id] = &model.OrgNode{ID: id, Kind: model.OrgOU, ParentID: "r-1", SCPIDs: []string{full, d.ID}, RCPIDs: []string{rcp}}
	}
	for i := 0; i < c.Accounts; i++ {
		a := Account(i)
		org.Nodes[a] = &model.OrgNode{ID: a, Kind: model.OrgAccount, ParentID: s.OUs[i%20], SCPIDs: []string{full}, RCPIDs: []string{rcp}}
	}
	b.SetOrg(org)

	// Managed policies.
	managedIDs := make([]string, c.ManagedDocs)
	for j := 0; j < c.ManagedDocs; j++ {
		var sts []string
		acct := Account(g.Intn(c.Accounts))
		for k := 0; k < c.StatementsPerDoc; k++ {
			sts = append(sts, g.scaleStatement(c, acct))
		}
		src := fmt.Sprintf("arn:aws:iam::%s:policy/m%d", acct, j)
		s.Managed = append(s.Managed, src)
		raw := `{"Version":"2012-10-17","Statement":[` + strings.Join(sts, ",") + `]}`
		managedIDs[j] = b.AddPolicy(opts(model.PolicyIdentity, src), []byte(raw)).ID
	}
	var boundaries []string
	for i := 0; i < 5; i++ {
		raw := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["svc%03d:*","s3:*","sqs:*","kms:*","lambda:*"],"Resource":"*"}]}`, i)
		boundaries = append(boundaries, b.AddPolicy(opts(model.PolicyBoundary, fmt.Sprintf("pb/%d", i)), []byte(raw)).ID)
	}

	// Principals: each takes the policies of one of a limited set of permission sets.
	used := map[int]bool{}
	setDocs := make([][3]int, c.PermissionSets)
	for i := range setDocs {
		setDocs[i] = [3]int{g.Intn(c.ManagedDocs), g.Intn(c.ManagedDocs), g.Intn(c.ManagedDocs)}
	}
	for i := 0; i < c.Principals; i++ {
		acct := Account(i % c.Accounts)
		p := &model.Principal{AccountID: acct, Path: "/"}
		if i%10 < 3 {
			p.ARN, p.Kind, p.UniqueID = fmt.Sprintf("arn:aws:iam::%s:user/u%d", acct, i), model.IAMUser, fmt.Sprintf("AIDA%d", i)
		} else {
			p.ARN, p.Kind, p.UniqueID = fmt.Sprintf("arn:aws:iam::%s:role/r%d", acct, i), model.IAMRole, fmt.Sprintf("AROA%d", i)
		}
		set := setDocs[g.Intn(c.PermissionSets)]
		for _, d := range set {
			p.IdentityPolicyIDs = append(p.IdentityPolicyIDs, managedIDs[d])
			used[d] = true
		}
		if g.Intn(5) == 0 {
			p.BoundaryPolicyID = boundaries[g.Intn(len(boundaries))]
		}
		if g.Intn(10) < 3 {
			p.Tags = map[string]string{"team": fmt.Sprintf("t%d", g.Intn(10))}
		}
		b.AddPrincipal(p)
		s.Principals = append(s.Principals, p.ARN)
	}

	for d := 0; d < c.ManagedDocs; d++ {
		if used[d] {
			s.UsedManaged = append(s.UsedManaged, d)
		}
	}

	// Resources and resource policies.
	rpEvery := c.Resources / max(c.ResourcePolicyDocs, 1)
	if rpEvery < 1 {
		rpEvery = 1
	}
	rpN := 0
	for r := 0; r < c.Resources; r++ {
		acct := Account(r % c.Accounts)
		res := &model.Resource{AccountID: acct, Region: "us-east-1"}
		kind := model.PolicyResource
		switch r % 10 {
		case 0, 1:
			res.ARN, res.Type, res.Region = fmt.Sprintf("arn:aws:s3:::a%s-b%d", acct[6:], r), "bucket", ""
			if r%50 == 0 {
				s.Buckets = append(s.Buckets, res.ARN)
				b.AddS3Bucket(&model.S3BucketState{BucketARN: res.ARN, OwnerAccount: acct, ObjectOwnership: "BucketOwnerEnforced"})
			}
		case 2:
			res.ARN, res.Type = fmt.Sprintf("arn:aws:kms:us-east-1:%s:key/k%d", acct, r), "key"
			kind = model.PolicyKMSKey
			if r%100 == 2 {
				s.Keys = append(s.Keys, res.ARN)
			}
		case 3, 4:
			res.ARN, res.Type = fmt.Sprintf("arn:aws:sqs:us-east-1:%s:q%d", acct, r), "queue"
		case 5:
			res.ARN, res.Type = fmt.Sprintf("arn:aws:sns:us-east-1:%s:t%d", acct, r), "topic"
		case 6, 7:
			res.ARN, res.Type = fmt.Sprintf("arn:aws:lambda:us-east-1:%s:function:f%d", acct, r), "function"
		default:
			res.ARN, res.Type = fmt.Sprintf("arn:aws:%s:us-east-1:%s:thing/%d", c.service(len(realServices)+r%c.Services), acct, r), "thing"
		}
		b.AddResource(res)
		if r%rpEvery == 0 && rpN < c.ResourcePolicyDocs && (r%10 <= 5) {
			other := Account(g.Intn(c.Accounts))
			raw := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"%s"},"Action":["s3:Get*","s3:List*"],"Resource":"*"},`+
				`{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::%s:role/r%d"},"Action":"sqs:*"}]}`,
				other, other, g.Intn(c.Principals))
			src := res.ARN + "#policy"
			s.RPSources = append(s.RPSources, src)
			doc := b.AddPolicy(opts(kind, src), []byte(raw))
			b.AddResourcePolicy(model.ResourcePolicy{ResourceARN: res.ARN, Kind: kind, PolicyID: doc.ID, RequiresExplicitAllow: kind == model.PolicyKMSKey})
			rpN++
		}
	}
	snap, err := b.Build()
	if err != nil {
		return nil, err
	}
	s.Snap = snap
	return s, nil
}

// withDoc returns a copy of the snapshot in which the document with the given id
// is replaced by the parsed raw JSON; every principal, resource policy and org
// node that referenced the old id references the new one. Everything else is
// shared with the original, which is not changed. A policy pull request looks
// like this to the evaluator.
func (s *Scaled) withDoc(oldID string, kind model.PolicyKind, src string, raw []byte) (*model.Snapshot, error) {
	res, err := policy.Parse(raw, policy.Options{Kind: kind, SourceARN: src})
	if err != nil {
		return nil, err
	}
	nd := res.Doc
	h := *s.Snap
	h.Policies = make(map[string]*model.PolicyDoc, len(s.Snap.Policies))
	for k, v := range s.Snap.Policies {
		if k != oldID {
			h.Policies[k] = v
		}
	}
	h.Policies[nd.ID] = nd
	swap := func(ids []string) ([]string, bool) {
		for i, id := range ids {
			if id == oldID {
				out := append([]string(nil), ids...)
				out[i] = nd.ID
				return out, true
			}
		}
		return ids, false
	}
	h.Principals = make(map[string]*model.Principal, len(s.Snap.Principals))
	for k, p := range s.Snap.Principals {
		if ids, ok := swap(p.IdentityPolicyIDs); ok {
			c := *p
			c.IdentityPolicyIDs = ids
			p = &c
		}
		h.Principals[k] = p
	}
	h.ResourcePolicies = make(map[string][]model.ResourcePolicy, len(s.Snap.ResourcePolicies))
	for k, rps := range s.Snap.ResourcePolicies {
		for i, rp := range rps {
			if rp.PolicyID == oldID {
				rps = append([]model.ResourcePolicy(nil), rps...)
				rps[i].PolicyID = nd.ID
			}
		}
		h.ResourcePolicies[k] = rps
	}
	return &h, nil
}

// WithManagedPolicyEdited returns the snapshot after identity policy i gains an
// Allow statement.
func (s *Scaled) WithManagedPolicyEdited(i int) (*model.Snapshot, error) {
	src := s.Managed[i]
	var old *model.PolicyDoc
	for _, d := range s.Snap.Policies {
		if d.SourceARN == src {
			old = d
			break
		}
	}
	raw := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["svc001:Get*","s3:GetObject"],"Resource":"*"}]}`
	return s.withDoc(old.ID, model.PolicyIdentity, src, []byte(raw))
}

// WithResourcePolicyEdited returns the snapshot after resource policy i is replaced.
func (s *Scaled) WithResourcePolicyEdited(i int) (*model.Snapshot, error) {
	src := s.RPSources[i]
	var old *model.PolicyDoc
	for _, d := range s.Snap.Policies {
		if d.SourceARN == src {
			old = d
			break
		}
	}
	raw := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*","Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-scale"}}}]}`
	return s.withDoc(old.ID, old.Kind, src, []byte(raw))
}

// WithSCPAttached returns the snapshot after a new SCP is attached to an OU.
func (s *Scaled) WithSCPAttached(ou string) (*model.Snapshot, error) {
	raw := []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"svc002:*","Resource":"*"}]}`)
	res, err := policy.Parse(raw, policy.Options{Kind: model.PolicySCP, SourceARN: "scp/new"})
	if err != nil {
		return nil, err
	}
	h := *s.Snap
	h.Policies = make(map[string]*model.PolicyDoc, len(s.Snap.Policies)+1)
	for k, v := range s.Snap.Policies {
		h.Policies[k] = v
	}
	h.Policies[res.Doc.ID] = res.Doc
	o := *s.Snap.Org
	o.Nodes = make(map[string]*model.OrgNode, len(s.Snap.Org.Nodes))
	for k, n := range s.Snap.Org.Nodes {
		if k == ou {
			c := *n
			c.SCPIDs = append(append([]string(nil), n.SCPIDs...), res.Doc.ID)
			n = &c
		}
		o.Nodes[k] = n
	}
	h.Org = &o
	return &h, nil
}
