package awstest

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"sort"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/snapshot"
)

// The accounts of a small world. M is the organization's management account.
const (
	AcctA = "111111111111"
	AcctB = "222222222222"
	AcctC = "333333333333"
	AcctM = "999999999999"
)

// Doc is one policy document of a World, by source name.
type Doc struct {
	Kind model.PolicyKind
	Src  string
	Raw  []byte
}

// WPrincipal is a principal of a World; its policies are named by source.
type WPrincipal struct {
	P        model.Principal
	Identity []string
	Boundary string
	Session  []string
}

// WRP is a resource-based policy attachment.
type WRP struct {
	Resource string
	Kind     model.PolicyKind
	Src      string
	Explicit bool
}

// World is a small random tenant held as plain data, so a test can mutate it and
// build the before and after snapshots of a policy change. Build turns it into a
// snapshot through snapshot.Builder.
type World struct {
	Org        *model.Organization
	SCP, RCP   map[string][]string // org node id to document sources
	Docs       map[string]*Doc
	Principals []*WPrincipal
	RPs        []WRP
	Grants     map[string][]model.KMSGrant
	S3         map[string]*model.S3BucketState
	Resources  map[string]*model.Resource
	Canon      map[string]string
	// Extra lists resources outside the inventory that queries should cover:
	// S3 objects and a resource that nothing names.
	Extra []string
	// SameService makes the world's index apply only the cells whose action and
	// resource belong to the same service (and sts on iam roles); see
	// SameServiceRule.
	SameService bool
}

// SameServiceRule is an index.Config.Applies rule: an action applies to a
// resource of its own service, and sts actions to iam roles.
func SameServiceRule(actionPrefix, resourceService string) bool {
	return actionPrefix == resourceService || (actionPrefix == "sts" && resourceService == "iam")
}

// Build assembles the snapshot.
func (w *World) Build() (*model.Snapshot, error) {
	b := snapshot.NewBuilder()
	ids := map[string]string{}
	srcs := make([]string, 0, len(w.Docs))
	for s := range w.Docs {
		srcs = append(srcs, s)
	}
	sort.Strings(srcs)
	for _, s := range srcs {
		d := w.Docs[s]
		ids[s] = b.AddPolicy(policy.Options{Kind: d.Kind, SourceARN: d.Src}, d.Raw).ID
	}
	id := func(src string) string {
		if v, ok := ids[src]; ok {
			return v
		}
		return "absent-" + src // a policy the snapshot refers to but does not hold
	}
	idList := func(ss []string) []string {
		var out []string
		for _, s := range ss {
			out = append(out, id(s))
		}
		return out
	}
	if w.Org != nil {
		o := *w.Org
		o.Nodes = map[string]*model.OrgNode{}
		for k, n := range w.Org.Nodes {
			c := *n
			c.SCPIDs, c.RCPIDs = idList(w.SCP[k]), idList(w.RCP[k])
			o.Nodes[k] = &c
		}
		b.SetOrg(&o)
	}
	for _, wp := range w.Principals {
		p := wp.P
		p.IdentityPolicyIDs = idList(wp.Identity)
		p.SessionPolicyIDs = idList(wp.Session)
		if wp.Boundary != "" {
			p.BoundaryPolicyID = id(wp.Boundary)
		}
		b.AddPrincipal(&p)
	}
	for _, rp := range w.RPs {
		b.AddResourcePolicy(model.ResourcePolicy{ResourceARN: rp.Resource, Kind: rp.Kind, PolicyID: id(rp.Src), RequiresExplicitAllow: rp.Explicit})
	}
	for _, gs := range w.Grants {
		for _, g := range gs {
			b.AddKMSGrant(g)
		}
	}
	for _, s := range w.S3 {
		c := *s
		b.AddS3Bucket(&c)
	}
	for _, r := range w.Resources {
		c := *r
		b.AddResource(&c)
	}
	for k, v := range w.Canon {
		b.SetCanonicalID(k, v)
	}
	return b.Build()
}

// Clone returns a deep enough copy for Mutate: maps and slices that Mutate edits
// are copied; documents are shared because Mutate replaces them whole.
func (w *World) Clone() *World {
	c := *w
	if w.Org != nil {
		o := *w.Org
		o.Nodes = map[string]*model.OrgNode{}
		for k, n := range w.Org.Nodes {
			nc := *n
			o.Nodes[k] = &nc
		}
		c.Org = &o
	}
	cp := func(m map[string][]string) map[string][]string {
		out := map[string][]string{}
		for k, v := range m {
			out[k] = append([]string(nil), v...)
		}
		return out
	}
	c.SCP, c.RCP = cp(w.SCP), cp(w.RCP)
	c.Docs = map[string]*Doc{}
	for k, v := range w.Docs {
		c.Docs[k] = v
	}
	c.Principals = make([]*WPrincipal, len(w.Principals))
	for i, p := range w.Principals {
		q := *p
		q.Identity = append([]string(nil), p.Identity...)
		q.Session = append([]string(nil), p.Session...)
		q.P.Tags = copyMap(p.P.Tags)
		c.Principals[i] = &q
	}
	c.RPs = append([]WRP(nil), w.RPs...)
	c.Grants = map[string][]model.KMSGrant{}
	for k, v := range w.Grants {
		c.Grants[k] = append([]model.KMSGrant(nil), v...)
	}
	c.S3 = map[string]*model.S3BucketState{}
	for k, v := range w.S3 {
		s := *v
		c.S3[k] = &s
	}
	c.Resources = map[string]*model.Resource{}
	for k, v := range w.Resources {
		r := *v
		r.Tags = copyMap(v.Tags)
		c.Resources[k] = &r
	}
	c.Canon = copyMap(w.Canon)
	c.Extra = append([]string(nil), w.Extra...)
	return &c
}

func copyMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// ---------------------------------------------------------------- generator

// Rand is the seeded generator the worlds draw from. The same seed always gives
// the same world.
type Rand struct {
	r *rand.Rand
	// vars lets generated Resource patterns use policy variables. A variable that
	// names an identity key makes every requester its own atom, so most worlds
	// leave them out and the requester atoms can merge.
	vars bool
}

// NewRand returns a generator for a seed.
func NewRand(seed uint64) *Rand {
	return &Rand{r: rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))} // #nosec G404 -- test data, not security
}

// resourcePatterns returns the identity-policy resource pool of this world.
func (g *Rand) resourcePatterns() []string {
	if g.vars {
		return identityResources
	}
	var out []string
	for _, r := range identityResources {
		if !strings.Contains(r, "${") {
			out = append(out, r)
		}
	}
	return out
}

// Intn returns a number in [0, n).
func (g *Rand) Intn(n int) int { return g.r.IntN(n) }

// Chance is true with probability p.
func (g *Rand) Chance(p float64) bool { return g.r.Float64() < p }

func pick[T any](g *Rand, xs []T) T { return xs[g.r.IntN(len(xs))] }

func picks[T any](g *Rand, xs []T, lo, hi int) []T {
	n := lo + g.r.IntN(hi-lo+1)
	out := make([]T, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, xs[g.r.IntN(len(xs))])
	}
	return out
}

var accounts = []string{AcctA, AcctB, AcctC}

var actionPatterns = []string{
	"*", "s3:*", "s3:Get*", "s3:Put*", "s3:GetObject", "s3:PutObject", "s3:ListBucket", "s3:DeleteObject", "s3:GetBucketAcl",
	"s3:PutBucketPolicy", "s3:PutBucketAcl", "s3:*Object", "kms:*", "kms:Decrypt", "kms:Encrypt", "kms:CreateGrant", "kms:RetireGrant",
	"kms:Describe*", "kms:GenerateDataKey", "sts:AssumeRole", "sts:*", "sts:Assume*", "iam:*", "iam:GetUser", "iam:PassRole",
	"sqs:*", "sqs:SendMessage", "sqs:*Message", "sns:Publish", "sns:*", "ec2:Describe*", "ec2:RunInstances", "ec2:*",
	"lambda:Invoke*", "lambda:*", "S3:getobject", "KMS:DECRYPT", "s3:Get?bject", "other:Thing",
}

func (g *Rand) actions() []string { return picks(g, actionPatterns, 1, 3) }

var identityResources = []string{
	"*", "arn:aws:s3:::*", "arn:aws:s3:::bkt-a-1", "arn:aws:s3:::bkt-a-1/*", "arn:aws:s3:::bkt-b-*", "arn:aws:s3:::bkt-*/*",
	"arn:aws:s3:::bkt-c-2", "arn:aws:s3:::bkt-c-2/logs/*", "arn:aws:s3:::bkt-a-1/${aws:username}/*", "arn:aws:s3:::bkt-${aws:PrincipalTag/team}-1",
	"arn:aws:s3:::bkt-a-1/${aws:PrincipalTag/team}/*", "arn:aws:kms:*:*:key/*", "arn:aws:kms:us-east-1:111111111111:key/k1",
	"arn:aws:kms:us-east-1:222222222222:key/*", "arn:aws:sqs:us-east-1:111111111111:*", "arn:aws:sqs:*:*:q1", "arn:aws:sns:us-east-1:*:t1",
	"arn:aws:lambda:us-east-1:333333333333:function:*", "arn:aws:iam::*:role/*", "arn:aws:iam::111111111111:role/app",
	"arn:aws:iam::222222222222:role/svc", "arn:aws:ec2:us-east-1:*:instance/*", "arn:aws:s3:::bkt-a-1/obj1", "arn:aws:s3",
}

var conditions = []map[string]any{
	{"StringEquals": map[string]any{"aws:PrincipalTag/team": "a"}},
	{"StringEquals": map[string]any{"aws:ResourceTag/team": "${aws:PrincipalTag/team}"}},
	{"ArnLike": map[string]any{"aws:PrincipalArn": []string{"arn:aws:iam::111111111111:user/a*", "arn:aws:iam::222222222222:role/*"}}},
	{"StringEquals": map[string]any{"aws:PrincipalAccount": AcctA}},
	{"StringNotEquals": map[string]any{"aws:ResourceAccount": AcctB}},
	{"Bool": map[string]any{"aws:SecureTransport": "true"}},
	{"IpAddress": map[string]any{"aws:SourceIp": "10.0.0.0/8"}},
	{"StringEquals": map[string]any{"aws:username": "alice"}},
	{"StringLike": map[string]any{"aws:userid": "AIDAA*"}},
	{"Null": map[string]any{"aws:PrincipalTag/team": "false"}},
	{"StringEquals": map[string]any{"aws:PrincipalOrgID": "o-abc123"}},
	{"StringEqualsIgnoreCase": map[string]any{"aws:PrincipalTag/env": "PROD"}},
	{"StringEquals": map[string]any{"aws:ResourceTag/env": "prod"}},
	{"StringEquals": map[string]any{"s3:x-amz-acl": "private"}},
	{"StringEquals": map[string]any{"aws:PrincipalArn": "arn:aws:iam::111111111111:role/app"}},
	{"DateGreaterThan": map[string]any{"aws:CurrentTime": "2020-01-01T00:00:00Z"}},
	{"StringEquals": map[string]any{"aws:SourceVpce": "vpce-1"}},
}

var principalElems = []any{
	AcctA, AcctB, AcctC, "arn:aws:iam::" + AcctA + ":root", "*", map[string]any{"AWS": "*"},
	map[string]any{"AWS": "arn:aws:iam::" + AcctA + ":user/alice"},
	map[string]any{"AWS": []string{"arn:aws:iam::" + AcctB + ":role/svc", "arn:aws:iam::" + AcctA + ":user/bob"}},
	map[string]any{"AWS": "arn:aws:iam::" + AcctA + ":role/app"},
	map[string]any{"Service": "sns.amazonaws.com"}, map[string]any{"Service": "lambda.amazonaws.com"},
	map[string]any{"AWS": "arn:aws:sts::" + AcctA + ":assumed-role/app/s1"},
	map[string]any{"AWS": "AIDAALICE"}, map[string]any{"CanonicalUser": "canon-b"},
}

func (g *Rand) statement(kind model.PolicyKind, resource string) map[string]any {
	st := map[string]any{}
	deny := g.Chance(0.2)
	st["Effect"] = map[bool]string{true: "Deny", false: "Allow"}[deny]
	if g.Chance(0.1) {
		st["NotAction"] = g.actions()
	} else {
		st["Action"] = g.actions()
	}
	rb := kind.IsResourceBased()
	switch {
	case kind == model.PolicySCP || kind == model.PolicyRCP:
		if !deny && g.Chance(0.85) {
			st["Action"], st["Resource"] = "*", "*"
			delete(st, "NotAction")
		} else {
			st["Resource"] = "*"
		}
	case rb:
		if g.Chance(0.6) {
			st["Resource"] = pick(g, []string{resource, resource + "/*", "*"})
		}
	case g.Chance(0.07):
		st["NotResource"] = picks(g, g.resourcePatterns(), 1, 2)
	default:
		st["Resource"] = picks(g, g.resourcePatterns(), 1, 3)
	}
	if rb || kind == model.PolicyRCP {
		switch {
		case kind == model.PolicyRCP:
			st["Principal"] = "*"
		case deny && g.Chance(0.2):
			st["NotPrincipal"] = map[string]any{"AWS": AcctA}
		default:
			st["Principal"] = pick(g, principalElems)
		}
	}
	if g.Chance(0.35) {
		c := map[string]any{}
		for _, one := range picks(g, conditions, 1, 2) {
			for op, kv := range one {
				c[op] = kv
			}
		}
		st["Condition"] = c
	}
	return st
}

func (g *Rand) doc(kind model.PolicyKind, resource string, n int) []byte {
	var sts []any
	for i := 0; i < n; i++ {
		sts = append(sts, g.statement(kind, resource))
	}
	b, _ := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": sts})
	return b
}

// NewWorld returns a random small tenant. The same seed gives the same world.
func NewWorld(seed uint64) *World {
	g := NewRand(seed)
	g.vars = g.Chance(0.3)
	sameService := g.Chance(0.5)
	w := &World{
		Docs: map[string]*Doc{}, Grants: map[string][]model.KMSGrant{}, S3: map[string]*model.S3BucketState{},
		Resources: map[string]*model.Resource{}, SCP: map[string][]string{}, RCP: map[string][]string{},
		Canon: map[string]string{"canon-a": AcctA, "canon-b": AcctB}, SameService: sameService,
	}
	addDoc := func(kind model.PolicyKind, src, resource string, n int) string {
		w.Docs[src] = &Doc{Kind: kind, Src: src, Raw: g.doc(kind, resource, n)}
		return src
	}

	// Organization.
	if g.Chance(0.75) {
		o := &model.Organization{OrgID: "o-abc123", ManagementAccountID: pick(g, []string{AcctM, AcctM, AcctC}),
			SCPEnabled: g.Chance(0.85), RCPEnabled: g.Chance(0.6), Nodes: map[string]*model.OrgNode{}}
		o.Nodes["r-1"] = &model.OrgNode{ID: "r-1", Kind: model.OrgRoot}
		o.Nodes["ou-1"] = &model.OrgNode{ID: "ou-1", Kind: model.OrgOU, ParentID: "r-1"}
		o.Nodes["ou-2"] = &model.OrgNode{ID: "ou-2", Kind: model.OrgOU, ParentID: "ou-1"}
		place := []struct{ acct, parent string }{{AcctA, "ou-1"}, {AcctB, "ou-2"}, {AcctC, pick(g, []string{"ou-1", "r-1"})}, {AcctM, "r-1"}}
		for _, pl := range place {
			if pl.acct == AcctC && g.Chance(0.15) {
				continue // an account outside the organization
			}
			o.Nodes[pl.acct] = &model.OrgNode{ID: pl.acct, Kind: model.OrgAccount, ParentID: pl.parent}
		}
		w.Org = o
		// FullAWSAccess at the root, then random list or deny SCPs lower down.
		w.Docs["scp/full"] = &Doc{Kind: model.PolicySCP, Src: "scp/full",
			Raw: []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`)}
		w.SCP["r-1"] = []string{"scp/full"}
		for _, n := range []string{"ou-1", "ou-2", AcctA, AcctB} {
			if _, ok := o.Nodes[n]; !ok {
				continue
			}
			switch {
			case g.Chance(0.5):
				w.SCP[n] = []string{"scp/full"}
			case g.Chance(0.5):
				w.SCP[n] = []string{addDoc(model.PolicySCP, "scp/"+n, "*", 1+g.Intn(3))}
			}
		}
		for _, n := range []string{"r-1", "ou-1", "ou-2"} {
			if g.Chance(0.4) {
				w.RCP[n] = []string{addDoc(model.PolicyRCP, "rcp/"+n, "*", 1+g.Intn(2))}
			}
		}
	}

	// Managed identity policies, boundaries and session policies.
	var managed []string
	for i := 0; i < 5; i++ {
		managed = append(managed, addDoc(model.PolicyIdentity, fmt.Sprintf("arn:aws:iam::%s:policy/m%d", pick(g, accounts), i), "*", 1+g.Intn(4)))
	}
	allow := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
	w.Docs["pb/open"] = &Doc{Kind: model.PolicyBoundary, Src: "pb/open", Raw: []byte(allow)}
	boundaries := []string{"pb/open", addDoc(model.PolicyBoundary, "pb/b1", "*", 1+g.Intn(3)), addDoc(model.PolicyBoundary, "pb/b2", "*", 1+g.Intn(3))}
	sessions := []string{addDoc(model.PolicySession, "sp/s1", "*", 1+g.Intn(3)), addDoc(model.PolicySession, "sp/s2", "*", 1+g.Intn(2))}
	if g.Chance(0.12) {
		w.Docs["arn:aws:iam::"+AcctA+":policy/broken"] = &Doc{Kind: model.PolicyIdentity, Src: "arn:aws:iam::" + AcctA + ":policy/broken", Raw: []byte(`{"Statement": [`)}
		managed = append(managed, "arn:aws:iam::"+AcctA+":policy/broken")
	}
	if g.Chance(0.1) {
		managed = append(managed, "arn:aws:iam::"+AcctB+":policy/not-in-snapshot")
	}

	tags := func() map[string]string {
		t := map[string]string{}
		if g.Chance(0.6) {
			t["team"] = pick(g, []string{"a", "b"})
		}
		if g.Chance(0.4) {
			t["env"] = pick(g, []string{"prod", "dev", "Prod"})
		}
		if len(t) == 0 {
			return nil
		}
		return t
	}
	addPrincipal := func(p model.Principal, session bool) {
		wp := &WPrincipal{P: p}
		wp.Identity = picks(g, managed, 0, 3)
		if g.Chance(0.4) {
			wp.Identity = append(wp.Identity, addDoc(model.PolicyIdentity, p.ARN+"#inline", "*", 1+g.Intn(3)))
		}
		if g.Chance(0.3) {
			wp.Boundary = pick(g, boundaries)
		}
		if session {
			wp.Session = []string{pick(g, sessions)}
		}
		w.Principals = append(w.Principals, wp)
	}
	users := []string{"alice", "bob", "amy", "carol"}
	for i, u := range users {
		acct := accounts[i%len(accounts)]
		arn := "arn:aws:iam::" + acct + ":user/" + u
		addPrincipal(model.Principal{ARN: arn, Kind: model.IAMUser, AccountID: acct, UniqueID: "AIDA" + strings.ToUpper(u), Path: "/", Tags: tags()}, false)
	}
	roles := []struct{ acct, name, path string }{{AcctA, "app", "/"}, {AcctB, "svc", "/"}, {AcctC, "etl", "/"}, {AcctA, "slr", "/aws-service-role/"}}
	for _, r := range roles {
		arn := "arn:aws:iam::" + r.acct + ":role" + r.path + r.name
		addPrincipal(model.Principal{ARN: arn, Kind: model.IAMRole, AccountID: r.acct, UniqueID: "AROA" + strings.ToUpper(r.name), Path: r.path,
			IsServiceLinked: r.path != "/", Tags: tags()}, false)
		w.RPs = append(w.RPs, WRP{Resource: arn, Kind: model.PolicyTrust, Src: addDoc(model.PolicyTrust, arn+"#trust", arn, 1+g.Intn(2)), Explicit: true})
		w.Resources[arn] = &model.Resource{ARN: arn, Type: "role", AccountID: r.acct, Region: ""}
	}
	// Twins: principals with the same policies and tags but another name, which
	// are interchangeable unless a policy tells them apart.
	for _, src := range []int{0, 4} {
		if g.Chance(0.7) && src < len(w.Principals) {
			twin := *w.Principals[src]
			twin.Identity = append([]string(nil), twin.Identity...)
			twin.P.ARN += "-twin"
			twin.P.UniqueID += "TWIN"
			w.Principals = append(w.Principals, &twin)
			if g.Chance(0.6) { // the same again with other tags: only a tag condition tells them apart
				retag := twin
				retag.Identity = append([]string(nil), twin.Identity...)
				retag.P.ARN += "2"
				retag.P.Tags = tags()
				w.Principals = append(w.Principals, &retag)
			}
		}
	}
	if g.Chance(0.7) {
		sess := "arn:aws:sts::" + AcctA + ":assumed-role/app/s1"
		addPrincipal(model.Principal{ARN: sess, Kind: model.RoleSession, AccountID: AcctA, EntityARN: "arn:aws:iam::" + AcctA + ":role/app",
			SessionTags: tags(), SourceIdentity: pick(g, []string{"", "ci"})}, true)
	}
	if g.Chance(0.3) {
		sess := "arn:aws:sts::" + AcctB + ":federated-user/fred"
		addPrincipal(model.Principal{ARN: sess, Kind: model.FederatedUserSession, AccountID: AcctB, EntityARN: "arn:aws:iam::" + AcctB + ":user/amy"}, g.Chance(0.5))
	}
	if g.Chance(0.5) {
		w.Principals = append(w.Principals, &WPrincipal{P: model.Principal{ARN: "sns.amazonaws.com", Kind: model.Service}})
	}
	if g.Chance(0.4) {
		w.Principals = append(w.Principals, &WPrincipal{P: model.Principal{ARN: "arn:aws:iam::" + AcctA + ":root", Kind: model.Root, AccountID: AcctA}})
	}

	// Resources: buckets, keys, queues, topics, functions.
	acctOf := map[string]string{"a": AcctA, "b": AcctB, "c": AcctC}
	rpN := 0
	addRP := func(res string, kind model.PolicyKind, explicit bool, n int) {
		rpN++
		src := fmt.Sprintf("%s#rp%d", res, rpN)
		w.RPs = append(w.RPs, WRP{Resource: res, Kind: kind, Src: addDoc(kind, src, res, n), Explicit: explicit})
	}
	for _, l := range []string{"a", "b", "c"} {
		for i := 1; i <= 2; i++ {
			bucket := fmt.Sprintf("arn:aws:s3:::bkt-%s-%d", l, i)
			w.Resources[bucket] = &model.Resource{ARN: bucket, Type: "bucket", AccountID: acctOf[l], Region: "us-east-1", Tags: tags()}
			st := &model.S3BucketState{BucketARN: bucket, OwnerAccount: acctOf[l],
				ObjectOwnership: pick(g, []string{"BucketOwnerEnforced", "BucketOwnerPreferred", "ObjectWriter"})}
			if g.Chance(0.3) {
				st.BucketACL = []model.ACLGrant{pick(g, []model.ACLGrant{
					{GranteeType: "Group", Grantee: AllUsersURI, Permission: "READ"},
					{GranteeType: "Group", Grantee: AuthenticatedUsersURI, Permission: "FULL_CONTROL"},
					{GranteeType: "CanonicalUser", Grantee: "canon-b", Permission: "WRITE"},
					{GranteeType: "Group", Grantee: LogDeliveryURI, Permission: "WRITE_ACP"},
				})}
			}
			if g.Chance(0.2) {
				st.ObjectACLs = map[string][]model.ACLGrant{bucket + "/obj1": {{GranteeType: "Group", Grantee: AllUsersURI, Permission: "READ"}}}
			}
			if g.Chance(0.25) {
				st.BPABucket = model.BPA{IgnorePublicAcls: g.Chance(0.5), RestrictPublicBuckets: g.Chance(0.5), BlockPublicAcls: g.Chance(0.5), BlockPublicPolicy: g.Chance(0.5)}
			}
			w.S3[bucket] = st
			if g.Chance(0.6) {
				addRP(bucket, model.PolicyResource, false, 1+g.Intn(3))
			}
		}
	}
	w.Extra = append(w.Extra, "arn:aws:s3:::bkt-a-1/obj1", "arn:aws:s3:::bkt-a-1/obj2", "arn:aws:s3:::bkt-b-1/key", "arn:aws:s3:::bkt-c-2/logs/x",
		"arn:aws:s3:::bkt-a-1/alice/f", "arn:aws:s3:::bkt-a-1/a/f", "arn:aws:s3:::bkt-a-1/b/f", "arn:aws:s3:::bkt-zzz")
	for _, l := range []string{"a", "b"} {
		key := fmt.Sprintf("arn:aws:kms:us-east-1:%s:key/k1", acctOf[l])
		w.Resources[key] = &model.Resource{ARN: key, Type: "key", AccountID: acctOf[l], Region: "us-east-1", Tags: tags()}
		addRP(key, model.PolicyKMSKey, true, 1+g.Intn(2))
		if g.Chance(0.5) {
			grantee := pick(g, []string{"arn:aws:iam::" + AcctA + ":role/app", "arn:aws:iam::" + AcctA + ":user/alice", "arn:aws:iam::" + AcctB + ":root", "sns.amazonaws.com"})
			gr := model.KMSGrant{KeyARN: key, GrantID: "g1", GranteePrincipal: grantee, Operations: picks(g, []string{"Decrypt", "Encrypt", "GenerateDataKey", "RetireGrant"}, 1, 2)}
			if g.Chance(0.3) {
				gr.ConstraintsECEquals = map[string]string{"purpose": "x"}
			}
			if g.Chance(0.2) {
				gr.RetiringPrincipal = "arn:aws:iam::" + AcctA + ":user/bob"
			}
			w.Grants[key] = []model.KMSGrant{gr}
		}
	}
	for _, q := range []string{"arn:aws:sqs:us-east-1:" + AcctA + ":q1", "arn:aws:sqs:us-east-1:" + AcctB + ":q1", "arn:aws:sns:us-east-1:" + AcctA + ":t1"} {
		acct := strings.Split(q, ":")[4]
		w.Resources[q] = &model.Resource{ARN: q, Type: "queue", AccountID: acct, Region: "us-east-1", Tags: tags()}
		if g.Chance(0.6) {
			addRP(q, model.PolicyResource, false, 1+g.Intn(2))
		}
	}
	w.Resources["arn:aws:lambda:us-east-1:"+AcctC+":function:f1"] = &model.Resource{ARN: "arn:aws:lambda:us-east-1:" + AcctC + ":function:f1", Type: "function", AccountID: AcctC, Region: "us-east-1", Tags: tags()}
	w.Resources["arn:aws:ec2:us-east-1:"+AcctA+":instance/i-1"] = &model.Resource{ARN: "arn:aws:ec2:us-east-1:" + AcctA + ":instance/i-1", Type: "instance", AccountID: AcctA, Region: "us-east-1"}
	return w
}

// Mutate changes the world the way a policy pull request does and says what it
// did. The same generator state gives the same change.
func (w *World) Mutate(g *Rand) string {
	srcs := make([]string, 0, len(w.Docs))
	for s := range w.Docs {
		srcs = append(srcs, s)
	}
	sort.Strings(srcs)
	switch g.Intn(12) {
	case 0, 1: // edit a document
		s := pick(g, srcs)
		d := *w.Docs[s]
		d.Raw = g.doc(d.Kind, strings.TrimSuffix(s, "#trust"), 1+g.Intn(3))
		w.Docs[s] = &d
		return "edit " + s
	case 2: // attach a managed policy
		p := pick(g, w.Principals)
		if len(p.P.ARN) > 0 && p.P.Kind != model.Service && p.P.Kind != model.Root {
			s := pick(g, srcs)
			if w.Docs[s].Kind == model.PolicyIdentity {
				p.Identity = append(p.Identity, s)
				return "attach " + s + " to " + p.P.ARN
			}
		}
		return "noop"
	case 3: // detach
		p := pick(g, w.Principals)
		if len(p.Identity) > 0 {
			p.Identity = p.Identity[1:]
			return "detach from " + p.P.ARN
		}
		return "noop"
	case 4: // SCP change
		if w.Org == nil {
			return "noop"
		}
		n := pick(g, []string{"ou-1", "ou-2", "r-1"})
		w.Docs["scp/new"] = &Doc{Kind: model.PolicySCP, Src: "scp/new", Raw: g.doc(model.PolicySCP, "*", 1+g.Intn(2))}
		w.SCP[n] = append(append([]string(nil), w.SCP[n]...), "scp/new")
		return "attach scp/new at " + n
	case 5: // RCP change
		if w.Org == nil {
			return "noop"
		}
		n := pick(g, []string{"ou-1", "ou-2", "r-1"})
		w.Docs["rcp/new"] = &Doc{Kind: model.PolicyRCP, Src: "rcp/new", Raw: g.doc(model.PolicyRCP, "*", 1)}
		w.RCP[n] = append(append([]string(nil), w.RCP[n]...), "rcp/new")
		return "attach rcp/new at " + n
	case 6: // a new bucket policy
		res := pick(g, []string{"arn:aws:s3:::bkt-a-1", "arn:aws:s3:::bkt-b-2", "arn:aws:sqs:us-east-1:" + AcctA + ":q1"})
		src := res + "#new"
		w.Docs[src] = &Doc{Kind: model.PolicyResource, Src: src, Raw: g.doc(model.PolicyResource, res, 1+g.Intn(2))}
		w.RPs = append(w.RPs, WRP{Resource: res, Kind: model.PolicyResource, Src: src})
		return "put policy on " + res
	case 7: // a new resource
		res := fmt.Sprintf("arn:aws:s3:::bkt-a-%d", 3+g.Intn(2))
		w.Resources[res] = &model.Resource{ARN: res, Type: "bucket", AccountID: AcctA, Region: "us-east-1"}
		return "create " + res
	case 8: // tags
		p := pick(g, w.Principals)
		if p.P.Kind == model.IAMUser || p.P.Kind == model.IAMRole {
			p.P.Tags = map[string]string{"team": pick(g, []string{"a", "b"})}
			return "retag " + p.P.ARN
		}
		return "noop"
	case 9: // S3 public access block
		buckets := make([]string, 0, len(w.S3))
		for k := range w.S3 {
			buckets = append(buckets, k)
		}
		sort.Strings(buckets)
		s := w.S3[pick(g, buckets)]
		s.BPABucket.RestrictPublicBuckets = !s.BPABucket.RestrictPublicBuckets
		s.BPABucket.IgnorePublicAcls = !s.BPABucket.IgnorePublicAcls
		return "flip bpa " + s.BucketARN
	case 10: // a principal leaves
		if len(w.Principals) > 3 {
			i := g.Intn(len(w.Principals))
			gone := w.Principals[i].P.ARN
			w.Principals = append(w.Principals[:i:i], w.Principals[i+1:]...)
			return "remove " + gone
		}
		return "noop"
	default: // a new principal joins
		arn := fmt.Sprintf("arn:aws:iam::%s:user/new%d", pick(g, accounts), g.Intn(100))
		w.Principals = append(w.Principals, &WPrincipal{P: model.Principal{ARN: arn, Kind: model.IAMUser, AccountID: strings.Split(arn, ":")[4], UniqueID: "AIDANEW", Path: "/"},
			Identity: picks(g, srcs[:min(len(srcs), 3)], 0, 1)})
		return "add " + arn
	}
}
