package awsorg

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/sigv4"
)

// Collector reads one estate. Accounts are read one after another, so a run is
// deterministic and a recorded replay can be sequenced.
type Collector struct {
	Client *Client
	Config *Config
	// Base are the keys AssumeRole is signed with.
	Base sigv4.Credentials
	// ExternalID is the sts:ExternalId sent on every AssumeRole.
	ExternalID string
	// Now stamps the snapshot (default time.Now).
	Now func() time.Time
}

type accountSession struct {
	session
	expires time.Time
}

func (c *Collector) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// assume returns a session in the account, assumed from the base keys.
func (c *Collector) assume(ctx context.Context, cache map[string]*accountSession, account string) (*accountSession, error) {
	// reuse a session until five minutes before it expires (an unparseable
	// expiry is zero: assume again each time)
	if s := cache[account]; s != nil && !s.expires.IsZero() && c.now().Add(5*time.Minute).Before(s.expires) {
		return s, nil
	}
	base := session{cl: c.Client, creds: c.Base}
	roleARN := "arn:aws:iam::" + account + ":role/" + c.Config.RoleName
	creds, exp, err := base.assumeRole(ctx, c.Config.Regions[0], roleARN, c.ExternalID, "tessera-collect")
	if err != nil {
		return nil, err
	}
	s := &accountSession{session: session{cl: c.Client, creds: creds}, expires: exp}
	cache[account] = s
	return s, nil
}

// Collect reads the estate and returns its snapshot. It fails only when the
// run cannot give a snapshot worth keeping: the organization (when one is
// configured) cannot be read, or no account can be read. Everything else that
// cannot be read becomes a Finding.
func (c *Collector) Collect(ctx context.Context) (*Collection, error) {
	if err := c.Config.Validate(); err != nil {
		return nil, err
	}
	b := newBuilder(c.now())
	cache := map[string]*accountSession{}

	accounts := slices.Clone(c.Config.AccountIDs)
	var mgmt *accountSession
	if c.Config.ManagementAccountID != "" {
		var err error
		if mgmt, err = c.assume(ctx, cache, c.Config.ManagementAccountID); err != nil {
			return nil, fmt.Errorf("awsorg: assume the role in the management account: %w", err)
		}
		tree, err := c.collectOrg(ctx, b, mgmt.session)
		if err != nil {
			return nil, fmt.Errorf("awsorg: read the organization: %w", err)
		}
		accounts = c.selectAccounts(b, tree)
	}

	var read []string
	for _, acct := range accounts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		s, err := c.assume(ctx, cache, acct)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			b.gap(acct, errCode(err), "cannot assume the reader role: "+errDetail(err), Scope{Type: ScopeAccounts, Targets: []string{acct}})
			continue
		}
		read = append(read, acct)
		c.collectAccount(ctx, b, s.session, acct)
	}
	if len(read) == 0 {
		return nil, errors.New("awsorg: no account could be read")
	}

	if mgmt != nil && c.Config.IdentityCenterRegion != "" {
		if s, err := c.assume(ctx, cache, c.Config.ManagementAccountID); err == nil {
			c.collectIdentityCenter(ctx, b, s.session, read)
		} else {
			b.gap(c.Config.ManagementAccountID, errCode(err), "Identity Center: "+errDetail(err), Scope{Type: ScopeAccounts, Targets: read})
		}
	}
	return b.finish(read)
}

// collectAccount reads IAM, S3 and the regional services of one account.
// Nothing here aborts the run: a failed read is a finding that covers what it
// could have changed.
func (c *Collector) collectAccount(ctx context.Context, b *builder, s session, account string) {
	acctScope := Scope{Type: ScopeAccounts, Targets: []string{account}}

	d, err := s.getAccountAuthorizationDetails(ctx)
	if err != nil {
		b.gap(account, errCode(err), "iam GetAccountAuthorizationDetails: "+errDetail(err), acctScope)
	} else {
		b.addIAM(account, d)
	}

	c.collectS3(ctx, b, s, account)
	for _, region := range c.Config.Regions {
		c.collectRegion(ctx, b, s, account, region)
	}
}

// selectAccounts picks the accounts of the organization to read: the active
// ones, narrowed to Config.AccountIDs when that is set.
func (c *Collector) selectAccounts(b *builder, tree *orgTree) []string {
	var out []string
	for _, a := range tree.accounts {
		if len(c.Config.AccountIDs) > 0 && !slices.Contains(c.Config.AccountIDs, a.ID) {
			continue
		}
		if a.Status != "" && a.Status != "ACTIVE" {
			b.gap(a.ID, "AccountNotActive", "account status is "+a.Status, Scope{Type: ScopeAccounts, Targets: []string{a.ID}})
			continue
		}
		out = append(out, a.ID)
	}
	for _, want := range c.Config.AccountIDs {
		if !slices.ContainsFunc(tree.accounts, func(a orgNodeRef) bool { return a.ID == want }) {
			b.gap(want, "AccountNotInOrganization", "the configured account is not in the organization", Scope{Type: ScopeAccounts, Targets: []string{want}})
		}
	}
	slices.Sort(out)
	return out
}

// ---------------------------------------------------------------- organization

type orgTree struct {
	accounts []orgNodeRef
	children map[string][]string // node id -> child node ids
}

// accountsUnder returns the account ids at or below a node.
func (t *orgTree) accountsUnder(b *builder, id string) []string {
	var out []string
	var walk func(string)
	walk = func(n string) {
		if node := b.snap.Org.Nodes[n]; node != nil && node.Kind == model.OrgAccount {
			out = append(out, n)
		}
		for _, ch := range t.children[n] {
			walk(ch)
		}
	}
	walk(id)
	return out
}

// collectOrg reads the organization tree, SCPs and RCPs into b.snap.Org. Any
// failure to read the tree fails the run (SCPs of an unread tree are unknown);
// a failure to read one policy is a finding over every account.
func (c *Collector) collectOrg(ctx context.Context, b *builder, s session) (*orgTree, error) {
	info, err := s.describeOrganization(ctx)
	if err != nil {
		return nil, err
	}
	org := &model.Organization{OrgID: info.ID, ManagementAccountID: info.ManagementAccount, Nodes: map[string]*model.OrgNode{},
		SCPEnabled: info.SCPEnabled, RCPEnabled: info.RCPEnabled}
	b.snap.Org = org
	tree := &orgTree{children: map[string][]string{}}

	roots, err := s.listRoots(ctx)
	if err != nil {
		return nil, err
	}
	var queue []string
	for _, r := range roots {
		org.Nodes[r.ID] = &model.OrgNode{ID: r.ID, Kind: model.OrgRoot, Name: r.Name}
		queue = append(queue, r.ID)
	}
	for len(queue) > 0 {
		parent := queue[0]
		queue = queue[1:]
		ous, err := s.listOUs(ctx, parent)
		if err != nil {
			return nil, err
		}
		for _, ou := range ous {
			if _, dup := org.Nodes[ou.ID]; dup {
				return nil, fmt.Errorf("organization node %s listed twice", ou.ID)
			}
			org.Nodes[ou.ID] = &model.OrgNode{ID: ou.ID, Kind: model.OrgOU, ParentID: parent, Name: ou.Name}
			tree.children[parent] = append(tree.children[parent], ou.ID)
			queue = append(queue, ou.ID)
		}
		accts, err := s.listAccounts(ctx, parent)
		if err != nil {
			return nil, err
		}
		for _, a := range accts {
			if _, dup := org.Nodes[a.ID]; dup {
				return nil, fmt.Errorf("organization node %s listed twice", a.ID)
			}
			org.Nodes[a.ID] = &model.OrgNode{ID: a.ID, Kind: model.OrgAccount, ParentID: parent, Name: a.Name}
			tree.children[parent] = append(tree.children[parent], a.ID)
			tree.accounts = append(tree.accounts, a)
		}
	}

	allAccounts := make([]string, 0, len(tree.accounts))
	for _, a := range tree.accounts {
		allAccounts = append(allAccounts, a.ID)
	}
	slices.Sort(allAccounts)
	for _, pt := range []struct {
		enabled bool
		filter  string
		kind    model.PolicyKind
		att     model.AttachmentType
		scope   ScopeType
	}{
		{info.SCPEnabled, policyTypeSCP, model.PolicySCP, model.AttachSCP, ScopeRequesterAccounts},
		{info.RCPEnabled, policyTypeRCP, model.PolicyRCP, model.AttachRCP, ScopeResourceAccounts},
	} {
		if !pt.enabled {
			continue
		}
		pols, err := s.listPolicies(ctx, pt.filter)
		if err != nil {
			return nil, err
		}
		for _, p := range pols {
			c.collectOrgPolicy(ctx, b, s, tree, allAccounts, p, pt.kind, pt.att, pt.scope)
		}
	}
	return tree, nil
}

func (c *Collector) collectOrgPolicy(ctx context.Context, b *builder, s session, tree *orgTree, all []string, p orgPolicySummary,
	kind model.PolicyKind, att model.AttachmentType, scope ScopeType) {
	// until we know where it is attached, a policy we cannot read could be anywhere
	everywhere := Scope{Type: scope, Targets: all}
	content, err := s.describePolicy(ctx, p.ID)
	if err != nil {
		b.gap(p.ARN, errCode(err), "organizations DescribePolicy: "+errDetail(err), everywhere)
		return
	}
	targets, err := s.listTargetsForPolicy(ctx, p.ID)
	if err != nil {
		b.gap(p.ARN, errCode(err), "organizations ListTargetsForPolicy: "+errDetail(err), everywhere)
		return
	}
	ref := b.parseDoc(kind, p.ARN, sha256Hex([]byte(content)), content, p.AWSManaged, Scope{Type: scope})
	for _, t := range targets {
		node := b.snap.Org.Nodes[t]
		if node == nil {
			b.gap(p.ARN, "UnknownTarget", "policy is attached to "+t+", which is not in the organization tree", everywhere)
			continue
		}
		for _, a := range tree.accountsUnder(b, t) {
			b.addTargets(ref, a)
		}
		if !ref.ok() {
			continue
		}
		if kind == model.PolicySCP {
			node.SCPIDs = append(node.SCPIDs, ref.id)
		} else {
			node.RCPIDs = append(node.RCPIDs, ref.id)
		}
		b.snap.Attachments = append(b.snap.Attachments, model.PolicyAttachment{PolicyID: ref.id, TargetARN: t, AttachmentType: att})
	}
}

// ---------------------------------------------------------------- Identity Center

// collectIdentityCenter maps Identity Center permission sets to the
// AWSReservedSSO_ roles they provision in each account. The permission sets'
// policies are not read: the provisioned role carries them, and the IAM
// details of its account already hold them.
func (c *Collector) collectIdentityCenter(ctx context.Context, b *builder, s session, accounts []string) {
	region := c.Config.IdentityCenterRegion
	gapScope := Scope{Type: ScopeAccounts, Targets: accounts}
	insts, err := s.listSSOInstances(ctx, region)
	if err != nil {
		b.gap("sso:"+region, errCode(err), "sso ListInstances: "+errDetail(err), gapScope)
		return
	}
	for _, inst := range insts {
		sets, err := s.listPermissionSets(ctx, region, inst.ARN)
		if err != nil {
			b.gap(inst.ARN, errCode(err), "sso ListPermissionSets: "+errDetail(err), gapScope)
			continue
		}
		for _, setARN := range sets {
			name, err := s.describePermissionSetName(ctx, region, inst.ARN, setARN)
			if err != nil {
				b.gap(setARN, errCode(err), "sso DescribePermissionSet: "+errDetail(err), gapScope)
				continue
			}
			for _, acct := range accounts {
				as, err := s.listAccountAssignments(ctx, region, inst.ARN, setARN, acct)
				if err != nil {
					b.gap(setARN, errCode(err), "sso ListAccountAssignments: "+errDetail(err), Scope{Type: ScopeAccounts, Targets: []string{acct}})
					continue
				}
				role := reservedSSORole(b, acct, name)
				for _, a := range as {
					a.PermissionSetName, a.RoleARN = name, role
					b.sso = append(b.sso, a)
				}
			}
		}
	}
}

// reservedSSORole finds the role Identity Center provisioned for a permission
// set in an account: AWSReservedSSO_<name>_<hash> under /aws-reserved/sso.amazonaws.com/.
func reservedSSORole(b *builder, account, permissionSet string) string {
	want := "AWSReservedSSO_" + permissionSet + "_"
	for _, arn := range sortedKeys(b.snap.Principals) {
		p := b.snap.Principals[arn]
		if p.Kind == model.IAMRole && p.AccountID == account && strings.HasPrefix(arn[strings.LastIndex(arn, "/")+1:], want) {
			return arn
		}
	}
	return ""
}
