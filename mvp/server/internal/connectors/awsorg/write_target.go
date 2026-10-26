package awsorg

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// WriteTarget is the provisioning target of an AWS estate (issue #660, LP-4): it takes access away (detach, delete
// an inline policy, a new default version of a managed policy, a group removal, an Identity Center assignment) and
// puts it back, and it never believes its own write. Apply reads the current state with the reader role, writes with
// the writer role, and Verify re-reads with the reader role and compares what it finds with the state the change
// should have left. A re-read that differs is a verdict that is not OK, which the engine turns into a mismatch and
// a finding.
//
// Every call goes through Client, whose HTTP is the safehttp client in production. The credentials are federated
// (the reader's and the writer's tokens have different subjects): there is no stored key.
type WriteTarget struct {
	Client *Client
	// Config is the connector the target writes through: its accounts, Identity Center region and management
	// account bound where the target may write.
	Config *Config
	// WriterRole is the role assumed in each account (default DefaultWriterRoleName); the reader role is Config.RoleName.
	WriterRole string
	// ReaderToken and WriterToken mint the web identity tokens of the two roles.
	ReaderToken, WriterToken TokenSource
	// Now defaults to time.Now.
	Now func() time.Time

	mu       sync.Mutex
	sessions map[string]*accountSession
	requests map[string]string // idempotency key -> the Identity Center request id of the last write
}

var (
	nameRE      = regexp.MustCompile(`^[\w+=,.@-]{1,128}$`)
	policyARNRE = regexp.MustCompile(`^arn:aws:iam::([0-9]{12}|aws):policy/[\w+=,.@/-]{1,512}$`)
	versionRE   = regexp.MustCompile(`^v[0-9]{1,4}$`)
	ssoARNRE    = regexp.MustCompile(`^arn:aws:sso:::(instance|permissionSet)/[\w/.-]{1,200}$`)
	ssoIDRE     = regexp.MustCompile(`^[0-9A-Za-z-]{1,64}$`)
	iamARNRE    = regexp.MustCompile(`^arn:aws:iam::([0-9]{12}):(role|user|group)/([\w+=,.@/-]{1,512})$`)
)

// maxDocBytes bounds a document in a request: IAM's own limit for a managed policy is 6144 characters.
const maxDocBytes = 10240

func (w *WriteTarget) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now()
}

func (w *WriteTarget) writerRole() string {
	if w.WriterRole != "" {
		return w.WriterRole
	}
	return DefaultWriterRoleName
}

// principal is the IAM principal of a request.
type principal struct{ account, kind, name string }

// parsePrincipal reads the ARN of a role, user or group. The name is the last segment (IAM calls take the name, not
// the path).
func parsePrincipal(arn string) (principal, error) {
	m := iamARNRE.FindStringSubmatch(arn)
	if m == nil {
		return principal{}, errors.New("the principal is not the ARN of an IAM role, user or group")
	}
	name := m[3][strings.LastIndex(m[3], "/")+1:]
	if !nameRE.MatchString(name) {
		return principal{}, errors.New("the principal's name is not a valid IAM name")
	}
	return principal{account: m[1], kind: m[2], name: name}, nil
}

// plan is a request checked and resolved: where it acts and as what.
type plan struct {
	req     target.Request
	aw      *target.AWSChange
	account string // the account whose roles are assumed
	pr      principal
}

// check validates a request against the grammar of its kind and the bounds of the connector. Nothing it accepts
// can name a resource outside the connector's accounts, a Tessera role, or a service-linked or Identity Center role.
func (w *WriteTarget) check(req target.Request) (*plan, error) {
	aw := req.AWS
	if !target.IsAWSKind(req.Kind) || aw == nil {
		return nil, target.Permanent("not an AWS change")
	}
	p := &plan{req: req, aw: aw}
	switch req.Kind {
	case target.AWSDeleteAssignment, target.AWSCreateAssignment:
		return w.checkSSO(p)
	}
	pr, err := parsePrincipal(req.Account.Username)
	if err != nil {
		return nil, target.Permanent("%v", err)
	}
	p.pr, p.account = pr, pr.account
	switch {
	case aw.PrincipalType != "" && aw.PrincipalType != pr.kind:
		return nil, target.Permanent("principal_type does not match the principal's ARN")
	case len(w.Config.AccountIDs) > 0 && !slices.Contains(w.Config.AccountIDs, pr.account):
		return nil, target.Permanent("account %s is not one of the connector's accounts", pr.account)
	case pr.kind == "role" && (pr.name == w.Config.RoleName || pr.name == w.writerRole() || strings.HasPrefix(pr.name, "AWSReservedSSO_") ||
		strings.Contains(req.Account.Username, ":role/aws-service-role/")):
		return nil, target.Permanent("the role %s is protected: Tessera's own roles, service-linked roles and Identity Center roles are never changed here", pr.name)
	}
	needKind := func(kinds ...string) error {
		if !slices.Contains(kinds, pr.kind) {
			return target.Permanent("%s applies to %s only", req.Kind, strings.Join(kinds, " or "))
		}
		return nil
	}
	switch req.Kind {
	case target.AWSDetachPolicy, target.AWSAttachPolicy:
		if !policyARNRE.MatchString(aw.PolicyARN) {
			return nil, target.Permanent("policy_arn is not a managed policy ARN")
		}
		return p, needKind("role", "user", "group")
	case target.AWSDeleteInlinePolicy, target.AWSPutInlinePolicy:
		if !nameRE.MatchString(aw.PolicyName) {
			return nil, target.Permanent("policy_name is not a valid IAM policy name")
		}
		if err := checkDocs(req.Kind, aw); err != nil {
			return nil, err
		}
		return p, needKind("role", "user", "group")
	case target.AWSSetPolicyVersion, target.AWSRestorePolicyVersion:
		m := policyARNRE.FindStringSubmatch(aw.PolicyARN)
		switch {
		case m == nil:
			return nil, target.Permanent("policy_arn is not a managed policy ARN")
		case m[1] == "aws":
			return nil, target.Permanent("an AWS-managed policy cannot be changed: detach it instead")
		case m[1] != pr.account:
			return nil, target.Permanent("the policy is in another account than the principal")
		case !versionRE.MatchString(aw.PriorVersionID):
			return nil, target.Permanent("prior_version_id is not a policy version id")
		}
		if err := checkDocs(req.Kind, aw); err != nil {
			return nil, err
		}
		return p, needKind("role", "user", "group")
	case target.AWSRemoveFromGroup, target.AWSAddToGroup:
		if !nameRE.MatchString(aw.Group) {
			return nil, target.Permanent("group is not a valid IAM group name")
		}
		return p, needKind("user")
	}
	return nil, target.Permanent("unknown AWS operation %s", req.Kind)
}

// checkDocs checks the documents of a request. The digest of the prior state is always recorded; what a revoke
// removes is stored verbatim beside it and must match it, and what a restore puts back must match it too: a request
// whose stored document does not match its recorded digest was altered, and is refused.
func checkDocs(kind string, aw *target.AWSChange) error {
	switch {
	case len(aw.Document) > maxDocBytes || len(aw.Prior) > maxDocBytes:
		return target.Permanent("a policy document is larger than %d bytes", maxDocBytes)
	case aw.PriorSHA256 == "":
		return target.Permanent("the change has no recorded digest of the prior state")
	}
	switch kind {
	case target.AWSDeleteInlinePolicy, target.AWSSetPolicyVersion:
		if aw.Prior == "" || target.DocDigest(aw.Prior) != aw.PriorSHA256 {
			return target.Permanent("the stored prior state is missing or does not match its recorded digest")
		}
	case target.AWSPutInlinePolicy:
		if target.DocDigest(aw.Document) != aw.PriorSHA256 {
			return target.Permanent("the document to put back does not match the digest recorded at the revoke")
		}
	}
	if (kind == target.AWSSetPolicyVersion || kind == target.AWSPutInlinePolicy) && aw.Document == "" {
		return target.Permanent("the change has no document")
	}
	return nil
}

func (w *WriteTarget) checkSSO(p *plan) (*plan, error) {
	aw := p.aw
	switch {
	case w.Config.ManagementAccountID == "" || w.Config.IdentityCenterRegion == "":
		return nil, target.Permanent("Identity Center changes need the connector's management_account_id and identity_center_region")
	case !accountRE.MatchString(aw.AccountID):
		return nil, target.Permanent("account_id is not a 12-digit account id")
	case len(w.Config.AccountIDs) > 0 && !slices.Contains(w.Config.AccountIDs, aw.AccountID):
		return nil, target.Permanent("account %s is not one of the connector's accounts", aw.AccountID)
	case !ssoARNRE.MatchString(aw.InstanceARN) || !ssoARNRE.MatchString(aw.PermissionSetARN):
		return nil, target.Permanent("instance_arn or permission_set_arn is not an Identity Center ARN")
	case !ssoIDRE.MatchString(p.req.Account.Username):
		return nil, target.Permanent("the principal is not an Identity Store id")
	case aw.SSOPrincipalType != "USER" && aw.SSOPrincipalType != "GROUP":
		return nil, target.Permanent("sso_principal_type must be USER or GROUP")
	}
	p.account = w.Config.ManagementAccountID
	return p, nil
}

// session returns the reader's or the writer's session in an account, assumed with the role's own web identity
// token and kept until five minutes before it expires.
func (w *WriteTarget) session(ctx context.Context, account string, writer bool) (session, error) {
	role, tokens, name := w.Config.RoleName, w.ReaderToken, "tessera-verify"
	if writer {
		role, tokens, name = w.writerRole(), w.WriterToken, "tessera-write"
	}
	key := account + "/" + role
	w.mu.Lock()
	defer w.mu.Unlock()
	if s := w.sessions[key]; s != nil && !s.expires.IsZero() && w.now().Add(5*time.Minute).Before(s.expires) {
		return s.session, nil
	}
	if tokens == nil {
		return session{}, target.Permanent("the connector has no web identity source: only federated connectors can write")
	}
	token, err := tokens(ctx)
	if err != nil {
		return session{}, err
	}
	creds, exp, err := session{cl: w.Client}.assumeRoleWithWebIdentity(ctx, w.Config.Regions[0], "arn:aws:iam::"+account+":role/"+role, token, name)
	if err != nil {
		return session{}, err
	}
	if w.sessions == nil {
		w.sessions = map[string]*accountSession{}
	}
	s := &accountSession{session: session{cl: w.Client, creds: creds}, expires: exp}
	w.sessions[key] = s
	return s.session, nil
}

// OpenWriteTarget builds the write target of a tenant's AWS connector: the connector's accounts and regions bound where
// it may write, and this federation's reader and writer tokens. Only a federated connector can write: a stored key is
// never used for a change. It is the hook the provisioning engine is given (provision.Engine.BuildAWS).
func (f *Federation) OpenWriteTarget(ctx context.Context, t tenancy.ID, connectorID, writerRole string, hc Doer, now func() time.Time) (target.Connector, error) {
	if f == nil || f.DB == nil {
		return nil, errors.New("this server cannot issue AWS federation tokens")
	}
	var k *store.AWSConnector
	err := f.DB.ReadTenant(ctx, t, func(tx *store.TenantTx) (err error) {
		k, err = tx.AWSConnector(connectorID)
		return err
	})
	if errors.Is(err, store.ErrNotFound) {
		return nil, errors.New("the AWS connector of this target no longer exists")
	} else if err != nil {
		return nil, err
	}
	cfg, err := ParseConfig(k.Config)
	if err != nil {
		return nil, fmt.Errorf("the AWS connector's settings are unreadable: %w", err)
	}
	if cfg.Mode() != AuthFederated {
		return nil, errors.New("only a federated AWS connector can write")
	}
	if writerRole != "" && !roleNameRE.MatchString(writerRole) {
		return nil, errors.New("the writer role name is not a valid IAM role name")
	}
	return &WriteTarget{Client: &Client{HTTP: hc, Now: now}, Config: cfg, WriterRole: writerRole,
		ReaderToken: f.Source(t, k.ID), WriterToken: f.WriterSource(t, k.ID), Now: now}, nil
}

// failure turns an error of a call into the engine's: a refusal by AWS (access denied, no such entity, a limit) is
// permanent, a throttle or a server error or a lost connection is worth another try.
func failure(op string, err error) error {
	if err == nil {
		return nil
	}
	var te *target.Error
	if errors.As(err, &te) {
		return err
	}
	var ae *Error
	switch {
	case errors.As(err, &ae):
		switch {
		case IsAccessDenied(err):
			return target.Permanent("%s: AWS denied the call (%s): the role may lack the permission, or a service control policy or the tessera:protected tag forbids it", op, ae.Code)
		case ae.Status >= 500 || ae.Status == 429 || retryable(ae.Status, ae.Code):
			return &target.Error{Status: ae.Status, Retryable: true, Msg: fmt.Sprintf("%s: AWS answered %s", op, ae.Code)}
		}
		return target.Permanent("%s: AWS answered %s: %s", op, ae.Code, ae.Message)
	case errors.Is(err, safehttp.ErrBlockedAddress), errors.Is(err, safehttp.ErrURL), errors.Is(err, safehttp.ErrRedirect), errors.Is(err, errSigning):
		return target.Permanent("%s: the request was refused before it was sent", op)
	}
	return target.Transport(op, err)
}

// Apply makes the change, reading first so that a repeated or already-made change converges, and refusing a revoke
// when the target no longer holds the state the change was evaluated against.
func (w *WriteTarget) Apply(ctx context.Context, req target.Request) error {
	p, err := w.check(req)
	if err != nil {
		return err
	}
	rd, err := w.session(ctx, p.account, false)
	if err != nil {
		return failure("assume the reader role", err)
	}
	var done bool
	if done, err = w.alreadyDone(ctx, rd, p, true); err != nil {
		return failure("read before the change", err)
	}
	if done {
		return nil
	}
	wr, err := w.session(ctx, p.account, true)
	if err != nil {
		return failure("assume the writer role", err)
	}
	return failure("write", w.write(ctx, wr, p))
}

// alreadyDone reads the target before a write. It returns true when the change is already in place, and an error
// when the write must not be made (the state it is meant to change is not the state it was evaluated against).
func (w *WriteTarget) alreadyDone(ctx context.Context, rd session, p *plan, guard bool) (bool, error) {
	aw, name := p.aw, p.pr.name
	switch p.req.Kind {
	case target.AWSDetachPolicy, target.AWSAttachPolicy:
		arns, found, err := rd.iamAttached(ctx, p.pr.kind, name)
		if err != nil {
			return false, err
		}
		if !found {
			return false, target.Permanent("the %s %s does not exist", p.pr.kind, name)
		}
		return slices.Contains(arns, aw.PolicyARN) == (p.req.Kind == target.AWSAttachPolicy), nil
	case target.AWSDeleteInlinePolicy, target.AWSPutInlinePolicy:
		doc, found, err := rd.iamInlinePolicy(ctx, p.pr.kind, name, aw.PolicyName)
		if err != nil {
			return false, err
		}
		if p.req.Kind == target.AWSDeleteInlinePolicy {
			if !found {
				return true, nil
			}
			if guard && target.DocDigest(doc) != aw.PriorSHA256 {
				return false, target.Permanent("the inline policy %s was changed since it was evaluated: not deleted", aw.PolicyName)
			}
			return false, nil
		}
		switch {
		case found && target.DocDigest(doc) == target.DocDigest(aw.Document):
			return true, nil
		case found:
			return false, target.Permanent("a different inline policy named %s exists: not overwritten", aw.PolicyName)
		}
		return false, nil
	case target.AWSSetPolicyVersion:
		def, found, err := rd.iamDefaultVersion(ctx, aw.PolicyARN)
		if err != nil {
			return false, err
		}
		if !found {
			return false, target.Permanent("the policy does not exist")
		}
		doc, _, err := rd.iamPolicyVersion(ctx, aw.PolicyARN, def)
		if err != nil {
			return false, err
		}
		if target.DocDigest(doc) == target.DocDigest(aw.Document) {
			return true, nil
		}
		if guard && (aw.PriorVersionID != "" && def != aw.PriorVersionID || target.DocDigest(doc) != aw.PriorSHA256) {
			return false, target.Permanent("the policy was changed since it was evaluated (default version %s): not right-sized", def)
		}
		vs, err := rd.iamPolicyVersions(ctx, aw.PolicyARN)
		if err != nil {
			return false, err
		}
		if len(vs) >= 5 {
			return false, target.Permanent("the policy already has five versions, the most IAM allows: delete one before right-sizing it")
		}
		return false, nil
	case target.AWSRestorePolicyVersion:
		def, found, err := rd.iamDefaultVersion(ctx, aw.PolicyARN)
		if err != nil {
			return false, err
		}
		if !found {
			return false, target.Permanent("the policy does not exist")
		}
		doc, have, err := rd.iamPolicyVersion(ctx, aw.PolicyARN, aw.PriorVersionID)
		if err != nil {
			return false, err
		}
		switch {
		case !have:
			return false, target.Permanent("version %s of the policy no longer exists: it cannot be restored", aw.PriorVersionID)
		case target.DocDigest(doc) != aw.PriorSHA256:
			return false, target.Permanent("version %s of the policy no longer holds the document recorded at the revoke: not restored", aw.PriorVersionID)
		}
		return def == aw.PriorVersionID, nil
	case target.AWSRemoveFromGroup, target.AWSAddToGroup:
		groups, found, err := rd.iamGroupsForUser(ctx, name)
		if err != nil {
			return false, err
		}
		if !found {
			return false, target.Permanent("the user %s does not exist", name)
		}
		return slices.Contains(groups, aw.Group) == (p.req.Kind == target.AWSAddToGroup), nil
	case target.AWSDeleteAssignment, target.AWSCreateAssignment:
		has, err := w.hasAssignment(ctx, rd, p)
		return has == (p.req.Kind == target.AWSCreateAssignment), err
	}
	return false, target.Permanent("unknown AWS operation %s", p.req.Kind)
}

func (w *WriteTarget) hasAssignment(ctx context.Context, rd session, p *plan) (bool, error) {
	as, err := rd.listAccountAssignments(ctx, w.Config.IdentityCenterRegion, p.aw.InstanceARN, p.aw.PermissionSetARN, p.aw.AccountID)
	if err != nil {
		return false, err
	}
	for _, a := range as {
		if a.PrincipalID == p.req.Account.Username && a.PrincipalType == p.aw.SSOPrincipalType {
			return true, nil
		}
	}
	return false, nil
}

func (w *WriteTarget) write(ctx context.Context, wr session, p *plan) error {
	aw, name, kind := p.aw, p.pr.name, p.pr.kind
	t := titleKind(kind)
	switch p.req.Kind {
	case target.AWSDetachPolicy:
		return wr.iamWrite(ctx, "Detach"+t+"Policy", url.Values{iamParam[kind]: {name}, "PolicyArn": {aw.PolicyARN}})
	case target.AWSAttachPolicy:
		return wr.iamWrite(ctx, "Attach"+t+"Policy", url.Values{iamParam[kind]: {name}, "PolicyArn": {aw.PolicyARN}})
	case target.AWSDeleteInlinePolicy:
		return wr.iamWrite(ctx, "Delete"+t+"Policy", url.Values{iamParam[kind]: {name}, "PolicyName": {aw.PolicyName}})
	case target.AWSPutInlinePolicy:
		return wr.iamWrite(ctx, "Put"+t+"Policy", url.Values{iamParam[kind]: {name}, "PolicyName": {aw.PolicyName}, "PolicyDocument": {aw.Document}})
	case target.AWSSetPolicyVersion:
		return wr.iamWrite(ctx, "CreatePolicyVersion", url.Values{"PolicyArn": {aw.PolicyARN}, "PolicyDocument": {aw.Document}, "SetAsDefault": {"true"}})
	case target.AWSRestorePolicyVersion:
		return wr.iamWrite(ctx, "SetDefaultPolicyVersion", url.Values{"PolicyArn": {aw.PolicyARN}, "VersionId": {aw.PriorVersionID}})
	case target.AWSRemoveFromGroup:
		return wr.iamWrite(ctx, "RemoveUserFromGroup", url.Values{"UserName": {name}, "GroupName": {aw.Group}})
	case target.AWSAddToGroup:
		return wr.iamWrite(ctx, "AddUserToGroup", url.Values{"UserName": {name}, "GroupName": {aw.Group}})
	case target.AWSDeleteAssignment, target.AWSCreateAssignment:
		st, err := wr.ssoAssignment(ctx, w.Config.IdentityCenterRegion, p.req.Kind == target.AWSDeleteAssignment, ssoAssignmentIn{
			InstanceArn: aw.InstanceARN, TargetId: aw.AccountID, TargetType: "AWS_ACCOUNT", PermissionSetArn: aw.PermissionSetARN,
			PrincipalType: aw.SSOPrincipalType, PrincipalId: p.req.Account.Username})
		if err != nil {
			return err
		}
		if st.RequestID != "" && ssoIDRE.MatchString(st.RequestID) {
			w.mu.Lock()
			if w.requests == nil {
				w.requests = map[string]string{}
			}
			w.requests[p.req.Key] = st.RequestID
			w.mu.Unlock()
		}
		if st.Status == "FAILED" {
			return target.Permanent("Identity Center refused the request: %s", clip(st.FailureReason, 200))
		}
		return nil
	}
	return target.Permanent("unknown AWS operation %s", p.req.Kind)
}

// Verify re-reads the target with the reader role and compares what it finds with the state the change leaves.
func (w *WriteTarget) Verify(ctx context.Context, req target.Request) (target.Verdict, error) {
	p, err := w.check(req)
	if err != nil {
		return target.Verdict{}, err
	}
	rd, err := w.session(ctx, p.account, false)
	if err != nil {
		return target.Verdict{}, failure("assume the reader role", err)
	}
	v, err := w.reread(ctx, rd, p)
	return v, failure("re-read", err)
}

func (w *WriteTarget) reread(ctx context.Context, rd session, p *plan) (target.Verdict, error) {
	aw, name, kind := p.aw, p.pr.name, p.pr.kind
	ref := req2ref(p)
	switch p.req.Kind {
	case target.AWSDetachPolicy, target.AWSAttachPolicy:
		arns, found, err := rd.iamAttached(ctx, kind, name)
		if err != nil || !found {
			return target.Verdict{}, orGone(err, found, kind, name)
		}
		want := p.req.Kind == target.AWSAttachPolicy
		has := slices.Contains(arns, aw.PolicyARN)
		return vd(has == want, fmt.Sprintf("%s %s: %s", ref, aw.PolicyARN, pick(want, "attached", "detached")),
			pick(has, "attached", "detached")), nil
	case target.AWSDeleteInlinePolicy, target.AWSPutInlinePolicy:
		doc, found, err := rd.iamInlinePolicy(ctx, kind, name, aw.PolicyName)
		if err != nil {
			return target.Verdict{}, err
		}
		if p.req.Kind == target.AWSDeleteInlinePolicy {
			return vd(!found, "inline policy "+aw.PolicyName+" of "+ref+" is gone",
				pick(found, "still present (digest "+short(target.DocDigest(doc))+")", "gone")), nil
		}
		want := target.DocDigest(aw.Document)
		return vd(found && target.DocDigest(doc) == want, "inline policy "+aw.PolicyName+" of "+ref+" has digest "+short(want),
			pick(found, "digest "+short(target.DocDigest(doc)), "absent")), nil
	case target.AWSSetPolicyVersion:
		def, found, err := rd.iamDefaultVersion(ctx, aw.PolicyARN)
		if err != nil {
			return target.Verdict{}, err
		}
		if !found {
			return vd(false, "policy "+aw.PolicyARN+" exists", "absent"), nil
		}
		doc, _, err := rd.iamPolicyVersion(ctx, aw.PolicyARN, def)
		if err != nil {
			return target.Verdict{}, err
		}
		want := target.DocDigest(aw.Document)
		got := target.DocDigest(doc)
		if got != want {
			return vd(false, "default version of "+aw.PolicyARN+" has digest "+short(want),
				"default version "+def+" has digest "+short(got)), nil
		}
		// the old version is kept until the revocation is final: restore needs it
		if aw.PriorVersionID != "" {
			vs, err := rd.iamPolicyVersions(ctx, aw.PolicyARN)
			if err != nil {
				return target.Verdict{}, err
			}
			if !slices.Contains(vs, aw.PriorVersionID) {
				return vd(false, "the prior version "+aw.PriorVersionID+" is kept", "the prior version is gone"), nil
			}
		}
		return vd(true, "default version of "+aw.PolicyARN+" has digest "+short(want), "default version "+def+" has digest "+short(got)), nil
	case target.AWSRestorePolicyVersion:
		def, found, err := rd.iamDefaultVersion(ctx, aw.PolicyARN)
		if err != nil {
			return target.Verdict{}, err
		}
		if !found {
			return vd(false, "policy "+aw.PolicyARN+" exists", "absent"), nil
		}
		doc, _, err := rd.iamPolicyVersion(ctx, aw.PolicyARN, def)
		if err != nil {
			return target.Verdict{}, err
		}
		got := target.DocDigest(doc)
		return vd(def == aw.PriorVersionID && got == aw.PriorSHA256, "default version "+aw.PriorVersionID+" with digest "+short(aw.PriorSHA256),
			"default version "+def+" with digest "+short(got)), nil
	case target.AWSRemoveFromGroup, target.AWSAddToGroup:
		groups, found, err := rd.iamGroupsForUser(ctx, name)
		if err != nil || !found {
			return target.Verdict{}, orGone(err, found, kind, name)
		}
		want := p.req.Kind == target.AWSAddToGroup
		in := slices.Contains(groups, aw.Group)
		return vd(in == want, fmt.Sprintf("%s is %s group %s", ref, pick(want, "in", "not in"), aw.Group),
			fmt.Sprintf("%s is %s group %s", ref, pick(in, "in", "not in"), aw.Group)), nil
	case target.AWSDeleteAssignment, target.AWSCreateAssignment:
		del := p.req.Kind == target.AWSDeleteAssignment
		w.mu.Lock()
		id := w.requests[p.req.Key]
		w.mu.Unlock()
		if id != "" {
			st, err := rd.ssoRequestStatus(ctx, w.Config.IdentityCenterRegion, del, aw.InstanceARN, id)
			if err != nil {
				return target.Verdict{}, err
			}
			switch st.Status {
			case "IN_PROGRESS":
				return vd(false, "the assignment request is finished", "the request is in progress"), nil
			case "FAILED":
				return vd(false, "the assignment request succeeded", "the request failed: "+clip(st.FailureReason, 200)), nil
			}
		}
		has, err := w.hasAssignment(ctx, rd, p)
		if err != nil {
			return target.Verdict{}, err
		}
		return vd(has == !del, "the assignment is "+pick(del, "gone", "present"), "the assignment is "+pick(has, "present", "gone")), nil
	}
	return target.Verdict{}, target.Permanent("unknown AWS operation %s", p.req.Kind)
}

func req2ref(p *plan) string {
	if p.pr.name != "" {
		return p.pr.kind + " " + p.pr.name
	}
	return "principal " + p.req.Account.Username
}

func vd(ok bool, expected, observed string) target.Verdict {
	return target.Verdict{OK: ok, Expected: expected, Observed: observed}
}

func pick(c bool, yes, no string) string {
	if c {
		return yes
	}
	return no
}

func short(digest string) string {
	if len(digest) > 12 {
		return digest[:12]
	}
	return digest
}

func orGone(err error, found bool, kind, name string) error {
	if err != nil {
		return err
	}
	if !found {
		return target.Permanent("the %s %s does not exist", kind, name)
	}
	return nil
}
