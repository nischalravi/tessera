package tfplan

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/awstest"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/snapshot"
	"github.com/nischalravi/tessera/mvp/server/internal/blast"
)

// Tests for the security review of #655: ordering, bounds, conditional answers, account and reference resolution.

const (
	docNarrow = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::prod-pii/*"}]}`
	docOpen   = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:*","Resource":"*"}]}`
)

type rc map[string]any

// res builds one resource change; module is "" for the root.
func res(module, typ, name string, actions []string, before, after, unknown any) rc {
	addr := typ + "." + name
	m := rc{"mode": "managed", "type": typ, "name": name,
		"change": map[string]any{"actions": actions, "before": before, "after": after, "after_unknown": unknown}}
	if module != "" {
		addr = module + "." + addr
		m["module_address"] = module
	}
	m["address"] = addr
	return m
}

func planOf(config any, changes ...rc) []byte {
	p := map[string]any{"format_version": "1.2", "planned_values": map[string]any{}, "resource_changes": changes}
	if config != nil {
		p["configuration"] = config
	}
	raw, _ := json.Marshal(p)
	return raw
}

func mapPlan(t *testing.T, raw []byte, snap *model.Snapshot, maxOps int) *Result {
	t.Helper()
	p, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return Map(p, NewEstate(snap), maxOps)
}

func apply(t *testing.T, snap *model.Snapshot, r *Result) {
	t.Helper()
	if _, err := snapshot.Apply(snap, blast.Changes(r.Operations), snapshot.ApplyOptions{FetchedAt: time.Unix(0, 0).UTC(),
		MultivaluedKey: func(string) bool { return false }}); err != nil {
		t.Fatalf("the mapped operations do not apply: %v\n%s", err, strings.Join(opLines(r.Operations), "\n"))
	}
}

func baseEstate(t *testing.T) *model.Snapshot {
	t.Helper()
	snap, _ := estate(t)
	return snap
}

// H1: a bucket policy that moves between modules is a delete in one resource and a create in the other. The new
// document is applied last whatever the addresses sort to, and both resources are reported as order-dependent.
func TestReview_BucketPolicyMoveBetweenModules(t *testing.T) {
	snap := baseEstate(t)
	doc := docNarrow
	var err error
	snap, err = snapshot.Apply(snap, []snapshot.PolicyChange{{Op: snapshot.OpPutResourcePolicy, TargetARN: awstest.EstateBucket, Document: &doc}},
		snapshot.ApplyOptions{FetchedAt: time.Unix(0, 0).UTC(), MultivaluedKey: func(string) bool { return false }})
	if err != nil {
		t.Fatal(err)
	}
	for _, names := range [][2]string{{"module.a", "module.z"}, {"module.z", "module.a"}} { // old, new
		raw := planOf(nil,
			res(names[0], "aws_s3_bucket_policy", "p", []string{"delete"}, rc{"bucket": "prod-pii", "policy": docNarrow}, nil, rc{}),
			res(names[1], "aws_s3_bucket_policy", "p", []string{"create"}, nil, rc{"bucket": "prod-pii", "policy": docOpen}, rc{"id": true}))
		r := mapPlan(t, raw, snap, 0)
		if len(r.Operations) != 2 {
			t.Fatalf("%v: operations = %v", names, opLines(r.Operations))
		}
		last := r.Operations[1]
		if last.Document == nil || *last.Document != docOpen || r.Operations[0].Document == nil || *r.Operations[0].Document != emptyPolicy {
			t.Errorf("%v: the removal must come first and the new document last: %v", names, opLines(r.Operations))
		}
		if got := findings(r); len(got) != 2 || !strings.HasSuffix(got[0], "conditional") || !strings.HasSuffix(got[1], "conditional") || !r.Conditional() {
			t.Errorf("%v: findings = %v", names, got)
		}
		apply(t, snap, r)
	}
}

// H2: a configuration with one expression of tens of thousands of references, and thousands of attachments that
// refer to it, costs nothing per lookup.
func TestReview_ReferenceBounds(t *testing.T) {
	refs := make([]string, 55000)
	for i := range refs {
		refs[i] = fmt.Sprintf("aws_iam_policy.p%d.arn", i)
	}
	var changes []rc
	// 2,500 instances of one resource (count) and one configuration entry with an enormous expression
	cfg := []rc{{"address": "aws_iam_role_policy_attachment.a", "mode": "managed", "expressions": rc{"role": rc{"references": refs}}}}
	for i := 0; i < 2500; i++ {
		c := res("", "aws_iam_role_policy_attachment", "a", []string{"create"}, nil, rc{"policy_arn": awstest.EstateS3Read}, rc{"role": true})
		c["address"] = fmt.Sprintf("aws_iam_role_policy_attachment.a[%d]", i)
		changes = append(changes, c)
	}
	raw := planOf(rc{"root_module": rc{"resources": cfg}}, changes...)
	start := time.Now()
	r := mapPlan(t, raw, baseEstate(t), 0)
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("a plan of 2,500 attachments with 55,000 references took %v", d)
	}
	if len(r.Operations) != 0 || r.Count(StatusConditional) != 2500 {
		t.Errorf("operations = %d, conditional = %d", len(r.Operations), r.Count(StatusConditional))
	}
	// the references past the per-expression cap are not kept at all
	p, _ := Parse(raw)
	for _, attrs := range p.refs {
		if len(attrs["role"]) != 0 {
			t.Fatalf("an expression of %d references was kept", len(attrs["role"]))
		}
	}
}

// H3: unsupported access-relevant changes make the answer conditional, and a group the plan creates or fills is not
// "no effect".
func TestReview_AccessRelevantUnsupported(t *testing.T) {
	raw := planOf(nil,
		res("", "aws_iam_group", "admins", []string{"create"}, nil, rc{"name": "admins"}, rc{"arn": true}),
		res("", "aws_iam_group_policy_attachment", "admin", []string{"create"}, nil,
			rc{"group": "admins", "policy_arn": awstest.EstateS3Read}, rc{}),
		res("", "aws_iam_user_group_membership", "mallory", []string{"create"}, nil, rc{"user": "mallory", "groups": []any{"admins"}}, rc{}))
	r := mapPlan(t, raw, baseEstate(t), 0)
	if !r.Conditional() {
		t.Errorf("a new admin group with a member is not conditional: %v", findings(r))
	}
	got := findings(r)
	want := []string{"aws_iam_group.admins unsupported", "aws_iam_group_policy_attachment.admin unresolved", "aws_iam_user_group_membership.mallory unsupported"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("findings = %v, want %v", got, want)
	}
	for _, f := range r.Findings {
		if f.Status == StatusUnsupported && !f.AccessRelevant {
			t.Errorf("%s is not marked access relevant", f.Address)
		}
	}
	// a resource with no bearing on access does not make it conditional
	if r := mapPlan(t, planOf(nil, res("", "aws_instance", "web", []string{"create"}, nil, rc{}, rc{})), baseEstate(t), 0); r.Conditional() || len(r.Findings) != 1 {
		t.Errorf("an instance: conditional=%v %v", r.Conditional(), findings(r))
	}
	for _, typ := range []string{"aws_iam_access_key", "aws_iam_user_login_profile", "aws_lambda_permission", "aws_kms_grant", "aws_kms_key_policy", "aws_sqs_queue_policy", "aws_organizations_account"} {
		if r := mapPlan(t, planOf(nil, res("", typ, "x", []string{"create"}, nil, rc{}, rc{})), baseEstate(t), 0); !r.Conditional() {
			t.Errorf("%s does not make the answer conditional", typ)
		}
	}
	// a group nobody is in, with a plan that does not touch groups, still reaches no principal
	r = mapPlan(t, planOf(nil, res("", "aws_iam_group_policy_attachment", "a", []string{"create"}, nil, rc{"group": "empty", "policy_arn": awstest.EstateS3Read}, rc{})), baseEstate(t), 0)
	if got := findings(r); !reflect.DeepEqual(got, []string{"aws_iam_group_policy_attachment.a no_effect"}) {
		t.Errorf("findings = %v", got)
	}
}

// M1: with the account known, an entity of another account is not used; with it unknown and several accounts in the
// estate, a name resolves only if the plan uses one provider configuration.
func TestReview_AccountResolution(t *testing.T) {
	snap := baseEstate(t)
	attach := res("", "aws_iam_role_policy_attachment", "a", []string{"create"}, nil, rc{"role": "DataEngineer", "policy_arn": awstest.EstateS3Read}, rc{})
	// the plan's own IAM ARNs name the dev account, the role is in prod
	known := res("", "aws_iam_policy", "other", []string{"update"},
		rc{"arn": "arn:aws:iam::222222222222:policy/Other", "name": "Other", "policy": docNarrow},
		rc{"arn": "arn:aws:iam::222222222222:policy/Other", "name": "Other", "policy": docNarrow}, rc{})
	r := mapPlan(t, planOf(nil, known, attach), snap, 0)
	if len(r.Operations) != 0 || r.Count(StatusUnresolved) != 1 {
		t.Errorf("cross-account fallback: operations %v findings %v", opLines(r.Operations), findings(r))
	}
	// no ARN names an account: one provider configuration is fine, two are not
	cfg := func(keys ...string) any {
		var rs []rc
		for i, k := range keys {
			rs = append(rs, rc{"address": fmt.Sprintf("aws_iam_role_policy_attachment.a%d", i), "mode": "managed", "provider_config_key": k, "expressions": rc{}})
		}
		return rc{"root_module": rc{"resources": rs}}
	}
	if r := mapPlan(t, planOf(cfg("aws"), attach), snap, 0); len(r.Operations) != 1 {
		t.Errorf("one provider: %v", findings(r))
	}
	r = mapPlan(t, planOf(cfg("aws", "aws.dev"), attach), snap, 0)
	if len(r.Operations) != 0 || r.Count(StatusUnresolved) != 1 {
		t.Errorf("two providers: operations %v findings %v", opLines(r.Operations), findings(r))
	}
}

// M2: a reference counts only for the attribute the caller expects, and a resolution is always reported as resting on
// the assumption that the expression is the bare attribute.
func TestReview_ReferenceAttributes(t *testing.T) {
	snap := baseEstate(t)
	policy := res("", "aws_iam_policy", "x", []string{"create"}, nil, rc{"name": "x", "path": "/", "policy": docNarrow}, rc{"arn": true})
	attach := res("", "aws_iam_role_policy_attachment", "a", []string{"create"}, nil, rc{"role": "DataEngineer"}, rc{"policy_arn": true})
	cfg := func(refs ...string) any {
		return rc{"root_module": rc{"resources": []rc{{"address": "aws_iam_role_policy_attachment.a", "mode": "managed",
			"expressions": rc{"policy_arn": rc{"references": refs}}}}}}
	}
	// policy_arn built from the policy's name is not its ARN
	r := mapPlan(t, planOf(cfg("aws_iam_policy.x.name", "aws_iam_policy.x"), policy, attach), snap, 0)
	if got := opLines(r.Operations); len(got) != 1 || !strings.HasPrefix(got[0], "put_policy_version") {
		t.Errorf("a name used as an ARN was resolved: %v %v", got, findings(r))
	}
	// the bare attribute resolves, with the caveat
	r = mapPlan(t, planOf(cfg("aws_iam_policy.x.arn", "aws_iam_policy.x"), policy, attach), snap, 0)
	if len(r.Operations) != 2 || !r.Conditional() {
		t.Fatalf("operations %v findings %v", opLines(r.Operations), findings(r))
	}
	var found bool
	for _, f := range r.Findings {
		found = found || (f.Address == "aws_iam_role_policy_attachment.a" && f.Status == StatusConditional && strings.Contains(f.Reason, "resolved by reference"))
	}
	if !found {
		t.Errorf("no caveat: %v", r.Findings)
	}
	// a decoy: the same references as replace(aws_iam_policy.x.arn, ...) look just like the bare attribute, hence the caveat;
	// but a reference to a second resource is refused
	decoy := res("", "aws_iam_policy", "decoy", []string{"create"}, nil, rc{"name": "decoy", "path": "/", "policy": docNarrow}, rc{"arn": true})
	r = mapPlan(t, planOf(cfg("aws_iam_policy.x.arn", "aws_iam_policy.decoy.arn"), policy, decoy, attach), snap, 0)
	if len(r.Operations) != 2 {
		t.Errorf("two candidate policies: %v", opLines(r.Operations))
	}
}

// M3: sets are deduplicated and capped, and Map stops once the plan has made more operations than allowed.
func TestReview_SetsAndCeiling(t *testing.T) {
	snap := baseEstate(t)
	users := make([]any, 0, 2000)
	for i := 0; i < 1500; i++ {
		users = append(users, "alice") // duplicates
	}
	for i := 0; i < 500; i++ {
		users = append(users, fmt.Sprintf("nobody-%d", i))
	}
	users = append(users, 7, "")
	raw := planOf(nil, res("", "aws_iam_policy_attachment", "a", []string{"create"}, nil,
		rc{"name": "a", "policy_arn": awstest.EstateS3Read, "users": users, "roles": []any{}, "groups": []any{}}, rc{}))
	r := mapPlan(t, raw, snap, 0)
	var dropped bool
	for _, f := range r.Findings {
		dropped = dropped || strings.Contains(f.Reason, "not usable")
	}
	if !dropped {
		t.Errorf("dropped entries are not reported: %v", findings(r))
	}
	if len(r.Operations) > 1 { // alice once; the 499 unknown names are unresolved findings, each reported once
		t.Errorf("operations = %d", len(r.Operations))
	}
	// the ceiling
	var changes []rc
	for i := 0; i < 50; i++ {
		changes = append(changes, res("", "aws_iam_user_policy", fmt.Sprintf("p%d", i), []string{"create"}, nil, rc{"user": "alice", "name": fmt.Sprintf("n%d", i), "policy": docNarrow}, rc{}))
	}
	if r := mapPlan(t, planOf(nil, changes...), snap, 10); !r.Exceeded || len(r.Operations) > 12 {
		t.Errorf("exceeded=%v operations=%d", r.Exceeded, len(r.Operations))
	}
	if r := mapPlan(t, planOf(nil, changes...), snap, 50); r.Exceeded || len(r.Operations) != 50 {
		t.Errorf("exceeded=%v operations=%d", r.Exceeded, len(r.Operations))
	}
}

// L1: inline_policy entries that cannot be used are reported.
func TestReview_DroppedInlineBlocks(t *testing.T) {
	raw := planOf(nil, res("", "aws_iam_role", "r", []string{"update"},
		rc{"arn": awstest.EstateEngineer, "name": "DataEngineer", "assume_role_policy": docNarrow, "inline_policy": []any{}},
		rc{"arn": awstest.EstateEngineer, "name": "DataEngineer", "assume_role_policy": docNarrow,
			"inline_policy": []any{rc{"name": "bad name!", "policy": docOpen}, "text", rc{"name": "ok", "policy": docOpen}}}, rc{}))
	r := mapPlan(t, raw, baseEstate(t), 0)
	if got := opLines(r.Operations); len(got) != 1 || !strings.HasPrefix(got[0], "put_inline "+awstest.EstateEngineer+" ok") {
		t.Errorf("operations = %v", got)
	}
	if got := findings(r); !reflect.DeepEqual(got, []string{"aws_iam_role.r unresolved"}) {
		t.Errorf("findings = %v", got)
	}
}

// L2: when a plan replaces an organization policy, what is attached now is detached by the ARN the snapshot holds.
func TestReview_ReplacedOrgPolicy(t *testing.T) {
	cfg := rc{"root_module": rc{"resources": []rc{{"address": "aws_organizations_policy_attachment.a", "mode": "managed",
		"expressions": rc{"policy_id": rc{"references": []string{"aws_organizations_policy.rcp.id", "aws_organizations_policy.rcp"}}}}}}}
	raw := planOf(cfg,
		res("", "aws_organizations_policy", "rcp", []string{"delete", "create"},
			rc{"arn": awstest.EstateFullRCP, "id": "p-RCPFullAWSAccess", "type": "RESOURCE_CONTROL_POLICY", "content": docOpen},
			rc{"type": "RESOURCE_CONTROL_POLICY", "name": "rcp", "content": docNarrow}, rc{"arn": true, "id": true}),
		res("", "aws_organizations_policy_attachment", "a", []string{"delete", "create"},
			rc{"policy_id": "p-RCPFullAWSAccess", "target_id": "ou-prod"}, rc{"target_id": "ou-prod"}, rc{"policy_id": true}))
	r := mapPlan(t, raw, baseEstate(t), 0)
	got := opLines(r.Operations)
	if len(got) != 3 || !strings.HasPrefix(got[1], "detach_rcp ou-prod "+awstest.EstateFullRCP+" ") || !strings.HasPrefix(got[0], "put_rcp arn:aws:organizations::000000000000:") ||
		!strings.HasPrefix(got[2], "attach_rcp ou-prod arn:aws:organizations::000000000000:") {
		t.Errorf("operations = %v findings = %v", got, findings(r))
	}
	apply(t, baseEstate(t), r)
}

// L3: a pair attached by one resource and detached by another is reported, and never makes the request fail.
func TestReview_AttachAndDetachByDifferentResources(t *testing.T) {
	snap := baseEstate(t)
	// bob does not hold S3Read: the plan attaches it with one resource and detaches it with another
	raw := planOf(nil,
		res("", "aws_iam_user_policy_attachment", "a_attach", []string{"create"}, nil, rc{"user": "bob", "policy_arn": awstest.EstateS3Read}, rc{}),
		res("", "aws_iam_role_policy_attachment", "z", []string{"update"}, rc{}, rc{}, rc{}),
		res("", "aws_iam_user_policy_attachment", "b_detach", []string{"delete"}, rc{"user": "bob", "policy_arn": awstest.EstateS3Read}, nil, rc{}))
	r := mapPlan(t, raw, snap, 0)
	apply(t, snap, r)
	if got := findings(r); !strings.Contains(strings.Join(got, ","), "aws_iam_user_policy_attachment.b_detach conditional") {
		t.Errorf("findings = %v", got)
	}
	// alice does hold it: detached by one resource, attached by another, which ends up attached is the plan's order
	raw = planOf(nil,
		res("", "aws_iam_user_policy_attachment", "a", []string{"delete"}, rc{"user": "alice", "policy_arn": awstest.EstateS3Read}, nil, rc{}),
		res("", "aws_iam_user_policy_attachment", "b", []string{"create"}, nil, rc{"user": "alice", "policy_arn": awstest.EstateS3Read}, rc{}))
	r = mapPlan(t, raw, snap, 0)
	apply(t, snap, r)
	if r.Count(StatusConditional) != 2 {
		t.Errorf("findings = %v", findings(r))
	}
}
