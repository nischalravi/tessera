package tfplan

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/awstest"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/snapshot"
	"github.com/nischalravi/tessera/mvp/server/internal/blast"
)

func estate(t testing.TB) (*model.Snapshot, *Estate) {
	t.Helper()
	snap, err := awstest.Estate()
	if err != nil {
		t.Fatal(err)
	}
	return snap, NewEstate(snap)
}

func fixture(t testing.TB, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func mapFixture(t *testing.T, name string) *Result {
	t.Helper()
	p, err := Parse(fixture(t, name))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	_, e := estate(t)
	return Map(p, e)
}

func opLine(o blast.Operation) string {
	s := fmt.Sprintf("%s %s", o.Op, o.TargetARN)
	if o.PolicyARN != nil {
		s += " " + *o.PolicyARN
	}
	return s + " <- " + o.Source
}

func opLines(ops []blast.Operation) []string {
	out := make([]string, len(ops))
	for i, o := range ops {
		out[i] = opLine(o)
	}
	return out
}

func findings(r *Result) []string {
	out := make([]string, len(r.Findings))
	for i, f := range r.Findings {
		out[i] = f.Address + " " + f.Status
	}
	return out
}

// the operations a plan produces must apply to the snapshot they were mapped against.
func mustApply(t testing.TB, r *Result) {
	t.Helper()
	snap, _ := estate(t)
	_, err := snapshot.Apply(snap, blast.Changes(r.Operations), snapshot.ApplyOptions{FetchedAt: time.Unix(0, 0).UTC(),
		MultivaluedKey: func(string) bool { return false }})
	if err != nil {
		t.Fatalf("the mapped operations do not apply: %v\n%s", err, strings.Join(opLines(r.Operations), "\n"))
	}
}

func TestMap_IAM(t *testing.T) {
	r := mapFixture(t, "iam.json")
	const prod = "arn:aws:iam::111111111111:"
	want := []string{
		"put_policy_version " + prod + "policy/deploy <- terraform:aws_iam_policy.deploy",
		"put_policy_version " + awstest.EstateS3Read + " <- terraform:aws_iam_policy.s3_read",
		"delete_inline " + prod + "group/eng list <- terraform:aws_iam_group_policy.list",
		"delete_inline " + awstest.EstateEngineer + " decrypt <- terraform:aws_iam_role_policy.decrypt",
		"detach " + awstest.EstateAlice + " " + awstest.EstateS3Read + " <- terraform:aws_iam_user_policy_attachment.alice_s3",
		"put_trust_policy " + awstest.EstateEngineer + " <- terraform:aws_iam_role.engineer",
		"put_inline " + awstest.EstateEngineer + " decrypt-v2 <- terraform:aws_iam_role_policy.decrypt",
		"put_inline " + awstest.EstateAlice + " assume <- terraform:aws_iam_user_policy.assume",
		"attach " + prod + "group/eng " + awstest.EstateS3Read + " <- terraform:aws_iam_group_policy_attachment.eng",
		"attach " + awstest.EstateEngineer + " " + prod + "policy/deploy <- terraform:aws_iam_role_policy_attachment.deploy",
	}
	if got := opLines(r.Operations); !reflect.DeepEqual(got, want) {
		t.Errorf("operations:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if len(r.Findings) != 0 || r.Conditional() {
		t.Errorf("findings = %v", findings(r))
	}
	if r.Resources != 9 || r.Mapped != 9 || r.Ignored != 0 {
		t.Errorf("counts = %d/%d/%d", r.Resources, r.Mapped, r.Ignored)
	}
	mustApply(t, r)
	// the documents travel with the operations
	if d := r.Operations[1].Document; d == nil || !strings.Contains(*d, `"s3:*"`) {
		t.Errorf("the widened document is not in the operation: %v", d)
	}
}

func TestMap_S3AndOrganization(t *testing.T) {
	r := mapFixture(t, "s3_org.json")
	lines := opLines(r.Operations)
	const placeholder = "arn:aws:organizations::000000000000:policy/o-tessera-plan/service_control_policy/p-aws_organizations_policy_deny_s3-"
	if len(lines) != 5 {
		t.Fatalf("operations:\n%s", strings.Join(lines, "\n"))
	}
	for i, prefix := range []string{
		"put_scp " + placeholder,
		"put_rcp arn:aws:organizations::aws:policy/resource_control_policy/p-RCPFullAWSAccess <- terraform:aws_organizations_policy.rcp",
		"detach_scp ou-prod " + awstest.EstateFullSCP + " <- terraform:aws_organizations_policy_attachment.full_prod",
		"put_resource_policy " + awstest.EstateBucket + " <- terraform:aws_s3_bucket_policy.pii",
		"attach_scp ou-prod " + placeholder,
	} {
		if !strings.HasPrefix(lines[i], prefix) {
			t.Errorf("operation %d = %q, want prefix %q", i, lines[i], prefix)
		}
	}
	// the placeholder of the new SCP is the same in its put and in the attachment that refers to it
	put, att := strings.Fields(lines[0])[1], strings.Fields(lines[4])[2]
	if put != att {
		t.Errorf("the attachment names %s, the policy is put as %s", att, put)
	}
	want := []string{"aws_organizations_policy.tags unsupported", "aws_s3_bucket_policy.ghost unresolved"}
	if got := findings(r); !reflect.DeepEqual(got, want) {
		t.Errorf("findings = %v, want %v", got, want)
	}
	mustApply(t, r)
}

func TestMap_UnknownUnsupportedAndSensitive(t *testing.T) {
	r := mapFixture(t, "unknown.json")
	want := []string{
		"aws_db_instance.db unsupported",
		"aws_iam_policy.dyn conditional",
		"aws_iam_role.newrole unresolved",
		"aws_iam_role_policy_attachment.admin unresolved",
		"aws_iam_role_policy_attachment.dyn conditional",
		"aws_iam_user_policy_attachment.sens unresolved",
		"aws_instance.web unsupported",
	}
	if got := findings(r); !reflect.DeepEqual(got, want) {
		t.Errorf("findings = %v\nwant %v", got, want)
	}
	if !r.Conditional() || r.Count(StatusConditional) != 2 || r.Count(StatusUnsupported) != 2 {
		t.Errorf("conditional=%v counts: %d conditional, %d unsupported", r.Conditional(), r.Count(StatusConditional), r.Count(StatusUnsupported))
	}
	// an unknown value is neither allow nor deny: the change is not applied
	for _, o := range r.Operations {
		if strings.Contains(o.Source, "dyn") || strings.Contains(o.Source, "newrole") {
			t.Errorf("an unknown or unresolved change became an operation: %s", opLine(o))
		}
	}
	if got := opLines(r.Operations); len(got) != 1 || !strings.HasPrefix(got[0], "put_inline "+awstest.EstateEngineer+" sens-doc") {
		t.Errorf("operations = %v", got)
	}
	if r.Resources != 8 || r.Ignored != 2 {
		t.Errorf("resources=%d ignored=%d", r.Resources, r.Ignored)
	}
	// nothing from the plan's values is in the findings
	raw, _ := json.Marshal(r.Findings)
	for _, secret := range []string{"SECRET-VALUE-123", "SENSITIVE-USER-NAME", "SECRET-RESOURCE-NAME", "AdministratorAccess", "ami-123"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("findings echo %q: %s", secret, raw)
		}
	}
	mustApply(t, r)
}

func TestMap_Deterministic(t *testing.T) {
	for _, name := range []string{"iam.json", "s3_org.json", "unknown.json"} {
		a, _ := json.Marshal(mapFixture(t, name))
		for i := 0; i < 5; i++ {
			if b, _ := json.Marshal(mapFixture(t, name)); string(a) != string(b) {
				t.Fatalf("%s: two runs differ", name)
			}
		}
	}
}

// the order of resource_changes does not change the answer.
func TestMap_OrderIndependent(t *testing.T) {
	p, err := Parse(fixture(t, "iam.json"))
	if err != nil {
		t.Fatal(err)
	}
	_, e := estate(t)
	a, _ := json.Marshal(Map(p, e))
	for i, j := 0, len(p.Changes)-1; i < j; i, j = i+1, j-1 {
		p.Changes[i], p.Changes[j] = p.Changes[j], p.Changes[i]
	}
	if b, _ := json.Marshal(Map(p, e)); string(a) != string(b) {
		t.Errorf("reversed plan gives a different answer:\n%s\n%s", a, b)
	}
}

func TestMap_NoEstate(t *testing.T) {
	p, err := Parse(fixture(t, "iam.json"))
	if err != nil {
		t.Fatal(err)
	}
	r := Map(p, NewEstate(nil))
	if len(r.Operations) > 2 {
		// only the policy documents can be put without an estate
		t.Errorf("operations against nothing: %v", opLines(r.Operations))
	}
	if r.Count(StatusUnresolved) == 0 {
		t.Errorf("an empty estate resolved everything: %v", findings(r))
	}
}

// plan builds a one-resource plan for the cases below.
func plan(typ, name string, actions []string, before, after, unknown any) []byte {
	raw, _ := json.Marshal(map[string]any{"format_version": "1.2", "planned_values": map[string]any{}, "resource_changes": []any{
		map[string]any{"address": typ + "." + name, "mode": "managed", "type": typ, "name": name,
			"change": map[string]any{"actions": actions, "before": before, "after": after, "after_unknown": unknown}}}})
	return raw
}

func TestMap_Cases(t *testing.T) {
	const narrow = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::prod-pii/*"}]}`
	const wide = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`
	obj := func(kv ...any) map[string]any {
		m := map[string]any{}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i].(string)] = kv[i+1]
		}
		return m
	}
	cases := []struct {
		name     string
		plan     []byte
		ops      []string
		findings []string
	}{
		{"policy replaced under the same name",
			plan("aws_iam_policy", "p", []string{"delete", "create"},
				obj("arn", awstest.EstateS3Read, "name", "S3Read", "path", "/", "policy", narrow),
				obj("name", "S3Read", "path", "/", "policy", wide), obj("arn", true)),
			[]string{"put_policy_version " + awstest.EstateS3Read + " <- terraform:aws_iam_policy.p"}, nil},
		{"policy document unchanged",
			plan("aws_iam_policy", "p", []string{"update"},
				obj("arn", awstest.EstateS3Read, "name", "S3Read", "policy", narrow, "tags", obj()),
				obj("arn", awstest.EstateS3Read, "name", "S3Read", "policy", narrow, "tags", obj("a", "b")), obj()),
			nil, []string{"aws_iam_policy.p no_effect"}},
		{"policy delete",
			plan("aws_iam_policy", "p", []string{"delete"}, obj("arn", awstest.EstateS3Read, "policy", narrow), nil, obj()),
			nil, []string{"aws_iam_policy.p no_effect"}},
		{"policy that is not JSON",
			plan("aws_iam_policy", "p", []string{"create"}, nil, obj("name", "x", "policy", "not json"), obj("arn", true)),
			nil, []string{"aws_iam_policy.p unresolved"}},
		{"managed policy on a role through the role's own attribute",
			plan("aws_iam_role", "r", []string{"update"},
				obj("arn", awstest.EstateEngineer, "name", "DataEngineer", "managed_policy_arns", []any{}, "inline_policy", []any{}, "assume_role_policy", narrow),
				obj("arn", awstest.EstateEngineer, "name", "DataEngineer", "managed_policy_arns", []any{awstest.EstateS3Read}, "inline_policy", []any{}, "assume_role_policy", narrow), obj()),
			[]string{"attach " + awstest.EstateEngineer + " " + awstest.EstateS3Read + " <- terraform:aws_iam_role.r"}, nil},
		{"inline policy block on a role and a removed one",
			plan("aws_iam_role", "r", []string{"update"},
				obj("arn", awstest.EstateEngineer, "name", "DataEngineer", "managed_policy_arns", []any{}, "assume_role_policy", narrow,
					"inline_policy", []any{obj("name", "decrypt", "policy", narrow)}),
				obj("arn", awstest.EstateEngineer, "name", "DataEngineer", "managed_policy_arns", []any{}, "assume_role_policy", narrow,
					"inline_policy", []any{obj("name", "extra", "policy", wide)}), obj()),
			[]string{"delete_inline " + awstest.EstateEngineer + " decrypt <- terraform:aws_iam_role.r",
				"put_inline " + awstest.EstateEngineer + " extra <- terraform:aws_iam_role.r"}, nil},
		{"role inline policies unknown",
			plan("aws_iam_role", "r", []string{"update"},
				obj("arn", awstest.EstateEngineer, "name", "DataEngineer", "assume_role_policy", narrow),
				obj("arn", awstest.EstateEngineer, "name", "DataEngineer", "assume_role_policy", narrow), obj("inline_policy", []any{obj("policy", true)})),
			nil, []string{"aws_iam_role.r conditional"}},
		{"role deleted",
			plan("aws_iam_role", "r", []string{"delete"}, obj("name", "DataEngineer"), nil, obj()),
			nil, []string{"aws_iam_role.r unsupported"}},
		{"permissions boundary set to a policy the snapshot has",
			plan("aws_iam_role", "r", []string{"update"},
				obj("arn", awstest.EstateEngineer, "name", "DataEngineer", "assume_role_policy", narrow, "permissions_boundary", nil),
				obj("arn", awstest.EstateEngineer, "name", "DataEngineer", "assume_role_policy", narrow, "permissions_boundary", awstest.EstateS3Read), obj()),
			[]string{"put_boundary " + awstest.EstateEngineer + " " + awstest.EstateS3Read + " <- terraform:aws_iam_role.r"}, nil},
		{"exclusive attachment moves from alice to bob",
			plan("aws_iam_policy_attachment", "a", []string{"update"},
				obj("name", "a", "policy_arn", awstest.EstateS3Read, "users", []any{"alice"}, "roles", []any{}, "groups", []any{}),
				obj("name", "a", "policy_arn", awstest.EstateS3Read, "users", []any{"bob"}, "roles", []any{}, "groups", []any{}), obj()),
			[]string{"detach " + awstest.EstateAlice + " " + awstest.EstateS3Read + " <- terraform:aws_iam_policy_attachment.a",
				"attach " + awstest.EstateBob + " " + awstest.EstateS3Read + " <- terraform:aws_iam_policy_attachment.a"}, nil},
		{"exclusive attachment with an unknown set",
			plan("aws_iam_policy_attachment", "a", []string{"create"}, nil,
				obj("name", "a", "policy_arn", awstest.EstateS3Read, "roles", []any{}, "groups", []any{}), obj("users", true)),
			nil, []string{"aws_iam_policy_attachment.a conditional"}},
		{"detach of a policy that is not attached",
			plan("aws_iam_user_policy_attachment", "a", []string{"delete"},
				obj("user", "bob", "policy_arn", awstest.EstateS3Read), nil, obj()),
			nil, []string{"aws_iam_user_policy_attachment.a unresolved"}},
		{"unknown user",
			plan("aws_iam_user_policy_attachment", "a", []string{"create"}, nil,
				obj("policy_arn", awstest.EstateS3Read), obj("user", true)),
			nil, []string{"aws_iam_user_policy_attachment.a conditional"}},
		{"group nobody is in",
			plan("aws_iam_group_policy_attachment", "a", []string{"create"}, nil,
				obj("group", "empty", "policy_arn", awstest.EstateS3Read), obj()),
			nil, []string{"aws_iam_group_policy_attachment.a no_effect"}},
		{"inline policy name from a prefix is unknown",
			plan("aws_iam_role_policy", "p", []string{"create"}, nil,
				obj("role", "DataEngineer", "policy", narrow), obj("name", true)),
			nil, []string{"aws_iam_role_policy.p conditional"}},
		{"inline policy name that AWS refuses",
			plan("aws_iam_role_policy", "p", []string{"create"}, nil,
				obj("role", "DataEngineer", "name", "bad name!", "policy", narrow), obj()),
			nil, []string{"aws_iam_role_policy.p unresolved"}},
		{"bucket policy removed",
			plan("aws_s3_bucket_policy", "b", []string{"delete"}, obj("bucket", "prod-pii", "policy", narrow), nil, obj()),
			nil, []string{"aws_s3_bucket_policy.b no_effect"}},
		{"bucket name not known until apply and not a bucket of the plan",
			plan("aws_s3_bucket_policy", "b", []string{"create"}, nil, obj("policy", narrow), obj("bucket", true)),
			nil, []string{"aws_s3_bucket_policy.b conditional"}},
		{"SCP type not enabled is not applied",
			plan("aws_organizations_policy", "s", []string{"create"}, nil,
				obj("name", "x", "type", "SERVICE_CONTROL_POLICY", "content", wide), obj("arn", true, "id", true)),
			[]string{"put_scp"}, nil},
		{"SCP content unknown",
			plan("aws_organizations_policy", "s", []string{"create"}, nil,
				obj("name", "x", "type", "SERVICE_CONTROL_POLICY"), obj("arn", true, "id", true, "content", true)),
			nil, []string{"aws_organizations_policy.s conditional"}},
		{"attachment to an account the organization does not have",
			plan("aws_organizations_policy_attachment", "a", []string{"create"}, nil,
				obj("policy_id", "p-FullAWSAccess", "target_id", "999999999999"), obj()),
			nil, []string{"aws_organizations_policy_attachment.a unresolved"}},
		{"attachment of an SCP to the root",
			plan("aws_organizations_policy_attachment", "a", []string{"delete"},
				obj("policy_id", "p-FullAWSAccess", "target_id", "r-estate"), nil, obj()),
			[]string{"detach_scp r-estate " + awstest.EstateFullSCP + " <- terraform:aws_organizations_policy_attachment.a"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Parse(tc.plan)
			if err != nil {
				t.Fatal(err)
			}
			snap, e := estate(t)
			if strings.HasPrefix(tc.name, "SCP type not enabled") {
				c := *snap
				org := *snap.Org
				org.SCPEnabled = false
				c.Org = &org
				e = NewEstate(&c)
				tc.ops = nil
				tc.findings = []string{"aws_organizations_policy.s unresolved"}
			}
			r := Map(p, e)
			var got []string
			for _, o := range r.Operations {
				got = append(got, opLine(o))
			}
			if len(got) != len(tc.ops) {
				t.Fatalf("operations = %v, want %v (findings %v)", got, tc.ops, findings(r))
			}
			for i := range got {
				if !strings.HasPrefix(got[i], tc.ops[i]) {
					t.Errorf("operation %d = %q, want %q", i, got[i], tc.ops[i])
				}
			}
			if gf := findings(r); !reflect.DeepEqual(gf, tc.findings) && (len(gf) != 0 || len(tc.findings) != 0) {
				t.Errorf("findings = %v, want %v", gf, tc.findings)
			}
			if e.snap != nil && !strings.HasPrefix(tc.name, "SCP type not enabled") {
				mustApply(t, r)
			}
		})
	}
}

func TestParse_Refused(t *testing.T) {
	deep := strings.Repeat(`{"a":`, MaxDepth+2) + "1" + strings.Repeat("}", MaxDepth+2)
	many := `{"format_version":"1.2","resource_changes":[` + strings.TrimSuffix(strings.Repeat(`{"address":"a.b","mode":"managed","type":"a","name":"b","change":{"actions":["no-op"]}},`, MaxResourceChanges+1), ",") + `]}`
	for name, tc := range map[string]struct{ in, code string }{
		"empty":            {``, "not_json"},
		"not json":         {`{`, "not_json"},
		"an array":         {`[]`, "not_json"},
		"trailing data":    {`{"format_version":"1.2","resource_changes":[]}{}`, "not_json"},
		"no format":        {`{"resource_changes":[]}`, "not_terraform_plan"},
		"format 2":         {`{"format_version":"2.0","resource_changes":[]}`, "not_terraform_plan"},
		"format text":      {`{"format_version":"1.x","resource_changes":[]}`, "not_terraform_plan"},
		"a state":          {`{"format_version":"1.0","terraform_version":"1.9.5","values":{"root_module":{}}}`, "not_terraform_plan"},
		"a cloudtrail log": {`{"Records":[{"eventName":"PutRolePolicy"}]}`, "not_terraform_plan"},
		"too deep":         {deep, "plan_too_deep"},
		"too many changes": {many, "plan_too_large"},
		"no address":       {`{"format_version":"1.2","resource_changes":[{"mode":"managed","type":"a","name":"b","change":{"actions":["create"]}}]}`, "invalid_plan"},
		"bad type":         {`{"format_version":"1.2","resource_changes":[{"address":"a","mode":"managed","type":"A B","name":"b","change":{"actions":["create"]}}]}`, "invalid_plan"},
		"bad mode":         {`{"format_version":"1.2","resource_changes":[{"address":"a","mode":"x","type":"a","name":"b","change":{"actions":["create"]}}]}`, "invalid_plan"},
		"no change":        {`{"format_version":"1.2","resource_changes":[{"address":"a","mode":"managed","type":"a","name":"b"}]}`, "invalid_plan"},
		"bad action":       {`{"format_version":"1.2","resource_changes":[{"address":"a","mode":"managed","type":"a","name":"b","change":{"actions":["explode"]}}]}`, "invalid_plan"},
		"no action":        {`{"format_version":"1.2","resource_changes":[{"address":"a","mode":"managed","type":"a","name":"b","change":{"actions":[]}}]}`, "invalid_plan"},
		"before a list":    {`{"format_version":"1.2","resource_changes":[{"address":"a","mode":"managed","type":"a","name":"b","change":{"actions":["create"],"before":[1]}}]}`, "invalid_plan"},
		"long address":     {`{"format_version":"1.2","resource_changes":[{"address":"` + strings.Repeat("a", 600) + `","mode":"managed","type":"a","name":"b","change":{"actions":["create"]}}]}`, "invalid_plan"},
	} {
		_, err := Parse([]byte(tc.in))
		var pe *Error
		if err == nil || !asError(err, &pe) || pe.Code != tc.code {
			t.Errorf("%s: err = %v, want code %s", name, err, tc.code)
		}
	}
	// an empty plan is a plan
	if p, err := Parse([]byte(`{"format_version":"1.2","planned_values":{}}`)); err != nil || len(p.Changes) != 0 {
		t.Errorf("a plan with no changes: %v %v", p, err)
	}
}

func asError(err error, out **Error) bool {
	e, ok := err.(*Error)
	if ok {
		*out = e
	}
	return ok
}

func TestStripIndex(t *testing.T) {
	for in, want := range map[string]string{
		"aws_iam_policy.x":                   "aws_iam_policy.x",
		"aws_iam_policy.x[0]":                "aws_iam_policy.x",
		`module.a["k]"].aws_iam_policy.x[1]`: "module.a.aws_iam_policy.x",
		`aws_iam_policy.x["a\"]b"]`:          "aws_iam_policy.x",
	} {
		if got := stripIndex(in); got != want {
			t.Errorf("stripIndex(%q) = %q, want %q", in, got, want)
		}
	}
}

// a policy that a module creates and attaches by reference resolves through the module path.
func TestMap_ReferenceInModule(t *testing.T) {
	raw := `{"format_version":"1.2","planned_values":{},"resource_changes":[
	 {"address":"module.iam.aws_iam_policy.p[0]","module_address":"module.iam","mode":"managed","type":"aws_iam_policy","name":"p","index":0,
	  "change":{"actions":["create"],"before":null,"after":{"name":"mod","path":"/","policy":"{\"Version\":\"2012-10-17\",\"Statement\":[]}"},"after_unknown":{"arn":true}}},
	 {"address":"module.iam.aws_iam_role_policy_attachment.a","module_address":"module.iam","mode":"managed","type":"aws_iam_role_policy_attachment","name":"a",
	  "change":{"actions":["create"],"before":null,"after":{"role":"DataEngineer"},"after_unknown":{"policy_arn":true}}}],
	 "configuration":{"root_module":{"module_calls":{"iam":{"module":{"resources":[
	  {"address":"aws_iam_role_policy_attachment.a","mode":"managed","expressions":{"policy_arn":{"references":["aws_iam_policy.p[0].arn","aws_iam_policy.p[0]","aws_iam_policy.p"]}}}]}}}}}}`
	p, err := Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	_, e := estate(t)
	r := Map(p, e)
	got := opLines(r.Operations)
	// the estate has two accounts and the plan names none, so the new policy has a placeholder ARN, and the attachment finds it by reference
	if len(got) != 2 || !strings.HasPrefix(got[1], "attach "+awstest.EstateEngineer+" arn:aws:iam::000000000000:policy/tessera-plan/module_iam") || strings.Fields(got[0])[1] != strings.Fields(got[1])[2] {
		t.Errorf("operations = %v findings = %v", got, findings(r))
	}
}

func FuzzParseMap(f *testing.F) {
	for _, n := range []string{"iam.json", "s3_org.json", "unknown.json"} {
		f.Add(fixture(f, n))
	}
	f.Add([]byte(`{"format_version":"1.2","planned_values":{}}`))
	f.Add([]byte(`{"format_version":"1.2","resource_changes":[{"address":"a","mode":"managed","type":"aws_iam_role","name":"b","change":{"actions":["update"],"before":{"name":"DataEngineer"},"after":{"name":"DataEngineer","assume_role_policy":"{}"},"after_unknown":true}}]}`))
	snap, err := awstest.Estate()
	if err != nil {
		f.Fatal(err)
	}
	e := NewEstate(snap)
	f.Fuzz(func(t *testing.T, raw []byte) {
		p, err := Parse(raw)
		if err != nil {
			if _, ok := err.(*Error); !ok {
				t.Fatalf("Parse returned %T, not *Error", err)
			}
			return
		}
		r := Map(p, e)
		if len(r.Operations) > MaxResourceChanges*8 {
			t.Fatalf("%d operations from %d changes", len(r.Operations), len(p.Changes))
		}
		for _, fi := range r.Findings {
			switch fi.Status {
			case StatusUnsupported, StatusConditional, StatusUnresolved, StatusNoEffect:
			default:
				t.Fatalf("finding status %q", fi.Status)
			}
		}
		// what the mapping returns applies to the snapshot it was checked against
		if _, err := snapshot.Apply(snap, blast.Changes(r.Operations), snapshot.ApplyOptions{FetchedAt: time.Unix(0, 0).UTC(),
			MultivaluedKey: func(string) bool { return false }}); err != nil {
			t.Fatalf("operations do not apply: %v", err)
		}
		a, _ := json.Marshal(r)
		if b, _ := json.Marshal(Map(p, e)); string(a) != string(b) {
			t.Fatal("two mappings of one plan differ")
		}
	})
}
