package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/awstest"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// The Terraform plan input of the blast-radius preview (issue #655, AC-9): a plan in the body of POST /api/policy/diff
// becomes operations against the base snapshot, what it cannot map is listed, and the route's ceilings, tenant scoping
// and audit apply to it.

type tfAnswer struct {
	diffAnswer
	Terraform *struct {
		FormatVersion      string `json:"format_version"`
		TerraformVersion   string `json:"terraform_version"`
		PlanSHA256         string `json:"plan_sha256"`
		Resources          int    `json:"resources"`
		Operations         int    `json:"operations"`
		Ignored            int    `json:"ignored"`
		Conditional        bool   `json:"conditional"`
		Unsupported        int    `json:"unsupported"`
		ConditionalChanges int    `json:"conditional_changes"`
		Unresolved         int    `json:"unresolved"`
		Findings           []struct {
			Address string `json:"address"`
			Status  string `json:"status"`
			Reason  string `json:"reason"`
		} `json:"findings"`
	} `json:"terraform"`
}

func planFixture(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "tfplan", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func tfDo(t *testing.T, h http.Handler, l authtest.Login, body string, want int) (tfAnswer, string) {
	t.Helper()
	rec := reqDo(h, l, "POST", "/api/policy/diff", body)
	if rec.Code != want {
		t.Fatalf("POST /api/policy/diff: %d, want %d: %.600s", rec.Code, want, rec.Body)
	}
	var out tfAnswer
	if want == 200 {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
	}
	return out, rec.Body.String()
}

func TestPolicyDiffAPI_TerraformPlan(t *testing.T) {
	f := storetest.TwoTenants(t)
	linkAWSAccounts(t, f, f.B)
	persistEstate(t, f.DB, f.B.ID, nil)
	h := newIsolationServerWith(f, withAWSCatalog).Handler()
	pa := reqLogin(t, f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "")

	// a plan that widens S3Read, gives it to the eng group and attaches a new policy to the DataEngineer role
	body := `{"terraform_plan":` + planFixture(t, "iam.json") + `}`
	ans, raw := tfDo(t, h, pa, body, 200)
	tf := ans.Terraform
	if tf == nil || tf.FormatVersion != "1.2" || tf.TerraformVersion != "1.9.5" || tf.Operations != 10 || tf.Resources != 9 || !tf.Conditional || tf.ConditionalChanges != 1 || len(tf.Findings) != 1 || len(tf.PlanSHA256) != 64 {
		t.Fatalf("terraform = %+v\n%.800s", tf, raw)
	}
	if ans.AWS == nil || len(ans.AWS.Operations) != 10 || ans.AWS.Operations[0].Source != "terraform:aws_iam_policy.deploy" {
		t.Fatalf("operations = %+v", ans.AWS)
	}
	if ans.Summary.IdentitiesGaining == 0 || ans.Summary.AWSPathsGained == 0 || len(ans.DiffSHA256) != 64 || ans.Tenant != f.B.Slug {
		t.Errorf("summary = %+v", ans.Summary)
	}
	for _, i := range ans.Identities {
		own := false
		for _, id := range f.B.IDs {
			own = own || id == i.IdentityID
		}
		if !own {
			t.Errorf("identity %d (%s) is not tenant B's", i.IdentityID, i.Name)
		}
	}
	// the same plan is the same bytes
	if _, again := tfDo(t, h, pa, body, 200); again != raw {
		t.Errorf("a second preview differs:\n%.400s\n%.400s", raw, again)
	}
	// the audit event carries the plan's totals and digest, not its content
	evs := httpEvents(ledger(t, f.DB, f.B.ID))
	if len(evs) == 0 || !strings.Contains(string(evs[0].Detail), `"policy_diff_tf_operations":10`) || !strings.Contains(string(evs[0].Detail), tf.PlanSHA256) ||
		strings.Contains(string(evs[0].Detail), "s3:*") {
		t.Errorf("audit detail: %v", evs)
	}
	if acts := reqAuditActions(t, f, f.B.ID); acts["policy.diff"] != 0 {
		t.Errorf("a preview wrote a domain event: %v", acts)
	}

	// explicit operations come first, the plan's after them
	both := `{"operations":[{"op":"attach","target_arn":"` + awstest.EstateBob + `","policy_arn":"` + awstest.EstateS3Read + `","source":"by hand"}],"terraform_plan":` + planFixture(t, "s3_org.json") + `}`
	ans, raw = tfDo(t, h, pa, both, 200)
	if ans.AWS == nil || len(ans.AWS.Operations) != 6 || ans.AWS.Operations[0].Source != "by hand" || !strings.HasPrefix(ans.AWS.Operations[1].Source, "terraform:") {
		t.Fatalf("operations = %+v\n%.600s", ans.AWS, raw)
	}
	if ans.Terraform.Operations != 5 || ans.Terraform.Unsupported != 1 || ans.Terraform.Unresolved != 1 || !ans.Terraform.Conditional {
		t.Errorf("terraform = %+v", ans.Terraform)
	}
}

func TestPolicyDiffAPI_TerraformPlanUnknownUnsupportedSensitive(t *testing.T) {
	f := storetest.TwoTenants(t)
	persistEstate(t, f.DB, f.B.ID, nil)
	h := newIsolationServerWith(f, withAWSCatalog).Handler()
	pa := reqLogin(t, f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "")

	ans, raw := tfDo(t, h, pa, `{"terraform_plan":`+planFixture(t, "unknown.json")+`}`, 200)
	tf := ans.Terraform
	if tf == nil || !tf.Conditional || tf.ConditionalChanges != 2 || tf.Unsupported != 2 || tf.Unresolved != 3 || tf.Ignored != 2 || tf.Operations != 1 || len(tf.Findings) != 7 {
		t.Fatalf("terraform = %+v\n%.1200s", tf, raw)
	}
	// nothing the plan marks sensitive, and no value of the plan, is in the answer
	for _, secret := range []string{"SECRET-VALUE-123", "SENSITIVE-USER-NAME", "SECRET-RESOURCE-NAME", "ami-123", "AdministratorAccess"} {
		if strings.Contains(raw, secret) {
			t.Errorf("the answer echoes %q", secret)
		}
	}
	for _, e := range evsDetail(t, f) {
		if strings.Contains(e, "SECRET") {
			t.Errorf("the audit event echoes the plan: %s", e)
		}
	}
	// a plan whose every change is unsupported or unknown is still an answer, with nothing applied
	only := `{"format_version":"1.2","planned_values":{},"resource_changes":[{"address":"aws_instance.x","mode":"managed","type":"aws_instance","name":"x","change":{"actions":["create"],"before":null,"after":{},"after_unknown":{}}}]}`
	ans, _ = tfDo(t, h, pa, `{"terraform_plan":`+only+`}`, 200)
	if ans.AWS != nil || ans.Terraform == nil || ans.Terraform.Unsupported != 1 || ans.Terraform.Operations != 0 || ans.Summary.IdentitiesGaining != 0 {
		t.Errorf("answer = %+v %+v", ans.AWS, ans.Terraform)
	}
}

func evsDetail(t *testing.T, f *storetest.Fixture) []string {
	var out []string
	for _, e := range httpEvents(ledger(t, f.DB, f.B.ID)) {
		out = append(out, string(e.Detail))
	}
	return out
}

func TestPolicyDiffAPI_TerraformPlanRefused(t *testing.T) {
	f := storetest.TwoTenants(t)
	persistEstate(t, f.DB, f.B.ID, nil)
	h := newIsolationServerWith(f, withAWSCatalog).Handler()
	pa := reqLogin(t, f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "")
	deep := strings.Repeat(`{"a":`, 200) + "1" + strings.Repeat("}", 200)
	manyChanges := strings.TrimSuffix(strings.Repeat(`{"address":"a.b","mode":"managed","type":"a","name":"b","change":{"actions":["no-op"]}},`, 5001), ",")
	for name, tc := range map[string]struct {
		body   string
		want   int
		code   string
		reason string
	}{
		"not a plan":      {`{"terraform_plan":{"Records":[]}}`, 422, "invalid_terraform_plan", "not_terraform_plan"},
		"a state":         {`{"terraform_plan":{"format_version":"1.0","values":{}}}`, 422, "invalid_terraform_plan", "not_terraform_plan"},
		"a string":        {`{"terraform_plan":"x"}`, 422, "invalid_terraform_plan", "not_json"},
		"a future format": {`{"terraform_plan":{"format_version":"2.0","resource_changes":[]}}`, 422, "invalid_terraform_plan", "not_terraform_plan"},
		"too deep":        {`{"terraform_plan":` + deep + `}`, 422, "invalid_terraform_plan", "plan_too_deep"},
		"bad change":      {`{"terraform_plan":{"format_version":"1.2","resource_changes":[{"address":"a"}]}}`, 422, "invalid_terraform_plan", "invalid_plan"},
		"too many":        {`{"terraform_plan":{"format_version":"1.2","resource_changes":[` + manyChanges + `]}}`, 413, "plan_too_large", ""},
		"oversize body":   {`{"terraform_plan":{"format_version":"1.2","planned_values":{"pad":"` + strings.Repeat("x", 2<<20) + `"}}}`, 413, "", ""},
		"empty":           {`{"terraform_plan":null}`, 422, "empty_change", ""},
	} {
		rec := reqDo(h, pa, "POST", "/api/policy/diff", tc.body)
		if rec.Code != tc.want || !strings.Contains(rec.Body.String(), tc.code) || !strings.Contains(rec.Body.String(), tc.reason) {
			t.Errorf("%s: %d %.300s, want %d %s %s", name, rec.Code, rec.Body, tc.want, tc.code, tc.reason)
		}
	}
	// no snapshot, no estate to map a plan against
	paA := signIn(t, f.DB, f.A.ID, authtest.User{Email: "pa@a.example", Roles: []auth.Role{auth.RolePolicyAdmin}}, authtest.Phr, storetest.Now)
	if rec := reqDo(h, paA, "POST", "/api/policy/diff", `{"terraform_plan":`+planFixture(t, "iam.json")+`}`); rec.Code != 404 || !strings.Contains(rec.Body.String(), "no_snapshot") {
		t.Errorf("tenant A has no snapshot, and may not use tenant B's: %d %.300s", rec.Code, rec.Body)
	}
}

func TestPolicyDiffAPI_TerraformPlanStepCeiling(t *testing.T) {
	f := storetest.TwoTenants(t)
	persistEstate(t, f.DB, f.B.ID, nil)
	h := newIsolationServerWith(f, func(c *Config) { withAWSCatalog(c); c.PolicyMaxSteps = 3 }).Handler()
	pa := reqLogin(t, f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "")
	rec := reqDo(h, pa, "POST", "/api/policy/diff", `{"terraform_plan":`+planFixture(t, "iam.json")+`}`)
	if rec.Code != 413 || !strings.Contains(rec.Body.String(), "plan_too_large") {
		t.Errorf("ten operations over a ceiling of 3: %d %.300s", rec.Code, rec.Body)
	}
}

// An unsupported change that can alter who has access makes the answer conditional (a new admin group with a member).
func TestPolicyDiffAPI_TerraformPlanAccessRelevantUnsupported(t *testing.T) {
	f := storetest.TwoTenants(t)
	persistEstate(t, f.DB, f.B.ID, nil)
	h := newIsolationServerWith(f, withAWSCatalog).Handler()
	pa := reqLogin(t, f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "")
	plan := `{"format_version":"1.2","planned_values":{},"resource_changes":[
	 {"address":"aws_iam_group.admins","mode":"managed","type":"aws_iam_group","name":"admins","change":{"actions":["create"],"before":null,"after":{"name":"admins"},"after_unknown":{}}},
	 {"address":"aws_iam_user_group_membership.m","mode":"managed","type":"aws_iam_user_group_membership","name":"m","change":{"actions":["create"],"before":null,"after":{"user":"mallory","groups":["admins"]},"after_unknown":{}}}]}`
	ans, raw := tfDo(t, h, pa, `{"terraform_plan":`+plan+`}`, 200)
	if ans.Terraform == nil || !ans.Terraform.Conditional || ans.Terraform.Unsupported != 2 || !strings.Contains(raw, `"access_relevant":true`) {
		t.Errorf("terraform = %+v\n%.600s", ans.Terraform, raw)
	}
}
