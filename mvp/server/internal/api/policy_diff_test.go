package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/awstest"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// The unified blast-radius preview (issue #654, AC-8): POST /api/policy/diff compiles a bundle and AWS operations
// into one answer, changes nothing, reads only the session's tenant, and gives the same bytes for the same change.

type diffAnswer struct {
	Tenant       string `json:"tenant"`
	BundleSHA256 string `json:"bundle_sha256"`
	DiffSHA256   string `json:"diff_sha256"`
	Kinds        []struct {
		Kind          string `json:"kind"`
		Created       int    `json:"created"`
		GrantsAdded   int    `json:"grants_added"`
		PlanSHA256    string `json:"plan_sha256"`
		Unchanged     int    `json:"unchanged"`
		GrantsRemoved int    `json:"grants_removed"`
	} `json:"kinds"`
	AWS *struct {
		BaseSnapshot string `json:"base_snapshot"`
		HeadSnapshot string `json:"head_snapshot"`
		Operations   []struct {
			Index  int    `json:"index"`
			Source string `json:"source"`
		} `json:"operations"`
	} `json:"aws"`
	Summary struct {
		IdentitiesGaining      int   `json:"identities_gaining"`
		IdentitiesLosing       int   `json:"identities_losing"`
		AgentsGaining          int   `json:"agents_gaining"`
		GraphPermissionsGained int   `json:"graph_permissions_gained"`
		AWSPathsGained         int64 `json:"aws_paths_gained"`
		UnlinkedPrincipals     int   `json:"unlinked_principals"`
	} `json:"summary"`
	ByIdentityType []struct {
		Type              string `json:"type"`
		IdentitiesGaining int    `json:"identities_gaining"`
	} `json:"by_identity_type"`
	ByResource []struct {
		Resource          string   `json:"resource"`
		Systems           []string `json:"systems"`
		IdentitiesGaining int      `json:"identities_gaining"`
		AgentsGaining     int      `json:"agents_gaining"`
	} `json:"by_resource"`
	Identities []struct {
		IdentityID int64  `json:"identity_id"`
		Name       string `json:"name"`
		Type       string `json:"type"`
	} `json:"identities"`
	Violations struct {
		Before               int `json:"before"`
		After                int `json:"after"`
		IntroducedTotal      int `json:"introduced_total"`
		AgentScopeIntroduced int `json:"agent_scope_introduced"`
		Introduced           []struct {
			PolicyID string `json:"policy_id"`
		} `json:"introduced"`
	} `json:"violations"`
}

func diffBody(files map[string]string, ops string) string {
	raw, _ := json.Marshal(map[string]any{"files": files})
	s := string(raw)
	if ops != "" {
		s = strings.TrimSuffix(s, "}") + `,"operations":[` + ops + `]}`
	}
	return s
}

func diffDo(t *testing.T, h http.Handler, l authtest.Login, body string, want int) (diffAnswer, string) {
	t.Helper()
	rec := reqDo(h, l, "POST", "/api/policy/diff", body)
	if rec.Code != want {
		t.Fatalf("POST /api/policy/diff: %d, want %d: %.600s", rec.Code, want, rec.Body)
	}
	var out diffAnswer
	if want == 200 {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
	}
	return out, rec.Body.String()
}

// linkAWSAccounts gives the estate's principals an aws account each, owned by the tenant's identities: alice and bob
// are people, the DataEngineer role belongs to the agent.
func linkAWSAccounts(t *testing.T, f *storetest.Fixture, tn storetest.Tenant) {
	t.Helper()
	err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
		for arn, who := range map[string]string{awstest.EstateAlice: "alice", awstest.EstateBob: "bob", awstest.EstateEngineer: "helper-bot"} {
			id := tn.IDs[who]
			kind := "user"
			if who == "helper-bot" {
				kind = "service"
			}
			if err := c.UpsertAccount(&store.Account{TenantID: tn.ID, System: "aws", ExternalID: arn, Username: arn, IdentityID: &id, Kind: kind, Status: "active"}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// ops that widen S3Read and give it to bob's group and to the DataEngineer role: alice, bob and the role (which the
// agent owns) gain a path to the bucket's objects.
const diffWidenOps = `{"op":"put_policy_version","target_arn":"` + awstest.EstateS3Read + `","document":"` + widenPolicy + `","source":"terraform:aws_iam_policy.s3_read"},` +
	`{"op":"attach","target_arn":"` + awstest.EstateGroup + `","policy_arn":"` + awstest.EstateS3Read + `","source":"terraform:aws_iam_group_policy_attachment.eng"},` +
	`{"op":"attach","target_arn":"` + awstest.EstateEngineer + `","policy_arn":"` + awstest.EstateS3Read + `"}`

// The acceptance fixture: N identities gain a new path to a bucket, and k of them are agents.
func TestPolicyDiffAPI_AWSIdentitiesGainPathToBucket(t *testing.T) {
	f := storetest.TwoTenants(t)
	linkAWSAccounts(t, f, f.B)
	persistEstate(t, f.DB, f.B.ID, nil)
	h := newIsolationServerWith(f, withAWSCatalog).Handler()
	pa := reqLogin(t, f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "")

	ans, raw := diffDo(t, h, pa, diffBody(nil, diffWidenOps), 200)
	if ans.Summary.IdentitiesGaining != 3 || ans.Summary.AgentsGaining != 1 || ans.Summary.IdentitiesLosing != 0 || ans.Summary.AWSPathsGained < 3 || ans.Summary.UnlinkedPrincipals != 0 {
		t.Fatalf("summary = %+v\n%s", ans.Summary, raw)
	}
	var bucket bool
	for _, r := range ans.ByResource {
		if strings.Contains(r.Resource, "prod-pii") && r.IdentitiesGaining == 3 && r.AgentsGaining == 1 && len(r.Systems) == 1 && r.Systems[0] == "aws" {
			bucket = true
		}
	}
	if !bucket {
		t.Errorf("no resource of the bucket is gained by 3 identities, 1 of them an agent: %+v", ans.ByResource)
	}
	types := map[string]int{}
	for _, ty := range ans.ByIdentityType {
		types[ty.Type] = ty.IdentitiesGaining
	}
	if types["human"] != 2 || types["ai_agent"] != 1 || len(types) != 2 {
		t.Errorf("by identity type = %v", types)
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
	if ans.AWS == nil || len(ans.AWS.Operations) != 3 || ans.AWS.Operations[0].Source != "terraform:aws_iam_policy.s3_read" ||
		ans.AWS.HeadSnapshot == "" || ans.AWS.HeadSnapshot == ans.AWS.BaseSnapshot || ans.Tenant != f.B.Slug || len(ans.DiffSHA256) != 64 {
		t.Errorf("answer = %+v", ans)
	}
	// the same change is the same bytes, so it can be posted and compared
	if _, again := diffDo(t, h, pa, diffBody(nil, diffWidenOps), 200); again != raw {
		t.Errorf("a second preview differs:\n%.400s\n%.400s", raw, again)
	}
	// the request's audit event carries the totals and the digest
	if evs := httpEvents(ledger(t, f.DB, f.B.ID)); len(evs) == 0 || !strings.Contains(string(evs[0].Detail), `"policy_diff_identities_gaining":3`) ||
		!strings.Contains(string(evs[0].Detail), `"policy_diff_agents_gaining":1`) || !strings.Contains(string(evs[0].Detail), ans.DiffSHA256) {
		t.Errorf("audit detail lacks the totals: %v", evs)
	}
	// it changed nothing: the snapshot list and the audit trail of the domain are as they were
	err := f.DB.ReadTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		all, err := c.AWSSnapshots(10)
		if len(all) != 1 {
			t.Errorf("snapshots after a preview = %d, want the one collected", len(all))
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if acts := reqAuditActions(t, f, f.B.ID); acts["policy.diff"] != 0 {
		t.Errorf("a preview wrote a domain event: %v", acts)
	}

	// another tenant with the same estate and its own accounts sees only its own identities
	linkAWSAccounts(t, f, f.A)
	persistEstate(t, f.DB, f.A.ID, nil)
	paA := signIn(t, f.DB, f.A.ID, authtest.User{Email: "pa@a.example", Roles: []auth.Role{auth.RolePolicyAdmin}}, authtest.Phr, storetest.Now)
	ansA, _ := diffDo(t, h, paA, diffBody(nil, diffWidenOps), 200)
	if ansA.Summary.IdentitiesGaining != 3 || ansA.Tenant != f.A.Slug {
		t.Fatalf("tenant A summary = %+v", ansA.Summary)
	}
	for _, i := range ansA.Identities {
		if i.IdentityID == f.B.IDs["alice"] || i.IdentityID == f.B.IDs["bob"] || i.IdentityID == f.B.IDs["helper-bot"] {
			t.Errorf("tenant A's answer names tenant B's identity %d", i.IdentityID)
		}
	}
}

func TestPolicyDiffAPI_BundleGraphAndAgentScopes(t *testing.T) {
	f := storetest.TwoTenants(t)
	// B has discovered an agent (its identity is a person of the fixture, which holds permissions); A has one B cannot name
	if err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		return c.UpsertAgentProfile(&store.AgentProfile{Source: "entra", ExternalID: "hb", IdentityID: f.B.IDs["alice"], Kind: "agent"}, storetest.Now)
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		return c.UpsertAgentProfile(&store.AgentProfile{Source: "entra", ExternalID: "only-a", IdentityID: f.A.IDs["alice"], Kind: "agent"}, storetest.Now)
	}); err != nil {
		t.Fatal(err)
	}
	h := newIsolationServer(f).Handler()
	pa := reqLogin(t, f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "")
	b := f.B.IDs

	// no change at all, an unreadable body and a stale sign-in are refused
	if rec := reqDo(h, pa, "POST", "/api/policy/diff", `{}`); rec.Code != 422 || !strings.Contains(rec.Body.String(), "empty_change") {
		t.Errorf("empty change: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, pa, "POST", "/api/policy/diff", `{"files":{},"extra":1}`); rec.Code != 422 {
		t.Errorf("unknown field: %d %s", rec.Code, rec.Body)
	}
	stale := signIn(t, f.DB, f.B.ID, authtest.User{Email: "st@b.example", Roles: []auth.Role{auth.RolePolicyAdmin}},
		authtest.Ctx{AAL: 2, Phr: true, AuthTime: storetest.Now.Add(-20 * time.Minute)}, storetest.Now)
	if rec := reqDo(h, stale, "POST", "/api/policy/diff", `{"files":{"x":"y"}}`); rec.Code != 401 || !strings.Contains(rec.Body.String(), "step_up_required") {
		t.Errorf("stale sign-in: %d %.200s", rec.Code, rec.Body)
	}

	// a role the UI made, exported, then given one more entitlement: its Engineering members gain the group
	body := fmt.Sprintf(`{"name":"Engineer","risk":"medium","requestable":true,"birthright":{"department":["Engineering"]},
		"entitlement_group_ids":[%d]}`, b["group:okta:eng"])
	if rec := reqDo(h, pa, "POST", "/api/roles", body); rec.Code != 201 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var exp struct {
		Files map[string]string `json:"files"`
	}
	rec := reqDo(h, pa, "GET", "/api/policy/roles/export", "")
	if err := json.Unmarshal(rec.Body.Bytes(), &exp); err != nil || rec.Code != 200 {
		t.Fatalf("export: %d %s %v", rec.Code, rec.Body, err)
	}
	// the export diffs as no change
	if ans, _ := diffDo(t, h, pa, diffBody(exp.Files, ""), 200); ans.Summary.IdentitiesGaining != 0 || len(ans.Kinds) != 1 || ans.Kinds[0].Kind != "roles" || ans.Kinds[0].Unchanged != 1 {
		t.Errorf("the export is a change: %+v", ans)
	}
	files := map[string]string{}
	for k, v := range exp.Files {
		files[k] = v
	}
	role := files["roles/engineer.yaml"]
	files["roles/engineer.yaml"] = strings.Replace(role, "entitlements:\n", fmt.Sprintf("entitlements:\n    - okta:%s\n", groupName(t, f, "group:okta:payments-clerks")), 1)
	if files["roles/engineer.yaml"] == role {
		t.Fatalf("the role file has no entitlements to extend:\n%s", role)
	}
	ans, raw := diffDo(t, h, pa, diffBody(files, ""), 200)
	if len(ans.Kinds) != 1 || ans.Kinds[0].GrantsAdded < 1 || ans.Summary.IdentitiesGaining < 1 || ans.Summary.GraphPermissionsGained < 1 ||
		len(ans.ByIdentityType) == 0 || ans.AWS != nil || ans.BundleSHA256 == "" {
		t.Fatalf("roles diff = %+v\n%.800s", ans, raw)
	}
	if _, again := diffDo(t, h, pa, diffBody(files, ""), 200); again != raw {
		t.Error("a second preview of the same bundle differs")
	}
	// nothing was written: the role still has its one entitlement, and no event of the preview's own was added
	rec = reqDo(h, pa, "POST", "/api/policy/roles/plan", diffBody(exp.Files, ""))
	if !strings.Contains(rec.Body.String(), `"roles_unchanged":1`) {
		t.Errorf("the role changed: %s", rec.Body)
	}

	// an agent scope nothing can satisfy: the agent's permissions become out-of-scope findings, before any apply
	scope := `schema: tessera.agentscope/v1
key: hb
name: Helper bot
agent:
  source: entra
  external_id: hb
allow:
  actions: [write]
  resources:
    - systems: [nowhere]
`
	agents := map[string]string{
		"tessera.yaml":   fmt.Sprintf("schema: tessera.repo/v1\ntenant: %s\nmanage:\n  agents: partial\n", f.B.Slug),
		"agents/hb.yaml": scope,
	}
	ans, raw = diffDo(t, h, pa, diffBody(agents, ""), 200)
	if ans.Violations.AgentScopeIntroduced < 1 || ans.Violations.After <= ans.Violations.Before || len(ans.Kinds) != 1 || ans.Kinds[0].Kind != "agents" || ans.Kinds[0].Created != 1 {
		t.Fatalf("agent scope diff = %+v\n%.800s", ans, raw)
	}
	found := false
	for _, v := range ans.Violations.Introduced {
		found = found || v.PolicyID == "agent-out-of-scope"
	}
	if !found {
		t.Errorf("no agent-out-of-scope finding listed: %+v", ans.Violations)
	}
	if rec := reqDo(h, pa, "GET", "/api/violations", ""); strings.Contains(rec.Body.String(), "agent-out-of-scope") {
		t.Error("the preview applied the scope")
	}
	// and the roles and scopes together are one answer, kinds in name order
	both := map[string]string{"tessera.yaml": fmt.Sprintf("schema: tessera.repo/v1\ntenant: %s\nmanage:\n  agents: partial\n  roles: partial\n", f.B.Slug),
		"agents/hb.yaml": scope, "roles/engineer.yaml": files["roles/engineer.yaml"], "birthright/engineer.cedar": files["birthright/engineer.cedar"]}
	if ans, raw = diffDo(t, h, pa, diffBody(both, ""), 200); len(ans.Kinds) != 2 || ans.Kinds[0].Kind != "agents" || ans.Kinds[1].Kind != "roles" {
		t.Errorf("both kinds = %+v\n%.600s", ans.Kinds, raw)
	}

	// findings come back as the plan routes give them; another tenant's bundle and agent are refused
	bad := map[string]string{"tessera.yaml": agents["tessera.yaml"], "agents/hb.yaml": strings.Replace(scope, "[write]", "[write, root]", 1)}
	if rec := reqDo(h, pa, "POST", "/api/policy/diff", diffBody(bad, "")); rec.Code != 422 || !strings.Contains(rec.Body.String(), `"invalid_bundle"`) || !strings.Contains(rec.Body.String(), `"invalid_actions"`) {
		t.Errorf("invalid bundle: %d %s", rec.Code, rec.Body)
	}
	foreign := map[string]string{"tessera.yaml": agents["tessera.yaml"], "agents/hb.yaml": strings.Replace(scope, "external_id: hb", "external_id: only-a", 1)}
	if rec := reqDo(h, pa, "POST", "/api/policy/diff", diffBody(foreign, "")); rec.Code != 422 || !strings.Contains(rec.Body.String(), `"unknown_agent"`) {
		t.Errorf("another tenant's agent: %d %s", rec.Code, rec.Body)
	}
	other := map[string]string{"tessera.yaml": strings.Replace(agents["tessera.yaml"], f.B.Slug, "globex", 1), "agents/hb.yaml": scope}
	if rec := reqDo(h, pa, "POST", "/api/policy/diff", diffBody(other, "")); rec.Code != 422 || !strings.Contains(rec.Body.String(), `"tenant_mismatch"`) {
		t.Errorf("another tenant's bundle: %d %s", rec.Code, rec.Body)
	}
	onlyConfig := map[string]string{"tessera.yaml": other["tessera.yaml"]}
	if rec := reqDo(h, pa, "POST", "/api/policy/diff", diffBody(onlyConfig, "")); rec.Code != 422 || !strings.Contains(rec.Body.String(), `"tenant_mismatch"`) {
		t.Errorf("a bundle with no kind naming another tenant: %d %s", rec.Code, rec.Body)
	}
	huge := map[string]string{"tessera.yaml": agents["tessera.yaml"], "agents/x.yaml": strings.Repeat("a", 300<<10)}
	if rec := reqDo(h, pa, "POST", "/api/policy/diff", diffBody(huge, "")); rec.Code != 422 || !strings.Contains(rec.Body.String(), "too_large") {
		t.Errorf("an oversized file: %d %.200s", rec.Code, rec.Body)
	}
	// operations need a collected snapshot
	if rec := reqDo(h, pa, "POST", "/api/policy/diff", diffBody(nil, diffWidenOps)); rec.Code == 200 {
		t.Errorf("operations with no AWS catalog or snapshot: %d", rec.Code)
	}
}

// A SoD ruleset in the bundle is checked against the graph after the change: findings it would raise are listed as
// introduced, and nothing is stored.
func TestPolicyDiffAPI_SoDRules(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	pa := reqLogin(t, f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "")
	doc := `schema: tessera.sod/v1
ruleset:
  key: payments
  name: Payments controls
  enabled: true
functions:
  - key: create
    name: Create a payment
    selectors: [{name_pattern: "payments:create*"}]
  - key: approve
    name: Approve a payment
    selectors: [{name_pattern: "payments:approve*"}]
risks:
  - key: pay-create-approve
    name: Create and approve a payment
    priority: high
    functions: [create, approve]
`
	files := map[string]string{
		"tessera.yaml":      fmt.Sprintf("schema: tessera.repo/v1\ntenant: %s\nmanage:\n  sod: partial\n", f.B.Slug),
		"sod/payments.yaml": doc,
	}
	ans, raw := diffDo(t, h, pa, diffBody(files, ""), 200)
	if len(ans.Kinds) != 1 || ans.Kinds[0].Kind != "sod" || ans.Kinds[0].Created < 1 || ans.Violations.After < ans.Violations.Before {
		t.Fatalf("answer = %+v\n%.600s", ans, raw)
	}
	for _, v := range ans.Violations.Introduced {
		if v.PolicyID != "pay-create-approve" {
			t.Errorf("an unrelated finding was introduced: %+v", v)
		}
	}
	if ans.Violations.IntroducedTotal != ans.Violations.After-ans.Violations.Before {
		t.Errorf("introduced %d, but %d before and %d after", ans.Violations.IntroducedTotal, ans.Violations.Before, ans.Violations.After)
	}
	if ans.Violations.IntroducedTotal < 1 || len(ans.Violations.Introduced) != ans.Violations.IntroducedTotal {
		t.Errorf("the rule raises no finding on the tiny world, where someone holds both: %+v", ans.Violations)
	}
	if rec := reqDo(h, pa, "POST", "/api/policy/sod/plan", diffBody(files, "")); !strings.Contains(rec.Body.String(), `"created":4`) {
		t.Errorf("the rule was stored by the preview: %s", rec.Body)
	}
}

func TestPolicyDiffAPI_StepCeiling(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServerWith(f, func(c *Config) { withAWSCatalog(c); c.PolicyMaxSteps = 2 }).Handler()
	pa := reqLogin(t, f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "")
	rec := reqDo(h, pa, "POST", "/api/policy/diff", diffBody(nil, diffWidenOps))
	if rec.Code != 413 || !strings.Contains(rec.Body.String(), "plan_too_large") {
		t.Errorf("three operations over a ceiling of 2: %d %.300s", rec.Code, rec.Body)
	}
}

func TestPolicyDiffAPI_BadOperations(t *testing.T) {
	f := storetest.TwoTenants(t)
	persistEstate(t, f.DB, f.B.ID, nil)
	h := newIsolationServerWith(f, withAWSCatalog).Handler()
	pa := reqLogin(t, f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "")
	for name, tc := range map[string]struct {
		ops  string
		want int
		code string
	}{
		"unknown op":     {`{"op":"drop_table","target_arn":"x"}`, 422, "invalid_body"},
		"unknown field":  {`{"op":"attach","target_arn":"x","extra":1}`, 422, "invalid_body"},
		"bad change":     {`{"op":"detach","target_arn":"` + awstest.EstateDevUser + `","policy_arn":"` + awstest.EstateS3Read + `"}`, 422, "invalid_change"},
		"long source":    {`{"op":"detach","target_arn":"x","source":"` + strings.Repeat("s", 201) + `"}`, 422, "invalid_change"},
		"missing policy": {`{"op":"put_resource_policy","target_arn":"` + awstest.EstateBucket + `"}`, 422, "invalid_change"},
	} {
		rec := reqDo(h, pa, "POST", "/api/policy/diff", diffBody(nil, tc.ops))
		if rec.Code != tc.want || !strings.Contains(rec.Body.String(), tc.code) {
			t.Errorf("%s: %d %.200s, want %d %s", name, rec.Code, rec.Body, tc.want, tc.code)
		}
	}
	if rec := reqDo(h, pa, "POST", "/api/policy/diff", `{"operations":[{"op":"attach","target_arn":"x","policy_arn":"y"}],"base_snapshot":"x"}`); rec.Code != 404 {
		t.Errorf("malformed base: %d %.200s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, pa, "POST", "/api/policy/diff", `{"operations":[{"op":"attach","target_arn":"x","policy_arn":"y"}],"profile":"moon"}`); rec.Code != 422 || !strings.Contains(rec.Body.String(), "invalid_profile") {
		t.Errorf("bad profile: %d %.200s", rec.Code, rec.Body)
	}
}

// A change that moves nothing in the graph or the policies still reports the violations the tenant has, the same
// baseline GET /api/violations gives; before this the preview skipped the simulation and answered 0 and 0 (issue #765).
func TestPolicyDiffAPI_NoOpReportsBaselineViolations(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	pa := reqLogin(t, f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "")

	rec := reqDo(h, pa, "GET", "/api/violations", "")
	var viol []json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &viol); err != nil || rec.Code != 200 {
		t.Fatalf("violations: %d %.200s %v", rec.Code, rec.Body, err)
	}
	if len(viol) == 0 {
		t.Fatal("the fixture tenant has no violations, so the baseline cannot be told from zero")
	}
	// an empty roles bundle changes nothing
	files := map[string]string{"tessera.yaml": fmt.Sprintf("schema: tessera.repo/v1\ntenant: %s\nmanage:\n    roles: partial\n", f.B.Slug)}
	ans, raw := diffDo(t, h, pa, diffBody(files, ""), 200)
	if ans.Summary.IdentitiesGaining != 0 || ans.Summary.IdentitiesLosing != 0 || ans.Violations.IntroducedTotal != 0 {
		t.Errorf("a no-op bundle is a change: %.600s", raw)
	}
	if ans.Violations.Before != len(viol) || ans.Violations.After != len(viol) {
		t.Errorf("no-op violations before/after = %d/%d, GET /api/violations has %d", ans.Violations.Before, ans.Violations.After, len(viol))
	}
}
