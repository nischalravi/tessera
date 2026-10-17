package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/awstest"
	awspolicy "github.com/nischalravi/tessera/mvp/server/internal/aws/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/awsorg"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
	policies "github.com/nischalravi/tessera/mvp/server/policies"
)

// The AWS evaluator's endpoints (issue #30, PR-11) over the awstest.Estate: a
// small estate whose answers are known (alice reads the objects of prod-pii,
// bob lists the bucket through a group, dev holds nothing).

const (
	estateObject = "arn:aws:s3:::prod-pii/customers.csv"
	estateRep    = "arn:aws:s3:::prod-pii/x" // the representative of the pattern arn:aws:s3:::prod-pii/*
)

func testAWSCatalog() (*AWSCatalog, error) {
	return &AWSCatalog{Cat: awstest.Catalog{}, Actions: awstest.Actions(), Applies: awstest.SameServiceRule,
		MultivaluedKey: awspolicy.IsGlobalMultivaluedKey}, nil
}

func withAWSCatalog(c *Config) { c.AWSCatalog = testAWSCatalog }

// persistEstate stores the Estate (and findings) as a snapshot of the tenant and returns its id.
func persistEstate(t testing.TB, db *store.DB, tenant tenancy.ID, findings awsorg.Findings) string {
	t.Helper()
	snap, err := awstest.Estate()
	if err != nil {
		t.Fatal(err)
	}
	col := &awsorg.Collection{Snapshot: snap, AccountIDs: []string{awstest.EstateDev, awstest.EstateProd}, Findings: findings}
	if snap.ID, err = awsorg.ContentID(col); err != nil {
		t.Fatal(err)
	}
	err = db.InTenant(context.Background(), tenant, func(tx *store.TenantTx) error {
		_, err := awsorg.Persist(tx, col, awsorg.PersistInput{Source: store.AWSSourceConnector, CatalogVersion: "awstest-1"})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return snap.ID
}

type awsClient struct {
	rdClient
	snapshot string
}

func newAWSEval(t *testing.T, findings awsorg.Findings, mutate ...func(*Config)) awsClient {
	t.Helper()
	c := newRD(t, append([]func(*Config){withAWSCatalog}, mutate...)...)
	return awsClient{c, persistEstate(t, c.st.DB, c.st.Tenant, findings)}
}

func (c rdClient) get(path string, want int) map[string]any {
	c.t.Helper()
	return c.json("GET", path, "", want)
}

func esc(s string) string { return url.QueryEscape(s) }

func canPath(principal, action, resource string, extra ...string) string {
	return "/api/aws/can?principal=" + esc(principal) + "&action=" + esc(action) + "&resource=" + esc(resource) + strings.Join(extra, "")
}

func TestAWSEvalCan(t *testing.T) {
	c := newAWSEval(t, nil)

	v := c.get(canPath(awstest.EstateAlice, "s3:GetObject", estateObject), 200)
	d := v["decision"].(map[string]any)
	if d["outcome"] != "allow" || d["fidelity"] != "exact" || d["snapshot_id"] != c.snapshot || d["catalog_version"] != "awstest-1" {
		t.Fatalf("decision = %v", d)
	}
	if len(d["steps"].([]any)) == 0 || len(d["decisive"].([]any)) == 0 {
		t.Errorf("the decision has no trace: %v", d)
	}
	if v["snapshot"].(map[string]any)["id"] != c.snapshot || v["profile"] != "default" || len(v["collection_gaps"].([]any)) != 0 {
		t.Errorf("view = %v", v)
	}
	id := v["explanation_id"].(string)
	if len(id) != 64 || !strings.HasPrefix(v["summary"].(string), "ALLOW") || !strings.Contains(v["narrative"].(string), "identity") {
		t.Errorf("summary %q narrative %q id %q", v["summary"], v["narrative"], id)
	}

	// the same question by its explanation id
	x := c.get("/api/aws/explanations/"+id, 200)
	if x["id"] != id || x["decision"].(map[string]any)["outcome"] != "allow" {
		t.Errorf("explanation = %v", x)
	}

	// a principal with no grant is denied, with the reason
	v = c.get(canPath(awstest.EstateBob, "s3:GetObject", estateObject), 200)
	if d := v["decision"].(map[string]any); d["outcome"] != "deny" || d["deny_kind"] != "implicit" {
		t.Errorf("bob = %v", d)
	}
	// a group policy reaches its members
	v = c.get(canPath(awstest.EstateBob, "s3:ListBucket", awstest.EstateBucket), 200)
	if v["decision"].(map[string]any)["outcome"] != "allow" {
		t.Errorf("bob list = %v", v["decision"])
	}

	// profile none leaves keys unknown; bare is a concrete request
	for _, p := range []string{"none", "bare", "tls,now", "any-network"} {
		if got := c.get(canPath(awstest.EstateAlice, "s3:GetObject", estateObject, "&profile="+esc(p)), 200); got["profile"] != p {
			t.Errorf("profile %s: %v", p, got["profile"])
		}
	}
}

func TestAWSEvalRefusesBadInput(t *testing.T) {
	c := newAWSEval(t, nil)
	for name, tc := range map[string]struct {
		path string
		want int
	}{
		"no principal":           {"/api/aws/can?action=s3:GetObject", 422},
		"no action":              {"/api/aws/can?principal=" + esc(awstest.EstateAlice), 422},
		"bad action":             {canPath(awstest.EstateAlice, "GetObject", ""), 422},
		"wildcard action":        {canPath(awstest.EstateAlice, "s3:*", ""), 422},
		"control character":      {canPath(awstest.EstateAlice, "s3:GetObject", "arn:aws:s3:::b\n"), 422},
		"too long a principal":   {canPath(strings.Repeat("a", awsMaxARNLen+1), "s3:GetObject", ""), 422},
		"bad profile":            {canPath(awstest.EstateAlice, "s3:GetObject", "", "&profile=moon"), 422},
		"unsupported profile":    {canPath(awstest.EstateAlice, "s3:GetObject", "", "&profile=corp-network"), 422},
		"too many profiles":      {canPath(awstest.EstateAlice, "s3:GetObject", "", "&profile=now,now,now,now,now"), 422},
		"malformed snapshot":     {canPath(awstest.EstateAlice, "s3:GetObject", "", "&snapshot=../etc"), 404},
		"unknown snapshot":       {canPath(awstest.EstateAlice, "s3:GetObject", "", "&snapshot="+strings.Repeat("0", 64)), 404},
		"unknown principal":      {canPath("arn:aws:iam::111111111111:user/nobody", "s3:GetObject", estateObject), 404},
		"malformed explanation":  {"/api/aws/explanations/xyz", 404},
		"unknown explanation":    {"/api/aws/explanations/" + strings.Repeat("a", 64), 404},
		"effective of nobody":    {"/api/aws/principals/arn:aws:iam::111111111111:user/nobody/effective", 404},
		"effective bad limit":    {"/api/aws/principals/" + awstest.EstateAlice + "/effective?limit=0", 422},
		"effective huge limit":   {"/api/aws/principals/" + awstest.EstateAlice + "/effective?limit=100000", 422},
		"effective bad cursor":   {"/api/aws/principals/" + awstest.EstateAlice + "/effective?cursor=-1", 422},
		"effective late cursor":  {"/api/aws/principals/" + awstest.EstateAlice + "/effective?cursor=99999999", 422},
		"effective bad service":  {"/api/aws/principals/" + awstest.EstateAlice + "/effective?service=S3:x", 422},
		"who-can without action": {"/api/aws/resources/" + awstest.EstateBucket + "/who-can", 422},
	} {
		if rec := c.do("GET", tc.path, ""); rec.Code != tc.want {
			t.Errorf("%s: %d, want %d: %.200s", name, rec.Code, tc.want, rec.Body.String())
		}
	}
}

func TestAWSEvalWithoutCatalogOrSnapshot(t *testing.T) {
	// no catalog configured: the evaluator answers 503, everything else is unaffected
	c := newRD(t)
	persistEstate(t, c.st.DB, c.st.Tenant, nil)
	for _, path := range []string{canPath(awstest.EstateAlice, "s3:GetObject", ""), "/api/aws/principals/" + awstest.EstateAlice + "/effective",
		"/api/aws/resources/" + awstest.EstateBucket + "/who-can?action=s3:ListBucket"} {
		rec := c.do("GET", path, "")
		if rec.Code != 503 || !strings.Contains(rec.Body.String(), "aws_catalog_unavailable") {
			t.Errorf("GET %s = %d %s", path, rec.Code, rec.Body.String())
		}
	}
	c.get("/api/aws/snapshots", 200)

	// a catalog that fails to load is the same 503, without its error text
	bad := newRD(t, func(cfg *Config) {
		cfg.AWSCatalog = func() (*AWSCatalog, error) { return nil, io.ErrUnexpectedEOF }
	})
	rec := bad.do("GET", canPath(awstest.EstateAlice, "s3:GetObject", ""), "")
	if rec.Code != 503 || strings.Contains(rec.Body.String(), "unexpected EOF") {
		t.Errorf("failing catalog = %d %s", rec.Code, rec.Body.String())
	}

	// a catalog and no snapshot
	none := newRD(t, withAWSCatalog)
	rec = none.do("GET", canPath(awstest.EstateAlice, "s3:GetObject", ""), "")
	if rec.Code != 404 || !strings.Contains(rec.Body.String(), "no_snapshot") {
		t.Errorf("no snapshot = %d %s", rec.Code, rec.Body.String())
	}
}

func TestAWSEvalEffective(t *testing.T) {
	c := newAWSEval(t, nil)
	// the ARN holds slashes and colons; it works raw and escaped
	for _, path := range []string{"/api/aws/principals/" + awstest.EstateAlice + "/effective?service=s3",
		"/api/aws/principals/" + esc(awstest.EstateAlice) + "/effective?service=s3"} {
		v := c.get(path, 200)
		if v["principal"] != awstest.EstateAlice || v["service"] != "s3" || v["snapshot"].(map[string]any)["id"] != c.snapshot {
			t.Fatalf("view = %v", v)
		}
		found := false
		for _, it := range v["items"].([]any) {
			m := it.(map[string]any)
			if m["action"] == "s3:GetObject" && m["resource"] == estateRep {
				found = true
				if m["outcome"] != "allow" || m["fidelity"] != "exact" || m["gap"] != false {
					t.Errorf("item = %v", m)
				}
			}
			if !strings.HasPrefix(m["action"].(string), "s3:") {
				t.Errorf("the service filter let %v through", m["action"])
			}
			if m["action"] == "s3:PutObject" && m["resource"] == estateRep {
				t.Errorf("alice can put objects: %v", m)
			}
		}
		if !found {
			t.Errorf("alice's s3:GetObject on %s is not in %v", estateRep, v["items"])
		}
	}

	// paging: one item at a time reaches the same total, in order
	all := c.get("/api/aws/principals/"+awstest.EstateAlice+"/effective?limit=500", 200)
	total := int(all["total"].(float64))
	if total == 0 || len(all["items"].([]any)) != total || all["next_cursor"] != nil {
		t.Fatalf("total %d, %d items, next %v", total, len(all["items"].([]any)), all["next_cursor"])
	}
	var got []string
	path := "/api/aws/principals/" + awstest.EstateAlice + "/effective?limit=2"
	for pages := 0; ; pages++ {
		if pages > total {
			t.Fatal("paging does not end")
		}
		v := c.get(path, 200)
		for _, it := range v["items"].([]any) {
			m := it.(map[string]any)
			got = append(got, m["action"].(string)+" "+m["resource"].(string))
		}
		next, ok := v["next_cursor"].(string)
		if !ok {
			break
		}
		path = "/api/aws/principals/" + awstest.EstateAlice + "/effective?limit=2&cursor=" + next
	}
	if len(got) != total {
		t.Errorf("paged %d items, total %d", len(got), total)
	}
	for i, it := range all["items"].([]any) {
		m := it.(map[string]any)
		if got[i] != m["action"].(string)+" "+m["resource"].(string) {
			t.Fatalf("page order differs at %d: %s vs %v", i, got[i], m)
		}
	}
}

func TestAWSEvalWhoCan(t *testing.T) {
	c := newAWSEval(t, nil)
	v := c.get("/api/aws/resources/"+estateRep+"/who-can?action=s3:GetObject", 200)
	if v["resource"] != estateRep || v["action"] != "s3:GetObject" {
		t.Fatalf("view = %v", v)
	}
	who := map[string]string{}
	for _, it := range v["items"].([]any) {
		m := it.(map[string]any)
		who[m["principal"].(string)] = m["outcome"].(string) + "/" + m["fidelity"].(string)
	}
	if who[awstest.EstateAlice] != "allow/exact" || who[awstest.EstateBob] != "" || who[awstest.EstateDevUser] != "" {
		t.Errorf("who can read the objects = %v", who)
	}
	// the group grant: bob lists the bucket
	v = c.get("/api/aws/resources/"+awstest.EstateBucket+"/who-can?action=s3:ListBucket", 200)
	found := false
	for _, it := range v["items"].([]any) {
		found = found || it.(map[string]any)["principal"] == awstest.EstateBob
	}
	if !found {
		t.Errorf("bob is not among who can list the bucket: %v", v["items"])
	}
}

// A stored policy that did not parse is a finding, not part of the snapshot; a
// decision it could affect is UNSUPPORTED, and bulk answers list it (design §3.3).
func TestAWSEvalFindingsFailClosed(t *testing.T) {
	finding := awsorg.Finding{Kind: store.AWSFindingPolicyUnparseable, SourceARN: awstest.EstateAlice + "#inline/broken", PolicyKind: "identity",
		Code: "invalid_json", Detail: "unexpected end", Scope: awsorg.Scope{Type: awsorg.ScopePrincipals, Targets: []string{awstest.EstateAlice}}}
	c := newAWSEval(t, awsorg.Findings{finding})

	// alice: UNSUPPORTED with the reason, and the gap named
	v := c.get(canPath(awstest.EstateAlice, "s3:GetObject", estateObject), 200)
	d := v["decision"].(map[string]any)
	if d["fidelity"] != "unsupported" || !strings.Contains(toJSON(d["fidelity_reasons"]), "POLICY_UNPARSEABLE") {
		t.Errorf("alice = %v", d)
	}
	if gaps := v["collection_gaps"].([]any); len(gaps) != 1 || gaps[0].(map[string]any)["code"] != "invalid_json" {
		t.Errorf("gaps = %v", gaps)
	}
	// bob is not reached by it
	if d := c.get(canPath(awstest.EstateBob, "s3:ListBucket", awstest.EstateBucket), 200)["decision"].(map[string]any); d["fidelity"] != "exact" {
		t.Errorf("bob = %v", d)
	}
	// the bulk answers say so too
	e := c.get("/api/aws/principals/"+awstest.EstateAlice+"/effective?service=s3", 200)
	if len(e["collection_gaps"].([]any)) != 1 {
		t.Errorf("effective gaps = %v", e["collection_gaps"])
	}
	for _, it := range e["items"].([]any) {
		m := it.(map[string]any)
		if m["fidelity"] != "unsupported" || m["gap"] != true {
			t.Errorf("an item of a principal with a gap is %v", m)
		}
	}
	if bob := c.get("/api/aws/principals/"+awstest.EstateBob+"/effective", 200); len(bob["collection_gaps"].([]any)) != 0 {
		t.Errorf("bob's gaps = %v", bob["collection_gaps"])
	}
	w := c.get("/api/aws/resources/"+estateRep+"/who-can?action=s3:GetObject", 200)
	for _, it := range w["items"].([]any) {
		m := it.(map[string]any)
		if m["principal"] == awstest.EstateAlice && (m["fidelity"] != "unsupported" || m["gap"] != true) {
			t.Errorf("alice in who-can = %v", m)
		}
	}
}

func toJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// Two tenants on one server: a snapshot, an index and a trace of one are
// never reachable from the other, even when the other asks for its id.
func TestAWSEvalTenantIsolation(t *testing.T) {
	f := storetest.TwoTenants(t)
	srv := New(Config{Store: f.DB, Clock: timeutil.Frozen(storetest.Now), Policies: policy.NewLoader(policies.FS),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Env: "test", AWSCatalog: testAWSCatalog, RateLimits: noRateLimits})
	a := asAdmin(t, srv, f.DB, f.A.ID, storetest.Now).Handler()
	b := asAdmin(t, srv, f.DB, f.B.ID, storetest.Now).Handler()
	snapA := persistEstate(t, f.DB, f.A.ID, nil)

	// A warms the cache and holds an explanation
	rec := serveOnce(a, "GET", canPath(awstest.EstateAlice, "s3:GetObject", estateObject), "")
	if rec.Code != 200 {
		t.Fatalf("A: %d %s", rec.Code, rec.Body.String())
	}
	var v map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &v)
	explA := v["explanation_id"].(string)

	for name, path := range map[string]string{
		"can":             canPath(awstest.EstateAlice, "s3:GetObject", estateObject),
		"can by id":       canPath(awstest.EstateAlice, "s3:GetObject", estateObject, "&snapshot="+snapA),
		"effective by id": "/api/aws/principals/" + awstest.EstateAlice + "/effective?snapshot=" + snapA,
		"who-can by id":   "/api/aws/resources/" + estateRep + "/who-can?action=s3:GetObject&snapshot=" + snapA,
		"explanation":     "/api/aws/explanations/" + explA,
		"snapshot":        "/api/aws/snapshots/" + snapA,
	} {
		if rec := serveOnce(b, "GET", path, ""); rec.Code != 404 || strings.Contains(rec.Body.String(), awstest.EstateAlice) && name != "can" {
			t.Errorf("B %s: %d %.200s, want 404 and nothing of A's", name, rec.Code, rec.Body.String())
		}
	}
	// A still has it
	if rec := serveOnce(a, "GET", "/api/aws/explanations/"+explA, ""); rec.Code != 200 {
		t.Errorf("A's explanation: %d", rec.Code)
	}
}

// The evaluator routes are declared graph.read; reading needs nothing more, and
// the settings need connections.* (the route table test checks every role).
func TestAWSEvalViewerCanReadButNotConfigure(t *testing.T) {
	st := testkit.Demo(t)
	srv := New(Config{Store: st.DB, Clock: timeutil.Frozen(testkit.Now), Policies: policy.NewLoader(policies.FS),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Env: "test", AWSCatalog: testAWSCatalog, RateLimits: noRateLimits,
		AllowedOrigins: []string{"http://localhost:5173"}})
	persistEstate(t, st.DB, st.Tenant, nil)
	h := srv.Handler()
	viewer := signIn(t, st.DB, st.Tenant, authtest.User{Email: "v@larkspur.example", Roles: []auth.Role{auth.RoleViewer}}, authtest.Phr, testkit.Now)
	do := func(method, path, body string) *http.Request { return authed(viewer, method, path, body) }
	for _, path := range []string{canPath(awstest.EstateAlice, "s3:GetObject", estateObject), "/api/aws/principals/" + awstest.EstateAlice + "/effective"} {
		if rec := serve(h, do("GET", path, "")); rec.Code != 200 {
			t.Errorf("viewer GET %s = %d %.200s", path, rec.Code, rec.Body.String())
		}
	}
	if rec := serve(h, do("GET", "/api/aws/pr-comment", "")); rec.Code != 403 {
		t.Errorf("viewer GET /api/aws/pr-comment = %d", rec.Code)
	}
	if rec := serve(h, do("PUT", "/api/aws/pr-comment", `{"enabled":false}`)); rec.Code != 403 {
		t.Errorf("viewer PUT /api/aws/pr-comment = %d", rec.Code)
	}
	// reading the diff needs only graph.read; posting it needs connections.manage
	body := `{"changes":[{"op":"put_bpa","target_arn":"` + awstest.EstateBucket + `","document":"{\"block_public_acls\":true}"}]}`
	if rec := serve(h, do("POST", "/api/aws/simulate-policy-change", body)); rec.Code != 200 {
		t.Errorf("viewer simulate = %d %.200s", rec.Code, rec.Body.String())
	}
	withComment := strings.Replace(body, `}]}`, `}],"comment":{"pull_number":1}}`, 1)
	if rec := serve(h, do("POST", "/api/aws/simulate-policy-change", withComment)); rec.Code != 403 {
		t.Errorf("viewer simulate with a comment = %d %.200s, want 403", rec.Code, rec.Body.String())
	}
	// a fresh enough admin of another role still needs a recent sign-in
	stale := signIn(t, st.DB, st.Tenant, authtest.User{Email: "s@larkspur.example", Roles: []auth.Role{auth.RoleTenantAdmin}},
		authtest.Ctx{AAL: 2, Phr: true, AuthTime: testkit.Now.Add(-20 * time.Minute)}, testkit.Now)
	if rec := serve(h, authed(stale, "POST", "/api/aws/simulate-policy-change", withComment)); rec.Code != 401 || !strings.Contains(rec.Body.String(), "step_up_required") {
		t.Errorf("stale admin simulate with a comment = %d %.200s, want step_up_required", rec.Code, rec.Body.String())
	}
}

// Applying a revoke is refused for a grant the evaluator found approximate or
// conditional (design §11.5, spec R2); a dry run is still answered.
func TestRevokeRefusesWeakEvaluatedGrants(t *testing.T) {
	c := newRD(t)
	var edgeID int64
	c.read(func(tx *store.TenantTx) error {
		es, err := tx.Edges()
		if err == nil {
			for _, e := range es {
				if e.Source == "connector" && edgeID == 0 {
					edgeID = e.ID
				}
			}
		}
		return err
	})
	testkit.Write(t, c.st, func(tx *store.TenantTx) error {
		e, err := tx.Edge(edgeID)
		if err != nil {
			return err
		}
		if err := tx.DeleteEdge(e.ID); err != nil {
			return err
		}
		_, err = tx.UpsertEvaluatorEdge(e.Src, e.Dst, e.Relation, testkit.Now, store.EdgeEvaluation{ExplanationID: "x", Outcome: "allow", Fidelity: "approximate"})
		if err != nil {
			return err
		}
		e, err = tx.EdgeBetween(e.Src, e.Dst)
		edgeID = e.ID
		return err
	})
	body := func(dry string) string {
		return `{"edge_id":` + strconv.FormatInt(edgeID, 10) + `,"dry_run":` + dry + `}`
	}
	if rec := c.do("POST", "/api/least-privilege/revoke", body("true")); rec.Code != 200 {
		t.Errorf("dry run = %d %s", rec.Code, rec.Body.String())
	}
	if rec := c.do("POST", "/api/least-privilege/revoke", body("false")); rec.Code != 409 {
		t.Errorf("apply = %d %s, want 409", rec.Code, rec.Body.String())
	}
}
