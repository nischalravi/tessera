package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/admin"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/awstest"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/awsorg"
	"github.com/nischalravi/tessera/mvp/server/internal/provision"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

const awsConnID = "11111111-1111-4111-8111-111111111111"

// awsStub stands in for the AWS write target at the engine's seam (the real one is tested against a signed, stateful
// fake AWS in internal/connectors/awsorg): it records what the engine sends and answers the re-read as told.
type awsStub struct {
	mu      sync.Mutex
	applied []target.Request
	drop    bool // the re-read does not show the change
}

func (s *awsStub) Apply(_ context.Context, r target.Request) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.applied = append(s.applied, r)
	return nil
}

func (s *awsStub) Verify(context.Context, target.Request) (target.Verdict, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.drop {
		return target.Verdict{Expected: "default version has the right-sized digest", Observed: "default version v1 has the old digest"}, nil
	}
	return target.Verdict{OK: true, Expected: "as intended", Observed: "as intended"}, nil
}

func (s *awsStub) calls() []target.Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]target.Request(nil), s.applied...)
}

type awsWB struct {
	t     *testing.T
	st    *testkit.DB
	srv   *Server
	c     client
	other client
	conn  string // the provisioning connection the aws target hangs on
	stub  *awsStub
}

// withDefaultVersion gives a managed policy of the estate the default version a collection records for it. The id of a
// document hashes its version, so the new id replaces the old one wherever the snapshot names it.
func withDefaultVersion(t *testing.T, snap *model.Snapshot, policyARN, version string) *model.Snapshot {
	t.Helper()
	var d *model.PolicyDoc
	for _, x := range snap.Policies {
		if x.SourceARN == policyARN {
			d = x
		}
	}
	if d == nil {
		t.Fatalf("no policy %s in the estate", policyARN)
	}
	oldID := d.ID
	newID := policy.DocumentID(d.Kind, d.SourceARN, version, d.RawJSON)
	d.VersionID = version
	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	var out model.Snapshot
	if err := json.Unmarshal([]byte(strings.ReplaceAll(string(raw), oldID, newID)), &out); err != nil {
		t.Fatal(err)
	}
	return &out
}

// newAWSWB is a tenant with a federated AWS connector that collected the estate (alice used one object of S3Read),
// a connection for the provisioning target, and an engine whose connectors are the stub.
func newAWSWB(t *testing.T) *awsWB { return newAWSWBWith(t, withLeveledCatalog) }

// newAWSWBWith is newAWSWB with the server configured by opt (which sets the AWS catalog).
func newAWSWBWith(t *testing.T, opt func(*Config)) *awsWB {
	t.Helper()
	st := testkit.Demo(t)
	srv := newTestAPIServerWith(t, st, opt)
	w := &awsWB{t: t, st: st, srv: srv, c: client{t, asLinkedAdmin(t, srv, st.DB, st.Tenant, testkit.Now).Handler()}, stub: &awsStub{}}
	l := signIn(t, st.DB, st.Tenant, authtest.User{Email: "second.admin@larkspur.example", Display: "Second Admin",
		Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, testkit.Now)
	w.other = client{t, l.Handler(srv.Handler())}
	w.addConnector(awsConnID, `{"regions":["us-east-1"],"account_ids":["111111111111"],"auth":"federated","role_name":"TesseraReader"}`)

	snap, err := awstest.Estate()
	if err != nil {
		t.Fatal(err)
	}
	snap.Principals[awstest.EstateAlice].CreateDate = "2020-01-01T00:00:00Z"
	snap = withDefaultVersion(t, snap, awstest.EstateS3Read, "v1")
	col := &awsorg.Collection{Snapshot: snap, AccountIDs: []string{awstest.EstateDev, awstest.EstateProd}}
	if snap.ID, err = awsorg.ContentID(col); err != nil {
		t.Fatal(err)
	}
	testkit.Write(t, st, func(tx *store.TenantTx) error {
		_, err := awsorg.Persist(tx, col, awsorg.PersistInput{Source: store.AWSSourceConnector, ConnectorID: awsConnID, CatalogVersion: "awstest-1"})
		return err
	})
	seedCallsFor(t, st, awsConnID, [2]string{"s3:GetObject", "arn:aws:s3:::prod-pii/customers.csv"})

	v := w.c.json("POST", "/api/connections", `{"name":"AWS writer (test)","connector_type":"demo-okta"}`, http.StatusCreated).(map[string]any)
	w.conn = v["id"].(string)
	eng := srv.Provisioning()
	eng.Backoff = func(int) time.Duration { return 0 }
	eng.Build = func(*store.ProvTarget, string) (target.Connector, error) { return w.stub, nil }
	return w
}

func (w *awsWB) addConnector(id, cfg string) {
	w.t.Helper()
	testkit.Write(w.t, w.st, func(tx *store.TenantTx) error {
		return tx.InsertAWSConnector(&store.AWSConnector{ID: id, Name: "prod-" + id[:4], Config: json.RawMessage(cfg), ExternalID: "ext", CreatedBy: "test",
			CreatedAt: testkit.Now, UpdatedAt: testkit.Now})
	})
}

func (w *awsWB) putTarget(body string, want int) map[string]any {
	w.t.Helper()
	return w.c.json("PUT", "/api/provisioning/targets/"+w.conn, body, want).(map[string]any)
}

func awsTargetBody(connector string, wb bool, extra string) string {
	return fmt.Sprintf(`{"kind":"aws","aws":{"connector_id":%q}%s,"write_back":%t}`, connector, extra, wb)
}

// enable turns write-back on the way the real flow ends (TestAWSTarget_WriteBackNeedsASecondAdmin goes through it).
func (w *awsWB) enable() {
	w.t.Helper()
	w.putTarget(awsTargetBody(awsConnID, false, ""), 200)
	testkit.Write(w.t, w.st, func(tx *store.TenantTx) error { return tx.SetProvTargetWriteBack(w.conn, true, testkit.Now) })
}

func (w *awsWB) run() provision.Stats {
	w.t.Helper()
	s, err := w.srv.Provisioning().RunTenant(context.Background(), w.st.Tenant)
	if err != nil {
		w.t.Fatal(err)
	}
	return s
}

func (w *awsWB) audit() string { return auditActionList(w.t, w.st.DB, w.st.Tenant) }

func (w *awsWB) ops() []any {
	w.t.Helper()
	return w.c.json("GET", "/api/provisioning/ops", "", 200).(map[string]any)["items"].([]any)
}

// reviewed returns the right-size answer a person reviews and the body that applies it.
func (w *awsWB) reviewed() (map[string]any, string) {
	w.t.Helper()
	v := w.c.json("POST", rsPath, rsBody(""), 200).(map[string]any)
	if v["verdict"] != "verified" || len(asString(v["document_sha256"])) != 64 {
		w.t.Fatalf("right-size = %v", v)
	}
	return v, rsBody(`,"candidate_sha256":"` + asString(v["document_sha256"]) + `"`)
}

// Configuring the target: it is for a federated connector of this tenant, holds no credential, and nothing but the
// aws kind may carry aws settings.
func TestAWSTarget_Config(t *testing.T) {
	w := newAWSWB(t)
	w.addConnector("22222222-2222-4222-8222-222222222222", `{"regions":["us-east-1"],"account_ids":["111111111111"]}`) // a stored-key connector
	for name, tc := range map[string]struct {
		body string
		want int
		code string
	}{
		"no aws settings":        {`{"kind":"aws"}`, 422, "invalid_aws"},
		"bad connector id":       {`{"kind":"aws","aws":{"connector_id":"conn-1"}}`, 422, "invalid_aws"},
		"bad writer role":        {`{"kind":"aws","aws":{"connector_id":"` + awsConnID + `","writer_role":"a b"}}`, 422, "invalid_aws"},
		"a token":                {awsTargetBody(awsConnID, false, `,"token":"x"`), 422, "invalid_credential"},
		"a dialect":              {awsTargetBody(awsConnID, false, `,"dialect":"entra"`), 422, "invalid_aws"},
		"an agent":               {awsTargetBody(awsConnID, false, `,"agent_id":"`+awsConnID+`"`), 422, "invalid_agent"},
		"unknown connector":      {awsTargetBody("33333333-3333-4333-8333-333333333333", false, ""), 422, "invalid_aws"},
		"a stored-key connector": {awsTargetBody("22222222-2222-4222-8222-222222222222", false, ""), 422, "invalid_aws"},
		"aws on another kind":    {`{"kind":"scim","base_url":"https://scim.example/scim/v2","aws":{"connector_id":"` + awsConnID + `"}}`, 422, "invalid_aws"},
	} {
		rec := w.c.do("PUT", "/api/provisioning/targets/"+w.conn, tc.body)
		if rec.Code != tc.want || !strings.Contains(rec.Body.String(), tc.code) {
			t.Errorf("%s: %d %s, want %d %s", name, rec.Code, rec.Body, tc.want, tc.code)
		}
	}
	v := w.putTarget(`{"kind":"aws","aws":{"connector_id":"`+awsConnID+`","writer_role":"TesseraWriter"}}`, 200)
	if v["kind"] != "aws" || v["base_url"] != "aws://"+awsConnID || v["has_credential"] != false || v["write_back"] != false {
		t.Fatalf("target = %v", v)
	}
	if a := v["aws"].(map[string]any); a["connector_id"] != awsConnID || a["writer_role"] != nil {
		t.Errorf("aws settings = %v (the default writer role is not stored)", a)
	}
	// the kind is listed among the operation kinds the ops list accepts
	if rec := w.c.do("GET", "/api/provisioning/ops?kind=aws_set_policy_version", ""); rec.Code != 200 {
		t.Errorf("ops by kind: %d %s", rec.Code, rec.Body)
	}
}

// The AWS write target is switched on by a second admin (#569), like every target kind, and the approver is told what
// it may write; once on, pointing it at another connector or role is a widening that needs the same again.
func TestAWSTarget_WriteBackNeedsASecondAdmin(t *testing.T) {
	w := newAWSWB(t)
	rec := w.putTarget(awsTargetBody(awsConnID, true, ""), 200)
	if rec["write_back"] != false || rec["write_back_pending"] != true {
		t.Fatalf("PUT write_back:true = %v", rec)
	}
	body := fmt.Sprintf(`{"type":%q,"payload":{"connection_id":%q,"config_hash":%q}}`, admin.TypeProvWriteBackEnable, w.conn, asString(rec["config_hash"]))
	ch := w.c.json("POST", "/api/admin/change-requests", body, http.StatusCreated).(map[string]any)
	if s := asString(ch["summary"]); !strings.Contains(s, "kind aws") || !strings.Contains(s, "TesseraWriter") || !strings.Contains(s, awsConnID) {
		t.Errorf("summary = %q", s)
	}
	id, hash := asString(ch["id"]), asString(ch["payload_hash"])
	approve := fmt.Sprintf(`{"payload_hash":%q}`, hash)
	if r := w.c.do("POST", "/api/admin/change-requests/"+id+"/approve", approve); r.Code != http.StatusForbidden {
		t.Fatalf("self approval: %d %s", r.Code, r.Body)
	}
	// until then a right-size is not queued
	if r := w.c.do("POST", rsPath+"/apply", rsBody(`,"candidate_sha256":"`+strings.Repeat("a", 64)+`"`)); r.Code != http.StatusConflict || !strings.Contains(r.Body.String(), "write_back_off") {
		t.Fatalf("apply before approval: %d %s", r.Code, r.Body)
	}
	if a := w.other.json("POST", "/api/admin/change-requests/"+id+"/approve", approve, 200).(map[string]any); a["status"] != "applied" {
		t.Fatalf("approved = %v", a)
	}
	if v := w.c.json("GET", "/api/provisioning/targets", "", 200).([]any)[0].(map[string]any); v["write_back"] != true {
		t.Fatalf("target = %v", v)
	}
	// a different connector or writer role while write-back is on is a widening
	for name, b := range map[string]string{
		"another writer role": `{"kind":"aws","aws":{"connector_id":"` + awsConnID + `","writer_role":"Other"},"write_back":true}`,
	} {
		if r := w.c.do("PUT", "/api/provisioning/targets/"+w.conn, b); r.Code != http.StatusConflict || !strings.Contains(r.Body.String(), "two_admin_change_required") {
			t.Errorf("%s: %d %s", name, r.Code, r.Body)
		}
	}
	// narrowing (turning it off) is one admin
	if v := w.putTarget(awsTargetBody(awsConnID, false, ""), 200); v["write_back"] != false {
		t.Errorf("turning off = %v", v)
	}
}

// A person applies a verified right-size: the request queues one operation on the aws target with the prior state
// recorded, the engine sends and re-reads it, and the same request is the same operation.
func TestAWSRightSizeApply(t *testing.T) {
	w := newAWSWB(t)
	rv, body := w.reviewed()
	apply := rsPath + "/apply"

	if r := w.c.do("POST", apply, body); r.Code != http.StatusConflict || !strings.Contains(r.Body.String(), "no_aws_target") {
		t.Errorf("no target: %d %s", r.Code, r.Body)
	}
	w.putTarget(awsTargetBody(awsConnID, false, ""), 200)
	if r := w.c.do("POST", apply, body); r.Code != http.StatusConflict || !strings.Contains(r.Body.String(), "write_back_off") {
		t.Errorf("write-back off: %d %s", r.Code, r.Body)
	}
	w.enable()

	for name, tc := range map[string]struct {
		body string
		want int
		code string
	}{
		"no digest":      {rsBody(""), 422, "invalid_candidate_sha256"},
		"bad digest":     {rsBody(`,"candidate_sha256":"zz"`), 422, "invalid_candidate_sha256"},
		"stale digest":   {rsBody(`,"candidate_sha256":"` + strings.Repeat("a", 64) + `"`), 409, "stale_candidate"},
		"unknown field":  {rsBody(`,"candidate_sha256":"` + asString(rv["document_sha256"]) + `","force":true`), 422, ""},
		"unknown policy": {`{"policy_arn":"arn:aws:iam::111111111111:policy/Nope","candidate_sha256":"` + strings.Repeat("a", 64) + `"}`, 404, ""},
	} {
		if r := w.c.do("POST", apply, tc.body); r.Code != tc.want || !strings.Contains(r.Body.String(), tc.code) {
			t.Errorf("%s: %d %s, want %d %s", name, r.Code, r.Body, tc.want, tc.code)
		}
	}
	if n := len(w.ops()); n != 0 {
		t.Fatalf("a refused apply queued %d operations", n)
	}

	got := w.c.json("POST", apply, body, http.StatusAccepted).(map[string]any)
	if got["kind"] != target.AWSSetPolicyVersion || got["status"] != "queued" || got["candidate_sha256"] != rv["document_sha256"] || got["prior_version_id"] == "" {
		t.Fatalf("apply = %v", got)
	}
	// the same request is the same operation
	again := w.c.json("POST", apply, body, http.StatusAccepted).(map[string]any)
	if again["op_id"] != got["op_id"] || len(w.ops()) != 1 {
		t.Errorf("a repeated apply made another operation: %v, %d ops", again, len(w.ops()))
	}
	if s := w.run(); s.Verified != 1 {
		t.Fatalf("stats = %+v", s)
	}
	calls := w.stub.calls()
	if len(calls) != 1 || calls[0].Kind != target.AWSSetPolicyVersion || calls[0].Account.Username != awstest.EstateAlice {
		t.Fatalf("sent = %+v", calls)
	}
	aw := calls[0].AWS
	if aw == nil || aw.PolicyARN != awstest.EstateS3Read || aw.Document != rv["document"] || aw.Prior == "" || aw.Prior == aw.Document ||
		aw.PriorSHA256 != target.DocDigest(aw.Prior) || aw.PriorVersionID == "" {
		t.Errorf("payload = %+v", aw)
	}
	for _, want := range []string{"aws.right_size.requested", "provision.enqueued", "provision.verified"} {
		if !strings.Contains(w.audit(), want) {
			t.Errorf("audit has no %s: %s", want, w.audit())
		}
	}
	if o := w.ops()[0].(map[string]any); o["status"] != "verified" || o["source"] != "leastpriv" {
		t.Errorf("op = %v", o)
	}
}

// A write the re-read does not show is a failed step with a finding and an audit event, and the operation cannot be
// restored (it was never verified).
func TestAWSRightSizeApply_MismatchIsAFailedStep(t *testing.T) {
	w := newAWSWB(t)
	w.enable()
	w.stub.drop = true
	_, body := w.reviewed()
	got := w.c.json("POST", rsPath+"/apply", body, http.StatusAccepted).(map[string]any)
	for i := 0; i < 5; i++ {
		w.run()
	}
	o := w.c.json("GET", "/api/provisioning/ops/"+asString(got["op_id"]), "", 200).(map[string]any)
	if o["status"] != "mismatch" {
		t.Fatalf("op = %v", o)
	}
	fs := w.c.json("GET", "/api/provisioning/findings?status=open", "", 200).([]any)
	if len(fs) != 1 || at(fs, 0, "code") != "verify_mismatch" || !strings.Contains(asString(at(fs, 0, "observed")), "old digest") {
		t.Errorf("findings = %v", fs)
	}
	if !strings.Contains(w.audit(), "provision.mismatch") {
		t.Errorf("no mismatch audit event: %s", w.audit())
	}
	if r := w.c.do("POST", "/api/aws/changes/"+asString(got["op_id"])+"/restore", ""); r.Code != http.StatusConflict || !strings.Contains(r.Body.String(), "not_verified") {
		t.Errorf("restore of an unverified change: %d %s", r.Code, r.Body)
	}
}

// Restore puts back what a verified change took: the same payload with its digest, once, and never for another
// tenant's, an unverified or a non-AWS operation.
func TestAWSRestore(t *testing.T) {
	w := newAWSWB(t)
	w.enable()
	_, body := w.reviewed()
	got := w.c.json("POST", rsPath+"/apply", body, http.StatusAccepted).(map[string]any)
	id := asString(got["op_id"])
	restore := "/api/aws/changes/" + id + "/restore"
	if r := w.c.do("POST", restore, ""); r.Code != http.StatusConflict || !strings.Contains(r.Body.String(), "not_verified") {
		t.Fatalf("restore before the change is verified: %d %s", r.Code, r.Body)
	}
	w.run()
	rest := w.c.json("POST", restore, "", http.StatusAccepted).(map[string]any)
	if rest["kind"] != target.AWSRestorePolicyVersion || rest["restore_of"] != id || rest["op_id"] == id {
		t.Fatalf("restore = %v", rest)
	}
	if again := w.c.json("POST", restore, "", http.StatusAccepted).(map[string]any); again["op_id"] != rest["op_id"] {
		t.Errorf("a second restore made another operation: %v", again)
	}
	if s := w.run(); s.Verified != 1 {
		t.Fatalf("stats = %+v", s)
	}
	calls := w.stub.calls()
	if len(calls) != 2 || calls[1].Kind != target.AWSRestorePolicyVersion || calls[1].AWS.RestoreOf != id ||
		calls[1].AWS.PriorVersionID != calls[0].AWS.PriorVersionID || calls[1].AWS.PriorSHA256 != calls[0].AWS.PriorSHA256 {
		t.Fatalf("sent = %+v", calls)
	}
	if !strings.Contains(w.audit(), "aws.change.restore_requested") {
		t.Errorf("no restore audit event: %s", w.audit())
	}
	// the restore itself is not restorable; an unknown or foreign id is not found; a non-AWS operation is refused
	if r := w.c.do("POST", "/api/aws/changes/"+asString(rest["op_id"])+"/restore", ""); r.Code != http.StatusUnprocessableEntity {
		t.Errorf("restore of a restore: %d %s", r.Code, r.Body)
	}
	if r := w.c.do("POST", "/api/aws/changes/"+awsConnID+"/restore", ""); r.Code != http.StatusNotFound {
		t.Errorf("unknown op: %d %s", r.Code, r.Body)
	}
	if r := w.c.do("POST", "/api/aws/changes/not-an-id/restore", ""); r.Code != http.StatusUnprocessableEntity {
		t.Errorf("bad id: %d %s", r.Code, r.Body)
	}
	foreign := insertProvOp(t, w.st.DB, w.st.Tenant, w.conn, "other-op")
	if r := w.c.do("POST", "/api/aws/changes/"+foreign+"/restore", ""); r.Code != http.StatusUnprocessableEntity || !strings.Contains(r.Body.String(), "not_restorable") {
		t.Errorf("non-AWS op: %d %s", r.Code, r.Body)
	}
}

// Applying and restoring need provisioning.manage with a fresh step-up; a viewer is refused.
func TestAWSWriteRoutesAreGated(t *testing.T) {
	w := newAWSWB(t)
	w.enable()
	_, body := w.reviewed()
	l := signIn(t, w.st.DB, w.st.Tenant, authtest.User{Email: "viewer@larkspur.example", Display: "Viewer", Roles: []auth.Role{auth.RoleViewer}}, authtest.Phr, testkit.Now)
	viewer := client{t, l.Handler(w.srv.Handler())}
	for _, p := range []string{rsPath + "/apply", "/api/aws/changes/" + awsConnID + "/restore"} {
		if r := viewer.do("POST", p, body); r.Code != http.StatusForbidden {
			t.Errorf("viewer %s: %d %s", p, r.Code, r.Body)
		}
	}
	stale := signIn(t, w.st.DB, w.st.Tenant, authtest.User{Email: "stale.admin@larkspur.example", Display: "Stale", Roles: []auth.Role{auth.RoleTenantAdmin}}, staleAuth, testkit.Now)
	sc := client{t, stale.Handler(w.srv.Handler())}
	if r := sc.do("POST", rsPath+"/apply", body); r.Code != http.StatusUnauthorized && r.Code != http.StatusForbidden {
		t.Errorf("stale authentication: %d %s", r.Code, r.Body)
	}
	if n := len(w.ops()); n != 0 {
		t.Errorf("a refused request queued %d operations", n)
	}
}
