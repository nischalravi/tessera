package api

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/admin"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/awstest"
	"github.com/nischalravi/tessera/mvp/server/internal/lp"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
	"github.com/nischalravi/tessera/mvp/server/internal/queue"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
	policies "github.com/nischalravi/tessera/mvp/server/policies"
)

// lpOn is a tenant whose AWS write target is on and whose loop is in staged mode.
func lpOn(t *testing.T) *awsWB {
	t.Helper()
	w := newAWSWB(t)
	w.enable()
	setLP(t, w, func(s *store.LPSettings) { s.Mode = store.LPModeStaged })
	return w
}

func setLP(t *testing.T, w *awsWB, f func(*store.LPSettings)) {
	t.Helper()
	testkit.Write(t, w.st, func(tx *store.TenantTx) error {
		s, err := tx.LPSettings()
		if err != nil {
			return err
		}
		f(s)
		return tx.PutLPSettings(s, testkit.Now)
	})
}

func (w *awsWB) lpTick(at time.Time) {
	w.t.Helper()
	// the collector kept running: the log coverage reaches the later time, and alice kept using the same call
	testkit.Write(w.t, w.st, func(tx *store.TenantTx) error {
		day := func(n int) string { return at.UTC().AddDate(0, 0, -n).Format("2006-01-02") }
		if err := tx.PutAWSUsageState(&store.AWSUsageState{ConnectorID: awsConnID, Source: store.AWSUsageCloudTrail,
			CoveredFrom: testkit.Now.UTC().AddDate(0, 0, -120).Format("2006-01-02"), CoveredTo: day(0), S3DataEvents: store.AWSDataEventsEnabled, UpdatedAt: at}); err != nil {
			return err
		}
		for i := 0; i < 60; i += 3 {
			if err := tx.SetAWSUsage(&store.AWSUsageDay{ConnectorID: awsConnID, PrincipalARN: awstest.EstateAlice, Action: "s3:GetObject",
				ResourceScope: "arn:aws:s3:::prod-pii/customers.csv", Day: day(i), Source: store.AWSUsageCloudTrail, Count: 1, LastSeen: at}); err != nil {
				return err
			}
		}
		return nil
	})
	w.srv.clock = func() time.Time { return at }
	defer func() { w.srv.clock = func() time.Time { return testkit.Now } }() // sessions are not valid at the later time
	if _, err := w.srv.queueLP(context.Background(), queue.Job{Tenant: w.st.Tenant}); err != nil {
		w.t.Fatal(err)
	}
}

func (w *awsWB) lpState(id string) string {
	w.t.Helper()
	return asString(w.c.json("GET", "/api/lp/revocations/"+id, "", 200).(map[string]any)["state"])
}

func (w *awsWB) lpPropose() map[string]any {
	w.t.Helper()
	v := w.c.json("POST", rsPath, rsBody(""), 200).(map[string]any)
	body := fmt.Sprintf(`{"principal":%q,"policy_arn":%q,"candidate_sha256":%q}`, awstest.EstateAlice, awstest.EstateS3Read, asString(v["document_sha256"]))
	return w.c.json("POST", "/api/lp/candidates", body, http.StatusCreated).(map[string]any)
}

func (w *awsWB) lpApprove(c map[string]any) {
	w.t.Helper()
	key := "items"
	if c["eligibility"] == store.LPEligAuto {
		key = "batch"
	}
	w.c.json("POST", "/api/lp/revocations/approve", fmt.Sprintf(`{%q:[%q]}`, key, asString(c["id"])), 200)
}

// The whole loop through the API: propose a verified right-size, announce it, wait out the announce period, revoke
// through the write target, then put it back; nothing moves before its time.
func TestLPAPI_Flow(t *testing.T) {
	w := lpOn(t)
	c := w.lpPropose()
	id := asString(c["id"])
	if c["state"] != "candidate" || c["principal"] != awstest.EstateAlice || len(asString(c["restore_sha256"])) != 64 {
		t.Fatalf("candidate = %v", c)
	}
	// the same grant cannot be proposed twice
	v := w.c.json("POST", rsPath, rsBody(""), 200).(map[string]any)
	dup := fmt.Sprintf(`{"principal":%q,"policy_arn":%q,"candidate_sha256":%q}`, awstest.EstateAlice, awstest.EstateS3Read, asString(v["document_sha256"]))
	if r := w.c.do("POST", "/api/lp/candidates", dup); r.Code != http.StatusConflict || !strings.Contains(r.Body.String(), "already_open") {
		t.Errorf("duplicate: %d %s", r.Code, r.Body)
	}
	w.lpApprove(c)
	if w.lpState(id) != "announced" || len(w.ops()) != 0 {
		t.Fatalf("after approval: %s, %d ops", w.lpState(id), len(w.ops()))
	}
	// inside the announce period nothing is executed
	w.lpTick(testkit.Now.Add(24 * time.Hour))
	if w.lpState(id) != "announced" || len(w.ops()) != 0 {
		t.Fatalf("inside the announce period: %s, %d ops", w.lpState(id), len(w.ops()))
	}
	later := testkit.Now.Add(8 * 24 * time.Hour)
	w.lpTick(later)
	if w.lpState(id) != "revoking" || len(w.ops()) != 1 {
		t.Fatalf("after the announce period: %s, %d ops: %v", w.lpState(id), len(w.ops()), w.c.json("GET", "/api/lp/revocations/"+id, "", 200))
	}
	w.runAt(later)
	w.lpTick(later.Add(time.Minute))
	d := w.c.json("GET", "/api/lp/revocations/"+id, "", 200).(map[string]any)
	if d["state"] != "revoked" || d["op_id"] == "" || len(d["events"].([]any)) < 4 {
		t.Fatalf("revoked = %v", d)
	}
	if calls := w.stub.calls(); len(calls) != 1 || calls[0].AWS == nil || calls[0].AWS.Prior == "" {
		t.Fatalf("sent = %+v", calls)
	}
	// put it back
	if r := w.c.do("POST", "/api/lp/revocations/"+id+"/restore", `{"trigger":"nobody"}`); r.Code != http.StatusUnprocessableEntity {
		t.Errorf("bad trigger: %d %s", r.Code, r.Body)
	}
	w.c.json("POST", "/api/lp/revocations/"+id+"/restore", `{}`, http.StatusAccepted)
	w.runAt(later.Add(time.Minute))
	w.lpTick(later.Add(2 * time.Minute))
	if st := w.lpState(id); st != "restored" {
		t.Fatalf("after restore: %s", st)
	}
	for _, want := range []string{"lp.revocation.candidate", "lp.revocation.announced", "lp.revocation.revoked", "lp.revocation.restored", "provision.verified"} {
		if !strings.Contains(w.audit(), want) {
			t.Errorf("audit has no %s: %s", want, w.audit())
		}
	}
	// a restored grant is exempt from being proposed again
	v = w.c.json("POST", rsPath, rsBody(""), 200).(map[string]any)
	again := fmt.Sprintf(`{"principal":%q,"policy_arn":%q,"candidate_sha256":%q}`, awstest.EstateAlice, awstest.EstateS3Read, asString(v["document_sha256"]))
	if r := w.c.do("POST", "/api/lp/candidates", again); r.Code < 400 {
		t.Errorf("proposed again after a restore: %d %s", r.Code, r.Body)
	}
}

// The kill switch: one person pauses and nothing new is executed; resuming is a change request that a different
// admin must approve.
func TestLPAPI_KillSwitch(t *testing.T) {
	w := lpOn(t)
	c := w.lpPropose()
	id := asString(c["id"])
	w.lpApprove(c)

	s := w.c.json("POST", "/api/lp/pause", `{"reason":"drill"}`, 200).(map[string]any)
	if s["paused"] != true || s["active"] != false || s["paused_reason"] != "drill" {
		t.Fatalf("paused = %v", s)
	}
	w.lpTick(testkit.Now.Add(8 * 24 * time.Hour))
	if len(w.ops()) != 0 || w.lpState(id) == "revoking" || w.lpState(id) == "revoked" {
		t.Fatalf("a paused loop executed: %s, %d ops", w.lpState(id), len(w.ops()))
	}
	if r := w.c.do("POST", "/api/lp/revocations/approve", `{"items":["`+id+`"]}`); r.Code < 400 {
		t.Errorf("approving while paused: %d %s", r.Code, r.Body)
	}

	body := fmt.Sprintf(`{"type":%q,"payload":{"paused":false}}`, admin.TypeLPSettingsUpdate)
	ch := w.c.json("POST", "/api/admin/change-requests", body, http.StatusCreated).(map[string]any)
	cid, approve := asString(ch["id"]), fmt.Sprintf(`{"payload_hash":%q}`, asString(ch["payload_hash"]))
	if r := w.c.do("POST", "/api/admin/change-requests/"+cid+"/approve", approve); r.Code != http.StatusForbidden {
		t.Fatalf("self approval of a resume: %d %s", r.Code, r.Body)
	}
	if g := w.c.json("GET", "/api/lp/settings", "", 200).(map[string]any); g["paused"] != true {
		t.Fatalf("resumed without a second person: %v", g)
	}
	w.other.json("POST", "/api/admin/change-requests/"+cid+"/approve", approve, 200)
	if g := w.c.json("GET", "/api/lp/settings", "", 200).(map[string]any); g["paused"] != false || g["active"] != true {
		t.Fatalf("after the second approval: %v", g)
	}

	// tightening is one admin and applies at once; so is a raised cap not
	w.c.json("POST", "/api/admin/change-requests", fmt.Sprintf(`{"type":%q,"payload":{"cap_per_run":5}}`, admin.TypeLPSettingsUpdate), http.StatusCreated)
	if g := w.c.json("GET", "/api/lp/settings", "", 200).(map[string]any); g["cap_per_run"] != float64(5) {
		t.Errorf("a smaller cap did not apply at once: %v", g)
	}
}

// Rules at the boundary: mode off, the digest of what was reviewed, bad ids and states, and the permission gate.
func TestLPAPI_Refusals(t *testing.T) {
	w := newAWSWB(t)
	w.enable()
	v := w.c.json("POST", rsPath, rsBody(""), 200).(map[string]any)
	body := fmt.Sprintf(`{"principal":%q,"policy_arn":%q,"candidate_sha256":%q}`, awstest.EstateAlice, awstest.EstateS3Read, asString(v["document_sha256"]))
	if r := w.c.do("POST", "/api/lp/candidates", body); r.Code != http.StatusConflict || !strings.Contains(r.Body.String(), "mode_off") {
		t.Errorf("mode off: %d %s", r.Code, r.Body)
	}
	setLP(t, w, func(s *store.LPSettings) { s.Mode = store.LPModeStaged })
	for name, tc := range map[string]struct {
		method, path, body string
		want               int
	}{
		"stale digest":     {"POST", "/api/lp/candidates", fmt.Sprintf(`{"principal":%q,"policy_arn":%q,"candidate_sha256":%q}`, awstest.EstateAlice, awstest.EstateS3Read, strings.Repeat("a", 64)), 409},
		"no digest":        {"POST", "/api/lp/candidates", fmt.Sprintf(`{"principal":%q,"policy_arn":%q}`, awstest.EstateAlice, awstest.EstateS3Read), 422},
		"not a principal":  {"POST", "/api/lp/candidates", fmt.Sprintf(`{"principal":"arn:aws:s3:::x","policy_arn":%q,"candidate_sha256":%q}`, awstest.EstateS3Read, strings.Repeat("a", 64)), 422},
		"bad state filter": {"GET", "/api/lp/revocations?state=bogus", "", 422},
		"bad limit":        {"GET", "/api/lp/revocations?limit=0", "", 422},
		"bad id":           {"GET", "/api/lp/revocations/not-an-id", "", 404},
		"unknown id":       {"GET", "/api/lp/revocations/" + store.NewID(), "", 404},
		"approve bad id":   {"POST", "/api/lp/revocations/approve", `{"batch":["x y"]}`, 422},
		"approve unknown":  {"POST", "/api/lp/revocations/approve", `{"items":["` + store.NewID() + `"]}`, 404},
		"unknown field":    {"POST", "/api/lp/pause", `{"force":true}`, 422},
	} {
		if r := w.c.do(tc.method, tc.path, tc.body); r.Code != tc.want {
			t.Errorf("%s: %d %s, want %d", name, r.Code, r.Body, tc.want)
		}
	}
}

// runAt runs the provisioning engine as of a later time (the operations the loop queued are due then).
func (w *awsWB) runAt(at time.Time) {
	w.t.Helper()
	w.srv.clock = func() time.Time { return at }
	defer func() { w.srv.clock = func() time.Time { return testkit.Now } }()
	if s := w.run(); s.Verified != 1 {
		w.t.Fatalf("stats = %+v", s)
	}
}

// Tenant B cannot read or act on tenant A's revocations: its ids are 404 there, and its list is empty.
func TestLPAPI_CrossTenant(t *testing.T) {
	f := storetest.TwoTenants(t)
	srv := New(Config{Store: f.DB, Clock: timeutil.Frozen(storetest.Now), Policies: policy.NewLoader(policies.FS),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Env: "test", RateLimits: noRateLimits,
		AllowedOrigins: []string{"http://localhost:5173"}})
	h := srv.Handler()
	la := signIn(t, f.DB, f.A.ID, testAdmin, authtest.Phr, storetest.Now)
	lb := signIn(t, f.DB, f.B.ID, testAdmin, authtest.Phr, storetest.Now)
	id := store.NewID()
	if err := f.DB.InTenant(context.Background(), f.A.ID, func(tx *store.TenantTx) error {
		p := `{"policy_arn":"arn:aws:iam::111111111111:policy/P"}`
		return tx.InsertLPRevocation(&store.LPRevocation{ID: id, State: store.LPCandidate, Kind: target.AWSSetPolicyVersion, Eligibility: store.LPEligItem,
			ConnectorID: "c", SnapshotID: "s", AccountID: "111111111111", Principal: "arn:aws:iam::111111111111:role/a",
			PolicyARN: "arn:aws:iam::111111111111:policy/P", UnusedDays: 120, Confidence: "high", Evidence: `{}`, CandidateSHA256: strings.Repeat("a", 64),
			RestorePayload: p, RestoreSHA256: lp.DigestPayload(p), CreatedBy: "x", CreatedAt: storetest.Now})
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.DB.InTenant(context.Background(), f.B.ID, func(tx *store.TenantTx) error {
		s, err := tx.LPSettings()
		if err != nil {
			return err
		}
		s.Mode = store.LPModeStaged
		return tx.PutLPSettings(s, storetest.Now)
	}); err != nil {
		t.Fatal(err)
	}
	a := func(m, p, b string) *httptest.ResponseRecorder { return serve(h, authed(la, m, p, b)) }
	b := func(m, p, b string) *httptest.ResponseRecorder { return serve(h, authed(lb, m, p, b)) }
	if rec := a("GET", "/api/lp/revocations/"+id, ""); rec.Code != 200 {
		t.Fatalf("A GET own = %d %s", rec.Code, rec.Body.String())
	}
	for _, p := range []string{"GET /api/lp/revocations/" + id, "POST /api/lp/revocations/" + id + "/object", "POST /api/lp/revocations/" + id + "/restore"} {
		m, path, _ := strings.Cut(p, " ")
		if rec := b(m, path, map[bool]string{true: `{"reason":"mine"}`, false: `{}`}[strings.HasSuffix(path, "/object")]); rec.Code != http.StatusNotFound {
			t.Errorf("B %s = %d %s", p, rec.Code, rec.Body.String())
		}
	}
	if rec := b("POST", "/api/lp/revocations/approve", `{"items":["`+id+`"]}`); rec.Code != http.StatusNotFound {
		t.Errorf("B approve A's = %d %s", rec.Code, rec.Body.String())
	}
	if rec := b("GET", "/api/lp/revocations", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"items":[]`) {
		t.Errorf("B list = %d %s", rec.Code, rec.Body.String())
	}
	if rec := a("GET", "/api/lp/revocations/"+id, ""); !strings.Contains(rec.Body.String(), `"state":"candidate"`) {
		t.Errorf("A's revocation changed: %s", rec.Body.String())
	}
}
