package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/jobs"
	"github.com/nischalravi/tessera/mvp/server/internal/roles/mining"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// grantPattern gives four people of tenant B the same two groups, so a run
// has something to find.
func grantPattern(t *testing.T, f *storetest.Fixture) {
	t.Helper()
	b := f.B.IDs
	err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		for _, who := range []string{"alice", "bob", "carol", "dave"} {
			for _, g := range []string{"group:okta:eng", "group:okta:platform"} {
				src, dst := key("account", b["acct:okta:"+who]), key("group", b[g])
				if _, err := c.EdgeBetween(src, dst); err == nil {
					continue
				} else if !errors.Is(err, store.ErrNotFound) {
					return err
				}
				if _, err := c.InsertEdge(&store.GrantEdge{Src: src, Dst: dst, Relation: "member_of", Source: "manual",
					CreatedAt: storetest.Now}); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func key(kind string, id int64) string { return fmt.Sprintf("%s:%d", kind, id) }

func edgeCount(t *testing.T, f *storetest.Fixture) int {
	t.Helper()
	n := 0
	if err := f.DB.ReadTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		es, err := c.Edges()
		n = len(es)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

type miningRunResp struct {
	Run        miningRunView         `json:"run"`
	Candidates []miningCandidateView `json:"candidates"`
}

func TestRoleMiningAPI_Flow(t *testing.T) {
	f := storetest.TwoTenants(t)
	grantPattern(t, f)
	srv := newIsolationServer(f)
	h := srv.Handler()
	admin := reqLogin(t, f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "")
	viewer := reqLogin(t, f, "alice@b.example", []auth.Role{auth.RoleViewer}, "alice")
	adminA := signInA(t, f, auth.RolePolicyAdmin)
	if mining.JobKind != jobs.RoleMining {
		t.Fatalf("queue kind %q != %q", mining.JobKind, jobs.RoleMining)
	}

	// a viewer cannot start a run; bad settings are refused
	if rec := reqDo(h, viewer, "POST", "/api/role-mining/runs", `{}`); rec.Code != 403 {
		t.Errorf("viewer run: %d", rec.Code)
	}
	if rec := reqDo(h, admin, "POST", "/api/role-mining/runs", `{"min_members":1}`); rec.Code != 422 || !strings.Contains(rec.Body.String(), "invalid_params") {
		t.Errorf("bad settings: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, admin, "POST", "/api/role-mining/runs", `{"nope":1}`); rec.Code != 422 {
		t.Errorf("unknown field: %d %s", rec.Code, rec.Body)
	}

	// two runs over the same data: same snapshot hash, same candidates
	var runs [2]miningRunView
	for i := range runs {
		rec := reqDo(h, admin, "POST", "/api/role-mining/runs", `{"min_members":3}`)
		if rec.Code != 201 {
			t.Fatalf("run %d: %d %s", i, rec.Code, rec.Body)
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &runs[i]); err != nil {
			t.Fatal(err)
		}
		if runs[i].Status != "succeeded" || runs[i].Candidates < 1 || runs[i].SnapshotHash == "" {
			t.Fatalf("run %d = %+v", i, runs[i])
		}
	}
	if runs[0].SnapshotHash != runs[1].SnapshotHash || runs[0].Candidates != runs[1].Candidates {
		t.Errorf("runs differ: %+v vs %+v", runs[0], runs[1])
	}
	get := func(l authtest.Login, path string, code int, v any) {
		t.Helper()
		rec := reqDo(h, l, "GET", path, "")
		if rec.Code != code {
			t.Fatalf("GET %s: %d %s", path, rec.Code, rec.Body)
		}
		if v != nil {
			if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
				t.Fatal(err)
			}
		}
	}
	var r0, r1 miningRunResp
	get(admin, "/api/role-mining/runs/"+runs[0].ID, 200, &r0)
	get(admin, "/api/role-mining/runs/"+runs[1].ID, 200, &r1)
	if len(r0.Candidates) == 0 || len(r0.Candidates) != len(r1.Candidates) {
		t.Fatalf("candidates %d vs %d", len(r0.Candidates), len(r1.Candidates))
	}
	var list struct {
		CanManage bool            `json:"can_manage"`
		Runs      []miningRunView `json:"runs"`
	}
	get(admin, "/api/role-mining/runs", 200, &list)
	if !list.CanManage || len(list.Runs) != 2 {
		t.Errorf("list = %+v", list)
	}

	// the candidate lists its members; another tenant sees nothing of it
	c0 := r0.Candidates[0]
	var detail miningCandidateView
	get(admin, "/api/role-mining/candidates/"+c0.ID, 200, &detail)
	if detail.Coverage < 3 || len(detail.Members) != detail.Coverage || len(detail.Entitlements) < 2 {
		t.Fatalf("detail = %+v", detail)
	}
	get(adminA, "/api/role-mining/candidates/"+c0.ID, 404, nil)
	get(adminA, "/api/role-mining/runs/"+runs[0].ID, 404, nil)
	if rec := reqDo(h, adminA, "POST", "/api/role-mining/candidates/"+c0.ID+"/dismiss", `{"reason":"x"}`); rec.Code != 404 {
		t.Errorf("cross-tenant dismiss: %d", rec.Code)
	}
	if rec := reqDo(h, adminA, "POST", "/api/role-mining/candidates/"+c0.ID+"/accept", `{}`); rec.Code != 404 {
		t.Errorf("cross-tenant accept: %d", rec.Code)
	}
	if rec := reqDo(h, adminA, "GET", "/api/role-mining/runs", ""); strings.Contains(rec.Body.String(), runs[0].ID) {
		t.Errorf("tenant A lists B's run: %s", rec.Body)
	}

	// dismiss needs a reason, and a decided candidate is final
	dis := "/api/role-mining/candidates/" + r1.Candidates[0].ID + "/dismiss"
	if rec := reqDo(h, admin, "POST", dis, `{"reason":""}`); rec.Code != 422 {
		t.Errorf("dismiss without reason: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, viewer, "POST", dis, `{"reason":"no"}`); rec.Code != 403 {
		t.Errorf("viewer dismiss: %d", rec.Code)
	}
	if rec := reqDo(h, admin, "POST", dis, `{"reason":"too broad"}`); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"dismissed"`) {
		t.Fatalf("dismiss: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, admin, "POST", dis, `{"reason":"again"}`); rec.Code != 409 {
		t.Errorf("dismiss twice: %d", rec.Code)
	}

	// accept: an edit that is not part of the candidate is refused; then the role is a draft
	acc := "/api/role-mining/candidates/" + c0.ID + "/accept"
	if rec := reqDo(h, admin, "POST", acc, `{"entitlement_group_ids":[999999]}`); rec.Code != 422 {
		t.Errorf("foreign entitlement: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, viewer, "POST", acc, `{}`); rec.Code != 403 {
		t.Errorf("viewer accept: %d", rec.Code)
	}
	edgesBefore := edgeCount(t, f)
	rec := reqDo(h, admin, "POST", acc, `{"name":"Mined platform baseline"}`)
	if rec.Code != 201 {
		t.Fatalf("accept: %d %s", rec.Code, rec.Body)
	}
	var accepted struct {
		Candidate miningCandidateView `json:"candidate"`
		Role      roleView            `json:"role"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &accepted); err != nil {
		t.Fatal(err)
	}
	ro := accepted.Role
	if accepted.Candidate.Status != "accepted" || accepted.Candidate.RoleID == nil || *accepted.Candidate.RoleID != ro.ID ||
		ro.Name != "Mined platform baseline" || ro.Version != 1 || ro.Birthright != nil || ro.Requestable ||
		ro.MemberCount != 0 || len(ro.Entitlements) != len(detail.Entitlements) {
		t.Errorf("accepted = %+v", accepted)
	}
	if n := edgeCount(t, f); n != edgesBefore {
		t.Errorf("accepting changed grants: %d -> %d edges", edgesBefore, n)
	}
	if rec := reqDo(h, admin, "POST", acc, `{}`); rec.Code != 409 {
		t.Errorf("accept twice: %d", rec.Code)
	}

	// every decision is audited
	got := reqAuditActions(t, f, f.B.ID)
	for _, a := range []string{"role_mining.run", "role_mining.complete", "role_mining.accept", "role_mining.dismiss", "role.create"} {
		if got[a] == 0 {
			t.Errorf("no %s audit event (%v)", a, got)
		}
	}
	if got["role_mining.run"] != 2 {
		t.Errorf("role_mining.run events = %d", got["role_mining.run"])
	}
}

// A large run (or async: true) is a job on the durable queue.
func TestRoleMiningAPI_Queued(t *testing.T) {
	f := storetest.TwoTenants(t)
	grantPattern(t, f)
	srv := newIsolationServer(f)
	h := srv.Handler()
	admin := reqLogin(t, f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "")

	rec := reqDo(h, admin, "POST", "/api/role-mining/runs", `{"async":true,"min_members":3}`)
	var run miningRunView
	if rec.Code != 202 || json.Unmarshal(rec.Body.Bytes(), &run) != nil || run.Status != "queued" {
		t.Fatalf("queued run: %d %s", rec.Code, rec.Body)
	}
	// one run at a time
	if rec := reqDo(h, admin, "POST", "/api/role-mining/runs", `{}`); rec.Code != 409 {
		t.Errorf("second run: %d %s", rec.Code, rec.Body)
	}
	for range 8 { // four jobs run at a time
		if err := srv.Queue().Tick(context.Background()); err != nil {
			t.Fatal(err)
		}
		srv.Queue().Wait()
	}
	var got miningRunResp
	rec = reqDo(h, admin, "GET", "/api/role-mining/runs/"+run.ID, "")
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &got) != nil {
		t.Fatalf("get run: %d %s", rec.Code, rec.Body)
	}
	if got.Run.Status != "succeeded" || len(got.Candidates) == 0 || got.Run.SnapshotHash == "" {
		t.Errorf("run after the queue ran = %+v", got.Run)
	}
}
