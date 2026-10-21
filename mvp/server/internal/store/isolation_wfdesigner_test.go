package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Workflow designer (schema/0480-0482, issue #298): definitions, versions, assignments, runs,
// service-account stages and requests are read and written only through the tenant's own handle.

const (
	wfA = "44444444-4444-4444-8444-444444444444"
	wfB = "55555555-5555-4555-8555-555555555555"
	saA = "66666666-6666-4666-8666-666666666666"
)

func TestIsolation_WorkflowDesigner(t *testing.T) {
	f := storetest.TwoTenants(t)
	ctx := context.Background()
	def := `{"steps":[{"id":"a","type":"approval","approver":"decider"}]}`
	a := seedReqRows(t, f.DB, f.A, "a")
	bob := f.A.IDs["bob"]
	err := f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		if err := c.InsertWorkflow(wfA, store.WorkflowScopeAccess, &store.WorkflowVersion{Name: "Two eyes", Definition: def, CreatedBy: "admin a"}, storetest.Now); err != nil {
			return err
		}
		ok, err := c.AddWorkflowVersion(&store.WorkflowVersion{WorkflowID: wfA, Version: 2, Name: "Two eyes 2", Definition: def, CreatedBy: "admin a"}, storetest.Now)
		if err != nil || !ok {
			t.Fatalf("second version: %v %v", ok, err)
		}
		if ok, err := c.AddWorkflowVersion(&store.WorkflowVersion{WorkflowID: wfA, Version: 2, Name: "x", Definition: def, CreatedBy: "x"}, storetest.Now); err != nil || ok {
			t.Errorf("stale version accepted: %v %v", ok, err)
		}
		if err := c.ReplaceWorkflowAssignments(wfA, []store.WorkflowAssignment{
			{Kind: store.WFTargetCatalogItem, TargetID: a.item}, {Kind: store.WFTargetRequestType, TargetID: "access"}}); err != nil {
			return err
		}
		if err := c.InsertWorkflowRun(&store.WorkflowRun{WorkflowID: wfA, Version: 2, SubjectKind: store.WFSubjectServiceAccount, SubjectID: saA,
			Plan: `{}`, StartedAt: storetest.Now}); err != nil {
			return err
		}
		if err := c.InsertServiceAccountRequest(&store.ServiceAccountRequest{ID: saA, Kind: store.SAKindCreate, Status: store.SAPending,
			Name: "svc-a", System: "okta", Username: "svc-a", PrimaryOwnerID: a.alice, BackupOwnerID: &bob, Justification: "x",
			RequestedBy: a.user.ID.String(), RequestedAt: storetest.Now}); err != nil {
			return err
		}
		return c.InsertWorkflowStage(&store.RequestStage{LineID: saA, Idx: 0, Kind: store.StageOwner, AssigneeID: &a.alice,
			Status: store.StageWaiting, StartedAt: &storetest.Now})
	})
	if err != nil {
		t.Fatal(err)
	}
	inA(t, f, func(c *store.TenantTx) error {
		if w, err := c.Workflow(wfA); err != nil || w.Version != 2 || w.Name != "Two eyes 2" {
			t.Errorf("A's workflow: %+v %v", w, err)
		}
		if vs, err := c.WorkflowVersions(wfA); err != nil || len(vs) != 2 || vs[0].Version != 2 {
			t.Errorf("A's versions: %v %v", vs, err)
		}
		if _, err := c.WorkflowVersion(wfA, 1); err != nil {
			t.Errorf("A's version 1: %v", err)
		}
		if as, err := c.WorkflowAssignments(); err != nil || len(as) != 2 {
			t.Errorf("A's assignments: %v %v", as, err)
		}
		if _, err := c.WorkflowAssignmentFor(store.WFTargetCatalogItem, a.item); err != nil {
			t.Errorf("A's assignment: %v", err)
		}
		if r, err := c.WorkflowRunFor(store.WFSubjectServiceAccount, saA); err != nil || r.Status != store.WFRunRunning {
			t.Errorf("A's run: %+v %v", r, err)
		}
		if n, err := c.WorkflowRunCount(wfA); err != nil || n != 1 {
			t.Errorf("A's run count: %d %v", n, err)
		}
		if ss, err := c.WorkflowStages(saA); err != nil || len(ss) != 1 {
			t.Errorf("A's stages: %v %v", ss, err)
		}
		if ws, err := c.WaitingWorkflowStages(); err != nil || len(ws) != 1 {
			t.Errorf("A's waiting stages: %v %v", ws, err)
		}
		if r, err := c.ServiceAccountRequest(saA); err != nil || r.Name != "svc-a" || r.BackupOwnerID == nil {
			t.Errorf("A's request: %+v %v", r, err)
		}
		if rs, err := c.ServiceAccountRequests(store.SARequestFilter{Status: store.SAPending}); err != nil || len(rs) != 1 {
			t.Errorf("A's requests: %v %v", rs, err)
		}
		if _, err := c.OpenServiceAccountCreate("svc-a"); err != nil {
			t.Errorf("A's open create: %v", err)
		}
		return nil
	})
	inB(t, f, func(c *store.TenantTx) error {
		if _, err := c.Workflow(wfA); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("B reads A's workflow: %v", err)
		}
		if _, err := c.WorkflowVersion(wfA, 1); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("B reads A's version: %v", err)
		}
		if l, err := c.Workflows(); err != nil || len(l) != 0 {
			t.Errorf("B lists A's workflows: %v %v", l, err)
		}
		if l, err := c.WorkflowVersions(wfA); err != nil || len(l) != 0 {
			t.Errorf("B lists A's versions: %v %v", l, err)
		}
		if l, err := c.WorkflowAssignments(); err != nil || len(l) != 0 {
			t.Errorf("B lists A's assignments: %v %v", l, err)
		}
		if _, err := c.WorkflowAssignmentFor(store.WFTargetRequestType, "access"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("B reads A's assignment: %v", err)
		}
		if _, err := c.WorkflowRunFor(store.WFSubjectServiceAccount, saA); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("B reads A's run: %v", err)
		}
		if n, err := c.WorkflowRunCount(wfA); err != nil || n != 0 {
			t.Errorf("B counts A's runs: %d %v", n, err)
		}
		if l, err := c.WorkflowStages(saA); err != nil || len(l) != 0 {
			t.Errorf("B reads A's stages: %v %v", l, err)
		}
		if l, err := c.WaitingWorkflowStages(); err != nil || len(l) != 0 {
			t.Errorf("B lists A's waiting stages: %v %v", l, err)
		}
		if _, err := c.ServiceAccountRequest(saA); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("B reads A's request: %v", err)
		}
		if l, err := c.ServiceAccountRequests(store.SARequestFilter{}); err != nil || len(l) != 0 {
			t.Errorf("B lists A's requests: %v %v", l, err)
		}
		if _, err := c.OpenServiceAccountCreate("svc-a"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("B sees A's open create: %v", err)
		}
		if _, err := c.OpenServiceAccountRequestFor(a.alice); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("B sees A's open request for an account: %v", err)
		}
		if _, err := c.ServiceAccountRequestByOp("op"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("B finds an operation: %v", err)
		}
		if ok, err := c.AddWorkflowVersion(&store.WorkflowVersion{WorkflowID: wfA, Version: 3, Name: "B", Definition: def, CreatedBy: "b"}, storetest.Now); ok || err != nil {
			t.Errorf("B versions A's workflow: %v %v", ok, err)
		}
		if ok, err := c.RetireWorkflow(wfA, "b", storetest.Now); ok || err != nil {
			t.Errorf("B retires A's workflow: %v %v", ok, err)
		}
		if err := c.FinishWorkflowRun(store.WFSubjectServiceAccount, saA, store.WFRunDenied, storetest.Now); err != nil {
			t.Errorf("B finish: %v", err)
		}
		if err := c.SaveWorkflowStage(&store.RequestStage{LineID: saA, Idx: 0, Status: store.StageApproved}, store.StageWaiting); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("B decides A's stage: %v", err)
		}
		if err := c.CloseOpenWorkflowStages(saA); err != nil {
			t.Errorf("B closes: %v", err)
		}
		if err := c.SaveServiceAccountRequest(&store.ServiceAccountRequest{ID: saA, Status: store.SAApproved}, store.SAPending); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("B saves A's request: %v", err)
		}
		return nil
	})
	// A's rows are untouched by B's attempts
	inA(t, f, func(c *store.TenantTx) error {
		if r, _ := c.WorkflowRunFor(store.WFSubjectServiceAccount, saA); r == nil || r.Status != store.WFRunRunning {
			t.Errorf("B finished A's run: %+v", r)
		}
		if ss, _ := c.WorkflowStages(saA); len(ss) != 1 || ss[0].Status != store.StageWaiting {
			t.Errorf("B closed A's stage: %v", ss)
		}
		if w, _ := c.Workflow(wfA); w == nil || w.Status != "active" {
			t.Errorf("B retired A's workflow: %+v", w)
		}
		return nil
	})
	// B cannot assign to, run against, or request on, A's rows
	for name, fn := range map[string]func(c *store.TenantTx) error{
		"assign": func(c *store.TenantTx) error {
			return c.ReplaceWorkflowAssignments(wfA, []store.WorkflowAssignment{{Kind: store.WFTargetRequestType, TargetID: "service_account_create"}})
		},
		"run": func(c *store.TenantTx) error {
			return c.InsertWorkflowRun(&store.WorkflowRun{WorkflowID: wfA, Version: 2, SubjectKind: store.WFSubjectAccessLine, SubjectID: "x",
				Plan: `{}`, StartedAt: storetest.Now})
		},
		"request owned by A's identity": func(c *store.TenantTx) error {
			return c.InsertServiceAccountRequest(&store.ServiceAccountRequest{ID: "x", Kind: store.SAKindCreate, Status: store.SAPending, Name: "n",
				PrimaryOwnerID: a.alice, Justification: "x", RequestedBy: a.user.ID.String(), RequestedAt: storetest.Now})
		},
		"stage on A's run": func(c *store.TenantTx) error {
			return c.InsertWorkflowStage(&store.RequestStage{LineID: saA, Idx: 1, Kind: store.StageDecider, Status: store.StageQueued})
		},
	} {
		if err := f.DB.InTenant(ctx, f.B.ID, fn); err == nil {
			t.Errorf("B managed to %s", name)
		}
	}
	// the same workflow name and request type are free in B: uniqueness is per tenant
	err = f.DB.InTenant(ctx, f.B.ID, func(c *store.TenantTx) error {
		if err := c.InsertWorkflow(wfB, store.WorkflowScopeAccess, &store.WorkflowVersion{Name: "Two eyes 2", Definition: def, CreatedBy: "admin b"}, storetest.Now); err != nil {
			return err
		}
		return c.ReplaceWorkflowAssignments(wfB, []store.WorkflowAssignment{{Kind: store.WFTargetRequestType, TargetID: "access"}})
	})
	if err != nil {
		t.Errorf("B's own workflow: %v", err)
	}
	// within a tenant a target holds one workflow
	err = f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		const other = "77777777-7777-4777-8777-777777777777"
		if err := c.InsertWorkflow(other, store.WorkflowScopeAccess, &store.WorkflowVersion{Name: "Other", Definition: def, CreatedBy: "a"}, storetest.Now); err != nil {
			return err
		}
		return c.ReplaceWorkflowAssignments(other, []store.WorkflowAssignment{{Kind: store.WFTargetRequestType, TargetID: "access"}})
	})
	if err == nil {
		t.Error("a target took two workflows")
	}
	// a run can be finished once, and a stage decided once
	inA(t, f, func(c *store.TenantTx) error {
		now := storetest.Now
		if err := c.FinishWorkflowRun(store.WFSubjectServiceAccount, saA, store.WFRunCompleted, now); err != nil {
			return err
		}
		r, _ := c.WorkflowRunFor(store.WFSubjectServiceAccount, saA)
		if r.Status != store.WFRunCompleted || r.FinishedAt == nil {
			t.Errorf("run not finished: %+v", r)
		}
		if err := c.FinishWorkflowRun(store.WFSubjectServiceAccount, saA, store.WFRunDenied, now); err != nil {
			return err
		}
		if r, _ = c.WorkflowRunFor(store.WFSubjectServiceAccount, saA); r.Status != store.WFRunCompleted {
			t.Errorf("a finished run changed: %+v", r)
		}
		st := &store.RequestStage{LineID: saA, Idx: 0, Status: store.StageApproved, DecidedAt: &now}
		if err := c.SaveWorkflowStage(st, store.StageWaiting); err != nil {
			t.Errorf("deciding the waiting stage: %v", err)
		}
		if err := c.SaveWorkflowStage(st, store.StageWaiting); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("deciding a decided stage: %v", err)
		}
		req, _ := c.ServiceAccountRequest(saA)
		req.Status, req.OpID = store.SAApproved, new(string)
		*req.OpID = "op-1"
		if err := c.SaveServiceAccountRequest(req, store.SAPending); err != nil {
			t.Errorf("saving the request: %v", err)
		}
		if err := c.SaveServiceAccountRequest(req, store.SAPending); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("saving from a stale status: %v", err)
		}
		if got, err := c.ServiceAccountRequestByOp("op-1"); err != nil || got.ID != saA {
			t.Errorf("by op: %v %v", got, err)
		}
		if _, err := c.OpenServiceAccountRequestFor(a.alice); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("open request for an account that has none: %v", err)
		}
		return c.CloseOpenWorkflowStages(saA)
	})
}

// wfDesignerCovered lists the methods TestIsolation_WorkflowDesigner exercises.
func wfDesignerCovered() map[string]bool {
	return map[string]bool{"Workflows": true, "Workflow": true, "InsertWorkflow": true, "AddWorkflowVersion": true,
		"RetireWorkflow": true, "WorkflowVersion": true, "WorkflowVersions": true, "WorkflowAssignments": true,
		"WorkflowAssignmentFor": true, "ReplaceWorkflowAssignments": true, "InsertWorkflowRun": true, "WorkflowRunFor": true,
		"FinishWorkflowRun": true, "WorkflowRunCount": true, "InsertWorkflowStage": true, "WorkflowStages": true,
		"WaitingWorkflowStages": true, "SaveWorkflowStage": true, "CloseOpenWorkflowStages": true,
		"InsertServiceAccountRequest": true, "ServiceAccountRequest": true, "ServiceAccountRequests": true,
		"SaveServiceAccountRequest": true, "OpenServiceAccountCreate": true, "OpenServiceAccountRequestFor": true,
		"ServiceAccountRequestByOp": true}
}
