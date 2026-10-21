package store

import (
	"database/sql"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// Workflow definitions, their versions and assignments (schema/0480_workflows.sql), the runs and
// service-account approval stages (0482_workflow_runs.sql) and service-account requests
// (0481_service_account_requests.sql), issue #298. The rules (step types, validation, resolving
// a path, who approves) live in internal/workflow, internal/requests and internal/svcaccounts;
// the store keeps the JSON as given.

// Workflow scopes.
const (
	WorkflowScopeAccess         = "access"
	WorkflowScopeServiceAccount = "service_account"
)

// Assignment target kinds.
const (
	WFTargetCatalogItem = "catalog_item"
	WFTargetRequestType = "request_type"
)

// Run subject kinds.
const (
	WFSubjectAccessLine     = "access_line"
	WFSubjectServiceAccount = "service_account_request"
)

// Run statuses.
const (
	WFRunRunning   = "running"
	WFRunCompleted = "completed"
	WFRunDenied    = "denied"
	WFRunCancelled = "cancelled"
)

// Workflow is a definition's identity and current version.
type Workflow struct {
	ID        string
	Name      string
	Scope     string
	Status    string // active | retired
	Version   int
	CreatedAt time.Time
	UpdatedBy string
	UpdatedAt time.Time
}

// WorkflowVersion is one immutable version; Definition is a JSON document.
type WorkflowVersion struct {
	WorkflowID  string
	Version     int
	Name        string
	Description string
	Definition  string
	CreatedBy   string
	CreatedAt   time.Time
}

// WorkflowAssignment says what a workflow routes.
type WorkflowAssignment struct {
	WorkflowID string
	Kind       string
	TargetID   string
}

// WorkflowRun is the resolved path of one routed subject; Plan is JSON. Its id is the subject's.
type WorkflowRun struct {
	ID          string
	WorkflowID  string
	Version     int
	SubjectKind string
	SubjectID   string
	Plan        string
	Status      string
	StartedAt   time.Time
	FinishedAt  *time.Time
}

const (
	wfCols  = `w.id, w.name, w.scope, w.status, w.version, w.created_at, w.updated_by, w.updated_at`
	wfvCols = `v.workflow_id, v.version, v.name, v.description, v.definition, v.created_by, v.created_at`
	wfrCols = `r.id, r.workflow_id, r.version, r.subject_kind, r.subject_id, r.plan, r.status, r.started_at, r.finished_at`
	// the columns of a service-account stage, in the order scanStage reads them
	wstageCols = `s.request_id, s.idx, s.kind, s.assignee_identity_id, s.status, s.started_at, s.due_at, s.decided_by,
	s.on_behalf_of, s.decided_at, s.reason`
)

var (
	wfList = tq("workflows.list", `SELECT `+wfCols+` FROM workflows w WHERE w.tenant_id = @tenant ORDER BY w.name, w.id`)
	wfGet  = tq("workflows.get", `SELECT `+wfCols+` FROM workflows w WHERE w.tenant_id = @tenant AND w.id = @id`)
	wfIns  = tq("workflows.insert", `
		INSERT INTO workflows (id, tenant_id, name, scope, status, version, created_at, updated_by, updated_at)
		VALUES (@id, @tenant, @name, @scope, 'active', 1, @now, @by, @now)`)
	wfBump = tq("workflows.bump", `
		UPDATE workflows SET name = @name, version = version + 1, updated_by = @by, updated_at = @now
		WHERE tenant_id = @tenant AND id = @id AND version = @version AND status = 'active'`)
	wfRetire = tq("workflows.retire", `
		UPDATE workflows SET status = 'retired', updated_by = @by, updated_at = @now
		WHERE tenant_id = @tenant AND id = @id AND status = 'active'`)
	wfvIns = tq("workflow_versions.insert", `
		INSERT INTO workflow_versions (tenant_id, workflow_id, version, name, description, definition, created_by, created_at)
		VALUES (@tenant, @id, @version, @name, @description, @definition, @by, @now)`)
	wfvGet = tq("workflow_versions.get", `
		SELECT `+wfvCols+` FROM workflow_versions v WHERE v.tenant_id = @tenant AND v.workflow_id = @id AND v.version = @version`)
	wfvList = tq("workflow_versions.list", `
		SELECT `+wfvCols+` FROM workflow_versions v WHERE v.tenant_id = @tenant AND v.workflow_id = @id ORDER BY v.version DESC`)
	wfaList = tq("workflow_assignments.list", `
		SELECT a.workflow_id, a.target_kind, a.target_id FROM workflow_assignments a
		WHERE a.tenant_id = @tenant ORDER BY a.target_kind, a.target_id`)
	wfaFor = tq("workflow_assignments.for_target", `
		SELECT a.workflow_id, a.target_kind, a.target_id FROM workflow_assignments a
		WHERE a.tenant_id = @tenant AND a.target_kind = @kind AND a.target_id = @target`)
	wfaClear = tq("workflow_assignments.clear", `
		DELETE FROM workflow_assignments WHERE tenant_id = @tenant AND workflow_id = @id`)
	wfaIns = tq("workflow_assignments.insert", `
		INSERT INTO workflow_assignments (tenant_id, workflow_id, target_kind, target_id)
		VALUES (@tenant, @id, @kind, @target)`)
	wfrIns = tq("workflow_runs.insert", `
		INSERT INTO workflow_runs (id, tenant_id, workflow_id, version, subject_kind, subject_id, plan, status, started_at)
		VALUES (@id, @tenant, @workflow, @version, @kind, @subject, @plan, 'running', @started_at)`)
	wfrFor = tq("workflow_runs.for_subject", `
		SELECT `+wfrCols+` FROM workflow_runs r WHERE r.tenant_id = @tenant AND r.subject_kind = @kind AND r.subject_id = @subject`)
	wfrFinish = tq("workflow_runs.finish", `
		UPDATE workflow_runs SET status = @status, finished_at = @at
		WHERE tenant_id = @tenant AND subject_kind = @kind AND subject_id = @subject AND status = 'running'`)
	wfrCount = tq("workflow_runs.count_for_workflow", `
		SELECT count(*) FROM workflow_runs r WHERE r.tenant_id = @tenant AND r.workflow_id = @id`)

	wstageIns = tq("workflow_stages.insert", `
		INSERT INTO workflow_stages (tenant_id, request_id, idx, kind, assignee_identity_id, status, started_at, due_at,
			decided_by, decided_at, reason)
		VALUES (@tenant, @line_id, @idx, @kind, @assignee, @status, @started_at, @due_at, @decided_by, @decided_at, @reason)`)
	wstageFor = tq("workflow_stages.for_run", `
		SELECT `+wstageCols+` FROM workflow_stages s WHERE s.tenant_id = @tenant AND s.request_id = @line_id ORDER BY s.idx`)
	wstageWaiting = tq("workflow_stages.waiting", `
		SELECT `+wstageCols+` FROM workflow_stages s WHERE s.tenant_id = @tenant AND s.status = 'waiting'
		ORDER BY s.started_at, s.request_id`)
	wstageSave = tq("workflow_stages.save", `
		UPDATE workflow_stages SET status = @status, started_at = @started_at, due_at = @due_at,
			decided_by = @decided_by, on_behalf_of = @on_behalf_of, decided_at = @decided_at, reason = @reason
		WHERE tenant_id = @tenant AND request_id = @line_id AND idx = @idx AND status = @from`)
	wstageCloseOpen = tq("workflow_stages.close_open", `
		UPDATE workflow_stages SET status = 'closed' WHERE tenant_id = @tenant AND request_id = @line_id
			AND status IN ('queued','waiting')`)
)

func scanWorkflow(s scanner) (*Workflow, error) {
	var w Workflow
	var created, updated string
	if err := s.Scan(&w.ID, &w.Name, &w.Scope, &w.Status, &w.Version, &created, &w.UpdatedBy, &updated); err != nil {
		return nil, err
	}
	var err error
	if w.CreatedAt, err = ParseRT(created); err != nil {
		return nil, err
	}
	w.UpdatedAt, err = ParseRT(updated)
	return &w, err
}

func scanWorkflowVersion(s scanner) (*WorkflowVersion, error) {
	var v WorkflowVersion
	var at string
	if err := s.Scan(&v.WorkflowID, &v.Version, &v.Name, &v.Description, &v.Definition, &v.CreatedBy, &at); err != nil {
		return nil, err
	}
	var err error
	v.CreatedAt, err = ParseRT(at)
	return &v, err
}

func scanWorkflowAssignment(s scanner) (*WorkflowAssignment, error) {
	var a WorkflowAssignment
	err := s.Scan(&a.WorkflowID, &a.Kind, &a.TargetID)
	return &a, err
}

func scanWorkflowRun(s scanner) (*WorkflowRun, error) {
	var r WorkflowRun
	var started string
	var finished nullTime
	if err := s.Scan(&r.ID, &r.WorkflowID, &r.Version, &r.SubjectKind, &r.SubjectID, &r.Plan, &r.Status, &started, &finished); err != nil {
		return nil, err
	}
	var err error
	if r.StartedAt, err = timeutil.ParseDB(started); err != nil {
		return nil, err
	}
	r.FinishedAt, err = finished.ptr()
	return &r, err
}

// Workflows lists the tenant's workflows by name.
func (tx *TenantTx) Workflows() ([]*Workflow, error) { return collect(tx, scanWorkflow, wfList) }

// Workflow returns one by id; ErrNotFound if it is not the tenant's.
func (tx *TenantTx) Workflow(id string) (*Workflow, error) {
	return one(tx, scanWorkflow, wfGet, sql.Named("id", id))
}

// InsertWorkflow creates a workflow at version 1 with its first version row.
func (tx *TenantTx) InsertWorkflow(id, scope string, v *WorkflowVersion, now time.Time) error {
	if _, err := tx.exec(wfIns, sql.Named("id", id), sql.Named("name", v.Name), sql.Named("scope", scope),
		sql.Named("by", v.CreatedBy), sql.Named("now", RT(now))); err != nil {
		return err
	}
	v.WorkflowID, v.Version = id, 1
	return tx.insertWorkflowVersion(v, now)
}

func (tx *TenantTx) insertWorkflowVersion(v *WorkflowVersion, now time.Time) error {
	_, err := tx.exec(wfvIns, sql.Named("id", v.WorkflowID), sql.Named("version", v.Version), sql.Named("name", v.Name),
		sql.Named("description", v.Description), sql.Named("definition", v.Definition), sql.Named("by", v.CreatedBy),
		sql.Named("now", RT(now)))
	return err
}

// AddWorkflowVersion appends version v.Version (the current one plus one) and moves the workflow
// on; false means the current version is no longer v.Version-1 (or it is retired).
func (tx *TenantTx) AddWorkflowVersion(v *WorkflowVersion, now time.Time) (bool, error) {
	res, err := tx.exec(wfBump, sql.Named("id", v.WorkflowID), sql.Named("name", v.Name), sql.Named("version", v.Version-1),
		sql.Named("by", v.CreatedBy), sql.Named("now", RT(now)))
	if err != nil {
		return false, err
	}
	if n, err := res.RowsAffected(); err != nil || n == 0 {
		return false, err
	}
	return true, tx.insertWorkflowVersion(v, now)
}

// RetireWorkflow retires an active workflow; false if it already was.
func (tx *TenantTx) RetireWorkflow(id, by string, now time.Time) (bool, error) {
	res, err := tx.exec(wfRetire, sql.Named("id", id), sql.Named("by", by), sql.Named("now", RT(now)))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// WorkflowVersion returns one version; ErrNotFound if there is none.
func (tx *TenantTx) WorkflowVersion(id string, version int) (*WorkflowVersion, error) {
	return one(tx, scanWorkflowVersion, wfvGet, sql.Named("id", id), sql.Named("version", version))
}

// WorkflowVersions lists a workflow's versions, newest first.
func (tx *TenantTx) WorkflowVersions(id string) ([]*WorkflowVersion, error) {
	return collect(tx, scanWorkflowVersion, wfvList, sql.Named("id", id))
}

// WorkflowAssignments lists every assignment of the tenant.
func (tx *TenantTx) WorkflowAssignments() ([]*WorkflowAssignment, error) {
	return collect(tx, scanWorkflowAssignment, wfaList)
}

// WorkflowAssignmentFor returns the assignment of a target; ErrNotFound if it has none.
func (tx *TenantTx) WorkflowAssignmentFor(kind, target string) (*WorkflowAssignment, error) {
	return one(tx, scanWorkflowAssignment, wfaFor, sql.Named("kind", kind), sql.Named("target", target))
}

// ReplaceWorkflowAssignments sets what a workflow routes. A target another workflow already
// holds is a unique-constraint error; the service checks first.
func (tx *TenantTx) ReplaceWorkflowAssignments(id string, targets []WorkflowAssignment) error {
	if _, err := tx.exec(wfaClear, sql.Named("id", id)); err != nil {
		return err
	}
	for _, t := range targets {
		if _, err := tx.exec(wfaIns, sql.Named("id", id), sql.Named("kind", t.Kind), sql.Named("target", t.TargetID)); err != nil {
			return err
		}
	}
	return nil
}

// InsertWorkflowRun records the resolved path of a subject (the run's id is the subject's).
func (tx *TenantTx) InsertWorkflowRun(r *WorkflowRun) error {
	_, err := tx.exec(wfrIns, sql.Named("id", r.SubjectID), sql.Named("workflow", r.WorkflowID), sql.Named("version", r.Version),
		sql.Named("kind", r.SubjectKind), sql.Named("subject", r.SubjectID), sql.Named("plan", r.Plan),
		sql.Named("started_at", T(r.StartedAt)))
	return err
}

// WorkflowRunFor returns a subject's run; ErrNotFound if it was not routed by a workflow.
func (tx *TenantTx) WorkflowRunFor(kind, subject string) (*WorkflowRun, error) {
	return one(tx, scanWorkflowRun, wfrFor, sql.Named("kind", kind), sql.Named("subject", subject))
}

// FinishWorkflowRun ends a running run (status completed, denied or cancelled).
func (tx *TenantTx) FinishWorkflowRun(kind, subject, status string, at time.Time) error {
	_, err := tx.exec(wfrFinish, sql.Named("kind", kind), sql.Named("subject", subject), sql.Named("status", status),
		sql.Named("at", T(at)))
	return err
}

// WorkflowRunCount is how many runs a workflow has started.
func (tx *TenantTx) WorkflowRunCount(id string) (int, error) {
	return tx.count(wfrCount, sql.Named("id", id))
}

// InsertWorkflowStage adds a stage to a service-account request (st.LineID is the request id); a stage
// the requester's own consent approves is inserted already decided.
func (tx *TenantTx) InsertWorkflowStage(st *RequestStage) error {
	_, err := tx.exec(wstageIns, sql.Named("line_id", st.LineID), sql.Named("idx", st.Idx), sql.Named("kind", st.Kind),
		sql.Named("assignee", IP(st.AssigneeID)), sql.Named("status", st.Status), sql.Named("started_at", TP(st.StartedAt)),
		sql.Named("due_at", TP(st.DueAt)), sql.Named("decided_by", SP(st.DecidedBy)), sql.Named("decided_at", TP(st.DecidedAt)),
		sql.Named("reason", SP(st.Reason)))
	return err
}

// WorkflowStages lists a run's stages in order (LineID is the run id).
func (tx *TenantTx) WorkflowStages(runID string) ([]*RequestStage, error) {
	return collect(tx, scanStage, wstageFor, sql.Named("line_id", runID))
}

// WaitingWorkflowStages lists every waiting service-account stage, oldest first.
func (tx *TenantTx) WaitingWorkflowStages() ([]*RequestStage, error) {
	return collect(tx, scanStage, wstageWaiting)
}

// SaveWorkflowStage writes a stage's decision; it fails with ErrNotFound unless the stage is
// still in status from (a concurrent decision lost).
func (tx *TenantTx) SaveWorkflowStage(st *RequestStage, from string) error {
	res, err := tx.exec(wstageSave, sql.Named("line_id", st.LineID), sql.Named("idx", st.Idx), sql.Named("status", st.Status),
		sql.Named("started_at", TP(st.StartedAt)), sql.Named("due_at", TP(st.DueAt)), sql.Named("decided_by", SP(st.DecidedBy)),
		sql.Named("on_behalf_of", SP(st.OnBehalfOf)), sql.Named("decided_at", TP(st.DecidedAt)), sql.Named("reason", SP(st.Reason)),
		sql.Named("from", from))
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrNotFound
	}
	return nil
}

// CloseOpenWorkflowStages closes a run's queued and waiting stages (the request ended).
func (tx *TenantTx) CloseOpenWorkflowStages(runID string) error {
	_, err := tx.exec(wstageCloseOpen, sql.Named("line_id", runID))
	return err
}
