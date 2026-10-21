package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/workflow"
)

// The workflow designer (issue #298): versioned definitions that route approvals.
//
//	GET  /api/workflows                    every workflow at its current version, with the editor's vocabulary (graph.read)
//	POST /api/workflows                    {name, description, scope, steps}: version 1
//	POST /api/workflows/validate           {scope, steps}: {valid, issues}; saves nothing
//	GET  /api/workflows/{id}               one, with its earlier versions
//	PUT  /api/workflows/{id}               {version, name, description, steps}: appends the next version
//	POST /api/workflows/{id}/retire        stops it routing new requests; requests in flight finish on it
//	PUT  /api/workflows/{id}/assignments   {targets: [{kind, target_id}]}: the catalog items and request types it routes
//
// Reading needs graph.read. Creating, editing, retiring and assigning need workflows.manage and a
// fresh phishing-resistant sign-in (routing decides who approves access), and are audited in
// the same transaction. Validation needs workflows.manage and changes nothing. A target with no
// workflow keeps the item's approval policy.

func (s *Server) registerWorkflowRoutes() {
	const G, P, PU = http.MethodGet, http.MethodPost, http.MethodPut
	manage := needStepUp(auth.PermWorkflowsManage, auth.StepUpPolicy)
	s.handle(G, "/api/workflows", read, need(auth.PermGraphRead), s.listWorkflows)
	s.handle(P, "/api/workflows", write, manage, s.createWorkflow)
	// a literal segment, so it comes before {id}: the first registered route that matches wins
	s.handle(P, "/api/workflows/validate", write, need(auth.PermWorkflowsManage), s.validateWorkflow).answersRead = true
	s.handle(G, "/api/workflows/{id}", read, need(auth.PermGraphRead), s.getWorkflow)
	s.handle(PU, "/api/workflows/{id}", write, manage, s.editWorkflow)
	s.handle(P, "/api/workflows/{id}/retire", write, manage, s.retireWorkflow)
	s.handle(PU, "/api/workflows/{id}/assignments", write, manage, s.assignWorkflow)
}

// wfErr gives a workflow refusal its status, code and issues.
func wfErr(err error) error {
	var we *workflow.Error
	if errors.As(err, &we) {
		e := &readiness.Error{Status: we.Status, Code: we.Code, Msg: we.Msg}
		if len(we.Issues) > 0 {
			e.Extra = map[string]any{"issues": we.Issues}
		}
		return e
	}
	return err
}

func workflowID(p *params) (string, error) {
	id := strings.TrimSpace(p.path["id"])
	if !idRE.MatchString(id) {
		return "", &readiness.Error{Status: http.StatusNotFound, Code: "workflow_not_found", Msg: "workflow not found"}
	}
	return id, nil
}

type workflowVocabulary struct {
	StepTypes    []string            `json:"step_types"`
	Approvers    map[string][]string `json:"approvers"`
	Notify       []string            `json:"notify"`
	Attributes   map[string][]string `json:"attributes"`
	Ops          []string            `json:"ops"`
	RequestTypes map[string][]string `json:"request_types"`
	Limits       map[string]int      `json:"limits"`
}

var vocabulary = workflowVocabulary{
	StepTypes: workflow.Types,
	Approvers: map[string][]string{store.WorkflowScopeAccess: workflow.AccessApprovers,
		store.WorkflowScopeServiceAccount: workflow.ServiceAccountApprovers},
	Notify: []string{workflow.NotifyRequester, workflow.NotifyBeneficiary, workflow.NotifyOwner, workflow.NotifyGroup},
	Attributes: map[string][]string{store.WorkflowScopeAccess: workflow.AccessAttributes,
		store.WorkflowScopeServiceAccount: workflow.ServiceAccountAttributes},
	Ops: workflow.Ops,
	RequestTypes: map[string][]string{store.WorkflowScopeAccess: workflow.RequestTypes(store.WorkflowScopeAccess),
		store.WorkflowScopeServiceAccount: workflow.RequestTypes(store.WorkflowScopeServiceAccount)},
	Limits: map[string]int{"steps": workflow.MaxSteps, "approvals_per_path": workflow.MaxApprovalsPerPath, "name": workflow.MaxName,
		"message": workflow.MaxMessage, "hours": workflow.MaxHours, "values": workflow.MaxValues},
}

type workflowList struct {
	Workflows []*workflow.View `json:"workflows"`
	CanManage bool             `json:"can_manage"`
	workflowVocabulary
}

func (s *Server) listWorkflows(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	ws, err := workflow.List(store.TxFrom(r.Context()))
	if err != nil {
		return nil, err
	}
	return workflowList{Workflows: ws, CanManage: s.can(r, auth.PermWorkflowsManage), workflowVocabulary: vocabulary}, nil
}

func (s *Server) createWorkflow(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	var b workflow.Spec
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	v, err := workflow.Create(store.TxFrom(r.Context()), b, actor(r), s.clock().UTC())
	if err != nil {
		return nil, wfErr(err)
	}
	return statusBody{http.StatusCreated, v}, nil
}

type validateBody struct {
	Scope string          `json:"scope"`
	Steps []workflow.Step `json:"steps"`
}

func (s *Server) validateWorkflow(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	var b validateBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	issues, err := workflow.Check(store.TxFrom(r.Context()), b.Scope, b.Steps)
	if err != nil {
		return nil, err
	}
	if issues == nil {
		issues = []workflow.Issue{}
	}
	return map[string]any{"valid": len(issues) == 0, "issues": issues}, nil
}

type workflowDetail struct {
	*workflow.View
	Versions []workflowVersion `json:"versions"`
}

type workflowVersion struct {
	Version int `json:"version"`
	workflow.Spec
}

func (s *Server) workflowDetail(tx *store.TenantTx, id string) (any, error) {
	v, err := workflow.Get(tx, id)
	if err != nil {
		return nil, wfErr(err)
	}
	vs, err := tx.WorkflowVersions(id)
	if err != nil {
		return nil, err
	}
	out := workflowDetail{View: v, Versions: make([]workflowVersion, 0, len(vs))}
	for _, ver := range vs {
		d, err := workflow.ParseDefinition(ver.Definition)
		if err != nil {
			return nil, err
		}
		out.Versions = append(out.Versions, workflowVersion{ver.Version, workflow.Spec{Name: ver.Name, Description: ver.Description,
			Scope: v.Scope, Steps: d.Steps}})
	}
	return out, nil
}

func (s *Server) getWorkflow(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id, err := workflowID(p)
	if err != nil {
		return nil, err
	}
	return s.workflowDetail(store.TxFrom(r.Context()), id)
}

type editWorkflowBody struct {
	Version     int             `json:"version"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Steps       []workflow.Step `json:"steps"`
}

func (s *Server) editWorkflow(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id, err := workflowID(p)
	if err != nil {
		return nil, err
	}
	var b editWorkflowBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	tx := store.TxFrom(r.Context())
	if _, err := workflow.Edit(tx, id, b.Version, workflow.Spec{Name: b.Name, Description: b.Description, Steps: b.Steps}, actor(r), s.clock().UTC()); err != nil {
		return nil, wfErr(err)
	}
	return s.workflowDetail(tx, id)
}

func (s *Server) retireWorkflow(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id, err := workflowID(p)
	if err != nil {
		return nil, err
	}
	v, err := workflow.Retire(store.TxFrom(r.Context()), id, actor(r), s.clock().UTC())
	return v, wfErr(err)
}

type assignBody struct {
	Targets []workflow.Target `json:"targets"`
}

func (s *Server) assignWorkflow(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id, err := workflowID(p)
	if err != nil {
		return nil, err
	}
	var b assignBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	v, err := workflow.SetTargets(store.TxFrom(r.Context()), id, b.Targets, actor(r), s.clock().UTC())
	return v, wfErr(err)
}
