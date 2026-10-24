package workflow

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/questionnaires"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Request types a workflow can be assigned to.
const (
	RequestAccess     = "access"
	RequestSACreate   = "service_account_create"
	RequestSAChange   = "service_account_change"
	RequestSATransfer = "service_account_transfer"
)

// RequestTypes lists them by scope.
func RequestTypes(scope string) []string {
	if scope == store.WorkflowScopeServiceAccount {
		return []string{RequestSACreate, RequestSAChange, RequestSATransfer}
	}
	return []string{RequestAccess}
}

// Error is a refused change; Code is stable for API clients.
type Error struct {
	Status int
	Code   string
	Msg    string
	Issues []Issue
}

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

func refuse(status int, code, format string, args ...any) error {
	return &Error{Status: status, Code: code, Msg: fmt.Sprintf(format, args...)}
}

// Spec is what an editor sends.
type Spec struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Scope       string `json:"scope"` // on create only
	Steps       []Step `json:"steps"`
}

// Target is where a workflow applies.
type Target struct {
	Kind     string `json:"kind"` // catalog_item | request_type
	TargetID string `json:"target_id"`
}

// View is a workflow at its current version.
type View struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Scope       string    `json:"scope"`
	Status      string    `json:"status"`
	Version     int       `json:"version"`
	Steps       []Step    `json:"steps"`
	Targets     []Target  `json:"targets"`
	Runs        int       `json:"runs"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedBy   string    `json:"updated_by"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (s Spec) trimmed() Spec {
	s.Name, s.Description = strings.TrimSpace(s.Name), strings.TrimSpace(s.Description)
	return s
}

func (s Spec) checkText() error {
	switch {
	case s.Name == "" || len(s.Name) > MaxName:
		return refuse(422, "invalid_name", "a name of 1 to %d characters is required", MaxName)
	case len(s.Description) > MaxDescription:
		return refuse(422, "invalid_description", "the description is at most %d characters", MaxDescription)
	}
	return nil
}

// Check validates a definition, including the questionnaires and groups it names, and returns
// every issue (none: it can be saved).
func Check(tx *store.TenantTx, scope string, steps []Step) ([]Issue, error) {
	d := Definition{Steps: steps}
	issues := d.Validate(scope)
	if len(issues) > 0 {
		return issues, nil
	}
	for _, s := range steps {
		if s.QuestionnaireID != "" {
			if n, err := questionnaires.Current(tx, s.QuestionnaireID); err != nil {
				return nil, err
			} else if n == nil {
				issues = append(issues, Issue{Step: s.ID, Code: "questionnaire_not_found", Msg: "the questionnaire does not exist or is retired"})
			}
		}
		if s.When != nil && s.When.Dataset != "" {
			if _, err := tx.DatasetByName(s.When.Dataset); errors.Is(err, store.ErrNotFound) {
				issues = append(issues, Issue{Step: s.ID, Code: "dataset_not_found", Msg: "the dataset does not exist"})
			} else if err != nil {
				return nil, err
			}
		}
		if s.GroupID != "" {
			if _, err := tx.GrpGroup(store.GroupID(s.GroupID)); errors.Is(err, store.ErrNotFound) {
				issues = append(issues, Issue{Step: s.ID, Code: "group_not_found", Msg: "the group does not exist"})
			} else if err != nil {
				return nil, err
			}
		}
	}
	return issues, nil
}

func (s Spec) check(tx *store.TenantTx, scope string) error {
	if err := s.checkText(); err != nil {
		return err
	}
	issues, err := Check(tx, scope, s.Steps)
	if err != nil {
		return err
	}
	if len(issues) > 0 {
		return &Error{Status: 422, Code: "invalid_workflow", Msg: issues[0].String(), Issues: issues}
	}
	return nil
}

func encode(steps []Step) (string, string, error) {
	raw, err := json.Marshal(Definition{Steps: steps})
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256(raw)
	return string(raw), hex.EncodeToString(sum[:]), nil
}

func nameTaken(tx *store.TenantTx, name, except string) error {
	all, err := tx.Workflows()
	if err != nil {
		return err
	}
	for _, w := range all {
		if w.ID != except && strings.EqualFold(w.Name, name) {
			return refuse(409, "name_taken", "a workflow named %q exists", w.Name)
		}
	}
	return nil
}

func version(id string, v int, s Spec, by string) (*store.WorkflowVersion, string, error) {
	raw, hash, err := encode(s.Steps)
	if err != nil {
		return nil, "", err
	}
	return &store.WorkflowVersion{WorkflowID: id, Version: v, Name: s.Name, Description: s.Description, Definition: raw, CreatedBy: by}, hash, nil
}

// Create adds a workflow at version 1. The change is audited in the same transaction.
func Create(tx *store.TenantTx, s Spec, by string, now time.Time) (*View, error) {
	s = s.trimmed()
	if err := s.check(tx, s.Scope); err != nil {
		return nil, err
	}
	if err := nameTaken(tx, s.Name, ""); err != nil {
		return nil, err
	}
	id := uuid.NewString()
	v, hash, err := version(id, 1, s, by)
	if err != nil {
		return nil, err
	}
	if err := tx.InsertWorkflow(id, s.Scope, v, now); err != nil {
		return nil, err
	}
	if err := tx.Audit(now, by, "workflow.create", ojson.Object{{Key: "workflow_id", Value: id}, {Key: "name", Value: s.Name},
		{Key: "scope", Value: s.Scope}, {Key: "version", Value: 1}, {Key: "steps", Value: len(s.Steps)},
		{Key: "definition_hash", Value: hash}}); err != nil {
		return nil, err
	}
	return Get(tx, id)
}

// Edit appends a new version. ver is the version the editor read; a different current version
// is a conflict, so two admins cannot silently overwrite each other. The assignments are kept
// when the new version still satisfies them, and the edit is refused otherwise.
func Edit(tx *store.TenantTx, id string, ver int, s Spec, by string, now time.Time) (*View, error) {
	s = s.trimmed()
	cur, err := Get(tx, id)
	if err != nil {
		return nil, err
	}
	switch {
	case cur.Status != "active":
		return nil, refuse(409, "workflow_retired", "a retired workflow cannot be edited")
	case cur.Version != ver:
		return nil, refuse(409, "version_conflict", "the workflow changed since version %d (now %d); reload it", ver, cur.Version)
	}
	if err := s.check(tx, cur.Scope); err != nil {
		return nil, err
	}
	if err := nameTaken(tx, s.Name, id); err != nil {
		return nil, err
	}
	for _, t := range cur.Targets {
		if err := checkTarget(tx, cur.Scope, Definition{Steps: s.Steps}, t); err != nil {
			return nil, err
		}
	}
	v, hash, err := version(id, ver+1, s, by)
	if err != nil {
		return nil, err
	}
	if ok, err := tx.AddWorkflowVersion(v, now); err != nil {
		return nil, err
	} else if !ok {
		return nil, refuse(409, "version_conflict", "the workflow changed since version %d; reload it", ver)
	}
	if err := tx.Audit(now, by, "workflow.update", ojson.Object{{Key: "workflow_id", Value: id}, {Key: "name", Value: s.Name},
		{Key: "version", Value: ver + 1}, {Key: "previous_version", Value: ver}, {Key: "steps", Value: len(s.Steps)},
		{Key: "definition_hash", Value: hash}}); err != nil {
		return nil, err
	}
	return Get(tx, id)
}

// Retire stops a workflow routing new requests: its assignments are removed (those targets go
// back to the item's approval policy) and requests in flight finish on it.
func Retire(tx *store.TenantTx, id, by string, now time.Time) (*View, error) {
	cur, err := Get(tx, id)
	if err != nil {
		return nil, err
	}
	if cur.Status != "active" {
		return nil, refuse(409, "workflow_retired", "the workflow is already retired")
	}
	if ok, err := tx.RetireWorkflow(id, by, now); err != nil {
		return nil, err
	} else if !ok {
		return nil, refuse(409, "workflow_retired", "the workflow is already retired")
	}
	if err := tx.ReplaceWorkflowAssignments(id, nil); err != nil {
		return nil, err
	}
	if err := tx.Audit(now, by, "workflow.retire", ojson.Object{{Key: "workflow_id", Value: id}, {Key: "name", Value: cur.Name},
		{Key: "targets_removed", Value: targetDetail(cur.Targets)}}); err != nil {
		return nil, err
	}
	return Get(tx, id)
}

func targetDetail(ts []Target) []string {
	out := make([]string, len(ts))
	for i, t := range ts {
		out[i] = t.Kind + ":" + t.TargetID
	}
	return out
}

// checkTarget validates one assignment of a definition of a scope.
func checkTarget(tx *store.TenantTx, scope string, d Definition, t Target) error {
	switch t.Kind {
	case store.WFTargetCatalogItem:
		if scope != store.WorkflowScopeAccess {
			return refuse(422, "invalid_target", "a service-account workflow is assigned to service-account request types")
		}
		if _, err := tx.CatalogItem(t.TargetID); errors.Is(err, store.ErrNotFound) {
			return refuse(404, "item_not_found", "catalog item %s not found", t.TargetID)
		} else if err != nil {
			return err
		}
	case store.WFTargetRequestType:
		if !slices.Contains(RequestTypes(scope), t.TargetID) {
			return refuse(422, "invalid_target", "request type %q does not take a %s workflow", t.TargetID, scope)
		}
	default:
		return refuse(422, "invalid_target", "a target is a catalog_item or a request_type")
	}
	has := func(approver string) func(Step) bool {
		return func(s Step) bool { return s.Type == TypeApproval && s.Approver == approver }
	}
	if t.Kind == store.WFTargetRequestType {
		switch t.TargetID {
		case RequestSATransfer:
			for _, a := range []string{ApproverOldOwner, ApproverNewOwner} {
				if d.MinOnEveryPath(has(a)) < 1 {
					return refuse(422, "transfer_needs_both_owners", "a transfer needs the approval of both the old and the new owner on every path (%s is missing on one)", a)
				}
			}
		case RequestSACreate:
			if hasAny(d, has(ApproverOldOwner)) {
				return refuse(422, "invalid_approver", "a new service account has no old owner to approve")
			}
		case RequestSAChange:
			if hasAny(d, has(ApproverNewOwner)) {
				return refuse(422, "invalid_approver", "a change keeps the owner, so there is no new owner to approve")
			}
		}
	}
	return nil
}

func hasAny(d Definition, pred func(Step) bool) bool { return slices.ContainsFunc(d.Steps, pred) }

// SetTargets sets where a workflow applies. A target another active workflow holds is a
// conflict (409); a catalog item's own workflow wins over the access request type's.
func SetTargets(tx *store.TenantTx, id string, targets []Target, by string, now time.Time) (*View, error) {
	cur, err := Get(tx, id)
	if err != nil {
		return nil, err
	}
	if cur.Status != "active" {
		return nil, refuse(409, "workflow_retired", "a retired workflow cannot be assigned")
	}
	if len(targets) > 500 {
		return nil, refuse(422, "too_many_targets", "at most 500 targets")
	}
	seen := map[Target]bool{}
	rows := make([]store.WorkflowAssignment, 0, len(targets))
	for _, t := range targets {
		if seen[t] {
			continue
		}
		seen[t] = true
		if err := checkTarget(tx, cur.Scope, Definition{Steps: cur.Steps}, t); err != nil {
			return nil, err
		}
		if held, err := tx.WorkflowAssignmentFor(t.Kind, t.TargetID); err == nil && held.WorkflowID != id {
			return nil, refuse(409, "target_taken", "%s %s is already routed by another workflow", t.Kind, t.TargetID)
		} else if err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
		rows = append(rows, store.WorkflowAssignment{WorkflowID: id, Kind: t.Kind, TargetID: t.TargetID})
	}
	if err := tx.ReplaceWorkflowAssignments(id, rows); err != nil {
		return nil, err
	}
	if err := tx.Audit(now, by, "workflow.assign", ojson.Object{{Key: "workflow_id", Value: id}, {Key: "name", Value: cur.Name},
		{Key: "targets", Value: targetDetail(cur.Targets)}, {Key: "new_targets", Value: targetDetail(toTargets(rows))}}); err != nil {
		return nil, err
	}
	return Get(tx, id)
}

func toTargets(rows []store.WorkflowAssignment) []Target {
	out := make([]Target, len(rows))
	for i, r := range rows {
		out[i] = Target{r.Kind, r.TargetID}
	}
	return out
}

func parseDef(v *store.WorkflowVersion) (Definition, error) {
	var d Definition
	if err := json.Unmarshal([]byte(v.Definition), &d); err != nil {
		return d, fmt.Errorf("workflow: version %d of %s: %w", v.Version, v.WorkflowID, err)
	}
	return d, nil
}

// Get returns a workflow at its current version.
func Get(tx *store.TenantTx, id string) (*View, error) {
	w, err := tx.Workflow(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(404, "workflow_not_found", "workflow not found")
	} else if err != nil {
		return nil, err
	}
	as, err := tx.WorkflowAssignments()
	if err != nil {
		return nil, err
	}
	return view(tx, w, as)
}

func view(tx *store.TenantTx, w *store.Workflow, as []*store.WorkflowAssignment) (*View, error) {
	v, err := tx.WorkflowVersion(w.ID, w.Version)
	if err != nil {
		return nil, err
	}
	d, err := parseDef(v)
	if err != nil {
		return nil, err
	}
	runs, err := tx.WorkflowRunCount(w.ID)
	if err != nil {
		return nil, err
	}
	out := &View{ID: w.ID, Name: w.Name, Description: v.Description, Scope: w.Scope, Status: w.Status, Version: w.Version,
		Steps: d.Steps, Targets: []Target{}, Runs: runs, CreatedAt: w.CreatedAt, UpdatedBy: w.UpdatedBy, UpdatedAt: w.UpdatedAt}
	for _, a := range as {
		if a.WorkflowID == w.ID {
			out.Targets = append(out.Targets, Target{a.Kind, a.TargetID})
		}
	}
	return out, nil
}

// List returns every workflow at its current version.
func List(tx *store.TenantTx) ([]*View, error) {
	ws, err := tx.Workflows()
	if err != nil {
		return nil, err
	}
	as, err := tx.WorkflowAssignments()
	if err != nil {
		return nil, err
	}
	out := make([]*View, 0, len(ws))
	for _, w := range ws {
		v, err := view(tx, w, as)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// Resolved is the workflow that routes a request, at the version in force.
type Resolved struct {
	ID      string
	Name    string
	Version int
	Def     Definition
	sets    Sets // the datasets its conditions name
	// setVersions are those datasets' versions when the workflow was resolved (0: no such dataset)
	setVersions map[string]int
}

func resolveTarget(tx *store.TenantTx, kind, target string) (*Resolved, error) {
	a, err := tx.WorkflowAssignmentFor(kind, target)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	w, err := tx.Workflow(a.WorkflowID)
	if err != nil {
		return nil, err
	}
	if w.Status != "active" {
		return nil, nil
	}
	v, err := tx.WorkflowVersion(w.ID, w.Version)
	if err != nil {
		return nil, err
	}
	d, err := parseDef(v)
	if err != nil {
		return nil, err
	}
	sets, vers, err := loadSets(tx, d)
	if err != nil {
		return nil, err
	}
	return &Resolved{ID: w.ID, Name: w.Name, Version: w.Version, Def: d, sets: sets, setVersions: vers}, nil
}

// ForItem is the workflow that routes requests for a catalog item: the item's own, else the
// access request type's, else nil (the item's approval policy routes it, as before workflows).
func ForItem(tx *store.TenantTx, itemID string) (*Resolved, error) {
	if r, err := resolveTarget(tx, store.WFTargetCatalogItem, itemID); err != nil || r != nil {
		return r, err
	}
	return resolveTarget(tx, store.WFTargetRequestType, RequestAccess)
}

// ForRequestType is the workflow assigned to a request type, or nil.
func ForRequestType(tx *store.TenantTx, requestType string) (*Resolved, error) {
	return resolveTarget(tx, store.WFTargetRequestType, requestType)
}

// Resolve compiles the workflow for a request's attributes.
func (r *Resolved) Resolve(attrs map[string]string) (*Plan, error) {
	p, err := r.Def.compile(r.ID, r.Version, attrs, r.sets)
	if err == nil && len(r.setVersions) > 0 {
		// which version of each dataset decided the path, for an audit of the routing
		p.Datasets = r.setVersions
	}
	return p, err
}

// datasetNames lists the datasets a definition's conditions name.
func (d Definition) datasetNames() []string {
	var out []string
	for _, s := range d.Steps {
		if s.When != nil && s.When.Dataset != "" && !slices.Contains(out, s.When.Dataset) {
			out = append(out, s.When.Dataset)
		}
	}
	return out
}

func loadSets(tx *store.TenantTx, d Definition) (Sets, map[string]int, error) {
	names := d.datasetNames()
	if len(names) == 0 {
		return nil, nil, nil
	}
	sets := Sets{}
	vers := map[string]int{}
	for _, n := range names {
		ds, err := tx.DatasetByName(n)
		if errors.Is(err, store.ErrNotFound) {
			vers[n] = 0
			continue
		} else if err != nil {
			return nil, nil, err
		}
		vals, err := tx.DatasetValues(ds.ID, ds.Count+1, 0)
		if err != nil {
			return nil, nil, err
		}
		vers[n] = ds.Version
		set := make(map[string]bool, len(vals))
		for _, v := range vals {
			set[v] = true
		}
		sets[n] = set
	}
	return sets, vers, nil
}

// DatasetsInUse lists the datasets the conditions of active workflows (at their current version) name.
func DatasetsInUse(tx *store.TenantTx) (map[string][]string, error) {
	ws, err := tx.Workflows()
	if err != nil {
		return nil, err
	}
	out := map[string][]string{}
	for _, w := range ws {
		if w.Status != "active" {
			continue
		}
		v, err := tx.WorkflowVersion(w.ID, w.Version)
		if err != nil {
			return nil, err
		}
		d, err := parseDef(v)
		if err != nil {
			return nil, err
		}
		for _, n := range d.datasetNames() {
			out[n] = append(out[n], w.Name)
		}
	}
	return out, nil
}

// Record stores a request's resolved plan as its run.
func Record(tx *store.TenantTx, subjectKind, subjectID string, p *Plan, now time.Time) error {
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return tx.InsertWorkflowRun(&store.WorkflowRun{WorkflowID: p.Workflow, Version: p.Version, SubjectKind: subjectKind,
		SubjectID: subjectID, Plan: string(raw), StartedAt: now})
}

// PlanFor returns the plan a request follows, or nil when no workflow routes it.
func PlanFor(tx *store.TenantTx, subjectKind, subjectID string) (*Plan, error) {
	r, err := tx.WorkflowRunFor(subjectKind, subjectID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return Parse(r.Plan)
}

// ParseDefinition reads a stored definition.
func ParseDefinition(raw string) (Definition, error) {
	var d Definition
	err := json.Unmarshal([]byte(raw), &d)
	return d, err
}

// Names returns a run's workflow name and version for display ("" when none routes it).
func Names(tx *store.TenantTx, subjectKind, subjectID string) (name string, version int, err error) {
	r, err := tx.WorkflowRunFor(subjectKind, subjectID)
	if errors.Is(err, store.ErrNotFound) {
		return "", 0, nil
	} else if err != nil {
		return "", 0, err
	}
	w, err := tx.Workflow(r.WorkflowID)
	if err != nil {
		return "", 0, err
	}
	return w.Name, r.Version, nil
}
