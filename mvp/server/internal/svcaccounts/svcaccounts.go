// Package svcaccounts is the service-account request flow (issue #298): a request to create,
// change or transfer a service account, with mandatory owners.
//
// Owners are the ownership of the account (internal/ownership, #167): a primary and a backup,
// both active people, different people. A create names both; a change keeps the primary and
// may change the backup and the purpose; a transfer names the new primary (the backup stays
// unless given). A request that would leave an account without both owners is refused.
//
// Approval is the workflow engine's. The workflow assigned to the request type
// (service_account_create, service_account_change, service_account_transfer) selects the
// stages; with none assigned the built-in default applies: create asks the new owner and a
// decider, change the current owner and a decider, transfer the old owner, the new owner and a
// decider. A transfer is refused a workflow unless both owners approve on every path. The
// stages, delegations, escalation and four-eyes rules are the approval routing's
// (requests.AuthorizeStages): nobody decides a request they made or two stages of one request.
// A stage whose owner is the requester (an owner asking to hand the account over) is approved
// by the request itself, and at least one other stage must remain, so a request never
// approves itself.
//
// The last approval makes the change in Tessera (the identity, its ownership, its account) and
// asks the provisioning engine to make it in the target system when that connection has
// write-back on: a create waits for the target to confirm the account before it is fulfilled;
// a change or transfer pushes the new purpose or owner as an account update and is fulfilled at
// once. Every step is audited in the caller's transaction.
package svcaccounts

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/notify"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/ownership"
	"github.com/nischalravi/tessera/mvp/server/internal/provision"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
	"github.com/nischalravi/tessera/mvp/server/internal/questionnaires"
	"github.com/nischalravi/tessera/mvp/server/internal/requests"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/workflow"
)

// Limits.
const (
	MaxName     = 100
	MaxUsername = 100
)

// Kinds are the request kinds.
var Kinds = []string{store.SAKindCreate, store.SAKindChange, store.SAKindTransfer}

var usernameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]*$`)

func refuse(status int, code, format string, args ...any) error {
	return &requests.Error{Status: status, Code: code, Msg: fmt.Sprintf(format, args...)}
}

// RequestType is the workflow request type of a kind.
func RequestType(kind string) string { return "service_account_" + kind }

// Input is a request as filed.
type Input struct {
	Kind           string
	IdentityID     *int64 // change, transfer: the service account
	Name           string // create
	System         string // create: the application the account lives in
	Username       string // create: the account's name there
	Purpose        string
	Description    string // create
	PrimaryOwnerID *int64 // create, transfer
	BackupOwnerID  *int64
	Justification  string
	// Answers to the questionnaires the workflow asks: questionnaire id -> question id -> value.
	Answers map[string]map[string]any
}

// defaultApprovers is the routing of a request type no workflow is assigned to.
func defaultApprovers(kind string) []string {
	switch kind {
	case store.SAKindCreate:
		return []string{workflow.ApproverNewOwner, workflow.ApproverDecider}
	case store.SAKindChange:
		return []string{workflow.ApproverOldOwner, workflow.ApproverDecider}
	}
	return []string{workflow.ApproverOldOwner, workflow.ApproverNewOwner, workflow.ApproverDecider}
}

func defaultPlan(kind string) *workflow.Plan {
	p := &workflow.Plan{Path: []string{}, Stages: []workflow.StagePlan{}, Actions: []workflow.Action{}, Questionnaires: []string{}}
	for _, a := range defaultApprovers(kind) {
		p.Stages = append(p.Stages, workflow.StagePlan{Step: a, Approver: a, Label: Label(a), EscalateAfterHours: workflow.DefaultEscalateHours})
	}
	return p
}

// Label names an approver for people.
func Label(approver string) string {
	switch approver {
	case workflow.ApproverOldOwner:
		return "Current owner approval"
	case workflow.ApproverNewOwner:
		return "New owner approval"
	case workflow.ApproverManager:
		return "Manager approval"
	case workflow.ApproverGroup:
		return "Group approval"
	}
	return "Decider approval"
}

// StageLabel is the label of stage idx of a request: from its workflow's plan, or the default's.
func StageLabel(tx *store.TenantTx, r *store.ServiceAccountRequest, idx int) (string, error) {
	plan, err := workflow.PlanFor(tx, store.WFSubjectServiceAccount, r.ID)
	if err != nil {
		return "", err
	}
	if sp := plan.StageAt(idx); sp != nil {
		return sp.Label, nil
	}
	if sp := defaultPlan(r.Kind).StageAt(idx); sp != nil && plan == nil {
		return sp.Label, nil
	}
	return "Approval", nil
}

// person checks that an identity is an active person and returns it.
func person(tx *store.TenantTx, id *int64, role string) (*store.Identity, error) {
	if id == nil {
		return nil, refuse(422, role+"_owner_required", "a service account needs a %s owner", role)
	}
	i, err := tx.Identity(*id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(404, role+"_owner_not_found", "the %s owner was not found", role)
	} else if err != nil {
		return nil, err
	}
	if i.Type != "human" || i.Status != "active" {
		return nil, refuse(409, role+"_owner_not_active", "the %s owner must be an active person", role)
	}
	return i, nil
}

// owners returns the account's current primary and backup owner and its owner group and purpose.
func owners(tx *store.TenantTx, i *store.Identity) (primary, backup, group *int64, purpose string, err error) {
	primary = i.OwnerID
	o, err := tx.Ownership(store.OwnedIdentity, strconv.FormatInt(i.ID, 10))
	if errors.Is(err, store.ErrNotFound) {
		return primary, nil, nil, "", nil
	} else if err != nil {
		return nil, nil, nil, "", err
	}
	if o.PrimaryID != nil {
		primary = o.PrimaryID
	}
	return primary, o.BackupID, o.GroupID, o.Purpose, nil
}

func serviceAccount(tx *store.TenantTx, id *int64) (*store.Identity, error) {
	if id == nil {
		return nil, refuse(422, "account_required", "name the service account")
	}
	i, err := tx.Identity(*id)
	if errors.Is(err, store.ErrNotFound) || err == nil && i.Type != "service" {
		return nil, refuse(404, "account_not_found", "service account not found")
	} else if err != nil {
		return nil, err
	}
	if i.Status != "active" {
		return nil, refuse(409, "account_not_active", "%s is not active", i.Name)
	}
	return i, nil
}

func ptr[T any](v T) *T { return &v }

// File files a request: it validates it, resolves the workflow, and starts the first stage.
func File(tx *store.TenantTx, in Input, by requests.Actor, now time.Time) (*store.ServiceAccountRequest, error) {
	just := strings.TrimSpace(in.Justification)
	if just == "" || len(just) > requests.MaxJustification {
		return nil, refuse(422, "justification_required", "a justification of 1 to %d characters is required", requests.MaxJustification)
	}
	if len(strings.TrimSpace(in.Purpose)) > ownership.MaxPurpose {
		return nil, refuse(422, "invalid_purpose", "the purpose is at most %d characters", ownership.MaxPurpose)
	}
	if len(in.Description) > ownership.MaxPurpose {
		return nil, refuse(422, "invalid_description", "the description is at most %d characters", ownership.MaxPurpose)
	}
	r := &store.ServiceAccountRequest{ID: uuid.NewString(), Kind: in.Kind, Status: store.SAPending, Purpose: strings.TrimSpace(in.Purpose),
		Description: strings.TrimSpace(in.Description), Justification: just, RequestedBy: by.UserID.String(), RequestedAt: now}
	var err error
	switch in.Kind {
	case store.SAKindCreate:
		err = fileCreate(tx, r, in)
	case store.SAKindChange:
		err = fileChange(tx, r, in)
	case store.SAKindTransfer:
		err = fileTransfer(tx, r, in)
	default:
		err = refuse(422, "invalid_kind", "kind is create, change or transfer")
	}
	if err != nil {
		return nil, err
	}
	if r.PrimaryOwnerID == 0 {
		return nil, refuse(422, "primary_owner_required", "a service account needs a primary owner")
	}
	if r.IdentityID != nil {
		if open, err := tx.OpenServiceAccountRequestFor(*r.IdentityID); err == nil {
			return nil, refuse(409, "request_open", "there is already an open request about this account (%s)", open.Kind)
		} else if !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
	}
	res, plan, err := resolvePlan(tx, r)
	if err != nil {
		return nil, err
	}
	// the questionnaires its workflow asks
	needs, err := planNeeds(tx, plan)
	if err != nil {
		return nil, err
	}
	checked, err := questionnaires.Validate(needs, in.Answers)
	if err != nil {
		var qe *questionnaires.Error
		if errors.As(err, &qe) {
			return nil, &requests.Error{Status: qe.Status, Code: qe.Code, Msg: qe.Msg}
		}
		return nil, err
	}
	stages, err := buildStages(tx, r, plan, by, now)
	if err != nil {
		return nil, err
	}
	if err := tx.InsertServiceAccountRequest(r); err != nil {
		return nil, err
	}
	if res != nil {
		if err := workflow.Record(tx, store.WFSubjectServiceAccount, r.ID, plan, now); err != nil {
			return nil, err
		}
	}
	for _, st := range stages {
		if err := tx.InsertWorkflowStage(st); err != nil {
			return nil, err
		}
	}
	if err := questionnaires.Record(tx, store.QSubjectRequestLine, r.ID, checked, by.Display, now); err != nil {
		return nil, err
	}
	detail := ojson.Object{{Key: "request_id", Value: r.ID}, {Key: "kind", Value: r.Kind}, {Key: "name", Value: r.Name},
		{Key: "identity_id", Value: r.IdentityID}, {Key: "system", Value: r.System}, {Key: "primary_owner_id", Value: r.PrimaryOwnerID},
		{Key: "backup_owner_id", Value: r.BackupOwnerID}, {Key: "previous_primary_id", Value: r.PreviousPrimaryID},
		{Key: "justification", Value: just}, {Key: "stages", Value: len(stages)}}
	if res != nil {
		detail = append(detail, ojson.KV{Key: "workflow_id", Value: res.ID}, ojson.KV{Key: "workflow_version", Value: res.Version})
	} else {
		detail = append(detail, ojson.KV{Key: "workflow_id", Value: nil})
	}
	if len(checked) > 0 {
		detail = append(detail, ojson.KV{Key: "questionnaires", Value: questionnaires.AuditDetail(checked)})
	}
	if err := tx.Audit(now, by.Display, "service_account.request.submit", detail); err != nil {
		return nil, err
	}
	if err := fireActions(tx, r, plan, -1, now); err != nil {
		return nil, err
	}
	return r, notifyWaiting(tx, r, stages, now)
}

// resolvePlan finds the workflow that routes a request (nil: none, the default routing does)
// and the path it selects for the request's attributes. r needs Kind, System, IdentityID,
// PrimaryOwnerID and RequestedBy.
func resolvePlan(tx *store.TenantTx, r *store.ServiceAccountRequest) (*workflow.Resolved, *workflow.Plan, error) {
	res, err := workflow.ForRequestType(tx, RequestType(r.Kind))
	if err != nil {
		return nil, nil, err
	}
	if res == nil {
		return nil, defaultPlan(r.Kind), nil
	}
	ben, err := tx.Identity(r.PrimaryOwnerID)
	if err != nil {
		return nil, nil, err
	}
	org, err := requests.RequesterOrg(tx, r.RequestedBy)
	if err != nil {
		return nil, nil, err
	}
	sys := r.System
	if sys == "" && r.IdentityID != nil {
		accts, err := tx.IdentityAccounts(*r.IdentityID)
		if err != nil {
			return nil, nil, err
		}
		for _, a := range accts {
			if a.Status == "active" {
				sys = a.System
				break
			}
		}
	}
	dept := ""
	if ben.Department != nil {
		dept = *ben.Department
	}
	plan, err := res.Resolve(map[string]string{"kind": r.Kind, "system": sys, "requester_org": org, "owner_org": dept})
	return res, plan, err
}

// planNeeds are the questionnaires a plan asks the requester to answer.
func planNeeds(tx *store.TenantTx, plan *workflow.Plan) ([]questionnaires.Need, error) {
	var needs []questionnaires.Need
	for _, qid := range plan.Questionnaires {
		n, err := questionnaires.Current(tx, qid)
		if err != nil {
			return nil, err
		}
		if n != nil {
			needs = questionnaires.Union(needs, []questionnaires.Need{*n})
		}
	}
	return needs, nil
}

// Needs are the questionnaires the workflow of a request would ask, for the form (a request
// for an account of the given kind, system and owner, filed by user).
func Needs(tx *store.TenantTx, kind, system string, identityID *int64, primaryOwnerID int64, user string) ([]questionnaires.Need, error) {
	if !slices.Contains(Kinds, kind) {
		return nil, refuse(422, "invalid_kind", "kind is create, change or transfer")
	}
	if _, err := tx.Identity(primaryOwnerID); errors.Is(err, store.ErrNotFound) {
		return nil, refuse(404, "primary_owner_not_found", "the primary owner was not found")
	} else if err != nil {
		return nil, err
	}
	_, plan, err := resolvePlan(tx, &store.ServiceAccountRequest{Kind: kind, System: system, IdentityID: identityID, PrimaryOwnerID: primaryOwnerID, RequestedBy: user})
	if err != nil {
		return nil, err
	}
	return planNeeds(tx, plan)
}

func fileCreate(tx *store.TenantTx, r *store.ServiceAccountRequest, in Input) error {
	r.Name, r.System, r.Username = strings.TrimSpace(in.Name), strings.TrimSpace(in.System), strings.TrimSpace(in.Username)
	switch {
	case in.IdentityID != nil:
		return refuse(422, "invalid_account", "a new service account has no existing account")
	case r.Name == "" || len(r.Name) > MaxName:
		return refuse(422, "invalid_name", "a name of 1 to %d characters is required", MaxName)
	case r.Username == "" || len(r.Username) > MaxUsername || !usernameRE.MatchString(r.Username):
		return refuse(422, "invalid_username", "the account name is 1 to %d letters, digits, . _ @ or -", MaxUsername)
	}
	systems, err := ownership.Systems(tx)
	if err != nil {
		return err
	}
	if !slices.Contains(systems, r.System) {
		return refuse(422, "unknown_system", "%q is not an application of this tenant", r.System)
	}
	if err := setOwners(tx, r, in.PrimaryOwnerID, in.BackupOwnerID); err != nil {
		return err
	}
	if _, err := tx.AccountByXID(r.System, r.Username); err == nil {
		return refuse(409, "account_exists", "%s already has an account named %s", r.System, r.Username)
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if _, err := tx.IdentityByExternalID(externalID(r)); err == nil {
		return refuse(409, "account_exists", "that service account exists")
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if open, err := tx.OpenServiceAccountCreate(r.Name); err == nil {
		return refuse(409, "request_open", "request %s already asks for a service account named %s", open.ID, r.Name)
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return nil
}

func externalID(r *store.ServiceAccountRequest) string {
	return "svc:" + r.System + ":" + strings.ToLower(r.Username)
}

// setOwners checks the owners a request leaves the account with and records them.
func setOwners(tx *store.TenantTx, r *store.ServiceAccountRequest, primary, backup *int64) error {
	p, err := person(tx, primary, "primary")
	if err != nil {
		return err
	}
	b, err := person(tx, backup, "backup")
	if err != nil {
		return err
	}
	if p.ID == b.ID {
		return refuse(422, "same_owner", "the backup owner must be someone else")
	}
	r.PrimaryOwnerID, r.BackupOwnerID = p.ID, &b.ID
	return nil
}

func fileChange(tx *store.TenantTx, r *store.ServiceAccountRequest, in Input) error {
	i, err := serviceAccount(tx, in.IdentityID)
	if err != nil {
		return err
	}
	primary, backup, _, purpose, err := owners(tx, i)
	if err != nil {
		return err
	}
	if primary == nil {
		return refuse(409, "no_owner", "%s has no owner; transfer it to give it one", i.Name)
	}
	r.IdentityID, r.Name, r.PreviousPrimaryID, r.PreviousBackupID = &i.ID, i.Name, primary, backup
	if in.PrimaryOwnerID != nil && *in.PrimaryOwnerID != *primary {
		return refuse(422, "owner_change", "a change keeps the primary owner; transfer the account to change it")
	}
	newBackup := backup
	if in.BackupOwnerID != nil {
		newBackup = in.BackupOwnerID
	}
	if r.Purpose == "" {
		r.Purpose = purpose
	}
	if r.Purpose == purpose && sameID(newBackup, backup) {
		return refuse(422, "no_change", "the request changes neither the purpose nor the backup owner")
	}
	return setOwners(tx, r, primary, newBackup)
}

func fileTransfer(tx *store.TenantTx, r *store.ServiceAccountRequest, in Input) error {
	i, err := serviceAccount(tx, in.IdentityID)
	if err != nil {
		return err
	}
	primary, backup, _, purpose, err := owners(tx, i)
	if err != nil {
		return err
	}
	r.IdentityID, r.Name, r.PreviousPrimaryID, r.PreviousBackupID = &i.ID, i.Name, primary, backup
	if in.PrimaryOwnerID == nil {
		return refuse(422, "primary_owner_required", "name the new primary owner")
	}
	if primary != nil && *in.PrimaryOwnerID == *primary {
		return refuse(422, "same_owner", "the new owner already owns the account")
	}
	newBackup := backup
	if in.BackupOwnerID != nil {
		newBackup = in.BackupOwnerID
	}
	if r.Purpose == "" {
		r.Purpose = purpose
	}
	return setOwners(tx, r, in.PrimaryOwnerID, newBackup)
}

func sameID(a, b *int64) bool { return a == nil && b == nil || a != nil && b != nil && *a == *b }

// buildStages makes the stages of a plan for a request. Stages whose owner is the requester
// are approved by the request itself; at least one other must remain.
func buildStages(tx *store.TenantTx, r *store.ServiceAccountRequest, plan *workflow.Plan, by requests.Actor, now time.Time) ([]*store.RequestStage, error) {
	var out []*store.RequestStage
	opened, remaining := false, 0
	for i := range plan.Stages {
		sp := &plan.Stages[i]
		st := &store.RequestStage{LineID: r.ID, Idx: i, Kind: sp.Kind(), Status: store.StageQueued}
		switch sp.Approver {
		case workflow.ApproverOldOwner:
			st.AssigneeID = r.PreviousPrimaryID
		case workflow.ApproverNewOwner:
			st.AssigneeID = &r.PrimaryOwnerID
		case workflow.ApproverManager:
			o, err := tx.Identity(r.PrimaryOwnerID)
			if err != nil {
				return nil, err
			}
			st.AssigneeID = o.ManagerID
		}
		own := (sp.Approver == workflow.ApproverOldOwner || sp.Approver == workflow.ApproverNewOwner) &&
			st.AssigneeID != nil && by.IdentityID != nil && *st.AssigneeID == *by.IdentityID
		switch {
		case own: // the owner asking is their consent
			uid := by.UserID.String()
			st.Status, st.StartedAt, st.DecidedBy, st.DecidedAt = store.StageApproved, &now, &uid, &now
			st.Reason = ptr("requested by the owner")
		case !opened:
			if err := requests.BeginStage(tx, st, sp, sp.EscalateAfterHours, now); err != nil {
				return nil, err
			}
			opened = true
			remaining++
		default:
			remaining++
		}
		out = append(out, st)
	}
	if remaining == 0 {
		return nil, refuse(409, "needs_another_approver", "every approval of this request is yours; another person must approve it")
	}
	return out, nil
}

// notifyWaiting tells the approvers of the waiting stage.
func notifyWaiting(tx *store.TenantTx, r *store.ServiceAccountRequest, stages []*store.RequestStage, now time.Time) error {
	for _, st := range stages {
		if st.Status != store.StageWaiting {
			continue
		}
		if st.StartedAt != nil && now.Before(*st.StartedAt) {
			return nil // held by a workflow wait: it shows in the inbox when it opens
		}
		var to []notify.Recipient
		var err error
		plan, err := workflow.PlanFor(tx, store.WFSubjectServiceAccount, r.ID)
		if err != nil {
			return err
		}
		if sp := plan.StageAt(st.Idx); sp != nil && sp.Approver == workflow.ApproverGroup && !(st.DueAt != nil && !now.Before(*st.DueAt)) {
			to, err = requests.GroupRecipients(tx, sp.GroupID, now)
		} else {
			to, err = notify.StageApprovers(tx, now, st)
		}
		if err != nil {
			return err
		}
		label, err := StageLabel(tx, r, st.Idx)
		if err != nil {
			return err
		}
		_, err = notify.Emit(tx, now, notify.Message{Kind: notify.KindApprovalNeeded, Key: "service_account.approval_needed:" + r.ID + ":" + strconv.Itoa(st.Idx),
			Subject: "Approval needed: " + r.Kind + " service account " + r.Name,
			Body:    "A request to " + r.Kind + " the service account " + r.Name + " is waiting for you (" + label + ").\nJustification: " + r.Justification,
			Link:    "/requests", Skip: []string{r.RequestedBy}}, to...)
		return err
	}
	return nil
}

// fireActions sends the notices of a plan anchored after stage idx (-1: when filed).
func fireActions(tx *store.TenantTx, r *store.ServiceAccountRequest, plan *workflow.Plan, idx int, now time.Time) error {
	if plan == nil { // the default routing has no notices
		return nil
	}
	for _, a := range plan.Actions {
		if a.After != idx {
			continue
		}
		var to []notify.Recipient
		var err error
		switch a.Notify {
		case workflow.NotifyRequester:
			if u, ok, e := notify.User(tx, r.RequestedBy); e != nil {
				return e
			} else if ok {
				to = append(to, u)
			}
		case workflow.NotifyBeneficiary:
			to, err = notify.Identity(tx, r.PrimaryOwnerID)
		case workflow.NotifyOwner:
			if r.PreviousPrimaryID != nil {
				to, err = notify.Identity(tx, *r.PreviousPrimaryID)
			}
		case workflow.NotifyGroup:
			to, err = requests.GroupRecipients(tx, a.GroupID, now)
		}
		if err != nil {
			return err
		}
		body := a.Message
		if body == "" {
			body = "The request to " + r.Kind + " the service account " + r.Name + " reached the step " + a.Step + " of its workflow."
		}
		if err := notify.WorkflowNotice(tx, now, r.ID+":"+a.Step, "Service account request: "+r.Name, body, "/requests", nil, to...); err != nil {
			return err
		}
	}
	return nil
}

func subject(r *store.ServiceAccountRequest) requests.Subject {
	return requests.Subject{RequestedBy: r.RequestedBy, Kind: store.WFSubjectServiceAccount, ID: r.ID}
}

func get(tx *store.TenantTx, id string) (*store.ServiceAccountRequest, error) {
	r, err := tx.ServiceAccountRequest(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(404, "request_not_found", "request not found")
	}
	return r, err
}

// Get returns a request.
func Get(tx *store.TenantTx, id string) (*store.ServiceAccountRequest, error) { return get(tx, id) }

func authorize(tx *store.TenantTx, r *store.ServiceAccountRequest, by requests.Actor, now time.Time) (*requests.Authority, []*store.RequestStage, error) {
	if r.Status != store.SAPending {
		return nil, nil, refuse(409, "not_pending", "the request is %s", r.Status)
	}
	stages, err := tx.WorkflowStages(r.ID)
	if err != nil {
		return nil, nil, err
	}
	a, err := requests.AuthorizeStages(tx, subject(r), stages, by, now)
	return a, stages, err
}

// CanDecide reports whether by may decide the request now (for views).
func CanDecide(tx *store.TenantTx, r *store.ServiceAccountRequest, by requests.Actor, now time.Time) (bool, error) {
	_, _, err := authorize(tx, r, by, now)
	var re *requests.Error
	if errors.As(err, &re) {
		return false, nil
	}
	return err == nil, err
}

// Pending lists the pending requests by may decide now, oldest first.
func Pending(tx *store.TenantTx, by requests.Actor, now time.Time) ([]*store.ServiceAccountRequest, error) {
	all, err := tx.ServiceAccountRequests(store.SARequestFilter{Status: store.SAPending})
	if err != nil {
		return nil, err
	}
	var out []*store.ServiceAccountRequest
	for i := len(all) - 1; i >= 0; i-- {
		if ok, err := CanDecide(tx, all[i], by, now); err != nil {
			return nil, err
		} else if ok {
			out = append(out, all[i])
		}
	}
	return out, nil
}

func reasonOf(reason string, required bool) (*string, error) {
	r := strings.TrimSpace(reason)
	if len(r) > requests.MaxReason || required && r == "" {
		return nil, refuse(422, "reason_required", "a reason of 1 to %d characters is required", requests.MaxReason)
	}
	if r == "" {
		return nil, nil
	}
	return &r, nil
}

// Approve approves the waiting stage; the last approval makes the change.
func Approve(tx *store.TenantTx, id string, by requests.Actor, reason string, now time.Time) (*store.ServiceAccountRequest, error) {
	r, err := get(tx, id)
	if err != nil {
		return nil, err
	}
	why, err := reasonOf(reason, false)
	if err != nil {
		return nil, err
	}
	a, stages, err := authorize(tx, r, by, now)
	if err != nil {
		return nil, err
	}
	st, uid := a.Stage, by.UserID.String()
	st.Status, st.DecidedBy, st.OnBehalfOf, st.DecidedAt, st.Reason = store.StageApproved, &uid, a.OnBehalfOf, &now, why
	if err := tx.SaveWorkflowStage(st, store.StageWaiting); errors.Is(err, store.ErrNotFound) {
		return nil, refuse(409, "already_decided", "the stage was decided by someone else")
	} else if err != nil {
		return nil, err
	}
	plan, err := workflow.PlanFor(tx, store.WFSubjectServiceAccount, r.ID)
	if err != nil {
		return nil, err
	}
	if err := fireActions(tx, r, plan, st.Idx, now); err != nil {
		return nil, err
	}
	for _, next := range stages {
		if next.Idx > st.Idx && next.Status == store.StageQueued {
			sp, hours := plan.StageAt(next.Idx), workflow.DefaultEscalateHours
			if sp != nil {
				hours = sp.EscalateAfterHours
			}
			if err := requests.BeginStage(tx, next, sp, hours, now); err != nil {
				return nil, err
			}
			if err := tx.SaveWorkflowStage(next, store.StageQueued); err != nil {
				return nil, err
			}
			if err := notifyWaiting(tx, r, []*store.RequestStage{next}, now); err != nil {
				return nil, err
			}
			return r, tx.Audit(now, by.Display, "service_account.request.stage.approve", ojson.Object{{Key: "request_id", Value: r.ID},
				{Key: "stage", Value: st.Idx}, {Key: "kind", Value: st.Kind}, {Key: "escalated", Value: a.Escalated}})
		}
	}
	// the last stage: make the change
	r.DecidedBy, r.DecidedAt, r.DecisionReason = &uid, &now, why
	if err := fulfil(tx, r, by, now); err != nil {
		return nil, err
	}
	if err := tx.FinishWorkflowRun(store.WFSubjectServiceAccount, r.ID, store.WFRunCompleted, now); err != nil {
		return nil, err
	}
	if err := notifyDecided(tx, r, true, uid, now); err != nil {
		return nil, err
	}
	return r, tx.Audit(now, by.Display, "service_account.request.approve", ojson.Object{{Key: "request_id", Value: r.ID},
		{Key: "kind", Value: r.Kind}, {Key: "identity_id", Value: r.IdentityID}, {Key: "status", Value: r.Status},
		{Key: "primary_owner_id", Value: r.PrimaryOwnerID}, {Key: "backup_owner_id", Value: r.BackupOwnerID}, {Key: "op_id", Value: r.OpID}})
}

// Deny rejects a pending request; a reason is required.
func Deny(tx *store.TenantTx, id string, by requests.Actor, reason string, now time.Time) (*store.ServiceAccountRequest, error) {
	r, err := get(tx, id)
	if err != nil {
		return nil, err
	}
	why, err := reasonOf(reason, true)
	if err != nil {
		return nil, err
	}
	a, _, err := authorize(tx, r, by, now)
	if err != nil {
		return nil, err
	}
	st, uid := a.Stage, by.UserID.String()
	st.Status, st.DecidedBy, st.OnBehalfOf, st.DecidedAt, st.Reason = store.StageDenied, &uid, a.OnBehalfOf, &now, why
	if err := tx.SaveWorkflowStage(st, store.StageWaiting); errors.Is(err, store.ErrNotFound) {
		return nil, refuse(409, "already_decided", "the stage was decided by someone else")
	} else if err != nil {
		return nil, err
	}
	return r, end(tx, r, store.SADenied, store.WFRunDenied, "service_account.request.deny", by, &uid, why, now)
}

// Cancel withdraws a pending request; only its requester may.
func Cancel(tx *store.TenantTx, id string, by requests.Actor, now time.Time) (*store.ServiceAccountRequest, error) {
	r, err := get(tx, id)
	if err != nil {
		return nil, err
	}
	if r.RequestedBy != by.UserID.String() {
		return nil, refuse(404, "request_not_found", "request not found")
	}
	if r.Status != store.SAPending {
		return nil, refuse(409, "not_pending", "the request is %s", r.Status)
	}
	return r, end(tx, r, store.SACancelled, store.WFRunCancelled, "service_account.request.cancel", by, nil, nil, now)
}

func end(tx *store.TenantTx, r *store.ServiceAccountRequest, status, runStatus, event string, by requests.Actor, decider *string, why *string, now time.Time) error {
	r.Status, r.ClosedAt = status, &now
	if decider != nil {
		r.DecidedBy, r.DecidedAt, r.DecisionReason = decider, &now, why
	}
	if err := tx.SaveServiceAccountRequest(r, store.SAPending); err != nil {
		return err
	}
	if err := tx.CloseOpenWorkflowStages(r.ID); err != nil {
		return err
	}
	if err := tx.FinishWorkflowRun(store.WFSubjectServiceAccount, r.ID, runStatus, now); err != nil {
		return err
	}
	if status == store.SADenied {
		if err := notifyDecided(tx, r, false, *decider, now); err != nil {
			return err
		}
	}
	d := ojson.Object{{Key: "request_id", Value: r.ID}, {Key: "kind", Value: r.Kind}, {Key: "name", Value: r.Name}}
	if why != nil {
		d = append(d, ojson.KV{Key: "reason", Value: *why})
	}
	return tx.Audit(now, by.Display, event, d)
}

func notifyDecided(tx *store.TenantTx, r *store.ServiceAccountRequest, approved bool, decider string, now time.Time) error {
	u, ok, err := notify.User(tx, r.RequestedBy)
	if err != nil || !ok {
		return err
	}
	kind, word := notify.KindRequestApproved, "approved"
	if !approved {
		kind, word = notify.KindRequestDenied, "denied"
	}
	_, err = notify.Emit(tx, now, notify.Message{Kind: kind, Key: "service_account.decided:" + r.ID,
		Subject: "Service account request " + word + ": " + r.Name,
		Body:    "Your request to " + r.Kind + " the service account " + r.Name + " was " + word + ".", Link: "/requests",
		Skip: []string{decider}}, u)
	return err
}

// ---------------------------------------------------------------- fulfilment

// CompleteAccount is the provisioning completion that makes a created account's row once the
// target system confirms it.
const CompleteAccount = "svcaccounts.create_account"

type accountData struct {
	RequestID  string `json:"request_id"`
	IdentityID int64  `json:"identity_id"`
	System     string `json:"system"`
	Username   string `json:"username"`
}

func init() {
	provision.RegisterCompletion(CompleteAccount, func(tx *store.TenantTx, now time.Time, raw json.RawMessage) error {
		var d accountData
		if err := json.Unmarshal(raw, &d); err != nil {
			return err
		}
		if err := ensureAccount(tx, d.IdentityID, d.System, d.Username, now); err != nil {
			return err
		}
		r, err := tx.ServiceAccountRequest(d.RequestID)
		if err != nil {
			return err
		}
		if r.Status != store.SAApproved {
			return nil
		}
		r.Status, r.FulfilledAt = store.SAFulfilled, &now
		if err := tx.SaveServiceAccountRequest(r, store.SAApproved); err != nil {
			return err
		}
		return tx.Audit(now, "system", "service_account.request.fulfill", ojson.Object{{Key: "request_id", Value: r.ID},
			{Key: "identity_id", Value: d.IdentityID}, {Key: "system", Value: d.System}, {Key: "username", Value: d.Username}})
	})
}

func ensureAccount(tx *store.TenantTx, identityID int64, system, username string, now time.Time) error {
	if _, err := tx.AccountByXID(system, username); err == nil {
		return nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	_, err := tx.InsertAccount(&store.Account{System: system, ExternalID: username, IdentityID: &identityID, Username: username,
		Kind: "service", Status: "active", CreatedAt: &now})
	return err
}

func fulfil(tx *store.TenantTx, r *store.ServiceAccountRequest, by requests.Actor, now time.Time) error {
	uid := by.UserID.String()
	switch r.Kind {
	case store.SAKindCreate:
		return fulfilCreate(tx, r, by, &uid, now)
	case store.SAKindChange:
		if err := setOwnership(tx, r, by, &uid, now); err != nil {
			return err
		}
		return pushUpdate(tx, r, map[string]string{"description": r.Purpose}, now)
	}
	if err := setOwnership(tx, r, by, &uid, now); err != nil {
		return err
	}
	o, err := tx.Identity(r.PrimaryOwnerID)
	if err != nil {
		return err
	}
	owner := o.Name
	if o.Email != nil {
		owner = *o.Email
	}
	return pushUpdate(tx, r, map[string]string{"owner": owner}, now)
}

// setOwnership writes the request's owners and purpose as the account's ownership (#167),
// keeping its owner group. The owners are checked again: they may have left since filing.
func setOwnership(tx *store.TenantTx, r *store.ServiceAccountRequest, by requests.Actor, uid *string, now time.Time) error {
	var group *int64
	key := strconv.FormatInt(*r.IdentityID, 10)
	if o, err := tx.Ownership(store.OwnedIdentity, key); err == nil {
		group = o.GroupID
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	_, err := ownership.Set(tx, ownership.Ref{Kind: store.OwnedIdentity, Key: key},
		ownership.Spec{PrimaryID: &r.PrimaryOwnerID, BackupID: r.BackupOwnerID, GroupID: group, Purpose: r.Purpose}, by.Display, uid, now)
	return asRequestError(err)
}

func asRequestError(err error) error {
	var oe *ownership.Error
	if errors.As(err, &oe) {
		return &requests.Error{Status: oe.Status, Code: oe.Code, Msg: oe.Msg}
	}
	return err
}

func fulfilCreate(tx *store.TenantTx, r *store.ServiceAccountRequest, by requests.Actor, uid *string, now time.Time) error {
	if _, err := tx.IdentityByExternalID(externalID(r)); err == nil {
		return refuse(409, "account_exists", "that service account was made since the request was filed; deny it")
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if _, err := tx.AccountByXID(r.System, r.Username); err == nil {
		return refuse(409, "account_exists", "%s has an account named %s since the request was filed; deny it", r.System, r.Username)
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if _, err := person(tx, &r.PrimaryOwnerID, "primary"); err != nil {
		return err
	}
	id, err := tx.InsertIdentity(&store.Identity{ExternalID: externalID(r), Name: r.Name, Type: "service", Status: "active",
		OwnerID: &r.PrimaryOwnerID, Source: ptr("service_account_request"), Description: ptr(r.Description), CreatedAt: now})
	if err != nil {
		return err
	}
	r.IdentityID = &id
	if err := setOwnership(tx, r, by, uid, now); err != nil {
		return err
	}
	op, routed, err := provision.Submit(tx, now, provision.Change{System: r.System, Kind: target.CreateAccount,
		Account: target.Account{Username: r.Username, ExternalID: r.Username, DisplayName: r.Name},
		Source:  provision.SourceAPI, Key: "service-account-request:" + r.ID + ":create", Completion: CompleteAccount,
		Data: accountData{RequestID: r.ID, IdentityID: id, System: r.System, Username: r.Username}})
	if err != nil {
		return err
	}
	if routed { // the account row appears when the target confirms it
		r.Status, r.OpID = store.SAApproved, &op.ID
		return tx.SaveServiceAccountRequest(r, store.SAPending)
	}
	if err := ensureAccount(tx, id, r.System, r.Username, now); err != nil {
		return err
	}
	r.Status, r.FulfilledAt, r.ClosedAt = store.SAFulfilled, &now, &now
	return tx.SaveServiceAccountRequest(r, store.SAPending)
}

// pushUpdate asks the provisioning engine to update the account in each system it has one in.
func pushUpdate(tx *store.TenantTx, r *store.ServiceAccountRequest, attrs map[string]string, now time.Time) error {
	accts, err := tx.IdentityAccounts(*r.IdentityID)
	if err != nil {
		return err
	}
	for _, a := range accts {
		if a.Status != "active" {
			continue
		}
		op, routed, err := provision.Submit(tx, now, provision.Change{System: a.System, Kind: target.UpdateAccount,
			Account: target.Account{Username: a.Username, ExternalID: a.ExternalID, Attrs: attrs}, Source: provision.SourceAPI,
			Key: "service-account-request:" + r.ID + ":update:" + strconv.FormatInt(a.ID, 10)})
		if err != nil {
			return err
		}
		if routed && r.OpID == nil {
			r.OpID = &op.ID
		}
	}
	r.Status, r.FulfilledAt, r.ClosedAt = store.SAFulfilled, &now, &now
	return tx.SaveServiceAccountRequest(r, store.SAPending)
}
