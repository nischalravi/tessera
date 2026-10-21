package requests

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/notify"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/provision"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
	"github.com/nischalravi/tessera/mvp/server/internal/questionnaires"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/workflow"
)

// Workflows on access requests (issue #298). An item with no workflow assigned, directly or
// through the access request type, is routed by its approval policy exactly as before; every
// function here returns early for it. A line a workflow routes copies the stages of the path
// the workflow selects for the line's attributes when it is filed (workflow.Compile), keeps
// that plan as its run, and then runs on the same stages, approvals, delegations, escalation
// and four-eyes rules as any line.

// RequesterOrg is the department of the person a platform user is ("" when unknown).
func RequesterOrg(tx *store.TenantTx, userID string) (string, error) {
	id, err := uuid.Parse(userID)
	if err != nil {
		return "", nil
	}
	u, err := tx.PlatformUser(id)
	if errors.Is(err, store.ErrNotFound) || err == nil && u.IdentityID == nil {
		return "", nil
	} else if err != nil {
		return "", err
	}
	i, err := tx.Identity(*u.IdentityID)
	if errors.Is(err, store.ErrNotFound) || err == nil && i.Department == nil {
		return "", nil
	} else if err != nil {
		return "", err
	}
	return *i.Department, nil
}

func deptOf(i *store.Identity) string {
	if i.Department == nil {
		return ""
	}
	return *i.Department
}

// planLine resolves the workflow that routes a line (nil: none, the item's policy does).
func planLine(tx *store.TenantTx, l *store.RequestLine, ben *store.Identity) (*workflow.Plan, error) {
	r, err := workflow.ForItem(tx, l.CatalogItemID)
	if err != nil || r == nil {
		return nil, err
	}
	it, err := tx.CatalogItem(l.CatalogItemID)
	if err != nil {
		return nil, err
	}
	g, err := tx.Group(it.GroupID)
	if err != nil {
		return nil, err
	}
	org, err := RequesterOrg(tx, l.RequestedBy)
	if err != nil {
		return nil, err
	}
	attrs := map[string]string{"risk": it.Risk, "item": it.ID, "privileged": strconv.FormatBool(g.Privileged), "system": g.System,
		"requester_org": org, "beneficiary_org": deptOf(ben)}
	return r.Resolve(attrs)
}

func startPlanned(tx *store.TenantTx, l *store.RequestLine, ben *store.Identity, it *store.CatalogItem, plan *workflow.Plan, now time.Time) error {
	for i := range plan.Stages {
		sp := &plan.Stages[i]
		st := &store.RequestStage{LineID: l.ID, Idx: i, Kind: sp.Kind(), Status: store.StageQueued}
		switch sp.Approver {
		case workflow.ApproverManager:
			st.AssigneeID = ben.ManagerID
		case workflow.ApproverOwner:
			st.AssigneeID = it.OwnerIdentityID
		}
		if i == 0 {
			if err := BeginStage(tx, st, sp, sp.EscalateAfterHours, now); err != nil {
				return err
			}
		}
		if err := tx.InsertRequestStage(st); err != nil {
			return err
		}
	}
	if err := workflow.Record(tx, store.WFSubjectAccessLine, l.ID, plan, now); err != nil {
		return err
	}
	return fireActions(tx, l, plan, -1, now)
}

// workflowNeeds are the questionnaires the workflow paths of the cart's lines ask, by line.
func workflowNeeds(tx *store.TenantTx, plan *workflow.Plan) ([]questionnaires.Need, error) {
	if plan == nil {
		return nil, nil
	}
	var out []questionnaires.Need
	for _, id := range plan.Questionnaires {
		n, err := questionnaires.Current(tx, id)
		if err != nil {
			return nil, err
		}
		if n != nil {
			out = questionnaires.Union(out, []questionnaires.Need{*n})
		}
	}
	return out, nil
}

// fireActions sends the notices of a plan anchored after stage idx (-1: when filed).
func fireActions(tx *store.TenantTx, l *store.RequestLine, plan *workflow.Plan, idx int, now time.Time) error {
	for _, a := range plan.Actions {
		if a.After != idx {
			continue
		}
		var to []notify.Recipient
		var err error
		switch a.Notify {
		case workflow.NotifyRequester:
			if r, ok, e := notify.User(tx, l.RequestedBy); e != nil {
				return e
			} else if ok {
				to = append(to, r)
			}
		case workflow.NotifyBeneficiary:
			to, err = notify.Identity(tx, l.BeneficiaryID)
		case workflow.NotifyOwner:
			var it *store.CatalogItem
			if it, err = tx.CatalogItem(l.CatalogItemID); err == nil && it.OwnerIdentityID != nil {
				to, err = notify.Identity(tx, *it.OwnerIdentityID)
			}
		case workflow.NotifyGroup:
			to, err = GroupRecipients(tx, a.GroupID, now)
		}
		if err != nil {
			return err
		}
		g, err := tx.Group(l.GroupID)
		if err != nil {
			return err
		}
		body := a.Message
		if body == "" {
			body = "The request for " + g.System + ":" + g.Name + " reached the step " + a.Step + " of its workflow."
		}
		if err := notify.WorkflowNotice(tx, now, l.ID+":"+a.Step, "Request update: "+g.System+":"+g.Name, body, "/requests", nil, to...); err != nil {
			return err
		}
	}
	return nil
}

// afterStage runs what a plan does once stage idx of the line was approved: its notices, and
// when the line is fully approved its provisioning step and the end of the run.
func afterStage(tx *store.TenantTx, l *store.RequestLine, idx int, final bool, by Actor, now time.Time) error {
	plan, err := workflow.PlanFor(tx, store.WFSubjectAccessLine, l.ID)
	if err != nil || plan == nil {
		return err
	}
	if err := fireActions(tx, l, plan, idx, now); err != nil {
		return err
	}
	if !final {
		return nil
	}
	if plan.Provision {
		if err := provisionGrant(tx, l, by, now); err != nil {
			return err
		}
	}
	return tx.FinishWorkflowRun(store.WFSubjectAccessLine, l.ID, store.WFRunCompleted, now)
}

// provisionGrant asks the provisioning engine to add the entitlement in the target system when
// its connection has write-back on (otherwise the grant lives in Tessera only, as for any line).
func provisionGrant(tx *store.TenantTx, l *store.RequestLine, by Actor, now time.Time) error {
	g, err := tx.Group(l.GroupID)
	if err != nil {
		return err
	}
	acct, err := tx.Account(l.AccountID)
	if err != nil {
		return err
	}
	op, routed, err := provision.Submit(tx, now, provision.Change{System: g.System, Kind: target.AddEntitlement,
		Account: target.Account{Username: acct.Username, ExternalID: acct.ExternalID},
		Group:   target.Group{ExternalID: g.ExternalID, Name: g.Name}, Source: provision.SourceAPI, Key: "request:" + l.ID + ":add"})
	if err != nil {
		return err
	}
	if !routed {
		return nil
	}
	note := fmt.Sprintf("provisioning operation %s queued", op.ID)
	if err := event(tx, l.ID, "provisioning", by, &note, now); err != nil {
		return err
	}
	return tx.Audit(now, by.Display, "request.provision", ojson.Object{{Key: "request_id", Value: l.ID}, {Key: "op_id", Value: op.ID}})
}

// finishRun ends the line's workflow run (a no-op for a line no workflow routed).
func finishRun(tx *store.TenantTx, l *store.RequestLine, status string, now time.Time) error {
	return tx.FinishWorkflowRun(store.WFSubjectAccessLine, l.ID, status, now)
}
