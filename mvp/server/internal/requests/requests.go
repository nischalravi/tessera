// Package requests is the access request service (issue #164): the
// requestable catalog, request lines from submission to removal, and their
// history.
//
// A submission (a cart) names beneficiaries and catalog items; it files one
// pending line per beneficiary and item, all or nothing. A person with
// requests.decide approves or denies each line; approval grants the access
// in Tessera (a grant edge, source "request", from the beneficiary's account
// to the group, expiring with the requested duration) in the same
// transaction. Provisioning into the target system is #103; approval
// routing to managers and owners is #165.
//
// Rules: the beneficiary is active and eligible (identity type and
// department lists of the item), does not already hold the access and has
// no open line for it; a duration is required for privileged items and for
// items with a maximum, and never exceeds the maximum; nobody approves a
// line they requested or that grants them access. Every change is a line
// event and an audit event in the caller's transaction.
package requests

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/abac"
	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/jit"
	"github.com/nischalravi/tessera/mvp/server/internal/notify"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/questionnaires"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
	"github.com/nischalravi/tessera/mvp/server/internal/workflow"
)

// Limits.
const (
	MaxJustification = 1000
	MaxReason        = 500
	MaxLines         = 50 // beneficiaries × items in one submission
	// MaxHours caps any duration (a year); "until removed" is no duration.
	MaxHours = 24 * 365
)

// Risks and identity types an item may name.
var (
	Risks         = []string{"low", "medium", "high"}
	IdentityTypes = []string{"human", "service", "ai_agent"}
)

// Error is a refused request; Code is stable for API clients.
type Error struct {
	Status int
	Code   string
	Msg    string
}

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

func refuse(status int, code, format string, args ...any) error {
	return &Error{Status: status, Code: code, Msg: fmt.Sprintf(format, args...)}
}

// Actor is the signed-in user acting.
type Actor struct {
	UserID     uuid.UUID
	Display    string
	IdentityID *int64 // the person the user is, if linked
	AAL        int    // authentication assurance level of the session (0: unknown); the context.aal attribute
	Decider    bool   // holds requests.decide
}

func (a Actor) id() string { return a.UserID.String() }

// RefuseUnlinked fails closed for an approver whose platform user has no linked
// identity (403 approver_unlinked, issue #443): every "is the decider the
// beneficiary?" check compares identities, so it cannot prove such a person is
// someone else. The same rule as reviewer_unlinked (#439).
func RefuseUnlinked(by Actor) error {
	if by.UserID != uuid.Nil && by.IdentityID == nil {
		return refuse(403, ErrCodeApproverUnlinked, "your account is not linked to an identity, so it cannot approve requests; ask an administrator to link it")
	}
	return nil
}

// ErrCodeApproverUnlinked is the code of RefuseUnlinked's refusal.
const ErrCodeApproverUnlinked = "approver_unlinked"

// ---------------------------------------------------------------- catalog

// Entry is a group with its catalog item (Item nil: not in the catalog).
type Entry struct {
	Group *store.Group
	Item  *store.CatalogItem
}

// Catalog lists every group with its item; requestableOnly keeps the items
// people can request.
func Catalog(tx *store.TenantTx, requestableOnly bool) ([]Entry, error) {
	groups, err := tx.GroupsBySystemName(nil)
	if err != nil {
		return nil, err
	}
	items, err := tx.CatalogItems()
	if err != nil {
		return nil, err
	}
	byGroup := make(map[int64]*store.CatalogItem, len(items))
	for _, it := range items {
		byGroup[it.GroupID] = it
	}
	out := make([]Entry, 0, len(groups))
	for _, g := range groups {
		it := byGroup[g.ID]
		if requestableOnly && (it == nil || !it.Requestable) {
			continue
		}
		out = append(out, Entry{Group: g, Item: it})
	}
	return out, nil
}

// ItemSpec is an item's editable metadata.
type ItemSpec struct {
	Requestable         bool
	Description         string
	OwnerIdentityID     *int64
	Risk                string
	EligibleTypes       []string
	EligibleDepartments []string
	DefaultHours        *float64
	MaxHours            *float64
	// Populations are the guest populations the item is open to (guest
	// access, issue #75); nil leaves them as they are, empty closes the item
	// to guests.
	Populations []string
}

// PutItem creates or updates a group's catalog item.
func PutItem(tx *store.TenantTx, groupID int64, s ItemSpec, by Actor, now time.Time) (*store.CatalogItem, error) {
	g, err := tx.Group(groupID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(404, "group_not_found", "group not found")
	} else if err != nil {
		return nil, err
	}
	switch {
	case !slices.Contains(Risks, s.Risk):
		return nil, refuse(422, "invalid_risk", "risk is low, medium or high")
	case len(s.Description) > 1000:
		return nil, refuse(422, "invalid_description", "the description is at most 1000 characters")
	case !hoursOK(s.DefaultHours) || !hoursOK(s.MaxHours):
		return nil, refuse(422, "invalid_duration", "durations are between 0 and %d hours", MaxHours)
	case s.DefaultHours != nil && s.MaxHours != nil && *s.DefaultHours > *s.MaxHours:
		return nil, refuse(422, "invalid_duration", "the default duration exceeds the maximum")
	case g.Privileged && s.DefaultHours == nil && s.Requestable:
		return nil, refuse(422, "privileged_needs_duration", "a privileged item needs a default duration")
	}
	for _, t := range s.EligibleTypes {
		if !slices.Contains(IdentityTypes, t) {
			return nil, refuse(422, "invalid_type", "eligible types are human, service or ai_agent")
		}
	}
	for _, d := range s.EligibleDepartments {
		if strings.TrimSpace(d) == "" || len(d) > 200 {
			return nil, refuse(422, "invalid_department", "department names are 1 to 200 characters")
		}
	}
	for _, pop := range s.Populations {
		if !slices.Contains(GuestPopulations, pop) {
			return nil, refuse(422, "invalid_population", "populations are visitor, contractor, volunteer or partner")
		}
	}
	if s.OwnerIdentityID != nil {
		o, err := tx.Identity(*s.OwnerIdentityID)
		if errors.Is(err, store.ErrNotFound) {
			return nil, refuse(404, "owner_not_found", "owner not found")
		} else if err != nil {
			return nil, err
		}
		if o.Status != "active" || o.Type != "human" {
			return nil, refuse(409, "owner_not_active", "the owner is an active person")
		}
	}
	id := uuid.NewString()
	if old, err := tx.CatalogItemForGroup(g.ID); err == nil {
		id = old.ID
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	uid := by.id()
	it := &store.CatalogItem{ID: id, GroupID: g.ID, Requestable: s.Requestable, Description: strings.TrimSpace(s.Description),
		OwnerIdentityID: s.OwnerIdentityID, Risk: s.Risk, EligibleTypes: s.EligibleTypes, EligibleDepartments: s.EligibleDepartments,
		DefaultHours: s.DefaultHours, MaxHours: s.MaxHours, UpdatedBy: &uid, UpdatedAt: now}
	if err := tx.PutCatalogItem(it); err != nil {
		return nil, err
	}
	detail := ojson.Object{{Key: "catalog_item_id", Value: id},
		{Key: "group_id", Value: g.ID}, {Key: "group", Value: g.System + ":" + g.Name},
		{Key: "requestable", Value: s.Requestable}, {Key: "risk", Value: s.Risk}}
	if s.Populations != nil {
		pops := slices.Clone(s.Populations)
		slices.Sort(pops)
		pops = slices.Compact(pops)
		if err := tx.SetCatalogPopulations(id, pops); err != nil {
			return nil, err
		}
		detail = append(detail, ojson.KV{Key: "populations", Value: pops})
	}
	if err := tx.Audit(now, by.Display, "catalog.item.put", detail); err != nil {
		return nil, err
	}
	return tx.CatalogItem(id)
}

func hoursOK(h *float64) bool { return h == nil || (*h > 0 && *h <= MaxHours) }

// ---------------------------------------------------------------- submit

// Submission is a cart.
type Submission struct {
	Beneficiaries []int64
	Items         []string // catalog item ids
	Justification string
	DurationHours *float64 // nil: each item's default, then the tenant's
	Attachments   []string // references, only if the tenant's settings allow them
	// Answers are the answers to the questionnaires the items ask (questionnaire id ->
	// question id -> value); Submit validates them against the version in force.
	Answers map[string]map[string]any
}

// Submit files one pending line per beneficiary and item, or none.
// forOthers is whether the actor holds requests.create_for_others; the tenant's
// request settings (justification, durations, attachments, request for others)
// are enforced here, so no client can bypass them.
func Submit(tx *store.TenantTx, s Submission, by Actor, forOthers bool, now time.Time) (string, []*store.RequestLine, error) {
	just := strings.TrimSpace(s.Justification)
	set, _, err := LoadSettings(tx)
	if err != nil {
		return "", nil, err
	}
	switch {
	case len(s.Beneficiaries) == 0 || len(s.Items) == 0:
		return "", nil, refuse(422, "empty_request", "name at least one person and one item")
	case len(s.Beneficiaries)*len(s.Items) > MaxLines:
		return "", nil, refuse(422, "too_many_lines", "at most %d person-item pairs per request", MaxLines)
	case !hoursOK(s.DurationHours):
		return "", nil, refuse(422, "invalid_duration", "durations are between 0 and %d hours", MaxHours)
	}
	if err := set.checkJustification(just); err != nil {
		return "", nil, err
	}
	attachments, err := set.checkAttachments(s.Attachments)
	if err != nil {
		return "", nil, err
	}
	batch := uuid.NewString()
	seen := map[[2]string]bool{}
	var lines []*store.RequestLine
	for _, bid := range s.Beneficiaries {
		ben, err := tx.Identity(bid)
		if errors.Is(err, store.ErrNotFound) {
			return "", nil, refuse(404, "beneficiary_not_found", "person not found")
		} else if err != nil {
			return "", nil, err
		}
		if err := set.checkForOthers(ben, by, forOthers); err != nil {
			return "", nil, err
		}
		// the beneficiary's organization can tighten the tenant's settings (issue #298)
		bset, err := set.forBeneficiary(tx, ben)
		if err != nil {
			return "", nil, err
		}
		if err := bset.checkJustification(just); err != nil {
			return "", nil, err
		}
		if ben.Status != "active" {
			return "", nil, refuse(409, "beneficiary_not_active", "%s is not active", ben.Name)
		}
		for _, iid := range s.Items {
			k := [2]string{fmt.Sprint(ben.ID), iid}
			if seen[k] {
				continue
			}
			seen[k] = true
			l, err := line(tx, batch, ben, iid, s.DurationHours, just, by, bset, now)
			if err != nil {
				return "", nil, err
			}
			lines = append(lines, l)
		}
	}
	plans := map[string]*workflow.Plan{} // by line: the path a workflow selects (issue #298); none: the item's policy
	for _, l := range lines {
		ben, err := tx.Identity(l.BeneficiaryID)
		if err != nil {
			return "", nil, err
		}
		if plans[l.ID], err = planLine(tx, l, ben); err != nil {
			return "", nil, err
		}
	}
	checked, perLine, err := checkAnswers(tx, lines, plans, s.Answers)
	if err != nil {
		return "", nil, err
	}
	for _, l := range lines {
		if err := tx.InsertRequestLine(l); err != nil {
			return "", nil, err
		}
		if err := questionnaires.Record(tx, store.QSubjectRequestLine, l.ID, forItem(checked, perLine[l.ID]), by.Display, now); err != nil {
			return "", nil, err
		}
		ben, err := tx.Identity(l.BeneficiaryID)
		if err != nil {
			return "", nil, err
		}
		if err := startStages(tx, l, ben, plans[l.ID], now); err != nil {
			return "", nil, err
		}
		if err := event(tx, l.ID, "submitted", by, nil, now); err != nil {
			return "", nil, err
		}
		if err := notifyWaiting(tx, l, now); err != nil {
			return "", nil, err
		}
	}
	ids := make([]string, len(lines))
	for i, l := range lines {
		ids[i] = l.ID
	}
	detail := ojson.Object{{Key: "batch_id", Value: batch}, {Key: "lines", Value: ids}, {Key: "justification", Value: just}}
	if len(attachments) > 0 {
		detail = append(detail, ojson.KV{Key: "attachments", Value: attachments})
	}
	if len(checked) > 0 {
		detail = append(detail, ojson.KV{Key: "questionnaires", Value: questionnaires.AuditDetail(checked)})
	}
	if err := tx.Audit(now, by.Display, "request.submit", detail); err != nil {
		return "", nil, err
	}
	return batch, lines, nil
}

// attributeEligible applies the attribute policy bound to the item (issue
// #162), on top of the type and department lists: the beneficiary's
// attributes, the item's and the request context must satisfy its condition.
// A missing attribute, or a policy that cannot be read, denies.
func attributeEligible(tx *store.TenantTx, it *store.CatalogItem, g *store.Group, ben *store.Identity, by Actor,
	now time.Time) error {
	b, err := tx.AbacBinding(store.BindCatalogItem, it.ID)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	} else if err != nil {
		return err
	}
	p, err := tx.AbacPolicy(b.PolicyID)
	if err != nil {
		return err
	}
	cond, err := abac.Condition(p)
	if err != nil || p.Status != store.AbacActive {
		return refuse(409, "not_eligible", "%s is not eligible for %s (attribute policy %s cannot be evaluated)", ben.Name,
			g.System+":"+g.Name, p.Name)
	}
	resolver, err := abac.NewResolver(tx, now)
	if err != nil {
		return err
	}
	attrs := abac.Merge(resolver.Identity(ben), abac.ContextAttrs(now, by.AAL), abac.ItemAttrs(it, g))
	if !abac.Eval(cond, attrs) {
		return refuse(409, "not_eligible", "%s is not eligible for %s (attribute policy %s)", ben.Name, g.System+":"+g.Name, p.Name)
	}
	return nil
}

func line(tx *store.TenantTx, batch string, ben *store.Identity, itemID string, hours *float64, just string, by Actor,
	set Settings, now time.Time) (*store.RequestLine, error) {
	it, err := tx.CatalogItem(itemID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(404, "item_not_found", "catalog item not found")
	} else if err != nil {
		return nil, err
	}
	g, err := tx.Group(it.GroupID)
	if err != nil {
		return nil, err
	}
	name := g.System + ":" + g.Name
	switch {
	case !it.Requestable:
		return nil, refuse(409, "not_requestable", "%s cannot be requested", name)
	case len(it.EligibleTypes) > 0 && !slices.Contains(it.EligibleTypes, ben.Type):
		return nil, refuse(409, "not_eligible", "%s is not eligible for %s", ben.Name, name)
	case len(it.EligibleDepartments) > 0 && (ben.Department == nil || !slices.Contains(it.EligibleDepartments, *ben.Department)):
		return nil, refuse(409, "not_eligible", "%s is not eligible for %s (department)", ben.Name, name)
	}
	if err := guestChecks(tx, ben, it, g); err != nil {
		return nil, err
	}
	if err := attributeEligible(tx, it, g, ben, by, now); err != nil {
		return nil, err
	}
	if hours == nil {
		hours = it.DefaultHours
	}
	if hours == nil {
		hours = set.DefaultHours
	}
	if err := set.checkDuration(hours, name); err != nil {
		return nil, err
	}
	switch {
	case hours == nil && (g.Privileged || it.MaxHours != nil):
		return nil, refuse(422, "duration_required", "%s needs a duration", name)
	case hours != nil && it.MaxHours != nil && *hours > *it.MaxHours:
		return nil, refuse(422, "duration_too_long", "%s allows at most %g hours", name, *it.MaxHours)
	}
	acct, err := jit.AccountFor(tx, ben.ID, g)
	var je *jit.Error
	if errors.As(err, &je) {
		return nil, refuse(409, "no_account", "%s has no active account that can receive %s", ben.Name, name)
	} else if err != nil {
		return nil, err
	}
	if has, err := holds(tx, acct.ID, g.ID, now); err != nil {
		return nil, err
	} else if has {
		return nil, refuse(409, "already_has_access", "%s already has %s", ben.Name, name)
	}
	if _, err := tx.OpenRequestLine(ben.ID, g.ID); err == nil {
		return nil, refuse(409, "already_requested", "%s already has an open request for %s", ben.Name, name)
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	return &store.RequestLine{ID: uuid.NewString(), BatchID: batch, CatalogItemID: it.ID, GroupID: g.ID,
		BeneficiaryID: ben.ID, AccountID: acct.ID, RequestedBy: by.id(), Justification: just, DurationHours: hours,
		Status: store.RequestPending, RequestedAt: now}, nil
}

// holds reports a live direct grant from the account to the group.
func holds(tx *store.TenantTx, acct, group int64, now time.Time) (bool, error) {
	e, err := tx.EdgeBetween(graph.Key("account", acct), graph.Key("group", group))
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return e.ExpiresAt == nil || e.ExpiresAt.After(now), nil
}

func event(tx *store.TenantTx, lineID, ev string, by Actor, note *string, now time.Time) error {
	e := &store.RequestEvent{LineID: lineID, Event: ev, Actor: by.Display, Note: note, At: now}
	if by.UserID != uuid.Nil {
		id := by.id()
		e.ActorUserID = &id
	}
	return tx.AddRequestEvent(e)
}

// ---------------------------------------------------------------- decisions

func get(tx *store.TenantTx, id string) (*store.RequestLine, error) {
	l, err := tx.RequestLine(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(404, "request_not_found", "request not found")
	}
	return l, err
}

func reasonPtr(reason string, required bool) (*string, error) {
	r := strings.TrimSpace(reason)
	if len(r) > MaxReason || (required && r == "") {
		return nil, refuse(422, "reason_required", "a reason of 1 to %d characters is required", MaxReason)
	}
	if r == "" {
		return nil, nil
	}
	return &r, nil
}

// Approve grants a pending line.
func Approve(tx *store.TenantTx, id string, by Actor, reason string, now time.Time) (*store.RequestLine, error) {
	l, err := get(tx, id)
	if err != nil {
		return nil, err
	}
	r, err := reasonPtr(reason, false)
	if err != nil {
		return nil, err
	}
	said := r // what the approver wrote, for the notification
	auth, err := authorize(tx, l, by, now)
	if err != nil {
		return nil, err
	}
	// the person or account may have changed since the request (a leaver)
	if ben, err := tx.Identity(l.BeneficiaryID); err != nil {
		return nil, err
	} else if ben.Status != "active" {
		return nil, refuse(409, "beneficiary_not_active", "%s is no longer active; deny the request", ben.Name)
	}
	if acct, err := tx.Account(l.AccountID); err != nil {
		return nil, err
	} else if acct.Status != "active" {
		return nil, refuse(409, "account_not_active", "the receiving account is no longer active; deny the request")
	}
	if has, err := holds(tx, l.AccountID, l.GroupID, now); err != nil {
		return nil, err
	} else if has {
		return nil, refuse(409, "already_has_access", "the person already has this access; deny the request")
	}
	if auth.Stage != nil {
		stages, err := tx.RequestStages(l.ID)
		if err != nil {
			return nil, err
		}
		more, err := approveStage(tx, l, auth, by, r, now)
		if err != nil {
			return nil, err
		}
		note := stageNote(auth, len(stages), r)
		if more { // the next stage decides; nothing is granted yet
			if err := event(tx, l.ID, "approved", by, note, now); err != nil {
				return nil, err
			}
			if err := afterStage(tx, l, auth.Stage.Idx, false, by, now); err != nil {
				return nil, err
			}
			if err := notifyWaiting(tx, l, now); err != nil { // the next stage's approvers
				return nil, err
			}
			return l, tx.Audit(now, by.Display, "request.stage.approve", stageDetail(l, auth, r))
		}
		r = note
	}
	src, dst := graph.Key("account", l.AccountID), graph.Key("group", l.GroupID)
	if old, err := tx.EdgeBetween(src, dst); err == nil { // an expired grant: replace it
		if err := tx.DeleteEdge(old.ID, now); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	var exp *time.Time
	if l.DurationHours != nil {
		t := now.Add(timeutil.Delta(*l.DurationHours, timeutil.MicrosPerHour))
		exp = &t
	}
	edge, err := tx.InsertEdge(&store.GrantEdge{Src: src, Dst: dst, Relation: "member_of", Source: "request",
		ExpiresAt: exp, CreatedAt: now, Ref: "line:" + l.ID})
	if err != nil {
		return nil, err
	}
	uid := by.id()
	l.Status, l.DecidedBy, l.DecidedAt, l.DecisionReason, l.EdgeID, l.ExpiresAt = store.RequestApproved, &uid, &now, r, &edge, exp
	if err := tx.SaveRequestLine(l, store.RequestPending); err != nil {
		return nil, err
	}
	if err := event(tx, l.ID, "approved", by, r, now); err != nil {
		return nil, err
	}
	if auth.Stage != nil {
		if err := afterStage(tx, l, auth.Stage.Idx, true, by, now); err != nil {
			return nil, err
		}
	}
	if err := notify.RequestDecided(tx, now, l, true, uid, said); err != nil {
		return nil, err
	}
	return l, tx.Audit(now, by.Display, "request.approve", lineDetail(l, r))
}

// Deny rejects a pending line; a reason is required.
func Deny(tx *store.TenantTx, id string, by Actor, reason string, now time.Time) (*store.RequestLine, error) {
	l, err := get(tx, id)
	if err != nil {
		return nil, err
	}
	r, err := reasonPtr(reason, true)
	if err != nil {
		return nil, err
	}
	said := r
	auth, err := authorize(tx, l, by, now)
	if err != nil {
		return nil, err
	}
	if auth.Stage != nil {
		st, uid := auth.Stage, by.id()
		st.Status, st.DecidedBy, st.OnBehalfOf, st.DecidedAt, st.Reason = store.StageDenied, &uid, auth.OnBehalfOf, &now, r
		if err := tx.SaveRequestStage(st, store.StageWaiting); err != nil {
			return nil, err
		}
		if err := tx.CloseOpenStages(l.ID); err != nil {
			return nil, err
		}
		stages, err := tx.RequestStages(l.ID)
		if err != nil {
			return nil, err
		}
		r = stageNote(auth, len(stages), r)
	}
	uid := by.id()
	l.Status, l.DecidedBy, l.DecidedAt, l.DecisionReason, l.ClosedAt = store.RequestDenied, &uid, &now, r, &now
	if err := tx.SaveRequestLine(l, store.RequestPending); err != nil {
		return nil, err
	}
	if err := event(tx, l.ID, "denied", by, r, now); err != nil {
		return nil, err
	}
	if err := finishRun(tx, l, store.WFRunDenied, now); err != nil {
		return nil, err
	}
	if err := notify.RequestDecided(tx, now, l, false, uid, said); err != nil {
		return nil, err
	}
	return l, tx.Audit(now, by.Display, "request.deny", lineDetail(l, r))
}

// Cancel withdraws a pending line; only its requester may.
func Cancel(tx *store.TenantTx, id string, by Actor, now time.Time) (*store.RequestLine, error) {
	l, err := get(tx, id)
	if err != nil {
		return nil, err
	}
	if l.RequestedBy != by.id() {
		return nil, refuse(404, "request_not_found", "request not found") // others' lines are not theirs to see here
	}
	if l.Status != store.RequestPending {
		return nil, refuse(409, "not_pending", "the request is %s", l.Status)
	}
	l.Status, l.ClosedAt = store.RequestCancelled, &now
	if err := tx.SaveRequestLine(l, store.RequestPending); err != nil {
		return nil, err
	}
	if err := tx.CloseOpenStages(l.ID); err != nil {
		return nil, err
	}
	if err := event(tx, l.ID, "cancelled", by, nil, now); err != nil {
		return nil, err
	}
	if err := finishRun(tx, l, store.WFRunCancelled, now); err != nil {
		return nil, err
	}
	return l, tx.Audit(now, by.Display, "request.cancel", lineDetail(l, nil))
}

// Remove ends an approved line's access early. decider is true for holders
// of requests.decide; anyone else may remove only their own access.
func Remove(tx *store.TenantTx, id string, by Actor, decider bool, reason string, now time.Time) (*store.RequestLine, error) {
	l, err := get(tx, id)
	if err != nil {
		return nil, err
	}
	own := by.IdentityID != nil && *by.IdentityID == l.BeneficiaryID
	if !decider && !own {
		return nil, refuse(403, "forbidden", "you can remove only your own access")
	}
	r, err := reasonPtr(reason, false)
	if err != nil {
		return nil, err
	}
	if l.Status != store.RequestApproved {
		return nil, refuse(409, "not_active", "the request is %s", l.Status)
	}
	if l.EdgeID != nil {
		if err := tx.DeleteRequestEdge(*l.EdgeID); err != nil {
			return nil, err
		}
	}
	l.Status, l.ClosedAt = store.RequestRemoved, &now
	if err := tx.SaveRequestLine(l, store.RequestApproved); err != nil {
		return nil, err
	}
	if err := event(tx, l.ID, "removed", by, r, now); err != nil {
		return nil, err
	}
	return l, tx.Audit(now, by.Display, "request.remove", lineDetail(l, r))
}

func stageDetail(l *store.RequestLine, a *Authority, reason *string) ojson.Object {
	d := ojson.Object{{Key: "request_id", Value: l.ID}, {Key: "stage", Value: a.Stage.Idx}, {Key: "kind", Value: a.Stage.Kind},
		{Key: "escalated", Value: a.Escalated}}
	if a.OnBehalfOf != nil {
		d = append(d, ojson.KV{Key: "on_behalf_of", Value: *a.OnBehalfOf})
	}
	if reason != nil {
		d = append(d, ojson.KV{Key: "reason", Value: *reason})
	}
	return d
}

func lineDetail(l *store.RequestLine, reason *string) ojson.Object {
	d := ojson.Object{{Key: "request_id", Value: l.ID}, {Key: "batch_id", Value: l.BatchID},
		{Key: "group_id", Value: l.GroupID}, {Key: "beneficiary_id", Value: l.BeneficiaryID}, {Key: "status", Value: l.Status}}
	if l.ExpiresAt != nil {
		d = append(d, ojson.KV{Key: "expires_at", Value: timeutil.ISO(*l.ExpiresAt)})
	}
	if reason != nil {
		d = append(d, ojson.KV{Key: "reason", Value: *reason})
	}
	return d
}

// ---------------------------------------------------------------- sweep

// Sweeper is the actor of sweep events.
const Sweeper = "requests.sweeper"

// NeedsSweep reports whether Sweep would change anything at now.
func NeedsSweep(tx *store.TenantTx, now time.Time) (bool, error) {
	n, err := tx.CountDueRequestLines(now)
	return n > 0, err
}

// Sweep closes approved lines that expired (removing their grant) or whose
// grant was removed elsewhere, for example by an access review or a revoke.
func Sweep(tx *store.TenantTx, now time.Time) (int, error) {
	due, err := tx.DueRequestLines(now)
	if err != nil {
		return 0, err
	}
	by := Actor{Display: Sweeper}
	for _, l := range due {
		status, ev, note := store.RequestExpired, "expired", (*string)(nil)
		if l.ExpiresAt == nil || l.ExpiresAt.After(now) {
			n := "the grant was removed outside the request"
			status, ev, note = store.RequestRemoved, "removed", &n
		} else if l.EdgeID != nil {
			if err := tx.DeleteRequestEdge(*l.EdgeID); err != nil {
				return 0, err
			}
		}
		l.Status, l.ClosedAt = status, &now
		if err := tx.SaveRequestLine(l, store.RequestApproved); err != nil {
			return 0, err
		}
		if err := event(tx, l.ID, ev, by, note, now); err != nil {
			return 0, err
		}
		if err := tx.Audit(now, Sweeper, "request."+ev, lineDetail(l, note)); err != nil {
			return 0, err
		}
	}
	return len(due), nil
}

// SweepAll runs Sweep for every active tenant in its own transaction (the
// background sweeper); a tenant with nothing due is left untouched.
func SweepAll(ctx context.Context, db *store.DB, now time.Time) error {
	return db.ForEachActiveTenant(ctx, func(_ context.Context, tx *store.TenantTx) error {
		need, err := NeedsSweep(tx, now)
		if err != nil || !need {
			return err
		}
		_, err = Sweep(tx, now)
		return err
	})
}
