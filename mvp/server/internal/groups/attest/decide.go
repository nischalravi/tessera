package attest

import (
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/gov"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/privs"
	"github.com/nischalravi/tessera/mvp/server/internal/reviews"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// CampaignView is a campaign as the API shows it.
type CampaignView struct {
	ID               string     `json:"id"`
	GroupID          string     `json:"group_id"`
	GroupName        string     `json:"group_name,omitempty"`
	Kind             string     `json:"kind"`
	Status           string     `json:"status"`
	StartedAt        time.Time  `json:"started_at"`
	DueAt            time.Time  `json:"due_at"`
	ClosedAt         *time.Time `json:"closed_at,omitempty"`
	OverdueAction    string     `json:"overdue_action"`
	Reviewers        string     `json:"reviewers"`
	ReviewerGroup    string     `json:"reviewer_group,omitempty"`
	ReminderDays     []int      `json:"reminder_days"`
	PopulationCount  int        `json:"population_count"`
	PopulationHash   string     `json:"population_hash"`
	ReviewCampaignID *int64     `json:"review_campaign_id,omitempty"`
	RemindersSent    int        `json:"reminders_sent"`
	Counts           *Counts    `json:"counts,omitempty"`
}

// Counts are the progress of a campaign.
type Counts struct {
	Total   int `json:"total"`
	Keep    int `json:"keep"`
	Revoke  int `json:"revoke"`
	Pending int `json:"pending"` // undecided
	Applied int `json:"applied"` // revocations carried out
}

// ItemView is one identity of a campaign with its decision and the usage context.
type ItemView struct {
	ID           string          `json:"id"`
	Identity     int64           `json:"identity_id"`
	IdentityName string          `json:"identity_name,omitempty"`
	How          string          `json:"how"`
	ReviewItemID *int64          `json:"review_item_id,omitempty"`
	Reasons      []string        `json:"reasons"`
	Context      json.RawMessage `json:"context,omitempty"`
	Decision     *string         `json:"decision"`
	Comment      *string         `json:"comment,omitempty"`
	DecidedAt    *time.Time      `json:"decided_at,omitempty"`
	ApplyState   string          `json:"apply_state"`
	ApplyDetail  string          `json:"apply_detail,omitempty"`
}

// ViewOf renders a campaign (without counts).
func ViewOf(c *store.GrpAttestCampaign) CampaignView {
	var days []int
	_ = json.Unmarshal([]byte(c.ReminderDays), &days) // written by Put from []int
	if days == nil {
		days = []int{}
	}
	v := CampaignView{ID: c.ID, GroupID: string(c.GroupID), Kind: c.Kind, Status: c.Status, StartedAt: c.StartedAt, DueAt: c.DueAt,
		ClosedAt: c.ClosedAt, OverdueAction: c.OverdueAction, Reviewers: c.ReviewerType, ReminderDays: days,
		PopulationCount: c.PopulationCount, PopulationHash: c.PopulationHash, ReviewCampaignID: c.ReviewCampaign, RemindersSent: c.RemindersSent}
	if c.ReviewerGroup != nil {
		v.ReviewerGroup = string(*c.ReviewerGroup)
	}
	return v
}

// Detail returns a campaign with its progress and all its items.
func Detail(tx *store.TenantTx, id string) (*CampaignView, []ItemView, error) {
	c, err := tx.GrpAttestCampaign(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil, gov.NotFound("no such attestation")
	}
	if err != nil {
		return nil, nil, err
	}
	v := ViewOf(c)
	if g, err := tx.GrpGroup(c.GroupID); err == nil {
		v.GroupName = g.Name
	}
	items, err := tx.GrpAttestItems(c.ID)
	if err != nil {
		return nil, nil, err
	}
	reviewItems := map[int64]*store.ReviewItem{}
	if c.ReviewCampaign != nil {
		ris, err := tx.CampaignItems(*c.ReviewCampaign)
		if err != nil {
			return nil, nil, err
		}
		for _, ri := range ris {
			reviewItems[ri.ID] = ri
		}
	}
	people, _, err := tx.IdentityMap()
	if err != nil {
		return nil, nil, err
	}
	counts := Counts{Total: len(items)}
	out := make([]ItemView, 0, len(items))
	for _, it := range items {
		iv := ItemView{ID: it.ID, Identity: it.Identity, How: it.How, ReviewItemID: it.ReviewItem, Reasons: []string{},
			ApplyState: it.ApplyState, ApplyDetail: it.ApplyDetail}
		if p := people[it.Identity]; p != nil {
			iv.IdentityName = p.Name
		}
		if it.ReviewItem != nil {
			if ri := reviewItems[*it.ReviewItem]; ri != nil {
				iv.Reasons, iv.Context, iv.Decision, iv.Comment, iv.DecidedAt = ri.Reasons, ri.Context, ri.Decision, ri.Comment, ri.DecidedAt
			}
		}
		switch {
		case iv.Decision == nil:
			counts.Pending++
		case *iv.Decision == "keep":
			counts.Keep++
		default:
			counts.Revoke++
		}
		if it.ApplyState == store.ApplyApplied {
			counts.Applied++
		}
		out = append(out, iv)
	}
	v.Counts = &counts
	return &v, out, nil
}

// Campaign returns a campaign with its items to a reviewer: someone who administers
// the group or is in the reviewer group (403 for anyone else). verified says the
// stored items still match the count and hash frozen when it started.
func Campaign(e Env, id string) (v *CampaignView, items []ItemView, verified bool, err error) {
	c, err := e.Tx.GrpAttestCampaign(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil, false, gov.NotFound("no such attestation")
	}
	if err != nil {
		return nil, nil, false, err
	}
	if ok, err := e.isReviewer(e.Checker, c); err != nil {
		return nil, nil, false, err
	} else if !ok {
		return nil, nil, false, &privs.DeniedError{Object: privs.GroupObject(c.GroupID), Privilege: privs.Admin}
	}
	if v, items, err = Detail(e.Tx, id); err != nil {
		return nil, nil, false, err
	}
	verified, err = Verify(e.Tx, id)
	return v, items, verified, err
}

// isReviewer reports whether the checker's subject may decide the campaign's
// items: it administers the group, or is a member of the reviewer group.
func (e Env) isReviewer(ck *privs.Checker, c *store.GrpAttestCampaign) (bool, error) {
	if ok, err := ck.Has(privs.GroupObject(c.GroupID), privs.Admin); err != nil || ok {
		return ok, err
	}
	if c.ReviewerType == store.ReviewersGroup && c.ReviewerGroup != nil && ck.Subject().Identity != nil {
		return e.eng().IsMember(e.Tx, e.Now, *c.ReviewerGroup, store.MembersListID(e.Tx.Tenant()), *ck.Subject().Identity)
	}
	return false, nil
}

// Reviewer reports whether the checker's subject may see and decide a campaign.
func Reviewer(e Env, c *store.GrpAttestCampaign) (bool, error) { return e.isReviewer(e.Checker, c) }

// Decide records keep or revoke on one identity of an open campaign, as the
// platform user ur. A revoke is carried out at once, through the membership
// engine with the deciding user's privileges, and read back; a nested member
// (one the group has through another group) cannot be removed here and is
// reported as such.
func Decide(e Env, ur store.UserRef, campaignID, itemID, decision string, comment *string) (*ItemView, error) {
	if decision != "keep" && decision != "revoke" {
		return nil, gov.Invalid("invalid_decision", "decision is keep or revoke")
	}
	c, err := e.Tx.GrpAttestCampaign(campaignID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, gov.NotFound("no such attestation")
	}
	if err != nil {
		return nil, err
	}
	// a caller who may not decide learns nothing about the campaign
	if ok, err := e.isReviewer(e.Checker, c); err != nil {
		return nil, err
	} else if !ok {
		return nil, &privs.DeniedError{Object: privs.GroupObject(c.GroupID), Privilege: privs.Admin}
	}
	if c.Status != store.AttestOpen {
		return nil, gov.Conflict("attestation_closed", "this attestation is %s", c.Status)
	}
	it, err := e.Tx.GrpAttestItem(itemID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && it.CampaignID != c.ID) {
		return nil, gov.NotFound("no such item in this attestation")
	}
	if err != nil {
		return nil, err
	}
	if it.ReviewItem == nil {
		return nil, gov.Conflict("item_unavailable", "the item has no review item")
	}
	ri, err := e.Tx.Item(*it.ReviewItem)
	if err != nil {
		return nil, err
	}
	if ri.Decision != nil && *ri.Decision != "" {
		return nil, gov.Conflict("already_decided", "this item was decided: %s", *ri.Decision)
	}
	if _, err := reviews.Decide(e.Tx, e.Now, ri.ID, decision, ur, comment); err != nil {
		switch {
		case errors.Is(err, reviews.ErrSelfReview):
			return nil, gov.Forbidden("self_review", "You cannot decide an item about your own access; another reviewer must decide it.")
		case errors.Is(err, reviews.ErrReviewerUnlinked):
			return nil, gov.Forbidden("reviewer_unlinked", "Your account is not linked to an identity, so it cannot decide reviews. Ask an administrator to link it.")
		}
		var re *reviews.Error
		if errors.As(err, &re) {
			return nil, gov.Invalid("invalid_decision", "%s", re.Msg)
		}
		return nil, err
	}
	if decision == "keep" {
		if err := e.Tx.SetGrpAttestItemApplied(it.ID, store.ApplySkipped, "kept", e.Now); err != nil {
			return nil, err
		}
	} else if err := e.applyRevoke(e.Checker, e.By, c, it); err != nil {
		return nil, err
	}
	if err := e.finishIfDone(c); err != nil {
		return nil, err
	}
	_, items, err := Detail(e.Tx, c.ID)
	if err != nil {
		return nil, err
	}
	for i := range items {
		if items[i].ID == it.ID {
			return &items[i], nil
		}
	}
	return nil, gov.NotFound("no such item in this attestation")
}

// finishIfDone completes an open campaign when every item is decided and carried out.
func (e Env) finishIfDone(c *store.GrpAttestCampaign) error {
	if c.Status != store.AttestOpen {
		return nil
	}
	items, err := e.Tx.GrpAttestItems(c.ID)
	if err != nil {
		return err
	}
	for _, it := range items {
		if it.ApplyState == store.ApplyPending {
			return nil
		}
	}
	return e.complete(c, store.AttestCompleted, map[string]any{"items": len(items)})
}

// applyRevoke carries out a revoke decision: it removes the identity's direct
// membership as the subject of ck (who must hold update on the group), and
// reads the membership back before it records the item as applied. by is the
// platform user the change is attributed to.
func (e Env) applyRevoke(ck *privs.Checker, by string, c *store.GrpAttestCampaign, it *store.GrpAttestItem) error {
	set := func(state, detail string) error {
		return e.Tx.SetGrpAttestItemApplied(it.ID, state, detail, e.Now)
	}
	if it.How == "nested" {
		return set(store.ApplySkipped, "nested: remove the identity from the group it is nested through")
	}
	if ok, err := ck.Has(privs.GroupObject(it.GroupID), privs.Update); err != nil {
		return err
	} else if !ok {
		return set(store.ApplyDenied, "privilege_required: update on the group")
	}
	me := e.model()
	me.By = nil
	if by != "" {
		me.By = &by
	}
	me.ByIdentity, me.TenantAdmin = ck.Subject().Identity, ck.Subject().TenantAdmin
	if me.CauseRef == "" {
		me.CauseRef = "attestation:" + c.ID
	}
	out, err := me.RemoveMember(it.GroupID, strconv.FormatInt(it.Identity, 10))
	var mErr *model.Error
	switch {
	case errors.As(err, &mErr) && mErr.Kind == model.NotFound:
		return set(store.ApplySkipped, "already_removed")
	case errors.As(err, &mErr):
		return set(store.ApplyFailed, mErr.Code)
	case err != nil:
		return err
	}
	// read it back: the direct row is gone, and say whether the identity is still a member another way
	list := store.MembersListID(e.Tx.Tenant())
	if _, err := e.Tx.GrpDirectFind(it.GroupID, list, store.MemberIdentity, strconv.FormatInt(it.Identity, 10)); err == nil {
		return set(store.ApplyFailed, "the membership is still there after the removal")
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	detail := "removed"
	switch still, err := e.eng().IsMember(e.Tx, e.Now, it.GroupID, list, it.Identity); {
	case err != nil:
		return err
	case out.Queued:
		detail = "removed; the group's recompute is queued"
	case still:
		detail = "removed; still a member through another group"
	}
	return set(store.ApplyApplied, detail)
}
