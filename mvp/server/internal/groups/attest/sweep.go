package attest

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/engine"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/events"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/gov"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/inbox"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/privs"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Summary is what one pass did.
type Summary struct {
	Started   int
	Reminded  int
	Completed int
	Overdue   int // campaigns whose overdue action was applied or reported
}

// jobEnv is the context of a background pass for one campaign.
func jobEnv(tx *store.TenantTx, now time.Time, eng *engine.Engine, c *store.GrpAttestCampaign) Env {
	return Env{Tx: tx, Now: now, Engine: eng, Cause: store.CauseEngine, CauseRef: "attestation:" + c.ID}
}

// subjectOf is the privilege subject a campaign's overdue action acts as: the
// user who saved the settings, with what they hold now.
func subjectOf(tx *store.TenantTx, userID string, now time.Time) (privs.Subject, string, error) {
	s, err := privs.SubjectOfUser(tx, userID, now)
	if errors.Is(err, privs.ErrNoUser) {
		return privs.Subject{}, "author_unavailable", nil
	}
	return s, "", err
}

// Sweep moves every open campaign along: it carries out the revocations that
// were decided elsewhere (through the review API), sends reminders, completes a
// campaign whose items are all decided, and applies the overdue action of one
// whose window has ended.
func Sweep(tx *store.TenantTx, now time.Time, eng *engine.Engine, log *slog.Logger) (Summary, error) {
	var sum Summary
	if log == nil {
		log = slog.Default()
	}
	open, err := tx.GrpAttestCampaigns(store.GrpAttestFilter{Status: store.AttestOpen, Limit: 1000})
	if err != nil {
		return sum, err
	}
	for _, c := range open {
		e := jobEnv(tx, now, eng, c)
		g, err := tx.GrpGroup(c.GroupID)
		if err != nil {
			return sum, err
		}
		if g.Status == store.GroupDeleted {
			// the group is gone: so is the question
			if err := e.complete(c, store.AttestCancelled, map[string]any{"reason": "group_deleted"}); err != nil {
				return sum, err
			}
			continue
		}
		if err := e.applyDecided(c); err != nil {
			return sum, err
		}
		if err := e.finishIfDone(c); err != nil {
			return sum, err
		}
		if c.Status != store.AttestOpen {
			sum.Completed++
			continue
		}
		if n, err := e.remind(c); err != nil {
			return sum, err
		} else if n {
			sum.Reminded++
		}
		if now.After(c.DueAt) {
			did, err := e.overdue(c, g, log)
			if err != nil {
				return sum, err
			}
			if did {
				sum.Overdue++
			}
		}
	}
	return sum, nil
}

// applyDecided carries out the decisions that were recorded without going
// through Decide (the review API decides the same items). A revoke is applied
// with the privileges of the user who decided it, now.
func (e Env) applyDecided(c *store.GrpAttestCampaign) error {
	items, err := e.Tx.GrpAttestItems(c.ID)
	if err != nil {
		return err
	}
	for _, it := range items {
		if it.ApplyState != store.ApplyPending || it.ReviewItem == nil {
			continue
		}
		ri, err := e.Tx.Item(*it.ReviewItem)
		if err != nil {
			return err
		}
		switch {
		case ri.Decision == nil || *ri.Decision == "":
			continue
		case *ri.Decision == "keep":
			err = e.Tx.SetGrpAttestItemApplied(it.ID, store.ApplySkipped, "kept", e.Now)
		default:
			if ri.DecidedByUserID == nil {
				err = e.Tx.SetGrpAttestItemApplied(it.ID, store.ApplyDenied, "the decider is unknown", e.Now)
				break
			}
			by := ri.DecidedByUserID.String()
			sub, why, serr := subjectOf(e.Tx, by, e.Now)
			if serr != nil {
				return serr
			}
			if why != "" {
				err = e.Tx.SetGrpAttestItemApplied(it.ID, store.ApplyDenied, why, e.Now)
				break
			}
			ck := privs.NewChecker(e.Tx, e.Now, e.eng(), sub)
			if ok, rerr := e.isReviewer(ck, c); rerr != nil {
				return rerr
			} else if !ok {
				err = e.Tx.SetGrpAttestItemApplied(it.ID, store.ApplyDenied, "the decider is not a reviewer of this group", e.Now)
				break
			}
			err = e.applyRevoke(ck, by, c, it)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// remind records the reminders that have come due, once each.
func (e Env) remind(c *store.GrpAttestCampaign) (bool, error) {
	var days []int
	if err := json.Unmarshal([]byte(c.ReminderDays), &days); err != nil {
		return false, err
	}
	passed := 0
	for _, d := range days {
		if !e.Now.Before(c.DueAt.AddDate(0, 0, -d)) {
			passed++
		}
	}
	if passed <= c.RemindersSent {
		return false, nil
	}
	c.RemindersSent, c.LastReminderAt = passed, &e.Now
	if err := e.Tx.SaveGrpAttestCampaign(c); err != nil {
		return false, err
	}
	if err := e.emit(events.AttestationDue, c, map[string]any{"reminder": passed, "due_at": c.DueAt.UTC().Format(time.RFC3339)}); err != nil {
		return false, err
	}
	return true, e.audit("groups.attestation.reminder", c, ojson.KV{Key: "reminder", Value: passed})
}

// overdueTask asks the group's admins to deal with a campaign whose overdue
// action could not be applied, or is none.
func (e Env) overdueTask(g *store.NativeGroup, c *store.GrpAttestCampaign, reason string) (bool, error) {
	_, created, err := inbox.Open(e.Tx, e.Now, inbox.Input{Kind: store.TaskAttestationOverdue, Title: "Attestation of " + g.Name + " is overdue",
		Detail: map[string]any{"campaign": c.ID, "group": string(g.ID), "reason": reason}, ObjectType: store.RuleOwnerGroup, ObjectID: string(g.ID),
		DedupeKey: "attest-overdue:" + c.ID})
	return created, err
}

// overdue applies a campaign's overdue action once its due date has passed. It
// reports whether it did something this pass.
func (e Env) overdue(c *store.GrpAttestCampaign, g *store.NativeGroup, log *slog.Logger) (bool, error) {
	pending, err := e.undecided(c)
	if err != nil {
		return false, err
	}
	report := func(action, result, detail string) error {
		if err := e.emit(events.AttestationOverdueAction, c, map[string]any{"action": action, "result": result, "detail": detail,
			"undecided": len(pending)}); err != nil {
			return err
		}
		return e.audit("groups.attestation.overdue", c, ojson.KV{Key: "action", Value: action}, ojson.KV{Key: "result", Value: result},
			ojson.KV{Key: "detail", Value: detail}, ojson.KV{Key: "undecided", Value: len(pending)})
	}
	if c.OverdueAction == store.OverdueNone {
		created, err := e.overdueTask(g, c, "overdue")
		if err != nil || !created {
			return false, err
		}
		return true, report(c.OverdueAction, "task_opened", "")
	}
	sub, why, err := subjectOf(e.Tx, c.ActsAs, e.Now)
	if err != nil {
		return false, err
	}
	var ck *privs.Checker
	if why == "" {
		ck = privs.NewChecker(e.Tx, e.Now, e.eng(), sub)
		need := privs.Update
		if c.OverdueAction == store.OverdueDisable {
			need = privs.Admin
		}
		if ok, err := ck.Has(privs.GroupObject(g.ID), need); err != nil {
			return false, err
		} else if !ok {
			why = "privilege_required: " + string(need)
		}
	}
	if why != "" {
		// fail closed: the action does nothing, and the group's admins are asked
		log.Warn("attestation overdue action refused", "campaign", c.ID, "reason", why)
		created, err := e.overdueTask(g, c, why)
		if err != nil || !created {
			return false, err
		}
		return true, report(c.OverdueAction, "denied", why)
	}
	switch c.OverdueAction {
	case store.OverdueDisable:
		status := store.GroupDisabled
		by := c.ActsAs
		me := e.model()
		me.By, me.ByIdentity, me.TenantAdmin = &by, sub.Identity, sub.TenantAdmin
		if _, err := me.UpdateGroup(g.ID, model.UpdateGroupInput{Status: &status}); err != nil {
			var mErr *model.Error
			if errors.As(err, &mErr) {
				return false, e.failOverdue(g, c, report, mErr.Code)
			}
			return false, err
		}
		for _, it := range pending {
			if err := e.Tx.SetGrpAttestItemApplied(it.ID, store.ApplySkipped, "the group was disabled", e.Now); err != nil {
				return false, err
			}
		}
		if err := report(c.OverdueAction, "applied", "group disabled"); err != nil {
			return false, err
		}
	case store.OverdueRemove:
		removed := 0
		for _, it := range pending {
			if err := e.markNotAttested(it); err != nil {
				return false, err
			}
			if err := e.applyRevoke(ck, c.ActsAs, c, it); err != nil {
				return false, err
			}
			if cur, err := e.Tx.GrpAttestItem(it.ID); err != nil {
				return false, err
			} else if cur.ApplyState == store.ApplyApplied {
				removed++
			}
		}
		if err := report(c.OverdueAction, "applied", fmt.Sprintf("%d removed", removed)); err != nil {
			return false, err
		}
	}
	return true, e.complete(c, store.AttestOverdueApplied, map[string]any{"action": c.OverdueAction})
}

func (e Env) failOverdue(g *store.NativeGroup, c *store.GrpAttestCampaign, report func(action, result, detail string) error, code string) error {
	if _, err := e.overdueTask(g, c, code); err != nil {
		return err
	}
	return report(c.OverdueAction, "failed", code)
}

// undecided lists the items whose review item has no decision, in identity order.
func (e Env) undecided(c *store.GrpAttestCampaign) ([]*store.GrpAttestItem, error) {
	items, err := e.Tx.GrpAttestItems(c.ID)
	if err != nil {
		return nil, err
	}
	var out []*store.GrpAttestItem
	for _, it := range items {
		if it.ApplyState != store.ApplyPending || it.ReviewItem == nil {
			continue
		}
		ri, err := e.Tx.Item(*it.ReviewItem)
		if err != nil {
			return nil, err
		}
		if ri.Decision == nil || *ri.Decision == "" {
			out = append(out, it)
		}
	}
	return out, nil
}

// markNotAttested records the overdue revocation as the decision of the review
// item, so the certification record shows it.
func (e Env) markNotAttested(it *store.GrpAttestItem) error {
	if it.ReviewItem == nil {
		return nil
	}
	msg := "not attested before the due date"
	_, err := e.Tx.DecideItem(*it.ReviewItem, "revoke", &msg, e.Now, store.UserRef{})
	return err
}

// ---------------------------------------------------------------- the scheduler

// StartDue starts the periodic campaigns that have come due: for each group
// whose applicable settings are enabled and have no open campaign, when its
// last periodic campaign started (or, if it never had one, when the settings
// were saved) at least interval_days ago. It starts at most MaxStartsPerPass.
// A group that cannot be attested yet (too large, being recomputed) is skipped
// and its admins get an Inbox task.
func StartDue(tx *store.TenantTx, now time.Time, eng *engine.Engine) (int, error) {
	all, err := tx.GrpAttestSettingsEnabled()
	if err != nil || len(all) == 0 {
		return 0, err
	}
	var groups []*store.NativeGroup
	for _, s := range all {
		if s.OwnerType == store.RuleOwnerGroup {
			g, err := tx.GrpGroup(store.GroupID(s.OwnerID))
			if err != nil {
				return 0, err
			}
			groups = append(groups, g)
			continue
		}
		f, err := tx.GrpFolder(store.FolderID(s.OwnerID))
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return 0, err
		}
		below, err := tx.GrpGroupsBelow(f.Name)
		if err != nil {
			return 0, err
		}
		groups = append(groups, below...)
	}
	seen := map[store.GroupID]bool{}
	started := 0
	for _, g := range groups {
		if seen[g.ID] || g.Status != store.GroupActive {
			continue
		}
		seen[g.ID] = true
		s, _, ok, err := effective(tx, store.RuleOwnerGroup, string(g.ID))
		if err != nil {
			return started, err
		}
		if !ok || !s.Enabled {
			continue
		}
		recent, err := tx.GrpAttestCampaigns(store.GrpAttestFilter{Group: g.ID, Limit: 50})
		if err != nil {
			return started, err
		}
		base, open := s.UpdatedAt, false
		for _, c := range recent {
			if c.Kind != store.AttestPeriodic {
				continue
			}
			open = open || c.Status == store.AttestOpen
			if c.StartedAt.After(base) || c.StartedAt.Equal(base) {
				base = c.StartedAt
			}
		}
		if open || now.Before(base.AddDate(0, 0, s.IntervalDays)) {
			continue
		}
		e := Env{Tx: tx, Now: now, Engine: eng, Cause: store.CauseEngine, CauseRef: "attestation:schedule"}
		if _, _, err := Start(e, g.ID, StartInput{}); err != nil {
			var ge *gov.Error
			if errors.As(err, &ge) && ge.Kind == gov.KindConflict {
				// refused before anything was written: ask the admins to look
				if _, _, terr := inbox.Open(tx, now, inbox.Input{Kind: store.TaskAttestationOverdue, Title: "Attestation of " + g.Name + " could not start",
					Detail: map[string]any{"group": string(g.ID), "reason": ge.Code}, ObjectType: store.RuleOwnerGroup, ObjectID: string(g.ID),
					DedupeKey: "attest-start:" + string(g.ID) + ":" + ge.Code}); terr != nil {
					return started, terr
				}
				continue
			}
			return started, err
		}
		started++
		if started >= MaxStartsPerPass {
			break
		}
	}
	return started, nil
}

// Pass is one scheduler pass of a tenant: start what is due, then sweep.
func Pass(tx *store.TenantTx, now time.Time, eng *engine.Engine, log *slog.Logger) (Summary, error) {
	n, err := StartDue(tx, now, eng)
	if err != nil {
		return Summary{}, err
	}
	sum, err := Sweep(tx, now, eng, log)
	sum.Started = n
	return sum, err
}
