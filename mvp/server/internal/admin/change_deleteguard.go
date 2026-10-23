package admin

import (
	"errors"
	"fmt"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/deleteguard"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// TypeDeletionGuardUpdate changes the deletion threshold guard's settings
// (internal/deleteguard): the threshold, window and mode of categories, and how long a held
// deletion waits. Tightening a safety setting needs one admin (the request applies at once);
// loosening one (a weaker mode, or a higher limit per minute of window at the tenant's current size)
// takes two: the requester proposes, a different admin approves what the payload hash says.
const TypeDeletionGuardUpdate = "deletion_guard.update"

type deletionPolicyPayload struct {
	Category      string   `json:"category"`
	MaxCount      *int     `json:"max_count"`
	MaxPercent    *float64 `json:"max_percent"`
	WindowMinutes int      `json:"window_minutes"`
	Mode          string   `json:"mode"`
}

// deletionSourcePayload sets or removes one source's override for a category: its own threshold
// (mode with max_count, max_percent and window_minutes; no mode inherits the category's) and its feed
// sanity checks (feed_drop_percent, feed_empty_check; unset is the default, 20 and on).
type deletionSourcePayload struct {
	Kind            string   `json:"kind"`
	SourceID        string   `json:"source_id"`
	Category        string   `json:"category"`
	Remove          bool     `json:"remove,omitempty"`
	Mode            string   `json:"mode,omitempty"`
	MaxCount        *int     `json:"max_count,omitempty"`
	MaxPercent      *float64 `json:"max_percent,omitempty"`
	WindowMinutes   int      `json:"window_minutes,omitempty"`
	FeedDropPercent *float64 `json:"feed_drop_percent,omitempty"`
	FeedEmptyCheck  *bool    `json:"feed_empty_check,omitempty"`
}

func (p deletionSourcePayload) policy() deleteguard.SourcePolicy {
	return deleteguard.SourcePolicy{Kind: p.Kind, SourceID: p.SourceID, Category: p.Category, Mode: p.Mode, MaxCount: p.MaxCount,
		MaxPercent: p.MaxPercent, WindowMinutes: p.WindowMinutes, FeedDropPercent: p.FeedDropPercent, FeedEmptyCheck: p.FeedEmptyCheck}
}

type deletionGuardPayload struct {
	Policies        []deletionPolicyPayload `json:"policies,omitempty"`
	Sources         []deletionSourcePayload `json:"sources,omitempty"`
	HoldExpiryHours *int                    `json:"hold_expiry_hours,omitempty"`
}

func (p deletionPolicyPayload) policy() deleteguard.Policy {
	return deleteguard.Policy{Category: p.Category, MaxCount: p.MaxCount, MaxPercent: p.MaxPercent,
		WindowMinutes: p.WindowMinutes, Mode: p.Mode}
}

func init() {
	changeTypes[TypeDeletionGuardUpdate] = typed(TypeDeletionGuardUpdate, nil, planDeletionGuard, applyDeletionGuard,
		func(_ *env, v *deletionGuardPayload) string {
			var parts []string
			for _, p := range v.Policies {
				parts = append(parts, p.Category)
			}
			for _, p := range v.Sources {
				parts = append(parts, p.Kind+" "+p.SourceID+" "+p.Category)
			}
			if v.HoldExpiryHours != nil {
				parts = append(parts, "hold expiry")
			}
			return "Change the deletion threshold guard (" + strings.Join(parts, ", ") + ")"
		})
}

// planDeletionGuard checks the payload and decides who approves: two admins when any policy is
// looser than the current one.
func planDeletionGuard(e *env, v *deletionGuardPayload) (plan, error) {
	if len(v.Policies) == 0 && len(v.Sources) == 0 && v.HoldExpiryHours == nil {
		return plan{}, invalid("name at least one policy, source or hold_expiry_hours")
	}
	cur, err := deleteguard.Effective(e.tx)
	if err != nil {
		return plan{}, err
	}
	have := map[string]deleteguard.Policy{}
	for _, p := range cur {
		have[p.Category] = p
	}
	seen := map[string]bool{}
	loosens := false
	for _, pp := range v.Policies {
		next := pp.policy()
		if err := next.Check(); err != nil {
			return plan{}, invalid("%v", err)
		}
		if seen[pp.Category] {
			return plan{}, invalid("%s is named twice", pp.Category)
		}
		seen[pp.Category] = true
		pop, err := e.tx.DeletionPopulation(pp.Category)
		if err != nil {
			return plan{}, err
		}
		if !deleteguard.IsNoop(have[pp.Category], next) && deleteguard.Loosens(have[pp.Category], next, pop) {
			loosens = true
		}
	}
	if v.HoldExpiryHours != nil && (*v.HoldExpiryHours < 1 || *v.HoldExpiryHours > 8760) {
		return plan{}, invalid("hold_expiry_hours is 1 to 8760")
	}
	seenSrc := map[string]bool{}
	for _, sp := range v.Sources {
		k := sp.Kind + "|" + sp.SourceID + "|" + sp.Category
		if seenSrc[k] {
			return plan{}, invalid("%s %s %s is named twice", sp.Kind, sp.SourceID, sp.Category)
		}
		seenSrc[k] = true
		l, err := sourceLoosens(e, sp)
		if err != nil {
			return plan{}, err
		}
		loosens = loosens || l
	}
	return plan{twoPerson: loosens, target: "deletion_guard"}, nil
}

func applyDeletionGuard(e *env, ch *store.AdminChange, v *deletionGuardPayload) error {
	if _, err := planDeletionGuard(e, v); err != nil {
		return err
	}
	cur, err := deleteguard.Effective(e.tx)
	if err != nil {
		return err
	}
	have := map[string]deleteguard.Policy{}
	for _, p := range cur {
		have[p.Category] = p
	}
	by := ch.ID.String()
	detail := ojson.Object{{Key: "change_id", Value: ch.ID.String()}, {Key: "requested_by", Value: ch.RequestedBy.String()}}
	if ch.ApprovedBy != nil {
		detail = append(detail, ojson.KV{Key: "approved_by", Value: ch.ApprovedBy.String()})
	}
	for _, pp := range v.Policies {
		next := pp.policy()
		old := have[pp.Category]
		pop, err := e.tx.DeletionPopulation(pp.Category)
		if err != nil {
			return err
		}
		// the displayed default saved as it is stays unset: a stored row would end the hold_all that
		// source-driven runs get while the tenant has not set the category
		if !deleteguard.IsNoop(old, next) {
			if err := deleteguard.Set(e.tx, next, &by, e.now); err != nil {
				return err
			}
		}
		detail = append(detail, ojson.KV{Key: pp.Category, Value: ojson.Object{
			{Key: "from", Value: describePolicy(old)}, {Key: "to", Value: describePolicy(next)},
			{Key: "loosened", Value: !deleteguard.IsNoop(old, next) && deleteguard.Loosens(old, next, pop)}}})
	}
	for _, sp := range v.Sources {
		old, err := deleteguard.ResolveFor(e.tx, deleteguard.SourceRef{Kind: sp.Kind, ID: sp.SourceID}, sp.Category, true)
		if err != nil {
			return err
		}
		loosened, err := sourceLoosens(e, sp)
		if err != nil {
			return err
		}
		to := "removed (the category's settings apply)"
		if sp.Remove {
			err = e.tx.DeleteDeletionSourcePolicy(sp.Kind, sp.SourceID, sp.Category)
		} else {
			next := sp.policy()
			to = describeSource(next)
			err = deleteguard.SetSource(e.tx, next, &by, e.now)
			if err == nil {
				err = recordSourceApproval(e, ch, sp, next, &by)
			}
		}
		if err != nil {
			return err
		}
		detail = append(detail, ojson.KV{Key: sp.Kind + ":" + sp.SourceID + ":" + sp.Category, Value: ojson.Object{
			{Key: "from", Value: describeResolved(old)}, {Key: "to", Value: to}, {Key: "loosened", Value: loosened}}})
	}
	if v.HoldExpiryHours != nil {
		was, err := deleteguard.HoldExpiryHours(e.tx)
		if err != nil {
			return err
		}
		if err := e.tx.PutDeletionSettings(*v.HoldExpiryHours, &by, e.now); err != nil {
			return err
		}
		detail = append(detail, ojson.KV{Key: "hold_expiry_hours", Value: ojson.Object{{Key: "from", Value: was}, {Key: "to", Value: *v.HoldExpiryHours}}})
	}
	// in the transaction that applies the change, next to admin.change.applied
	_, err = audit.Record(e.tx.Context(), e.tx, "deletion_guard.policy_changed", detail, audit.At(e.now),
		audit.Target("admin_change", ch.ID.String()))
	return err
}

// recordSourceApproval records whether two admins approved an override as looser than the category as
// the category is now. Only that exempts it from the category's tenant-wide budget later; a category
// tightened afterwards (one admin) cannot turn a single-admin override into one (#494).
func recordSourceApproval(e *env, ch *store.AdminChange, sp deletionSourcePayload, next deleteguard.SourcePolicy, by *string) error {
	tp, err := deleteguard.PolicyOf(e.tx, sp.Category)
	if err != nil {
		return err
	}
	pop, err := e.tx.DeletionPopulation(sp.Category)
	if err != nil {
		return err
	}
	cat, over := deleteguard.Resolve(tp, nil, true), deleteguard.Resolve(tp, &next, true)
	two := ch.ApprovedBy != nil && cat.Mode != deleteguard.ModeOff && over.Overridden && deleteguard.Loosens(cat.Policy, over.Policy, pop)
	return deleteguard.SetSourceApproved(e.tx, deleteguard.SourceRef{Kind: sp.Kind, ID: sp.SourceID}, sp.Category, two, by, e.now)
}

func describePolicy(p deleteguard.Policy) string {
	c, pc := "-", "-"
	if p.MaxCount != nil {
		c = fmt.Sprint(*p.MaxCount)
	}
	if p.MaxPercent != nil {
		pc = fmt.Sprintf("%g%%", *p.MaxPercent)
	}
	return fmt.Sprintf("%s: count %s, percent %s per %d min", p.Mode, c, pc, p.WindowMinutes)
}

// sourceLoosens checks one source override of the payload (the source exists, the setting is valid) and
// says whether it is weaker than what applies to the source now.
func sourceLoosens(e *env, sp deletionSourcePayload) (bool, error) {
	ref := deleteguard.SourceRef{Kind: sp.Kind, ID: sp.SourceID}
	if !ref.Valid() {
		return false, invalid("%q is not a source kind (connection, loader, vms_source) with an id", sp.Kind)
	}
	if !deleteguard.ValidCategory(sp.Category) {
		return false, invalid("%q is not a deletion category", sp.Category)
	}
	if err := sourceExists(e.tx, ref); err != nil {
		return false, err
	}
	cur, err := deleteguard.ResolveFor(e.tx, ref, sp.Category, true)
	if err != nil {
		return false, err
	}
	tp, err := deleteguard.PolicyOf(e.tx, sp.Category)
	if err != nil {
		return false, err
	}
	var next deleteguard.Resolved
	if sp.Remove {
		if sp.Mode != "" || sp.MaxCount != nil || sp.MaxPercent != nil || sp.WindowMinutes != 0 || sp.FeedDropPercent != nil || sp.FeedEmptyCheck != nil {
			return false, invalid("a removal names no settings")
		}
		if _, err := e.tx.DeletionSourcePolicy(sp.Kind, sp.SourceID, sp.Category); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return false, invalid("%s %s has no override of %s to remove", sp.Kind, sp.SourceID, sp.Category)
			}
			return false, err
		}
		next = deleteguard.Resolve(tp, nil, true)
	} else {
		p := sp.policy()
		if err := p.Check(); err != nil {
			return false, invalid("%v", err)
		}
		next = deleteguard.Resolve(tp, &p, true)
	}
	pop, err := e.tx.DeletionPopulation(sp.Category)
	if err != nil {
		return false, err
	}
	return deleteguard.LoosensResolved(cur, next, pop), nil
}

// sourceExists refuses an override for a source the tenant does not have.
func sourceExists(tx *store.TenantTx, ref deleteguard.SourceRef) error {
	var err error
	switch ref.Kind {
	case deleteguard.SrcConnection:
		_, err = tx.Connection(ref.ID)
	case deleteguard.SrcLoader:
		_, err = tx.GrpLoader(ref.ID)
	case deleteguard.SrcVMS:
		_, err = tx.VmsSource(ref.ID)
	default:
		return invalid("%s sources have no settings yet", ref.Kind)
	}
	if errors.Is(err, store.ErrNotFound) {
		return invalid("no %s %s", ref.Kind, ref.ID)
	}
	return err
}

func describeSource(p deleteguard.SourcePolicy) string {
	out := "inherits the category's thresholds"
	if p.Mode != "" {
		out = describePolicy(deleteguard.Policy{MaxCount: p.MaxCount, MaxPercent: p.MaxPercent, WindowMinutes: p.WindowMinutes, Mode: p.Mode})
	}
	return out + "; " + describeFeed(p.FeedSettings())
}

func describeResolved(r deleteguard.Resolved) string {
	return describePolicy(r.Policy) + "; " + describeFeed(r.Feed)
}

func describeFeed(f deleteguard.Feed) string {
	return fmt.Sprintf("feed drop limit %g%%, empty feed check %t", f.DropPercent, f.EmptyCheck)
}
