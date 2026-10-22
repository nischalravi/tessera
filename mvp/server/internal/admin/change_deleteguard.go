package admin

import (
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

type deletionGuardPayload struct {
	Policies        []deletionPolicyPayload `json:"policies,omitempty"`
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
			if v.HoldExpiryHours != nil {
				parts = append(parts, "hold expiry")
			}
			return "Change the deletion threshold guard (" + strings.Join(parts, ", ") + ")"
		})
}

// planDeletionGuard checks the payload and decides who approves: two admins when any policy is
// looser than the current one.
func planDeletionGuard(e *env, v *deletionGuardPayload) (plan, error) {
	if len(v.Policies) == 0 && v.HoldExpiryHours == nil {
		return plan{}, invalid("name at least one policy or hold_expiry_hours")
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
		if deleteguard.Loosens(have[pp.Category], next, pop) {
			loosens = true
		}
	}
	if v.HoldExpiryHours != nil && (*v.HoldExpiryHours < 1 || *v.HoldExpiryHours > 8760) {
		return plan{}, invalid("hold_expiry_hours is 1 to 8760")
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
		if err := deleteguard.Set(e.tx, next, &by, e.now); err != nil {
			return err
		}
		detail = append(detail, ojson.KV{Key: pp.Category, Value: ojson.Object{
			{Key: "from", Value: describePolicy(old)}, {Key: "to", Value: describePolicy(next)},
			{Key: "loosened", Value: deleteguard.Loosens(old, next, pop)}}})
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
