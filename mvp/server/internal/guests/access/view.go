package access

import (
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/provision"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// States a reader sees for a bundle item.
const (
	StatePending  = "pending"  // waiting for the guest to claim, or for the target to confirm
	StateGranted  = "granted"  // the membership exists
	StateFailed   = "failed"   // the provisioning operation failed or did not verify
	StateRemoving = "removing" // the sponsorship ended and the removal is not verified yet
	StateRemoved  = "removed"
)

// ItemView is a bundle item as the API shows it.
type ItemView struct {
	ID            string     `json:"id"`
	SponsorshipID string     `json:"sponsorship_id"`
	GroupID       int64      `json:"group_id"`
	System        string     `json:"system"`
	Name          string     `json:"name"`
	State         string     `json:"state"`
	Detail        string     `json:"detail,omitempty"`
	OpID          *string    `json:"op_id"`
	OpStatus      *string    `json:"op_status"`
	ExpiresAt     time.Time  `json:"expires_at"`
	GrantedAt     *time.Time `json:"granted_at"`
	RemovedAt     *time.Time `json:"removed_at"`
}

// Views describes items for display: the state tells a reader whether the
// access is waiting, in place, failed, going or gone, and the operation that
// is doing it links to Admin → Provisioning.
func Views(tx *store.TenantTx, items []*store.BundleItem) ([]ItemView, error) {
	out := make([]ItemView, 0, len(items))
	for _, it := range items {
		v := ItemView{ID: it.ID, SponsorshipID: it.SponsorshipID, GroupID: it.GroupID, System: it.System, ExpiresAt: it.ExpiresAt,
			GrantedAt: it.GrantedAt, RemovedAt: it.RemovedAt}
		if g, err := getOrNil(tx.Group(it.GroupID)); err != nil {
			return nil, err
		} else if g != nil {
			v.Name = g.Name
		}
		opID := it.GrantOpID
		switch it.Status {
		case store.BundleGranted:
			v.State = StateGranted
		case store.BundleRemoved:
			v.State, opID = StateRemoved, firstOp(it.RemoveOpID, it.GrantOpID)
		case store.BundleRemoving:
			v.State, opID = StateRemoving, it.RemoveOpID
		default:
			v.State = StatePending
			v.Detail = "waiting for the guest to claim their account"
			if g, err := tx.Identity(it.GuestID); err == nil && g.Status == "active" {
				v.Detail = "waiting to be granted"
			}
		}
		if opID != nil {
			v.OpID = opID
			op, err := getOrNil(tx.ProvOp(*opID))
			if err != nil {
				return nil, err
			}
			if op != nil {
				v.OpStatus = &op.Status
				switch {
				case op.Status == provision.Failed || op.Status == provision.Mismatch || op.Status == provision.Cancelled:
					v.State = StateFailed
					v.Detail = "provisioning " + op.Status
					if op.LastError != nil {
						v.Detail += ": " + *op.LastError
					}
				case it.Status == store.BundlePending || it.Status == store.BundleRemoving:
					v.Detail = "provisioning " + op.Status
				}
			}
		}
		out = append(out, v)
	}
	return out, nil
}

func firstOp(a, b *string) *string {
	if a != nil {
		return a
	}
	return b
}
