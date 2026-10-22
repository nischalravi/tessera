package provision

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/deleteguard"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// The deletion threshold guard (internal/deleteguard) for provisioning: an operation that disables
// or deletes an account in a target system counts against the tenant's accounts threshold. One
// that passes it is not queued; it is held with everything needed to queue it again.

// ItemOp is the kind of a held operation.
const ItemOp = "prov_op"

// heldOp is what a held item carries: the connection and the change as it was submitted.
type heldOp struct {
	ConnectionID string `json:"connection_id"`
	Change       Change `json:"change"`
}

// guarded says whether an operation kind removes or disables an account.
func guarded(kind string) bool { return kind == target.DisableAccount || kind == target.DeleteAccount }

// guardOp vets a new operation; held says it was held and must not be queued.
func guardOp(tx *store.TenantTx, now time.Time, connectionID string, c Change) (held bool, err error) {
	if !guarded(c.Kind) {
		return false, nil
	}
	raw, err := json.Marshal(heldOp{ConnectionID: connectionID, Change: c})
	if err != nil {
		return false, err
	}
	d, err := deleteguard.AdmitFrom(tx, now, deleteguard.CatAccounts, deleteguard.SourceProvisioner, connectionID,
		"prov:"+connectionID+":"+c.Source, deleteguard.Item{Kind: ItemOp, Ref: string(raw),
			Label: fmt.Sprintf("%s %s in %s", c.Kind, c.Account.Username, c.System)})
	if err != nil {
		return false, err
	}
	return len(d.Held) > 0, nil
}

// ReleaseHeld queues a held operation again, as an approved override. It is gone when the same
// intent already has an operation in flight.
func ReleaseHeld(tx *store.TenantTx, now time.Time, it *store.DeletionHoldItem) (outcome, note string, err error) {
	var h heldOp
	if err := json.Unmarshal([]byte(it.Ref), &h); err != nil {
		return "", "", fmt.Errorf("provision: bad held operation: %w", err)
	}
	if existing, err := tx.ProvOpByKey(h.Change.Key); err == nil && InFlightStatus(existing.Status) {
		return deleteguard.ItemGone, "an operation for this is already in flight", nil
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		return "", "", err
	}
	if t, err := Route(tx, h.Change.System); err != nil {
		return "", "", err
	} else if t == nil {
		return deleteguard.ItemFailed, "the system has no connection with write-back on any more", nil
	}
	if _, err := Enqueue(tx, now, h.ConnectionID, h.Change); err != nil {
		var pe *Error
		if errors.As(err, &pe) {
			return deleteguard.ItemFailed, pe.Msg, nil
		}
		return "", "", err
	}
	return deleteguard.ItemReleased, "", nil
}
