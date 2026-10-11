package jml

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Ownership handover for a leaver (issue #167). For each object the leaver
// owns as primary, an active backup owner is promoted (and the backup slot
// cleared), otherwise the leaver's manager (or nobody, "security team")
// takes over. Where the leaver is the backup, the backup slot is cleared.

type handoverRow struct {
	kind, key, label string
	primary          any // *int64-ish: int64 or nil
	primaryName      string
	backup           any
	leaverWasPrimary bool
}

func ownershipHandover(c *store.TenantTx, leaverID int64, fallback any, fallbackName string) (map[string]handoverRow, error) {
	rows, err := c.OwnershipsOf(leaverID)
	if err != nil {
		return nil, err
	}
	out := map[string]handoverRow{}
	for _, o := range rows {
		label, err := ownedLabel(c, o)
		if err != nil {
			return nil, err
		}
		h := handoverRow{kind: o.Kind, key: o.Key, label: label}
		if o.PrimaryID != nil && *o.PrimaryID == leaverID {
			h.leaverWasPrimary = true
			h.primary, h.primaryName = fallback, fallbackName
			if o.BackupID != nil {
				b, err := getOrNil(c.Identity(*o.BackupID))
				if err != nil {
					return nil, err
				}
				if b != nil && b.Status == "active" && b.ID != leaverID {
					h.primary, h.primaryName = b.ID, b.Name
				}
			}
			h.backup = nil
		} else {
			h.primary = int64OrNil(o.PrimaryID)
			h.backup = nil
		}
		out[o.Kind+"/"+o.Key] = h
	}
	return out, nil
}

func int64OrNil(p *int64) any {
	if p == nil {
		return nil
	}
	return *p
}

func ownedLabel(c *store.TenantTx, o *store.Ownership) (string, error) {
	var id int64
	if o.Kind != store.OwnedApp {
		if _, err := fmt.Sscan(o.Key, &id); err != nil {
			return o.Key, nil
		}
	}
	switch o.Kind {
	case store.OwnedGroup:
		g, err := getOrNil(c.Group(id))
		if err != nil || g == nil {
			return o.Key, err
		}
		return g.System + ":" + g.Name, nil
	case store.OwnedResource:
		n, err := c.ResourceName(id)
		if errors.Is(err, store.ErrNotFound) {
			return o.Key, nil
		}
		return n, err
	case store.OwnedIdentity:
		i, err := getOrNil(c.Identity(id))
		if err != nil || i == nil {
			return o.Key, err
		}
		return i.Name, nil
	}
	return o.Key, nil
}

var kindNoun = map[string]string{store.OwnedApp: "application", store.OwnedGroup: "entitlement",
	store.OwnedResource: "resource", store.OwnedIdentity: "identity"}

func handoverSteps(m map[string]handoverRow) []Step {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	steps := make([]Step, 0, len(keys))
	for _, k := range keys {
		h := m[k]
		detail := fmt.Sprintf("Remove the leaver as backup owner of %s %s", kindNoun[h.kind], h.label)
		if h.leaverWasPrimary {
			detail = fmt.Sprintf("Make %s owner of %s %s", h.primaryName, kindNoun[h.kind], h.label)
		}
		steps = append(steps, Step{{Key: "action", Value: "reassign_ownership"}, {Key: "system", Value: "tessera"},
			{Key: "kind", Value: h.kind}, {Key: "key", Value: h.key}, {Key: "target", Value: h.label},
			{Key: "new_primary_id", Value: h.primary}, {Key: "new_backup_id", Value: h.backup}, {Key: "detail", Value: detail}})
	}
	return steps
}

func reassignOwnership(c *store.TenantTx, now time.Time, st Step) error {
	o, err := getOrNil(c.Ownership(stepStr(st, "kind"), stepStr(st, "key")))
	if err != nil || o == nil {
		return err
	}
	o.PrimaryID, o.BackupID, o.UpdatedAt = optInt(stepGet(st, "new_primary_id")), optInt(stepGet(st, "new_backup_id")), now
	if err := c.PutOwnership(o); err != nil {
		return err
	}
	if o.Kind != store.OwnedIdentity {
		return nil
	}
	// Keep identities.owner_id in step (reassign_owner covers active
	// identities only; this covers a disabled one too).
	var id int64
	if _, err := fmt.Sscan(o.Key, &id); err != nil {
		return nil
	}
	return c.SetIdentityOwner(id, o.PrimaryID)
}
