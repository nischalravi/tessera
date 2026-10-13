// Package access is guest access (design §8.2, §9.3, issue #75 / GU-12): the
// access bundle of a sponsorship, the system-managed reference groups and the
// identity assurance a guest reached.
//
// A sponsorship's bundle (catalog items chosen at invite) is recorded as
// guest_bundle_items when the sponsorship becomes active and granted once the
// guest has claimed: for each system the bundle touches the guest gets an
// account (a provisioning create_account operation when the system's
// connection has write-back on) and a membership of each bundle group (an
// add_entitlement operation). With write-back on, the graph edge is written
// only by the operation's completion, after the re-read of the target shows
// the change (internal/provision), never before. With write-back off the
// account and the edge are written directly. The edge's source is
// "guest_sponsorship", its source_ref is the sponsorship (the bundle item row)
// and it expires with the sponsorship, so the graph drops it on time even
// before a sweep removes it.
//
// Each sponsorship's bundle ends independently (§8.2): ending or revoking a
// sponsorship, the sweeper at its end date, or a lapsed transfer removes that
// sponsorship's memberships (remove_entitlement through provisioning when it is
// on) unless another live sponsorship of the same guest still needs the same
// group. Accounts are not disabled here: when the last sponsorship ends the
// lifecycle's leaver plan does it, and it leaves the edges this package is
// already removing alone.
//
// Reference groups (refgroups.go) are the people-groups policies and access
// reviews use ("guest:active", "ial:2", ...). They are Tessera-managed until
// the groups engine (GR-1/GR-2) takes them over.
//
// Every function works in the caller's tenant transaction, which also carries
// the audit event.
package access

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/jml"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/provision"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Completions the provisioning engine runs once the target confirms.
const (
	CompleteGrant  = "guest.bundle_grant"
	CompleteRemove = "guest.bundle_remove"
	// System is the actor of the engine's completions and the sweeper.
	System = "guest.access"
)

type itemRef struct {
	ItemID string `json:"item_id"`
}

func init() {
	provision.RegisterCompletion(CompleteGrant, func(tx *store.TenantTx, now time.Time, raw json.RawMessage) error {
		var d itemRef
		if err := json.Unmarshal(raw, &d); err != nil {
			return err
		}
		return completeGrant(tx, now, d.ItemID)
	})
	provision.RegisterCompletion(CompleteRemove, func(tx *store.TenantTx, now time.Time, raw json.RawMessage) error {
		var d itemRef
		if err := json.Unmarshal(raw, &d); err != nil {
			return err
		}
		return completeRemove(tx, now, d.ItemID)
	})
}

// bundleGroups reads the group ids of a sponsorship's stored bundle.
func bundleGroups(raw string) []int64 {
	var items []struct {
		GroupID int64 `json:"group_id"`
	}
	if json.Unmarshal([]byte(raw), &items) != nil {
		return nil
	}
	out := make([]int64, 0, len(items))
	for _, it := range items {
		out = append(out, it.GroupID)
	}
	return out
}

func getOrNil[T any](v *T, err error) (*T, error) {
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	return v, err
}

func audit(tx *store.TenantTx, now time.Time, actor, action string, it *store.BundleItem, extra ...ojson.KV) error {
	d := ojson.Object{{Key: "item_id", Value: it.ID}, {Key: "sponsorship_id", Value: it.SponsorshipID},
		{Key: "guest_identity_id", Value: it.GuestID}, {Key: "group_id", Value: it.GroupID}, {Key: "system", Value: it.System}}
	return tx.Audit(now, actor, action, append(d, extra...))
}

// ---------------------------------------------------------------- plan and grant

// Plan records the items of a sponsorship's bundle (pending), once. It is
// called when the sponsorship becomes active; nothing is granted before the
// guest has claimed (GrantPending).
func Plan(tx *store.TenantTx, ss *store.Sponsorship, actor string, now time.Time) error {
	ids := bundleGroups(ss.AccessBundle)
	if len(ids) == 0 {
		return nil
	}
	have, err := tx.BundleItems(store.BundleItemFilter{Sponsorship: ss.ID})
	if err != nil {
		return err
	}
	known := map[int64]bool{}
	for _, it := range have {
		known[it.GroupID] = true
	}
	added := 0
	for _, gid := range ids {
		if known[gid] {
			continue
		}
		known[gid] = true
		g, err := getOrNil(tx.Group(gid))
		if err != nil {
			return err
		}
		if g == nil {
			continue // the group left the catalog since the invitation
		}
		if err := tx.InsertBundleItem(&store.BundleItem{ID: store.NewID(), SponsorshipID: ss.ID, GuestID: ss.GuestIdentityID,
			GroupID: gid, System: g.System, Status: store.BundlePending, ExpiresAt: ss.EndsAt, CreatedAt: now, UpdatedAt: now}); err != nil {
			return err
		}
		added++
	}
	if added == 0 {
		return nil
	}
	return tx.Audit(now, actor, "guest.bundle.plan", ojson.Object{{Key: "sponsorship_id", Value: ss.ID},
		{Key: "guest_identity_id", Value: ss.GuestIdentityID}, {Key: "items", Value: added}, {Key: "ends_at", Value: ss.EndsAt.UTC().Format(time.RFC3339)}})
}

// GrantPending grants every pending item of the guest's live sponsorships,
// when the guest has claimed (status active). It submits provisioning
// operations where write-back is on and writes the graph directly otherwise;
// an item that already has an operation is left to it.
func GrantPending(tx *store.TenantTx, guestID int64, actor string, now time.Time) error {
	guest, err := tx.Identity(guestID)
	if err != nil {
		return err
	}
	if guest.Status != "active" {
		return nil
	}
	items, err := tx.BundleItems(store.BundleItemFilter{Guest: guestID, Status: store.BundlePending})
	if err != nil {
		return err
	}
	for _, it := range items {
		if it.GrantOpID != nil {
			continue
		}
		ss, err := tx.Sponsorship(it.SponsorshipID)
		if err != nil {
			return err
		}
		if !ss.Live() {
			continue
		}
		if err := grantItem(tx, now, actor, guest, ss, it); err != nil {
			return err
		}
	}
	return nil
}

func grantItem(tx *store.TenantTx, now time.Time, actor string, guest *store.Identity, ss *store.Sponsorship, it *store.BundleItem) error {
	g, err := tx.Group(it.GroupID)
	if err != nil {
		return err
	}
	t, err := provision.Route(tx, g.System)
	if err != nil {
		return err
	}
	if t == nil { // write-back off: the graph is changed at once, like the other features do
		acct, err := jml.EnsureAccount(tx, now, guest, g.System)
		if err != nil {
			return err
		}
		return writeEdge(tx, now, actor, it, acct, "direct")
	}
	uname, extID, have, err := accountIn(tx, guest, g.System)
	if err != nil {
		return err
	}
	if !have {
		if it.AccountOpID, err = ensureAccountOp(tx, now, guest, ss, g.System); err != nil {
			return err
		}
	}
	op, _, err := provision.Submit(tx, now, provision.Change{System: g.System, Kind: target.AddEntitlement,
		Account: target.Account{Username: uname, ExternalID: extID},
		Group:   target.Group{ExternalID: g.ExternalID, Name: g.Name}, Source: provision.SourceGuest,
		Key: fmt.Sprintf("guest:%s:%d:add", ss.ID, g.ID), Completion: CompleteGrant, Data: itemRef{it.ID}})
	if err != nil {
		return err
	}
	it.GrantOpID, it.UpdatedAt = &op.ID, now
	if err := tx.SaveBundleItem(it); err != nil {
		return err
	}
	return audit(tx, now, actor, "guest.bundle.request", it, ojson.KV{Key: "op_id", Value: op.ID},
		ojson.KV{Key: "via", Value: "provisioning"})
}

// accountIn is the guest's active account in a system, or the one an account
// creation will make.
func accountIn(tx *store.TenantTx, guest *store.Identity, system string) (uname, extID string, have bool, err error) {
	accts, err := tx.IdentityAccounts(guest.ID)
	if err != nil {
		return "", "", false, err
	}
	for _, a := range accts {
		if a.System == system && a.Status == "active" {
			return a.Username, a.ExternalID, true, nil
		}
	}
	uname, extID, err = jml.AccountSpec(guest, system)
	return uname, extID, false, err
}

// ensureAccountOp submits the guest's account creation in a system and
// returns its operation id. Another item of the same guest and system that has
// the operation in flight already is not asked twice.
func ensureAccountOp(tx *store.TenantTx, now time.Time, guest *store.Identity, ss *store.Sponsorship, system string) (*string, error) {
	others, err := tx.BundleItems(store.BundleItemFilter{Guest: guest.ID})
	if err != nil {
		return nil, err
	}
	for _, o := range others {
		if o.System != system || o.AccountOpID == nil {
			continue
		}
		if op, err := getOrNil(tx.ProvOp(*o.AccountOpID)); err != nil {
			return nil, err
		} else if op != nil && provision.InFlightStatus(op.Status) {
			return o.AccountOpID, nil
		}
	}
	key := fmt.Sprintf("guest:%s:%s:account", ss.ID, system)
	if err := jml.RouteEnsureAccount(tx, now, guest, system, key, provision.SourceGuest); err != nil {
		return nil, err
	}
	op, err := getOrNil(tx.ProvOpByKey(key))
	if err != nil || op == nil {
		return nil, err
	}
	return &op.ID, nil
}

// completeGrant runs when the target confirmed the membership: the edge is
// written now. A sponsorship that ended while the operation was in flight gets
// the membership removed again instead.
func completeGrant(tx *store.TenantTx, now time.Time, itemID string) error {
	it, err := getOrNil(tx.BundleItem(itemID))
	if err != nil || it == nil || it.Status == store.BundleRemoved || it.Status == store.BundleGranted {
		return err
	}
	ss, err := tx.Sponsorship(it.SponsorshipID)
	if err != nil {
		return err
	}
	guest, err := tx.Identity(it.GuestID)
	if err != nil {
		return err
	}
	if it.Status == store.BundleRemoving {
		return nil // End already asked for the removal, queued behind this operation
	}
	if !ss.Live() {
		return removeFromTarget(tx, now, System, ss, it, guest)
	}
	acct, err := jml.EnsureAccount(tx, now, guest, it.System)
	if err != nil {
		return err
	}
	return writeEdge(tx, now, System, it, acct, "provisioning")
}

// writeEdge writes the membership edge of a granted item, expiring with its
// sponsorship. An edge that is already there for another reason is left as it
// is (and not ours to remove); one this package wrote for another sponsorship
// is shared and lives until the later of the two.
func writeEdge(tx *store.TenantTx, now time.Time, actor string, it *store.BundleItem, acct *store.Account, via string) error {
	src, dst := graph.Key("account", acct.ID), graph.Key("group", it.GroupID)
	exp := it.ExpiresAt
	e, err := getOrNil(tx.EdgeBetween(src, dst))
	if err != nil {
		return err
	}
	switch {
	case e == nil:
		id, err := tx.InsertEdge(&store.GrantEdge{TenantID: tx.Tenant(), Src: src, Dst: dst, Relation: "member_of",
			Source: store.EdgeSourceGuest, ExpiresAt: &exp, CreatedAt: now})
		if err != nil {
			return err
		}
		it.EdgeID = &id
	case e.Source == store.EdgeSourceGuest:
		if e.ExpiresAt == nil || e.ExpiresAt.Before(exp) {
			if err := tx.SetEdgeExpiry(e.ID, exp); err != nil {
				return err
			}
		}
		it.EdgeID = &e.ID
	default:
		it.EdgeID = nil // someone else's grant: ours only in the record
	}
	it.Status, it.GrantedAt, it.UpdatedAt = store.BundleGranted, &now, now
	if err := tx.SaveBundleItem(it); err != nil {
		return err
	}
	return audit(tx, now, actor, "guest.bundle.grant", it, ojson.KV{Key: "via", Value: via},
		ojson.KV{Key: "expires_at", Value: exp.UTC().Format(time.RFC3339)})
}

// ---------------------------------------------------------------- renew

// Extend moves the expiry of a sponsorship's bundle to its (renewed) end date.
func Extend(tx *store.TenantTx, ss *store.Sponsorship, actor string, now time.Time) error {
	items, err := tx.BundleItems(store.BundleItemFilter{Sponsorship: ss.ID})
	if err != nil {
		return err
	}
	n := 0
	for _, it := range items {
		if it.Status != store.BundlePending && it.Status != store.BundleGranted {
			continue
		}
		it.ExpiresAt, it.UpdatedAt = ss.EndsAt, now
		if err := tx.SaveBundleItem(it); err != nil {
			return err
		}
		if it.EdgeID != nil && it.Status == store.BundleGranted {
			if err := syncEdgeExpiry(tx, it); err != nil {
				return err
			}
		}
		n++
	}
	if n == 0 {
		return nil
	}
	return tx.Audit(now, actor, "guest.bundle.extend", ojson.Object{{Key: "sponsorship_id", Value: ss.ID},
		{Key: "guest_identity_id", Value: ss.GuestIdentityID}, {Key: "items", Value: n},
		{Key: "expires_at", Value: ss.EndsAt.UTC().Format(time.RFC3339)}})
}

// syncEdgeExpiry sets the expiry of an edge to the latest end of the live
// items that share it.
func syncEdgeExpiry(tx *store.TenantTx, it *store.BundleItem) error {
	e, err := getOrNil(tx.Edge(*it.EdgeID))
	if err != nil || e == nil || e.Source != store.EdgeSourceGuest {
		return err
	}
	shared, err := tx.BundleItems(store.BundleItemFilter{Edge: *it.EdgeID})
	if err != nil {
		return err
	}
	latest := it.ExpiresAt
	for _, o := range shared {
		if (o.Status == store.BundleGranted || o.Status == store.BundlePending) && o.ExpiresAt.After(latest) {
			latest = o.ExpiresAt
		}
	}
	if e.ExpiresAt != nil && e.ExpiresAt.Equal(latest) {
		return nil
	}
	return tx.SetEdgeExpiry(e.ID, latest)
}

// ---------------------------------------------------------------- end

// End removes a sponsorship's bundle: it ended, was revoked or rejected, or a
// transfer lapsed. Other sponsorships of the guest keep what they gave.
func End(tx *store.TenantTx, ss *store.Sponsorship, actor string, now time.Time) error {
	items, err := tx.BundleItems(store.BundleItemFilter{Sponsorship: ss.ID})
	if err != nil {
		return err
	}
	for _, it := range items {
		if err := endItem(tx, now, actor, ss, it); err != nil {
			return err
		}
	}
	return nil
}

func endItem(tx *store.TenantTx, now time.Time, actor string, ss *store.Sponsorship, it *store.BundleItem) error {
	guest, err := tx.Identity(it.GuestID)
	if err != nil {
		return err
	}
	switch it.Status {
	case store.BundlePending:
		return endPending(tx, now, actor, ss, it, guest)
	case store.BundleGranted:
		if other, err := otherHolder(tx, it); err != nil {
			return err
		} else if other != nil { // another live sponsorship still needs the group: only this record ends
			if it.EdgeID != nil {
				if err := syncEdgeExpiry(tx, other); err != nil {
					return err
				}
			}
			return markRemoved(tx, now, actor, it, "another sponsorship keeps the access")
		}
		if it.EdgeID == nil { // the grant was never ours
			return markRemoved(tx, now, actor, it, "not an edge of this bundle")
		}
		return removeFromTarget(tx, now, actor, ss, it, guest)
	}
	return nil // removing: its operation is under way; removed: final
}

// endPending ends an item that was never granted: an operation not yet sent
// is cancelled; one already with the target is let finish (its completion
// removes the membership again).
func endPending(tx *store.TenantTx, now time.Time, actor string, ss *store.Sponsorship, it *store.BundleItem, guest *store.Identity) error {
	if it.GrantOpID == nil {
		return markRemoved(tx, now, actor, it, "ended before it was granted")
	}
	op, err := getOrNil(tx.ProvOp(*it.GrantOpID))
	if err != nil {
		return err
	}
	switch {
	case op == nil:
		return markRemoved(tx, now, actor, it, "ended before it was granted")
	case op.Status == provision.Queued || op.Status == provision.Failed || op.Status == provision.Mismatch:
		if _, err := provision.Cancel(tx, now, op.ID); err != nil {
			return err
		}
		return markRemoved(tx, now, actor, it, "ended before it was granted")
	case op.Status == provision.Cancelled:
		return markRemoved(tx, now, actor, it, "ended before it was granted")
	}
	// sent, waiting for its re-read, or verified: the target may have it
	return removeFromTarget(tx, now, actor, ss, it, guest)
}

// removeFromTarget removes a membership: through provisioning (the edge goes
// when the removal is verified) or, with write-back off, at once.
func removeFromTarget(tx *store.TenantTx, now time.Time, actor string, ss *store.Sponsorship, it *store.BundleItem, guest *store.Identity) error {
	g, err := tx.Group(it.GroupID)
	if err != nil {
		return err
	}
	t, err := provision.Route(tx, g.System)
	if err != nil {
		return err
	}
	if t == nil {
		if it.EdgeID != nil {
			if err := tx.DeleteEdge(*it.EdgeID); err != nil {
				return err
			}
		}
		return markRemoved(tx, now, actor, it, "")
	}
	uname, extID, have, err := accountIn(tx, guest, g.System)
	if err != nil {
		return err
	}
	if !have { // no account: nothing of ours is left in the target
		if it.EdgeID != nil {
			if err := tx.DeleteEdge(*it.EdgeID); err != nil {
				return err
			}
		}
		return markRemoved(tx, now, actor, it, "")
	}
	op, _, err := provision.Submit(tx, now, provision.Change{System: g.System, Kind: target.RemoveEntitlement,
		Account: target.Account{Username: uname, ExternalID: extID},
		Group:   target.Group{ExternalID: g.ExternalID, Name: g.Name}, Source: provision.SourceGuest,
		Key: fmt.Sprintf("guest:%s:%d:remove", ss.ID, g.ID), Completion: CompleteRemove, Data: itemRef{it.ID}})
	if err != nil {
		return err
	}
	it.Status, it.RemoveOpID, it.UpdatedAt = store.BundleRemoving, &op.ID, now
	if err := tx.SaveBundleItem(it); err != nil {
		return err
	}
	return audit(tx, now, actor, "guest.bundle.remove_requested", it, ojson.KV{Key: "op_id", Value: op.ID})
}

// completeRemove runs when the target confirmed the removal: the edge goes
// now, unless a live sponsorship asked for the group again meanwhile.
func completeRemove(tx *store.TenantTx, now time.Time, itemID string) error {
	it, err := getOrNil(tx.BundleItem(itemID))
	if err != nil || it == nil || it.Status == store.BundleRemoved {
		return err
	}
	if it.EdgeID != nil {
		if other, err := otherHolder(tx, it); err != nil {
			return err
		} else if other == nil {
			if err := tx.DeleteEdge(*it.EdgeID); err != nil {
				return err
			}
		}
	}
	return markRemoved(tx, now, System, it, "")
}

func markRemoved(tx *store.TenantTx, now time.Time, actor string, it *store.BundleItem, note string) error {
	it.Status, it.RemovedAt, it.UpdatedAt = store.BundleRemoved, &now, now
	if err := tx.SaveBundleItem(it); err != nil {
		return err
	}
	var extra []ojson.KV
	if note != "" {
		extra = append(extra, ojson.KV{Key: "note", Value: note})
	}
	return audit(tx, now, actor, "guest.bundle.remove", it, extra...)
}

// otherHolder is another item of the same guest and group, of a live
// sponsorship, that still needs the access.
func otherHolder(tx *store.TenantTx, it *store.BundleItem) (*store.BundleItem, error) {
	same, err := tx.BundleItems(store.BundleItemFilter{Guest: it.GuestID, Group: it.GroupID})
	if err != nil {
		return nil, err
	}
	for _, o := range same {
		if o.ID == it.ID || (o.Status != store.BundleGranted && o.Status != store.BundlePending) {
			continue
		}
		if ss, err := tx.Sponsorship(o.SponsorshipID); err != nil {
			return nil, err
		} else if ss.Live() {
			return o, nil
		}
	}
	return nil, nil
}
