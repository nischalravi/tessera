package merge

import (
	"strconv"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/correlation"
	"github.com/nischalravi/tessera/mvp/server/internal/guests/access"
	"github.com/nischalravi/tessera/mvp/server/internal/notify"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Window is how long a merge can be undone in this tenant: 180 days unless the
// tenant's matching settings say otherwise.
func Window(tx *store.TenantTx) (time.Duration, error) {
	s, err := tx.MatchingSettings()
	if err != nil {
		return 0, err
	}
	return time.Duration(s.UnmergeWindowDays) * 24 * time.Hour, nil
}

// Later is a row created after the merge that now belongs to the survivor. An
// unmerge leaves it there and lists it for a reviewer.
type Later struct {
	Table string    `json:"table"`
	ID    string    `json:"id"`
	At    time.Time `json:"at"`
}

// Unmerged is the result of an unmerge.
type Unmerged struct {
	*correlation.UnmergeResult
	CreatedAfter []Later
}

// Unmerge undoes a merge within the tenant's window: the recorded moves are
// replayed in reverse, the memberships are recomputed for both people, both are
// told, and the rows created since stay with the survivor and are listed.
// Credentials that were disabled by the merge are not restored: an administrator
// re-enables a user deliberately.
func Unmerge(tx *store.TenantTx, mergeID, reason string, actor Actor, now time.Time) (*Unmerged, error) {
	window, err := Window(tx)
	if err != nil {
		return nil, err
	}
	res, err := correlation.UnmergeWithin(tx, mergeID, reason, actor.UserID, now, window)
	if err != nil {
		return nil, err
	}
	m := res.Merge
	later, err := createdAfter(tx, m)
	if err != nil {
		return nil, err
	}
	for _, id := range []int64{m.SurvivorID, m.MergedID} {
		if err := access.Merged(tx, now, actor.Display, id); err != nil {
			return nil, err
		}
		to, err := notify.ContactsOf(tx, id)
		if err != nil {
			return nil, err
		}
		if err := notify.IdentitySeparated(tx, now, m.ID+":"+idStr(id), to); err != nil {
			return nil, err
		}
	}
	return &Unmerged{UnmergeResult: res, CreatedAfter: later}, tx.Audit(now, actor.Display, "identity.unmerge", ojson.Object{
		{Key: "merge_id", Value: m.ID}, {Key: "merged_id", Value: m.MergedID}, {Key: "survivor_id", Value: m.SurvivorID},
		{Key: "restored", Value: movesView(res.Restored)}, {Key: "kept", Value: movesView(res.Kept)},
		{Key: "created_after", Value: later}, {Key: "reason", Value: *m.UnmergeReason}})
}

func idStr(n int64) string { return strconv.FormatInt(n, 10) }

// createdAfter lists the survivor's rows created after the merge that the merge
// did not move.
func createdAfter(tx *store.TenantTx, m *store.IdentityMerge) ([]Later, error) {
	moved := map[string]bool{}
	for _, mv := range m.Moves {
		moved[mv.Table+"/"+mv.Key] = true
	}
	out := []Later{}
	add := func(table, id string, at time.Time) {
		if at.After(m.MergedAt) && !moved[table+"/"+id] {
			out = append(out, Later{table, id, at})
		}
	}
	srcs, err := tx.SourceRecordsFor(m.SurvivorID)
	if err != nil {
		return nil, err
	}
	for _, r := range srcs {
		add("identity_source_records", r.ID, r.ReceivedAt)
	}
	ids, err := tx.IdentifiersFor(m.SurvivorID)
	if err != nil {
		return nil, err
	}
	for _, x := range ids {
		add("identity_identifiers", x.ID, x.CreatedAt)
	}
	affs, err := tx.AffiliationsFor(m.SurvivorID)
	if err != nil {
		return nil, err
	}
	for _, a := range affs {
		add("affiliations", a.ID, a.CreatedAt)
	}
	sps, err := tx.Sponsorships(store.SponsorshipFilter{Guest: m.SurvivorID})
	if err != nil {
		return nil, err
	}
	for _, sp := range sps {
		add("sponsorships", sp.ID, sp.CreatedAt)
	}
	items, err := tx.BundleItems(store.BundleItemFilter{Guest: m.SurvivorID})
	if err != nil {
		return nil, err
	}
	for _, it := range items {
		add("guest_bundle_items", it.ID, it.CreatedAt)
	}
	return out, nil
}
