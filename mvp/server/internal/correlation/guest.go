package correlation

import (
	"errors"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// guestMoves lists what a merge re-points from the guest data model (schema
// 0226, 0227, 0229, 0205): the person's source records, identifiers,
// affiliations, sponsorships, access bundle items, lifecycle record and
// pending access requests. It refuses a merge that would make a person their
// own sponsor.
//
// Not moved: the assurance level (it belongs to the credentials' evidence, and
// credentials never move), claim tokens and sessions (the claim of the merged
// person's intake ends with the merge), and history (events, usage, decided
// requests).
func guestMoves(tx *store.TenantTx, mergedID, survivorID int64) ([]store.MergeMove, error) {
	var out []store.MergeMove
	srcs, err := tx.SourceRecordsFor(mergedID)
	if err != nil {
		return nil, err
	}
	for _, r := range srcs {
		out = append(out, store.MergeMove{Table: "identity_source_records", Key: r.ID, Column: "identity_id"})
	}
	ids, err := tx.IdentifiersFor(mergedID)
	if err != nil {
		return nil, err
	}
	for _, x := range ids {
		out = append(out, store.MergeMove{Table: "identity_identifiers", Key: x.ID, Column: "identity_id"})
	}
	affs, err := tx.AffiliationsFor(mergedID)
	if err != nil {
		return nil, err
	}
	for _, a := range affs {
		out = append(out, store.MergeMove{Table: "affiliations", Key: a.ID, Column: "identity_id"})
	}
	asGuest, err := tx.Sponsorships(store.SponsorshipFilter{Guest: mergedID})
	if err != nil {
		return nil, err
	}
	for _, sp := range asGuest {
		if sp.SponsorIdentityID == survivorID {
			return nil, refuse(409, "sponsorship_conflict", "the person to merge is a guest of the person they would merge into")
		}
		out = append(out, store.MergeMove{Table: "sponsorships", Key: sp.ID, Column: "guest_identity_id"})
	}
	asSponsor, err := tx.Sponsorships(store.SponsorshipFilter{Sponsor: mergedID})
	if err != nil {
		return nil, err
	}
	for _, sp := range asSponsor {
		if sp.GuestIdentityID == survivorID {
			return nil, refuse(409, "sponsorship_conflict", "the person to merge sponsors the person they would merge into")
		}
		if sp.Live() || sp.Status == store.SponsorTransferPending { // a final sponsorship stays history
			out = append(out, store.MergeMove{Table: "sponsorships", Key: sp.ID, Column: "sponsor_identity_id"})
		}
	}
	items, err := tx.BundleItems(store.BundleItemFilter{Guest: mergedID})
	if err != nil {
		return nil, err
	}
	for _, it := range items {
		out = append(out, store.MergeMove{Table: "guest_bundle_items", Key: it.ID, Column: "guest_identity_id"})
	}
	// one lifecycle record per person: the merged person's moves only if the survivor has none
	if _, err := tx.LifecycleFor(survivorID); errors.Is(err, store.ErrNotFound) {
		if id, err := tx.LifecycleRowID(mergedID); err == nil {
			out = append(out, store.MergeMove{Table: "identity_lifecycle", ID: id, Column: "identity_id"})
		} else if !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	// pending requests move unless the survivor already has an open one for the same group
	lines, err := tx.RequestLines(store.RequestFilter{Beneficiary: mergedID, Status: "pending"})
	if err != nil {
		return nil, err
	}
	for _, l := range lines {
		if _, err := tx.OpenRequestLine(survivorID, l.GroupID); err == nil {
			continue
		} else if !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
		out = append(out, store.MergeMove{Table: "access_request_lines", Key: l.ID, Column: "beneficiary_id"})
	}
	return out, nil
}
