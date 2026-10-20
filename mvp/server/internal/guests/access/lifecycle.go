package access

import (
	"context"
	"errors"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Sweeper is the actor of the periodic reconcile.
const Sweeper = "guest.access.sweeper"

// Claimed is what a completed claim sets in motion: the assurance the guest
// reached is recorded, the bundles of their live sponsorships are granted and
// they join the reference groups of their affiliations.
func Claimed(tx *store.TenantTx, now time.Time, guestID int64, ial, aal int) error {
	if err := tx.PutIdentityAssurance(&store.Assurance{IdentityID: guestID, IAL: ial, AAL: aal, Source: "claim", RecordedAt: now}); err != nil {
		return err
	}
	if err := GrantPending(tx, guestID, "claim", now); err != nil {
		return err
	}
	_, err := Recompute(tx, now, "claim", guestID, nil)
	return err
}

type stale struct {
	ended     []*store.BundleItem // bundle of a sponsorship that is over
	missing   []*store.BundleItem // granted, but the edge is gone (revoked elsewhere)
	ungranted []*store.BundleItem // waiting, with nothing asked of the target yet
}

func (s stale) n() int { return len(s.ended) + len(s.missing) + len(s.ungranted) }

func scan(tx *store.TenantTx) (stale, error) {
	var out stale
	for _, st := range []string{store.BundlePending, store.BundleGranted} {
		items, err := tx.BundleItems(store.BundleItemFilter{Status: st})
		if err != nil {
			return out, err
		}
		for _, it := range items {
			ss, err := tx.Sponsorship(it.SponsorshipID)
			if err != nil {
				return out, err
			}
			switch {
			case !ss.Live():
				out.ended = append(out.ended, it)
			case st == store.BundleGranted && it.EdgeID != nil:
				if _, err := tx.Edge(*it.EdgeID); errors.Is(err, store.ErrNotFound) {
					out.missing = append(out.missing, it)
				} else if err != nil {
					return out, err
				}
			case st == store.BundlePending && it.GrantOpID == nil:
				if g, err := tx.Identity(it.GuestID); err != nil {
					return out, err
				} else if g.Status == "active" {
					out.ungranted = append(out.ungranted, it)
				}
			}
		}
	}
	return out, nil
}

// NeedsReconcile reports whether Reconcile would change anything.
func NeedsReconcile(tx *store.TenantTx) (bool, error) {
	s, err := scan(tx)
	return s.n() > 0, err
}

// Reconcile repairs what the events missed: the bundle of a sponsorship that
// is over (ended some other way) is removed, an item whose edge was taken
// away elsewhere (an access review, the leaver plan) is recorded as removed,
// and a claimed guest's waiting items are granted.
func Reconcile(tx *store.TenantTx, now time.Time, actor string) (int, error) {
	s, err := scan(tx)
	if err != nil {
		return 0, err
	}
	for _, it := range s.ended {
		ss, err := tx.Sponsorship(it.SponsorshipID)
		if err != nil {
			return 0, err
		}
		if err := endItem(tx, now, actor, ss, it); err != nil {
			return 0, err
		}
	}
	for _, it := range s.missing {
		if err := markRemoved(tx, now, actor, it, "its edge was removed elsewhere"); err != nil {
			return 0, err
		}
	}
	for _, it := range s.ungranted {
		ss, err := tx.Sponsorship(it.SponsorshipID)
		if err != nil {
			return 0, err
		}
		guest, err := tx.Identity(it.GuestID)
		if err != nil {
			return 0, err
		}
		if err := grantItem(tx, now, actor, guest, ss, it); err != nil {
			return 0, err
		}
	}
	return s.n(), nil
}

// SweepAll reconciles every active tenant, each in its own transaction (the
// background sweeper): the bundles, then the reference groups. A tenant with
// nothing to do is left untouched. eligible is the sponsor policy's answer.
func SweepAll(ctx context.Context, db *store.DB, now time.Time, eligible Eligibility) error {
	return db.ForEachActiveTenant(ctx, func(_ context.Context, tx *store.TenantTx) error {
		return SweepTenant(tx, now, eligible)
	})
}

// SweepTenant is SweepAll for one tenant inside the caller's transaction (the
// durable queue's lifecycle job).
func SweepTenant(tx *store.TenantTx, now time.Time, eligible Eligibility) error {
	if need, err := NeedsReconcile(tx); err != nil {
		return err
	} else if need {
		if _, err := Reconcile(tx, now, Sweeper); err != nil {
			return err
		}
	}
	if need, err := NeedsRecompute(tx, now, eligible); err != nil || !need {
		return err
	}
	_, err := Recompute(tx, now, Sweeper, 0, eligible)
	return err
}
