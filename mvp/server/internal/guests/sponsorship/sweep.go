package sponsorship

import (
	"context"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// SweepResult counts what a sweep did.
type SweepResult struct{ Expired, TransferExpired int }

// NeedsSweep reports whether Sweep would change anything at now.
func NeedsSweep(tx *store.TenantTx, now time.Time) (bool, error) {
	due, err := tx.DueSponsorships(now)
	return len(due) > 0, err
}

// Sweep ends the sponsorships whose end date has passed (a sponsorship waiting
// for approval at its end is rejected) and those whose transfer was not
// accepted by its deadline. Each one lets the guest's lifecycle follow, so a
// person whose last sponsorship ends is ended too. It runs before the
// lifecycle sweep, which then finds nothing left to end.
func (s *Service) Sweep(tx *store.TenantTx, now time.Time) (SweepResult, error) {
	var res SweepResult
	due, err := tx.DueSponsorships(now)
	if err != nil {
		return res, err
	}
	by := Actor{Display: Sweeper}
	for _, ss := range due {
		ss.PolicyVersion = s.Policy.Version
		transfer := ss.Status == store.SponsorTransferPending && ss.TransferDeadline != nil && !ss.TransferDeadline.After(now) &&
			ss.EndsAt.After(now)
		switch {
		case transfer:
			if err := s.finalize(tx, ss, store.SponsorEnded, "transfer_expired", "the transfer was not accepted by its deadline", by, now); err != nil {
				return res, err
			}
			res.TransferExpired++
		case ss.Status == store.SponsorPendingApproval:
			if err := s.finalize(tx, ss, store.SponsorRejected, "rejected", "not approved before its end date", by, now); err != nil {
				return res, err
			}
			res.Expired++
		default:
			if err := s.finalize(tx, ss, store.SponsorEnded, "expired", "the term ended", by, now); err != nil {
				return res, err
			}
			res.Expired++
		}
		action := "sponsorship.expire"
		if transfer {
			action = "sponsorship.transfer_expire"
		}
		if err := tx.Audit(now, Sweeper, action, detail(ss, ojson.KV{Key: "reason", Value: *ss.EndReason})); err != nil {
			return res, err
		}
	}
	return res, nil
}

// SweepAll runs Sweep for every active tenant in its own transaction (the
// background sweeper); a tenant with nothing due is left untouched.
func (s *Service) SweepAll(ctx context.Context, db *store.DB, now time.Time) error {
	return db.ForEachActiveTenant(ctx, func(_ context.Context, tx *store.TenantTx) error {
		need, err := NeedsSweep(tx, now)
		if err != nil || !need {
			return err
		}
		_, err = s.Sweep(tx, now)
		return err
	})
}
