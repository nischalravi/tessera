package register

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/guests/sponsorship"
	"github.com/nischalravi/tessera/mvp/server/internal/notify"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Pending lists the requests waiting for the sponsor (the signed-in person),
// oldest first. A request that is past its time is not offered.
func (s *Service) Pending(tx *store.TenantTx, by sponsorship.Actor, now time.Time) ([]*store.Registration, error) {
	if by.IdentityID == nil {
		return []*store.Registration{}, nil
	}
	all, err := tx.RegistrationsForSponsor(*by.IdentityID, store.RegPending)
	if err != nil {
		return nil, err
	}
	out := all[:0]
	for _, r := range all {
		if r.ExpiresAt.After(now) {
			out = append(out, r)
		}
	}
	return out, nil
}

// mine loads a request the signed-in person may decide: theirs and pending.
// Another sponsor's request, another tenant's and an unknown id all answer
// the same 404.
func (s *Service) mine(tx *store.TenantTx, by sponsorship.Actor, id string, now time.Time) (*store.Registration, error) {
	r, err := tx.Registration(id)
	if errors.Is(err, store.ErrNotFound) || (err == nil && !by.Is(r.SponsorIdentityID)) {
		return nil, refuse(404, "registration_not_found", "registration request not found")
	}
	if err != nil {
		return nil, err
	}
	if r.Status != store.RegPending || !r.ExpiresAt.After(now) {
		return nil, refuse(409, "registration_not_pending", "this request was already decided or has expired")
	}
	return r, nil
}

// Approval is the sponsor's terms for an approved request. Zero values take the
// visitor's own: the "visitor" population and the dates they asked for.
type Approval struct {
	Population string
	EndsAt     time.Time
}

// Approve is the sponsor's yes: the guest is created through the ordinary
// invitation path (the sponsor policy still decides, and refuses with its own
// codes), which issues the claim link, and the request is closed and reduced to
// a tombstone. Only the named sponsor can approve.
func (s *Service) Approve(tx *store.TenantTx, by sponsorship.Actor, id string, in Approval, now time.Time) (*sponsorship.Result, error) {
	r, err := s.mine(tx, by, id, now)
	if err != nil {
		return nil, err
	}
	if r.GivenName == nil || r.FamilyName == nil || r.Email == nil || r.Purpose == nil {
		return nil, refuse(409, "registration_not_pending", "this request no longer holds its data")
	}
	pop := strings.ToLower(strings.TrimSpace(in.Population))
	if pop == "" {
		pop = store.PopVisitor
	}
	ends := in.EndsAt.UTC()
	if in.EndsAt.IsZero() {
		ends = r.EndsAt
	}
	inv := sponsorship.Invite{GivenName: *r.GivenName, FamilyName: *r.FamilyName, Email: *r.Email, Population: pop,
		Purpose: *r.Purpose, EndsAt: ends}
	if r.StartsAt.After(now) {
		inv.StartsAt = r.StartsAt
	}
	res, err := s.Guests.Invite(tx, by, inv, Channel, "", now)
	if err != nil {
		return nil, err
	}
	by2 := by.UserPtr()
	intake := res.Sponsorship.IntakeID
	if err := tx.DecideRegistration(r.ID, store.RegApproved, by2, &res.Guest.ID, &intake, now, now); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, refuse(409, "registration_not_pending", "this request was already decided")
		}
		return nil, err
	}
	// the person record holds the data from now on
	if err := tx.RedactRegistration(r.ID, now); err != nil {
		return nil, err
	}
	return res, s.audit(tx, now, "guest.registration.approve", r.ID, ojson.Object{{Key: "registration_id", Value: r.ID},
		{Key: "sponsor_identity_id", Value: r.SponsorIdentityID}, {Key: "guest_identity_id", Value: res.Guest.ID},
		{Key: "sponsorship_id", Value: res.Sponsorship.ID}, {Key: "intake_id", Value: intake}}, store.OutcomeSuccess)
}

// Deny is the sponsor's no: nothing was created, and the visitor gets a neutral
// email that names nobody and gives no reason. The reason, if the sponsor wrote
// one, is for the ledger only.
func (s *Service) Deny(tx *store.TenantTx, by sponsorship.Actor, id, reason string, now time.Time) error {
	r, err := s.mine(tx, by, id, now)
	if err != nil {
		return err
	}
	reason = strings.TrimSpace(reason)
	if len(reason) > sponsorship.MaxReason || hasControl(reason) {
		return refuse(422, "invalid_reason", "a reason is at most %d characters", sponsorship.MaxReason)
	}
	if err := tx.DecideRegistration(r.ID, store.RegDenied, by.UserPtr(), nil, nil, now.Add(s.retention()), now); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return refuse(409, "registration_not_pending", "this request was already decided")
		}
		return err
	}
	if err := notify.RegistrationDenied(tx, now, r, s.tenantName(tx.Context(), tx.Tenant())); err != nil {
		return err
	}
	return s.audit(tx, now, "guest.registration.deny", r.ID, ojson.Object{{Key: "registration_id", Value: r.ID},
		{Key: "sponsor_identity_id", Value: r.SponsorIdentityID}, {Key: "reason", Value: reason}}, store.OutcomeSuccess)
}

// SweepResult counts what a sweep did.
type SweepResult struct{ Expired, Redacted int }

// NeedsSweep reports whether the tenant holds any request with personal data.
func NeedsSweep(tx *store.TenantTx) (bool, error) {
	n, err := tx.RegistrationsHoldingData()
	return n > 0, err
}

// Sweep expires the pending requests whose time passed (nothing is created, the
// visitor is not written to) and reduces the denied and expired ones past their
// retention to tombstones, so no personal data of a registration outlives
// its retention.
func (s *Service) Sweep(tx *store.TenantTx, now time.Time) (SweepResult, error) {
	var res SweepResult
	due, err := tx.DueRegistrations(now)
	if err != nil {
		return res, err
	}
	for _, r := range due {
		if err := tx.DecideRegistration(r.ID, store.RegExpired, nil, nil, nil, now.Add(s.retention()), now); err != nil {
			return res, err
		}
		if err := s.audit(tx, now, "guest.registration.expire", r.ID, ojson.Object{{Key: "registration_id", Value: r.ID},
			{Key: "sponsor_identity_id", Value: r.SponsorIdentityID}}, store.OutcomeSuccess); err != nil {
			return res, err
		}
		res.Expired++
	}
	if res.Redacted, err = tx.RedactDueRegistrations(now); err != nil {
		return res, err
	}
	if res.Redacted > 0 {
		err = s.audit(tx, now, "guest.registration.purge", "", ojson.Object{{Key: "registrations", Value: res.Redacted}}, store.OutcomeSuccess)
	}
	return res, err
}

// SweepAll runs Sweep for every active tenant that holds a request, each in its
// own transaction.
func (s *Service) SweepAll(ctx context.Context, db *store.DB, now time.Time) error {
	return db.ForEachActiveTenant(ctx, func(_ context.Context, tx *store.TenantTx) error {
		need, err := NeedsSweep(tx)
		if err != nil || !need {
			return err
		}
		_, err = s.Sweep(tx, now)
		return err
	})
}
