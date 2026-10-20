package guestlife

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/jml"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/provision"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Deprovisioning (design §8.5). When a person's last sponsorship ends the
// lifecycle's leaver plan has already run (sponsorship-sourced memberships and
// time-bound grants end, accounts are disabled through provisioning and
// verified by re-read). This file adds what follows:
//
//   - at once: the person's sign-in sessions are revoked and a stage row starts
//     the grace period (0 days for visitors by default, 30 for the others);
//   - after the grace period, once every operation that ended their access is
//     verified: accounts in targets that ask for it are deleted, the NHI and
//     other ownership they still hold is reassigned, and the identity becomes
//     "deprovisioned";
//   - after the retention period (7 years for anyone who held access to in-scope
//     systems, 1 year for a visitor who held none): the person's operational
//     personal data is reduced to a tombstone. The audit ledger is not touched.

// DeprovisionResult counts what a deprovisioning pass did.
type DeprovisionResult struct{ Started, Deprovisioned, Purged, Blocked int }

// Deprovision starts the grace period of people whose last sponsorship ended,
// completes the grace period of those whose time is up and purges those whose
// retention is over. Every step is audited and idempotent: a stage row moves
// forward once.
func (s *Service) Deprovision(tx *store.TenantTx, now time.Time) (DeprovisionResult, error) {
	var res DeprovisionResult
	set, err := tx.GuestLifecycleSettings()
	if err != nil {
		return res, err
	}
	ids, err := tx.AwaitingDeprovisioning()
	if err != nil {
		return res, err
	}
	for _, id := range ids {
		ok, err := s.startGrace(tx, id, set, now)
		if err != nil {
			return res, err
		}
		if ok {
			res.Started++
		}
	}
	rows, err := tx.DeprovisioningList(store.StageGrace)
	if err != nil {
		return res, err
	}
	for _, d := range rows {
		if d.GraceUntil.After(now) {
			continue
		}
		done, err := s.finishGrace(tx, d, now)
		if err != nil {
			return res, err
		}
		if done {
			res.Deprovisioned++
		} else {
			res.Blocked++
		}
	}
	rows, err = tx.DeprovisioningList(store.StageDeprovisioned)
	if err != nil {
		return res, err
	}
	for _, d := range rows {
		if d.RetentionUntil.After(now) {
			continue
		}
		if err := s.purge(tx, d, set, now); err != nil {
			return res, err
		}
		res.Purged++
	}
	return res, nil
}

// lastPopulation is the population of the person's most recent sponsorship.
func lastPopulation(sps []*store.Sponsorship) string {
	var last *store.Sponsorship
	for _, x := range sps {
		t := x.EndsAt
		if x.EndedAt != nil {
			t = *x.EndedAt
		}
		l := time.Time{}
		if last != nil {
			l = last.EndsAt
			if last.EndedAt != nil {
				l = *last.EndedAt
			}
		}
		if last == nil || t.After(l) {
			last = x
		}
	}
	if last == nil {
		return store.PopVisitor
	}
	return last.Population
}

func (s *Service) startGrace(tx *store.TenantTx, id int64, set store.GuestLifecycleSettings, now time.Time) (bool, error) {
	person, err := tx.Identity(id)
	if err != nil {
		return false, err
	}
	sps, err := tx.Sponsorships(store.SponsorshipFilter{Guest: id})
	if err != nil {
		return false, err
	}
	for _, x := range sps {
		if x.Live() || x.Status == store.SponsorPendingApproval || x.Status == store.SponsorRequested {
			return false, nil // somebody still stands behind them
		}
	}
	if emp, err := hiredFrom(tx, id, now); err != nil || emp != nil {
		return false, err
	}
	pop := lastPopulation(sps)
	held, err := tx.HeldBundleAccess(id)
	if err != nil {
		return false, err
	}
	accts, err := tx.IdentityAccounts(id)
	if err != nil {
		return false, err
	}
	hasAccess := held > 0 || len(accts) > 0
	ended := now
	if person.TerminatedAt != nil {
		ended = *person.TerminatedAt
	}
	retention := set.RetentionDays
	if !hasAccess && pop == store.PopVisitor {
		retention = set.RetentionDaysVisitor
	}
	grace := ended.AddDate(0, 0, set.GraceDays[pop])
	d := &store.Deprovisioning{IdentityID: id, Population: pop, HeldAccess: hasAccess, EndedAt: ended, GraceUntil: grace,
		RetentionUntil: grace.AddDate(0, 0, retention), UpdatedAt: now}
	if _, err := tx.Deprovisioning(id); err == nil {
		err = tx.RestartDeprovisioning(d) // came back once and left again
		if err != nil {
			return false, err
		}
	} else if errors.Is(err, store.ErrNotFound) {
		if err := tx.InsertDeprovisioning(d); err != nil {
			return false, err
		}
	} else {
		return false, err
	}
	revoked, err := revokeSessions(tx, id, now)
	if err != nil {
		return false, err
	}
	return true, tx.Audit(now, Sweeper, "guest.deprovision.start", ojson.Object{kv("identity_id", id), kv("population", pop),
		kv("held_access", hasAccess), kv("sessions_revoked", revoked), kv("grace_until", iso(d.GraceUntil)),
		kv("retention_until", iso(d.RetentionUntil))})
}

// revokeSessions ends every sign-in session of the people who sign in as this identity.
func revokeSessions(tx *store.TenantTx, identityID int64, now time.Time) (int64, error) {
	users, err := tx.UsersLinkedTo(identityID)
	if err != nil {
		return 0, err
	}
	var n int64
	for _, u := range users {
		id, err := uuid.Parse(u)
		if err != nil {
			continue
		}
		k, err := tx.RevokeUserSessions(id, "guest lifecycle: last affiliation ended", now)
		if err != nil {
			return n, err
		}
		n += k
	}
	return n, nil
}

// unverified counts the provisioning operations that ended this person's access
// and are not verified yet: queued, sent, awaiting their re-read, or failed.
// (The leaver plan's operations are keyed "lifecycle:<id>:..." and a bundle's
// "guest:<sponsorship>:...".)
func unverified(tx *store.TenantTx, identityID int64) (int, error) {
	ops, err := tx.ProvOps(store.ProvOpFilter{})
	if err != nil {
		return 0, err
	}
	sps, err := tx.Sponsorships(store.SponsorshipFilter{Guest: identityID})
	if err != nil {
		return 0, err
	}
	prefixes := []string{fmt.Sprintf("lifecycle:%d:", identityID), fmt.Sprintf("guestlife:%d:", identityID)}
	for _, x := range sps {
		prefixes = append(prefixes, "guest:"+x.ID+":")
	}
	n := 0
	for _, o := range ops {
		match := false
		for _, p := range prefixes {
			match = match || strings.HasPrefix(o.IdempotencyKey, p)
		}
		if !match || o.Status == provision.Verified {
			continue
		}
		if o.Status == provision.Cancelled {
			continue
		}
		n++
	}
	return n, nil
}

func (s *Service) finishGrace(tx *store.TenantTx, d *store.Deprovisioning, now time.Time) (bool, error) {
	if n, err := unverified(tx, d.IdentityID); err != nil || n > 0 {
		return false, err // the target has not confirmed that access ended: wait
	}
	person, err := tx.Identity(d.IdentityID)
	if err != nil {
		return false, err
	}
	if person.Status != "terminated" { // active again by some other path: nothing to deprovision
		return false, nil
	}
	deletes, err := deleteAccounts(tx, d.IdentityID, now)
	if err != nil {
		return false, err
	}
	reassigned, err := jml.ExecuteLeaverSteps(tx, now, d.IdentityID, fmt.Sprintf("guestlife:%d:grace", d.IdentityID),
		"reassign_owner", "rotate_secret", "revoke_delegation", "reassign_reports")
	if err != nil {
		return false, err
	}
	if err := tx.SetIdentityStatus(d.IdentityID, store.StageDeprovisioned); err != nil {
		return false, err
	}
	if err := tx.AdvanceDeprovisioning(d.IdentityID, store.StageGrace, store.StageDeprovisioned, now); err != nil {
		return false, err
	}
	return true, tx.Audit(now, Sweeper, "guest.deprovision.complete", ojson.Object{kv("identity_id", d.IdentityID),
		kv("account_deletes_requested", deletes), kv("ownership_steps", reassigned)})
}

// deleteAccounts asks the targets that are set to delete accounts on
// deprovisioning to delete this person's (disabled) account. A target without
// write-back, or one left on "disable", keeps the account disabled.
func deleteAccounts(tx *store.TenantTx, identityID int64, now time.Time) (int, error) {
	accts, err := tx.IdentityAccounts(identityID)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, a := range accts {
		if a.Status != "disabled" {
			continue
		}
		t, err := provision.Route(tx, a.System)
		if err != nil || t == nil {
			if err != nil {
				return n, err
			}
			continue
		}
		var st provision.Settings
		if json.Unmarshal([]byte(t.Settings), &st) != nil || st.OnDeprovision != "delete" {
			continue
		}
		if _, err := provision.Enqueue(tx, now, t.ConnectionID, provision.Change{System: a.System, Kind: target.DeleteAccount,
			Account: target.Account{Username: a.Username, ExternalID: a.ExternalID}, Source: provision.SourceJML,
			Key: fmt.Sprintf("guestlife:%d:delete:%d", identityID, a.ID), Completion: provision.CompleteAccountDelete,
			Data: provision.AccountData{AccountID: a.ID}, NoRequeue: true}); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// purge reduces the person's operational records to a tombstone and records the
// stage. A person already purged only has the stage recorded: running it twice
// changes nothing more.
func (s *Service) purge(tx *store.TenantTx, d *store.Deprovisioning, set store.GuestLifecycleSettings, now time.Time) error {
	rep, err := tx.PurgeIdentityPII(d.IdentityID, set.KeepRematchHashes)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if err := tx.AdvanceDeprovisioning(d.IdentityID, store.StageDeprovisioned, store.StagePurged, now); err != nil {
		return err
	}
	// counts only: never the values
	return tx.Audit(now, Sweeper, "guest.purge", ojson.Object{kv("identity_id", d.IdentityID), kv("identity_record", rep.Identity),
		kv("identifiers", rep.Identifiers), kv("source_records", rep.SourceRecords), kv("platform_users", rep.Users),
		kv("external_logins", rep.Logins), kv("notifications", rep.Notifications), kv("email_messages", rep.Messages),
		kv("kept_identifier_hashes", set.KeepRematchHashes), kv("audit_ledger_modified", false)})
}
