package merge

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/identity/affiliations"
	"github.com/nischalravi/tessera/mvp/server/internal/identity/match"
	"github.com/nischalravi/tessera/mvp/server/internal/notify"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Review decisions (design §5.6).
const (
	DecisionLink      = "link"
	DecisionNewPerson = "new_person"
	DecisionReject    = "reject"
)

// Hooks are what a decision needs from packages that import this one.
type Hooks struct {
	// RejectIntake ends the invitation and the sponsorship of a rejected intake
	// (fraud, a duplicate request).
	RejectIntake func(tx *store.TenantTx, intakeID string, subject *int64, reason string, now time.Time) error
}

// Decided is the result of a review decision.
type Decided struct {
	Match   *store.MatchResult
	Outcome *Outcome // a link: applied, pending a second reviewer, or waiting for re-verification
}

// Decide records a reviewer's decision on a queued match result: link the
// intake's person to the candidate, keep them as a new person, or reject the
// intake. A reason is required. A link goes through Request, so it needs a
// second reviewer where the risk says so, and the claimant's IAL must reach
// the candidate's before anything is linked.
func Decide(tx *store.TenantTx, matchID, decision, reason string, actor Actor, h Hooks, now time.Time) (*Decided, error) {
	r, err := checkReason(reason)
	if err != nil {
		return nil, err
	}
	row, err := tx.MatchResult(matchID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(404, "match_not_found", "match not found")
	} else if err != nil {
		return nil, err
	}
	if row.Status != store.MatchReview && row.Status != store.MatchReverification {
		return nil, refuse(409, "already_decided", "this match was already decided")
	}
	switch decision {
	case DecisionLink:
		if row.CandidateID == nil {
			return nil, refuse(422, "no_candidate", "there is no candidate to link to")
		}
		if row.SubjectID == nil {
			return nil, refuse(409, "no_provisional_person", "the intake has no person of its own to link")
		}
		out, err := Request(tx, Input{MergedID: *row.SubjectID, SurvivorID: *row.CandidateID, Reason: r, Basis: BasisReviewer, MatchID: row.ID}, actor, now)
		if err != nil {
			return nil, err
		}
		if row, err = tx.MatchResult(row.ID); err != nil {
			return nil, err
		}
		return &Decided{Match: row, Outcome: out}, nil
	case DecisionNewPerson, DecisionReject:
	default:
		return nil, refuse(422, "invalid_decision", "decision is link, new_person or reject")
	}
	status, dec, intakeStatus := store.MatchNewPerson, "new", store.IntakeResolved
	if decision == DecisionReject {
		status, dec, intakeStatus = store.MatchRejected, "reject", store.IntakeRejected
	}
	rows, err := tx.MatchResults(store.MatchFilter{Intake: row.IntakeID})
	if err != nil {
		return nil, err
	}
	for _, x := range rows {
		if x.Status != store.MatchReview && x.Status != store.MatchReverification {
			continue
		}
		d := store.MatchResult{ID: x.ID, Status: store.MatchSuperseded, DecidedAt: &now}
		if x.ID == row.ID {
			by := actor.UserID
			d = store.MatchResult{ID: x.ID, Status: status, Decision: &dec, DecidedBy: &by, Reason: &r, DecidedAt: &now}
		}
		if err := tx.DecideMatchResult(&d); err != nil {
			return nil, err
		}
	}
	if err := tx.SetIntakeStatus(row.IntakeID, intakeStatus); err != nil {
		return nil, err
	}
	if decision == DecisionReject && h.RejectIntake != nil {
		if err := h.RejectIntake(tx, row.IntakeID, row.SubjectID, r, now); err != nil {
			return nil, err
		}
	}
	if err := tx.Audit(now, actor.Display, "identity.match.decide", ojson.Object{{Key: "match_id", Value: row.ID},
		{Key: "intake_id", Value: row.IntakeID}, {Key: "decision", Value: decision}, {Key: "candidate_id", Value: row.CandidateID},
		{Key: "reason", Value: r}}); err != nil {
		return nil, err
	}
	row, err = tx.MatchResult(row.ID)
	return &Decided{Match: row}, err
}

// recordReverification records a reviewer's link that may not be applied yet:
// the claimant is below the existing person's IAL, so nothing is linked and no
// access is granted until the claimant signs in as the existing person.
func recordReverification(tx *store.TenantTx, row *store.MatchResult, reason string, first, exec Actor, second *Actor, have, need int, now time.Time) error {
	dec, by := DecisionLink, first.UserID
	d := store.MatchResult{ID: row.ID, Status: store.MatchReverification, Decision: &dec, DecidedBy: &by, Reason: &reason, DecidedAt: &now}
	if second != nil {
		d.SecondReviewer = &second.UserID
	}
	if err := tx.DecideMatchResult(&d); err != nil {
		return err
	}
	return tx.Audit(now, exec.Display, "identity.match.reverification_required", ojson.Object{{Key: "match_id", Value: row.ID},
		{Key: "intake_id", Value: row.IntakeID}, {Key: "candidate_id", Value: row.CandidateID}, {Key: "claimant_ial", Value: have},
		{Key: "required_ial", Value: need}, {Key: "reason", Value: reason}})
}

// finishMatch records a link that was applied: the result is linked, its
// siblings are superseded, and the intake is resolved. A link by sign-in also
// keeps the rule that fired as a result of its own, so the explanation is there.
func finishMatch(tx *store.TenantTx, row *store.MatchResult, m *store.IdentityMerge, reason string, first, exec Actor, second *Actor, basis Basis, now time.Time) error {
	dec := DecisionLink
	if basis == BasisSignIn {
		dec = store.MatchOutcomeAutoLink
	}
	by := first.UserID
	d := store.MatchResult{ID: row.ID, Status: store.MatchLinked, Decision: &dec, DecidedBy: &by, Reason: &reason, DecidedAt: &now, MergeID: &m.ID}
	if second != nil {
		d.SecondReviewer = &second.UserID
	}
	if err := tx.DecideMatchResult(&d); err != nil {
		return err
	}
	rows, err := tx.MatchResults(store.MatchFilter{Intake: row.IntakeID})
	if err != nil {
		return err
	}
	for _, x := range rows {
		if x.ID == row.ID || x.Status != store.MatchReview && x.Status != store.MatchReverification {
			continue
		}
		if err := tx.DecideMatchResult(&store.MatchResult{ID: x.ID, Status: store.MatchSuperseded, DecidedAt: &now}); err != nil {
			return err
		}
	}
	if basis == BasisSignIn {
		doc, err := json.Marshal(struct {
			Mode  match.Mode    `json:"mode"`
			Score float64       `json:"score"`
			Rules []match.Fired `json:"rules"`
		}{match.SelfAsserted, 1, []match.Fired{{Rule: match.RuleSignedIn, Tier: match.TierA, Score: 1, Why: "the claimant signed in as this person"}}})
		if err != nil {
			return err
		}
		cid, sid, al := m.SurvivorID, m.MergedID, store.MatchOutcomeAutoLink
		if err := tx.InsertMatchResult(&store.MatchResult{ID: uuid.NewString(), IntakeID: row.IntakeID, SubjectID: &sid, CandidateID: &cid,
			Tier: string(match.TierA), Score: 1, Rules: string(doc), Outcome: store.MatchOutcomeAutoLink, Status: store.MatchLinked,
			Decision: &al, DecidedBy: &by, Reason: &reason, DecidedAt: &now, MergeID: &m.ID, CreatedAt: now}); err != nil {
			return err
		}
	}
	if err := finishLinkedIntake(tx, m.SurvivorID, row.IntakeID, now); err != nil {
		return err
	}
	return tx.Audit(now, exec.Display, "identity.match.decide", ojson.Object{{Key: "match_id", Value: row.ID},
		{Key: "intake_id", Value: row.IntakeID}, {Key: "decision", Value: dec}, {Key: "candidate_id", Value: m.SurvivorID},
		{Key: "merge_id", Value: m.ID}, {Key: "reason", Value: reason}})
}

// finishLinkedIntake is what a link means for the intake that caused it: its
// person is the existing person, who already has credentials, so the invitation
// is done: the sponsorship's pending affiliations start and the sponsor is told.
func finishLinkedIntake(tx *store.TenantTx, survivor int64, intakeID string, now time.Time) error {
	in, err := tx.Intake(intakeID)
	if err != nil {
		return err
	}
	if in.InvitationStatus != store.InvitationClaimed {
		if _, err := tx.RevokeClaimTokens(intakeID); err != nil {
			return err
		}
		if err := tx.SetIntakeInvitation(intakeID, store.InvitationClaimed, now); err != nil {
			return err
		}
		all, err := tx.Sponsorships(store.SponsorshipFilter{Guest: survivor})
		if err != nil {
			return err
		}
		for _, ss := range all {
			if ss.IntakeID != intakeID || !ss.Live() {
				continue
			}
			a, err := affiliations.ForSponsorship(tx, survivor, ss.ID)
			if err != nil {
				return err
			}
			if a != nil && a.Status == store.AffPending {
				if err := tx.ActivateAffiliation(a.ID); err != nil {
					return err
				}
			}
			if err := notify.GuestClaimed(tx, now, ss); err != nil {
				return err
			}
		}
	}
	return tx.SetIntakeStatus(intakeID, store.IntakeResolved)
}

// LinkBySignIn links an intake by proof of possession (Tier A, §5.3): the
// claimant authenticated as personID during the claim. It links only when that
// person is a candidate of this intake's match; it answers false, changing
// nothing, when they are not. The caller has checked that the sign-in meets the
// sponsorship's assurance level. No reviewer is needed: the claimant holds the
// existing person's credential. Nothing is transferred and no credential is created.
func LinkBySignIn(tx *store.TenantTx, intakeID string, personID int64, actor Actor, now time.Time) (bool, *store.IdentityMerge, error) {
	rows, err := tx.MatchResults(store.MatchFilter{Intake: intakeID, Candidate: personID})
	if err != nil {
		return false, nil, err
	}
	var row *store.MatchResult
	for _, x := range rows {
		if (x.Status == store.MatchReview || x.Status == store.MatchReverification) && x.SubjectID != nil {
			row = x
		}
	}
	if row == nil {
		return false, nil, nil
	}
	subj, err := tx.Identity(*row.SubjectID)
	if err != nil {
		return false, nil, err
	}
	person, err := tx.Identity(personID)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil, nil
	} else if err != nil {
		return false, nil, err
	}
	if subj.Status == store.IdentityStatusMerged || person.Status != "active" {
		return false, nil, nil
	}
	const reason = "link by sign-in: the claimant authenticated as the existing person"
	in := Input{MergedID: subj.ID, SurvivorID: personID, Reason: reason, Basis: BasisSignIn, MatchID: row.ID}
	out, err := applyFor(tx, in, reason, actor, actor, nil, row, now)
	if err != nil {
		return false, nil, err
	}
	return true, out.Merge, nil
}
