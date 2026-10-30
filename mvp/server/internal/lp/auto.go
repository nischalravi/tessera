package lp

import (
	"errors"
	"fmt"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/lpauto"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Automatic mode (issue #664, LP-8; design docs/design/least-privilege-loop.md sections 3, 4, 10 and 11). In auto
// mode a candidate that the tenant's policy covers is announced without a person approving the batch: silence
// counts as consent (decision 8), and the owners have announce_days to object. The policy comes from the access-as-code
// repository (internal/lpauto) and is applied by two people; the mode is set by two people. Everything else of the
// staged loop holds: caps, the kill switch, the recheck before the revoke, restores. When the calibration says the
// false-positive rate of high-confidence revocations is over 1 percent, auto mode pauses itself.

// ActorAutoPolicy is the actor of an announcement the automatic policy made.
const ActorAutoPolicy = ActorAuto

// AutoPolicy returns the tenant's applied policy; nil when none was applied.
func AutoPolicy(tx *store.TenantTx) (*lpauto.Policy, *store.LPAutoPolicy, error) {
	row, err := tx.LPAutoPolicy()
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil, nil
	} else if err != nil {
		return nil, nil, err
	}
	p, err := lpauto.FromJSON(row.Policy)
	if err != nil {
		return nil, nil, refuse(500, "auto_policy_corrupt", "the stored automatic policy is not valid: %v", err)
	}
	return p, row, nil
}

// CalibrationReview says whether the tenant's calibration asks for a review: the false-positive rate of high
// confidence is over 1 percent. It returns the reason, "" when it is not.
func CalibrationReview(tx *store.TenantTx, now time.Time) (string, error) {
	levels, err := Calibration(tx, now)
	if err != nil {
		return "", err
	}
	for _, l := range levels {
		if l.Review {
			return fmt.Sprintf("the false-positive rate of high confidence is %.1f%% (%d of %d revocations in %d days), over %d%%: review the rule",
				l.Percent, l.FalsePositives, l.Revocations, CalibrationDays, HighFalsePositivePercent), nil
		}
	}
	return "", nil
}

// autoPause pauses auto mode because the calibration asks for a review, and audits why. One person (the loop
// itself) pauses; resuming takes two admins, as for any pause.
func autoPause(tx *store.TenantTx, now time.Time, ex Executor, reason string) (*store.LPSettings, error) {
	s, err := Pause(tx, now, ActorAuto, "calibration: "+reason, ex)
	if err != nil {
		return nil, err
	}
	return s, tx.Audit(now, ActorAuto, "lp.auto_paused", ojson.Object{{Key: "trigger", Value: "calibration"}, {Key: "reason", Value: reason}})
}

// autoAnnounce announces the candidates the automatic policy covers, at most the policy's per-day count in 24
// hours, and returns how many it announced. It runs only in auto mode, active, not disabled. A candidate the policy
// does not cover stays a candidate for a person to approve as in staged mode.
func autoAnnounce(tx *store.TenantTx, now time.Time, s *store.LPSettings, ex Executor, t *Tick) error {
	pol, row, err := AutoPolicy(tx)
	if err != nil {
		return err
	}
	if pol == nil {
		t.Holds["no_auto_policy"]++
		return nil
	}
	cands, err := tx.LPRevocationsToAdvance(store.LPCandidate, 500)
	if err != nil {
		return err
	}
	if len(cands) == 0 {
		return nil
	}
	if why, err := ShadowBlock(tx, now); err != nil {
		return err
	} else if why != "" {
		t.Holds["evaluator_disagreement"]++
		return nil
	}
	done, err := tx.LPApprovedBySince(ActorAutoPolicy, now.Add(-24*time.Hour))
	if err != nil {
		return err
	}
	for _, r := range cands {
		if done >= pol.MaxPerDay {
			t.Holds["auto_policy_max_per_day"]++
			return nil
		}
		// a candidate approved to be announced needs every rule of design section 4 again, now
		if r.Eligibility != store.LPEligAuto || r.UnusedDays < s.AutoMinDays ||
			pol.Allows(lpauto.Candidate{Kind: r.Kind, Account: r.AccountID, Confidence: r.Confidence, UnusedDays: r.UnusedDays}) != "" {
			continue
		}
		if why, err := Guard(tx, now, r.Principal, r.PolicyARN); err != nil {
			return err
		} else if why != "" {
			continue
		}
		if err := ex.Ready(tx, r); err != nil {
			continue
		}
		until := now.AddDate(0, 0, s.AnnounceDays)
		r.ApprovedBy, r.ApprovedAt, r.AnnounceUntil = ActorAutoPolicy, &now, &until
		detail := fmt.Sprintf("announced by the automatic policy %.12s (commit %s): silence is consent, objections until %s",
			row.PolicySHA256, row.Commit, until.UTC().Format(time.RFC3339))
		if err := Move(tx, now, r, store.LPAnnounced, ActorAutoPolicy, detail); err != nil {
			return err
		}
		done++
		t.Announced++
	}
	return nil
}
