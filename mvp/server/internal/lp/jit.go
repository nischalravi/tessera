package lp

import (
	"errors"
	"fmt"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// JIT re-request in the revoke window (issue #663, LP-7; design sections 9 and 11, decision 5). A person who asks
// for just-in-time access to a grant the loop revoked, before the revocation is final, shows the revoke was wrong.
// The request is labelled a false positive and feeds the calibration. The access itself is the ordinary time-bound
// JIT grant (approved and expiring like any other): the standing grant stays revoked, and putting it back is the
// explicit restore, available until the revocation is final. Nothing here changes the revocation's state.

// ActorJIT is the audit actor of a label that a JIT request caused when the requester is not known by name.
const ActorJIT = "lp.jit"

// CalibrationDays is the window of the calibration (design section 10), and HighFalsePositivePercent the share of
// high-confidence revocations that, once exceeded, pauses the loop for auto and sends the rule to a person.
const (
	CalibrationDays          = 60
	HighFalsePositivePercent = 1
)

// JITRequest is what the loop needs of a JIT request: who asked (the principals their accounts carry), for which
// grant (the group's external id is the policy ARN that was revoked) and under which request.
type JITRequest struct {
	RequestID  int64
	Requester  string   // display name, the audit actor
	Principals []string // external ids of the requester's accounts
	Group      string   // external id of the requested group
}

// OnJITRequest labels every revoked (not yet final) grant the request asks for as a false positive. It returns the
// revocations it labelled; a revocation labelled before (a second request, a restore) is left as it was.
func OnJITRequest(tx *store.TenantTx, now time.Time, q JITRequest) ([]*store.LPRevocation, error) {
	var out []*store.LPRevocation
	if q.Group == "" {
		return nil, nil
	}
	for _, p := range q.Principals {
		if p == "" {
			continue
		}
		revoked, err := tx.LPRevokedForGrant(p, q.Group)
		if err != nil {
			return nil, err
		}
		for _, r := range revoked {
			ok, err := LabelFalsePositive(tx, now, r, store.LPFPJIT, fmt.Sprint(q.RequestID))
			if err != nil {
				return nil, err
			}
			if !ok {
				continue
			}
			out = append(out, r)
			actor := q.Requester
			if actor == "" {
				actor = ActorJIT
			}
			if err := tx.Audit(now, actor, "lp.jit.false_positive", ojson.Object{{Key: "revocation_id", Value: r.ID},
				{Key: "request_id", Value: q.RequestID}, {Key: "principal", Value: r.Principal}, {Key: "policy_arn", Value: r.PolicyARN},
				{Key: "confidence", Value: r.Confidence}}); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

// LabelFalsePositive records that the revocation was a false positive, once: the first label (source and reference)
// stands. It reports whether this call labelled it.
func LabelFalsePositive(tx *store.TenantTx, now time.Time, r *store.LPRevocation, source, ref string) (bool, error) {
	err := tx.InsertLPFalsePositive(&store.LPFalsePositive{RevocationID: r.ID, Source: source, Ref: ref, Principal: r.Principal,
		PolicyARN: r.PolicyARN, Confidence: r.Confidence, CreatedAt: now})
	if errors.Is(err, store.ErrDuplicate) {
		return false, nil
	}
	return err == nil, err
}

// CalibrationLevel is one confidence level's counts over the window.
type CalibrationLevel struct {
	Confidence     string  `json:"confidence"`
	Revocations    int     `json:"revocations"`
	FalsePositives int     `json:"false_positives"`
	Percent        float64 `json:"false_positive_percent"`
	// Review is set when the level is high and over HighFalsePositivePercent: the rule is reviewed by a person.
	Review bool `json:"review"`
}

// Calibration is restores plus JIT re-requests divided by revocations, per confidence level, over CalibrationDays.
func Calibration(tx *store.TenantTx, now time.Time) ([]CalibrationLevel, error) {
	rows, err := tx.LPCalibration(now.AddDate(0, 0, -CalibrationDays))
	if err != nil {
		return nil, err
	}
	out := make([]CalibrationLevel, 0, len(rows))
	for _, r := range rows {
		c := CalibrationLevel{Confidence: r.Confidence, Revocations: r.Revocations, FalsePositives: r.FalsePositives}
		if r.Revocations > 0 {
			c.Percent = float64(r.FalsePositives) * 100 / float64(r.Revocations)
			c.Review = r.Confidence == "high" && r.FalsePositives*100 > r.Revocations*HighFalsePositivePercent
		}
		out = append(out, c)
	}
	return out, nil
}
