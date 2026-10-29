package lp

import (
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Restore on denial (issue #662, LP-6; design section 5.2 and 6.2). A CloudTrail or EventBridge AccessDenied (or an
// IdP denial) for a principal with a revoked grant is only a trigger: the grant is restored when, and only when,
// the denied action is one the revocation removed. The restore is the ordinary one (the payload recorded at the
// revoke, its digest checked, the AWS write target, verified by re-reading the target) and it needs no second
// person. A pause or the operator switch never blocks it. The SLO is a verified restore within 15 minutes of the
// event's arrival; arrival is recorded in lp_denials.

// RestoreSLO is the design's bound from the arrival of a denial to the verified restore.
const RestoreSLO = 15 * time.Minute

// Denial is a normalized denial event.
type Denial struct {
	Source     string // store.LPDenialCloudTrail or store.LPDenialIdP
	EventID    string
	Principal  string // the IAM role, user or group ARN the access was denied to
	Action     string // service:Action
	Resource   string // the denied resource ARN, when the event named one
	OccurredAt *time.Time
}

// Removed says whether revocation r removed action: the API answers it from the policy documents recorded at the
// revoke (the evaluator's matching, never a guess).
type Removed func(r *store.LPRevocation, action, resource string) (bool, error)

// DenialResult is what a denial led to.
type DenialResult struct {
	// Outcome: duplicate (seen already), no_revocation (nothing revoked for the principal), action_not_removed
	// (the denial is for something the loop did not take away) or restore_requested.
	Outcome string
	Denial  *store.LPDenial
	// Restored are the revocations whose restore this event requested.
	Restored []*store.LPRevocation
}

// Outcomes of OnDenial that are not stored (they leave no row).
const (
	OutcomeDuplicate    = "duplicate"
	OutcomeNoRevocation = "no_revocation"
)

// OnDenial handles one denial event in the caller's transaction. It records the event when the principal has a
// revoked grant, requests the restore of every revoked grant whose removal covers the action, and audits both.
// A redelivery of a recorded event changes nothing.
func OnDenial(tx *store.TenantTx, now time.Time, d Denial, removed Removed, ex Executor) (*DenialResult, error) {
	if seen, err := tx.LPDenialSeen(d.Source, d.EventID); err != nil {
		return nil, err
	} else if seen {
		return &DenialResult{Outcome: OutcomeDuplicate}, nil
	}
	revoked, err := tx.LPRevokedForPrincipal(d.Principal)
	if err != nil {
		return nil, err
	}
	if len(revoked) == 0 {
		return &DenialResult{Outcome: OutcomeNoRevocation}, nil
	}
	rec := &store.LPDenial{Source: d.Source, EventID: d.EventID, Principal: d.Principal, Action: d.Action, Resource: d.Resource, OccurredAt: d.OccurredAt,
		ArrivedAt: now, Outcome: store.LPDenialActionNotRemoved, RevocationID: revoked[0].ID}
	res := &DenialResult{Denial: rec, Outcome: store.LPDenialActionNotRemoved}
	var ids []string
	for _, r := range revoked {
		hit, err := removed(r, d.Action, d.Resource)
		if err != nil {
			return nil, err
		}
		if !hit {
			continue
		}
		got, err := restore(tx, now, ActorDenial, "denial", "restore requested (denial "+d.Source+" "+d.EventID+": "+d.Action+")", r.ID, ex)
		if err != nil {
			return nil, err
		}
		res.Restored = append(res.Restored, got)
		ids = append(ids, got.ID)
	}
	if len(ids) > 0 {
		rec.Outcome, rec.RevocationID, res.Outcome = store.LPDenialRestoreRequested, ids[0], store.LPDenialRestoreRequested
		if len(ids) > 1 {
			rec.Detail = "also restored: " + strings.Join(ids[1:], ", ")
		}
	}
	if err := tx.InsertLPDenial(rec); err != nil {
		return nil, err
	}
	return res, tx.Audit(now, ActorDenial, "lp.denial."+rec.Outcome, ojson.Object{{Key: "denial_id", Value: rec.ID},
		{Key: "source", Value: d.Source}, {Key: "event_id", Value: d.EventID}, {Key: "principal", Value: d.Principal},
		{Key: "action", Value: d.Action}, {Key: "resource", Value: d.Resource}, {Key: "revocation_id", Value: rec.RevocationID}, {Key: "restored", Value: len(ids)}})
}
