package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// The approver's "check this URL" (issue #886). A proposal that seals a URL (an alert channel's or SIEM sink's target) shows
// the approver only its origin and a keyed fingerprint. On a create the approver has nothing trusted to compare the
// fingerprint with, and cannot compute the HMAC. So the approver types the URL they expect and the server answers match or
// no-match against the fingerprint it derived at submit, never the sealed value.
//
// Because the answer is an oracle for the sealed URL, it is bounded, and the bounds are counted by the sealed VALUE, not
// the request: at most MaxTargetChecksPerValue tries against one URL in TargetLockWindow whoever asks and however often
// it is filed again (then it is locked for checking and the approver decides without it); MaxTargetChecksPerApprover per
// approver and MaxTargetChecksPerTenant per tenant per TargetCheckWindow. A lockout is audited and raises the
// approver_check_locked alert, since anyone able to approve can burn the tries and deny the others the check. Every try
// is audited with the request-bound fingerprint of the submitted URL and never the URL.
//
// The counts are read and then written in one transaction. They hold exactly, with no row lock, because DB.InTenant
// serialises every writer of a tenant: Postgres takes pg_advisory_xact_lock(tenant) before the function runs
// (internal/store/db.go inTenantOn) and SQLite has a single writer lock. A change that ran this outside InTenant, or
// that split the count from the insert, would let concurrent checks overshoot the limits.
const (
	MaxTargetChecksPerValue    = 5
	MaxTargetChecksPerApprover = 20
	MaxTargetChecksPerTenant   = 60
	TargetCheckWindow          = time.Hour
	TargetLockWindow           = 30 * 24 * time.Hour
)

// Reasons a check is refused for the limit.
const (
	ReasonTargetCheckLocked  = "target_check_locked"
	ReasonTargetCheckRate    = "target_check_rate_limited"
	maxTargetCheckInputBytes = maxProposalSecret
)

// TargetCheck is the answer to one check: whether the URL matched, and how many attempts the request has left.
type TargetCheck struct {
	Match        bool
	AttemptsLeft int
}

// CheckTarget compares the URL an approver expects with the one proposal id seals. The caller needs admin.change.approve
// with a fresh step-up and must not be the person who filed the request.
func (s *Service) CheckTarget(ctx context.Context, p *auth.Principal, id uuid.UUID, target string) (*TargetCheck, error) {
	now := s.now()
	if d := auth.Check(p, auth.PermAdminChangeAppr, &auth.StepUpAdmin, now); d != nil {
		return nil, denied(d)
	}
	if p.UserID == nil {
		return nil, newErr(http.StatusForbidden, "user_required", "only a signed-in person can check a URL")
	}
	// the input is judged before anything is counted: a malformed one is not a guess
	if target == "" || len(target) > maxTargetCheckInputBytes || !strings.Contains(target, "://") || safehttp.Origin(strings.TrimSpace(target)) == "" {
		return nil, invalid("url must be an absolute URL of at most %d characters", maxTargetCheckInputBytes)
	}
	var (
		res     TargetCheck
		refused *Error
	)
	err := s.DB.InTenant(ctx, p.TenantID, func(tx *store.TenantTx) error {
		ch, err := tx.AdminChange(id)
		if err != nil {
			return err
		}
		own, err := tx.SameActor(ch.RequestedBy.String(), p.UserID.String())
		if err != nil {
			return err
		}
		if ch.Type != TypeConfigProposal {
			return conflict("no_sealed_url", "the request seals no URL")
		}
		switch {
		case own:
			return newErr(http.StatusForbidden, "self_check_refused", "a request's own proposer cannot check its URL; ask another approver")
		case ch.Status != store.ChangePendingApproval && ch.Status != store.ChangeCoolingOff:
			return conflict("invalid_state", "the request is %s; its URL can be checked while it is pending or cooling off", ch.Status)
		}
		var pl proposalPayload
		if json.Unmarshal(ch.Payload, &pl) != nil {
			return conflict(ReasonPayloadTampered, "the request cannot be read")
		}
		secrets, err := OpenProposalSecrets(s.Sealer, p.TenantID, ch.ID, ch.SecretEnc, pl.Kind)
		if err != nil {
			return conflict(ReasonPayloadTampered, "the sealed secrets of the request do not open")
		}
		sealedURL := secrets["target"]
		if sealedURL == "" {
			return conflict("no_sealed_url", "the request seals no URL")
		}
		sealedFP, err := sealedValueFP(s.Sealer, p.TenantID, sealedURL)
		if err != nil {
			return err
		}
		by := p.UserID.String()
		ev := func(action, outcome string, extra ...ojson.KV) error {
			d := append(ojson.Object{{Key: "change_id", Value: ch.ID.String()}, {Key: "by", Value: p.Display}}, extra...)
			_, err := audit.Record(tx.Context(), tx, action, d, audit.At(now), audit.Target("admin_change", ch.ID.String()), audit.Outcome(outcome))
			return err
		}
		perValue, err := tx.AdminChangeTargetChecksOf(sealedFP, now.Add(-TargetLockWindow))
		if err != nil {
			return err
		}
		perApprover, err := tx.AdminChangeTargetChecksBy(by, now.Add(-TargetCheckWindow))
		if err != nil {
			return err
		}
		perTenant, err := tx.AdminChangeTargetChecksTenant(now.Add(-TargetCheckWindow))
		if err != nil {
			return err
		}
		if perValue >= MaxTargetChecksPerValue || perApprover >= MaxTargetChecksPerApprover || perTenant >= MaxTargetChecksPerTenant {
			// recorded, and returned after the transaction commits (an error would roll the event back)
			if perValue >= MaxTargetChecksPerValue {
				refused = newErr(http.StatusTooManyRequests, ReasonTargetCheckLocked,
					"this URL has used its %d checks; decide the request on its origin and the change flag, or reject it", MaxTargetChecksPerValue)
			} else {
				refused = newErr(http.StatusTooManyRequests, ReasonTargetCheckRate, "too many URL checks in %s; try again later", TargetCheckWindow)
			}
			return ev("admin.change.target_check_refused", store.OutcomeFailure, ojson.KV{Key: "reason", Value: refused.Code})
		}
		got, err := TargetFingerprint(s.Sealer, p.TenantID, ch.ID, target)
		if err != nil {
			return err
		}
		// compared exactly as typed, apart from a pasted leading or trailing space or newline
		res.Match = seal.Equal([]byte(strings.TrimSpace(target)), []byte(sealedURL)) || seal.Equal([]byte(target), []byte(sealedURL))
		if err := tx.InsertAdminChangeTargetCheck(ch.ID, by, got, sealedFP, res.Match, now); err != nil {
			return err
		}
		res.AttemptsLeft = MaxTargetChecksPerValue - perValue - 1
		return ev("admin.change.target_checked", store.OutcomeSuccess, ojson.KV{Key: "matched", Value: res.Match},
			ojson.KV{Key: "submitted_fp", Value: got}, ojson.KV{Key: "attempts_left", Value: res.AttemptsLeft})
	})
	if err != nil {
		return nil, mapStore(err)
	}
	if refused != nil {
		return nil, refused
	}
	return &res, nil
}
