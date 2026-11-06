package admin

import (
	"context"
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
// Because the answer is an oracle for the sealed URL, it is bounded: at most MaxTargetChecksPerRequest attempts on one
// request (by anyone; then the request is locked for checking and the approver decides without it) and
// MaxTargetChecksPerApprover per approver per TargetCheckWindow across requests. Every attempt, and every refusal for the
// limit, is audited with the keyed fingerprint of the submitted URL and never the URL.
const (
	MaxTargetChecksPerRequest  = 5
	MaxTargetChecksPerApprover = 20
	TargetCheckWindow          = time.Hour
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
		_, want := ProposalTarget(ch)
		switch {
		case own:
			return newErr(http.StatusForbidden, "self_check_refused", "a request's own proposer cannot check its URL; ask another approver")
		case ch.Status != store.ChangePendingApproval && ch.Status != store.ChangeCoolingOff:
			return conflict("invalid_state", "the request is %s; its URL can be checked while it is pending or cooling off", ch.Status)
		case want == "":
			return conflict("no_sealed_url", "the request seals no URL")
		}
		by := p.UserID.String()
		ev := func(action, outcome string, extra ...ojson.KV) error {
			d := append(ojson.Object{{Key: "change_id", Value: ch.ID.String()}, {Key: "by", Value: p.Display}}, extra...)
			_, err := audit.Record(tx.Context(), tx, action, d, audit.At(now), audit.Target("admin_change", ch.ID.String()), audit.Outcome(outcome))
			return err
		}
		perRequest, err := tx.AdminChangeTargetChecks(ch.ID)
		if err != nil {
			return err
		}
		perApprover, err := tx.AdminChangeTargetChecksBy(by, now.Add(-TargetCheckWindow))
		if err != nil {
			return err
		}
		if perRequest >= MaxTargetChecksPerRequest || perApprover >= MaxTargetChecksPerApprover {
			// recorded, and returned after the transaction commits (an error would roll the event back)
			if perRequest >= MaxTargetChecksPerRequest {
				refused = newErr(http.StatusTooManyRequests, ReasonTargetCheckLocked,
					"this request has used its %d URL checks; decide it on the origin and fingerprint, or ask the proposer to file it again", MaxTargetChecksPerRequest)
			} else {
				refused = newErr(http.StatusTooManyRequests, ReasonTargetCheckRate,
					"you have used %d URL checks in %s; try again later", MaxTargetChecksPerApprover, TargetCheckWindow)
			}
			return ev("admin.change.target_check_refused", store.OutcomeFailure, ojson.KV{Key: "reason", Value: refused.Code})
		}
		got, err := TargetFingerprint(s.Sealer, p.TenantID, target)
		if err != nil {
			return err
		}
		res.Match = seal.Equal([]byte(got), []byte(want))
		if trimmed := strings.TrimSpace(target); !res.Match && trimmed != target {
			// a pasted trailing space or newline is not a different URL
			if t, err := TargetFingerprint(s.Sealer, p.TenantID, trimmed); err == nil {
				res.Match = seal.Equal([]byte(t), []byte(want))
			}
		}
		if err := tx.InsertAdminChangeTargetCheck(ch.ID, by, got, res.Match, now); err != nil {
			return err
		}
		res.AttemptsLeft = MaxTargetChecksPerRequest - perRequest - 1
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
