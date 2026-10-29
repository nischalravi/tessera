// Package lp is the staged revocation of unused access (issue #661, LP-5; design docs/design/least-privilege-loop.md
// sections 3, 4, 5 and 11). It keeps the state machine of a revocation, the caps and the kill switch, and decides
// nothing about AWS itself: what is proposed (a verified right-size) is computed by the API from the evaluator,
// and what is written goes through the provisioning engine's AWS write target, which the Executor queues. Every
// transition is written with its event and its audit event in the transaction that changes the row.
//
//	candidate -> announced -> revoking -> revoked -> finalized
//	    |            |           |           |
//	    |            |           |           +-> restoring -> restored
//	    +------------+-----------+-> exempted, superseded, failed
//
// Modes: off (the default), suggest (recommendations only, no rows here), staged (a person approves each batch,
// medium items one by one) and auto (LP-8: not available yet). Pausing is one person; resuming, a stronger mode,
// larger caps and a shorter announce or finalize period are an admin change request of type lp.settings.update
// (two people). A pause, the operator switch TESSERA_LP_DISABLE and an exhausted cap stop new executions at once;
// none of them ever blocks a restore.
package lp

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Bounds and defaults of the design (section 5, 5.1 and 11).
const (
	// ExemptionDays is how long an objection, a restore or a kept review item keeps a grant from being proposed again.
	ExemptionDays = 180
	// CandidateTTLDays is how long a candidate waits for approval before it is dropped.
	CandidateTTLDays = 30
	// MaxBatch bounds the revocations one approval names.
	MaxBatch = 100
	// RestoresPerRunPause is the number of restores in one run (one hour here) that pauses the loop.
	RestoresPerRunPause = 3
	// RestoreRatePausePercent is the rolling 7-day restore rate above which the loop pauses.
	RestoreRatePausePercent = 2
)

// Actors of what the loop does by itself.
const (
	ActorTick = "lp.worker"
	ActorAuto = "lp.auto"
	// ActorDenial restores on a denial event (LP-6).
	ActorDenial = "lp.denial"
)

// Error is a refusal with the API's status and code.
type Error struct {
	Status int
	Code   string
	Msg    string
}

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

func refuse(status int, code, format string, args ...any) error {
	return &Error{Status: status, Code: code, Msg: fmt.Sprintf(format, args...)}
}

// next lists the transitions a revocation may make.
var next = map[string][]string{
	store.LPCandidate: {store.LPAnnounced, store.LPExempted, store.LPSuperseded},
	// announced -> exempted is an objection; revoking -> announced is a pause that took the queued operation back
	store.LPAnnounced: {store.LPRevoking, store.LPExempted, store.LPSuperseded, store.LPFailed},
	store.LPRevoking:  {store.LPRevoked, store.LPFailed, store.LPAnnounced, store.LPSuperseded},
	store.LPRevoked:   {store.LPFinalized, store.LPRestoring},
	store.LPRestoring: {store.LPRestored, store.LPFailed},
}

// CanMove says whether the state machine allows from -> to.
func CanMove(from, to string) bool { return slices.Contains(next[from], to) }

// Terminal says whether a state ends the revocation.
func Terminal(state string) bool { return len(next[state]) == 0 }

// Move changes the state of r and records the event and the audit event in the same transaction. The caller sets
// the other fields (op id, times) of r first; Move sets the state. ErrState: another request moved the row first.
func Move(tx *store.TenantTx, now time.Time, r *store.LPRevocation, to, actor, detail string) error {
	from := r.State
	if !CanMove(from, to) {
		return fmt.Errorf("lp: a revocation cannot go from %s to %s", from, to)
	}
	r.State = to
	if err := tx.UpdateLPRevocation(r, from, now); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return refuse(409, "state_changed", "the revocation changed meanwhile: reload it")
		}
		return err
	}
	if err := tx.InsertLPEvent(&store.LPEvent{RevocationID: r.ID, From: from, To: to, Actor: actor, Detail: detail, CreatedAt: now}); err != nil {
		return err
	}
	d := ojson.Object{{Key: "id", Value: r.ID}, {Key: "from", Value: from}, {Key: "to", Value: to}, {Key: "principal", Value: r.Principal},
		{Key: "policy_arn", Value: r.PolicyARN}, {Key: "kind", Value: r.Kind}}
	if r.OpID != "" {
		d = append(d, ojson.KV{Key: "op_id", Value: r.OpID})
	}
	if r.RestoreOpID != "" {
		d = append(d, ojson.KV{Key: "restore_op_id", Value: r.RestoreOpID})
	}
	if to == store.LPRevoked || to == store.LPRestoring {
		// the digest of the payload a restore will put back: the audit trail shows what was held at the revoke
		d = append(d, ojson.KV{Key: "restore_sha256", Value: r.RestoreSHA256})
	}
	if detail != "" {
		d = append(d, ojson.KV{Key: "detail", Value: detail})
	}
	return tx.Audit(now, actor, "lp.revocation."+to, d)
}

// Executor is what the loop needs from the provisioning engine and the AWS write target. The API implements it.
type Executor interface {
	// Ready says whether the revocation can be carried out at all (an AWS write target with write-back on).
	Ready(tx *store.TenantTx, r *store.LPRevocation) error
	// Enqueue queues the revoking operation (idempotency key lp:<id>:revoke) and returns its id.
	Enqueue(tx *store.TenantTx, now time.Time, r *store.LPRevocation) (opID string, err error)
	// EnqueueRestore queues the restore of the state recorded at the revoke (key lp:<id>:restore).
	EnqueueRestore(tx *store.TenantTx, now time.Time, r *store.LPRevocation) (opID string, err error)
	// Cancel withdraws a queued operation; cancelled is false when it has already been sent.
	Cancel(tx *store.TenantTx, now time.Time, opID string) (cancelled bool, err error)
	// OpStatus is the provisioning status of an operation.
	OpStatus(tx *store.TenantTx, opID string) (string, error)
}

// Provisioning statuses the loop reads (internal/provision, kept as text to leave that package out of this one's API).
const (
	opVerified  = "verified"
	opFailed    = "failed"
	opMismatch  = "mismatch"
	opCancelled = "cancelled"
)

// Active says whether the settings allow new announcements and executions.
func Active(s *store.LPSettings) bool {
	return !s.Paused && (s.Mode == store.LPModeStaged || s.Mode == store.LPModeAuto)
}

// DigestPayload is the digest recorded at the revoke for a restore payload.
func DigestPayload(payload string) string { return seal.SHA256Hex([]byte(payload)) }

// Pause is the kill switch: one person (or the loop itself) stops new announcements and executions. Operations the
// loop queued that have not been sent are taken back and their revocations return to announced; operations already
// sent run to their verification. It never touches restores. Pausing a paused loop changes nothing.
func Pause(tx *store.TenantTx, now time.Time, actor, reason string, ex Executor) (*store.LPSettings, error) {
	s, err := tx.LPSettings()
	if err != nil {
		return nil, err
	}
	if s.Paused {
		return s, nil
	}
	s.Paused, s.PausedReason, s.PausedBy, s.PausedAt = true, reason, actor, &now
	s.UpdatedBy = actor
	if err := tx.PutLPSettings(s, now); err != nil {
		return nil, err
	}
	cancelled := 0
	if ex != nil {
		revoking, err := tx.LPRevocationsToAdvance(store.LPRevoking, 500)
		if err != nil {
			return nil, err
		}
		for _, r := range revoking {
			ok, err := ex.Cancel(tx, now, r.OpID)
			if err != nil {
				return nil, err
			}
			if !ok {
				continue
			}
			r.OpID, r.ExecutedAt = "", nil // not executed after all: the caps do not count it
			if err := Move(tx, now, r, store.LPAnnounced, actor, "paused: the queued operation was cancelled"); err != nil {
				return nil, err
			}
			cancelled++
		}
	}
	return s, tx.Audit(now, actor, "lp.paused", ojson.Object{{Key: "reason", Value: reason}, {Key: "cancelled", Value: cancelled}})
}

// Settings changes: the mode, the pause and the numbers of the design. Nil fields stay as they are.
type SettingsUpdate struct {
	Mode            *string `json:"mode,omitempty"`
	Paused          *bool   `json:"paused,omitempty"`
	CapPerRun       *int    `json:"cap_per_run,omitempty"`
	CapPerDay       *int    `json:"cap_per_day,omitempty"`
	CapPerAccount   *int    `json:"cap_per_account,omitempty"`
	CapPerPrincipal *int    `json:"cap_per_principal,omitempty"`
	AnnounceDays    *int    `json:"announce_days,omitempty"`
	FinalizeDays    *int    `json:"finalize_days,omitempty"`
	AutoMinDays     *int    `json:"auto_min_days,omitempty"`
}

func modeRank(m string) int {
	switch m {
	case store.LPModeStaged:
		return 1
	case store.LPModeAuto:
		return 2
	}
	return 0 // off and suggest change nothing in AWS
}

// Plan applies an update to the current settings and says whether it loosens them (so it takes two people):
// a stronger mode (off to suggest is not one), resuming, a larger cap, a shorter announce or finalize period or a
// lower auto threshold. Tightening and pausing take one. The mode auto is refused until its policy exists (LP-8).
func Plan(cur *store.LPSettings, u *SettingsUpdate) (next *store.LPSettings, loosens bool, err error) {
	n := *cur
	if u.Mode == nil && u.Paused == nil && u.CapPerRun == nil && u.CapPerDay == nil && u.CapPerAccount == nil &&
		u.CapPerPrincipal == nil && u.AnnounceDays == nil && u.FinalizeDays == nil && u.AutoMinDays == nil {
		return nil, false, refuse(422, "invalid_settings", "name at least one setting to change")
	}
	if u.Mode != nil {
		switch *u.Mode {
		case store.LPModeOff, store.LPModeSuggest, store.LPModeStaged:
		case store.LPModeAuto:
			return nil, false, refuse(422, "auto_not_available", "auto mode needs the auto policy in the access-as-code repository (LP-8), which is not built yet")
		default:
			return nil, false, refuse(422, "invalid_settings", "mode is off, suggest or staged")
		}
		n.Mode = *u.Mode
		loosens = loosens || modeRank(n.Mode) > modeRank(cur.Mode)
	}
	if u.Paused != nil {
		n.Paused = *u.Paused
		loosens = loosens || (cur.Paused && !n.Paused)
	}
	num := func(name string, in *int, dst *int, lo, hi int, loosensWhenHigher bool) error {
		if in == nil {
			return nil
		}
		if *in < lo || *in > hi {
			return refuse(422, "invalid_settings", "%s is %d to %d", name, lo, hi)
		}
		if (*in > *dst) == loosensWhenHigher && *in != *dst {
			loosens = true
		}
		*dst = *in
		return nil
	}
	for _, f := range []struct {
		name   string
		in     *int
		dst    *int
		lo, hi int
		higher bool
	}{
		{"cap_per_run", u.CapPerRun, &n.CapPerRun, 1, 1000, true},
		{"cap_per_day", u.CapPerDay, &n.CapPerDay, 1, 10000, true},
		{"cap_per_account", u.CapPerAccount, &n.CapPerAccount, 1, 1000, true},
		{"cap_per_principal", u.CapPerPrincipal, &n.CapPerPrincipal, 1, 100, true},
		{"announce_days", u.AnnounceDays, &n.AnnounceDays, 1, 90, false},
		{"finalize_days", u.FinalizeDays, &n.FinalizeDays, 1, 365, false},
		{"auto_min_days", u.AutoMinDays, &n.AutoMinDays, 1, 365, false},
	} {
		if err := num(f.name, f.in, f.dst, f.lo, f.hi, f.higher); err != nil {
			return nil, false, err
		}
	}
	if n.CapPerRun > n.CapPerDay {
		return nil, false, refuse(422, "invalid_settings", "cap_per_run cannot exceed cap_per_day")
	}
	if n.Paused && !cur.Paused {
		n.PausedReason = "paused by a settings change"
	} else if !n.Paused {
		n.PausedReason, n.PausedBy, n.PausedAt = "", "", nil
	}
	return &n, loosens, nil
}

// Hold says why a revocation may not be executed now: "" when it may. run is how many this run has queued already.
func Hold(tx *store.TenantTx, now time.Time, s *store.LPSettings, r *store.LPRevocation, run int) (string, error) {
	switch {
	case s.Paused:
		return "paused", nil
	case run >= s.CapPerRun:
		return "cap_per_run", nil
	}
	day := now.Add(-24 * time.Hour)
	for _, c := range []struct {
		name               string
		account, principal string
		limit              int
	}{{"cap_per_day", "", "", s.CapPerDay}, {"cap_per_principal", "", r.Principal, s.CapPerPrincipal},
		{"cap_per_account", r.AccountID, "", s.CapPerAccount}} {
		n, err := tx.LPExecutedSince(day, c.account, c.principal)
		if err != nil {
			return "", err
		}
		if n >= c.limit {
			return c.name, nil
		}
	}
	return "", nil
}

// Guard says why a grant must not be proposed or revoked: it is protected, exempted or already in a revocation. ""
// means it may be.
func Guard(tx *store.TenantTx, now time.Time, principal, policy string) (string, error) {
	ps, err := tx.LPProtected()
	if err != nil {
		return "", err
	}
	for _, p := range ps {
		if (p.Kind == "principal" && p.Ref == principal) || (p.Kind == "policy" && p.Ref == policy) {
			return "protected", nil
		}
	}
	if ex, err := tx.LPExempted(principal, policy, now); err != nil || ex {
		return "exempted", err
	}
	return "", nil
}

// ShadowBlock says whether an open engine disagreement makes the evaluator's "unused" untrustworthy: an
// engine_bug at any time in the last 30 days, or a disagreement under investigation that was checked in that window.
func ShadowBlock(tx *store.TenantTx, now time.Time) (string, error) {
	since := now.AddDate(0, 0, -30)
	for _, status := range []string{store.AWSTriageEngineBug, store.AWSTriageInvestigating} {
		cs, err := tx.AWSShadowChecks(store.AWSShadowDisagree, status, 50)
		if err != nil {
			return "", err
		}
		for _, c := range cs {
			if !c.CheckedAt.Before(since) {
				return status, nil
			}
		}
	}
	return "", nil
}

// Eligibility says how a candidate with this confidence and this many unused days is approved: auto (a batch
// approval covers it) or item (approved on its own). Low and unknown confidence are never acted on.
func Eligibility(s *store.LPSettings, confidence string, unusedDays int) (string, error) {
	switch confidence {
	case "high":
		if unusedDays >= s.AutoMinDays {
			return store.LPEligAuto, nil
		}
		return store.LPEligItem, nil
	case "medium":
		return store.LPEligItem, nil
	}
	return "", refuse(422, "confidence_too_low", "the evidence is rated %s: only high or medium confidence is acted on", confidence)
}

// Propose records a candidate. The caller has computed it (a verified right-size of a policy only this principal
// holds, EXACT, not privileged); this applies the loop's own rules: the mode, the protected list, exemptions, an
// open disagreement of the evaluator and a grant already in a revocation.
func Propose(tx *store.TenantTx, now time.Time, actor string, c *store.LPRevocation) error {
	s, err := tx.LPSettings()
	if err != nil {
		return err
	}
	if s.Mode != store.LPModeStaged && s.Mode != store.LPModeAuto {
		return refuse(409, "mode_off", "the loop is in mode %s: candidates are built in staged mode", s.Mode)
	}
	if why, err := Guard(tx, now, c.Principal, c.PolicyARN); err != nil {
		return err
	} else if why != "" {
		return refuse(422, "grant_"+why, "the grant is %s: the loop does not propose it", why)
	}
	if why, err := ShadowBlock(tx, now); err != nil {
		return err
	} else if why != "" {
		return refuse(422, "evaluator_disagreement", "an evaluator disagreement is %s: unused access is not revoked until it is resolved", why)
	}
	if n, err := tx.LPOpenForGrant(c.Principal, c.PolicyARN); err != nil {
		return err
	} else if n > 0 {
		return refuse(409, "already_open", "the grant already has a revocation in progress")
	}
	elig, err := Eligibility(s, c.Confidence, c.UnusedDays)
	if err != nil {
		return err
	}
	if c.RestoreSHA256 != DigestPayload(c.RestorePayload) {
		return refuse(422, "payload_digest_mismatch", "the restore payload does not match its digest")
	}
	c.Eligibility, c.State, c.CreatedBy, c.CreatedAt = elig, store.LPCandidate, actor, now
	if c.ID == "" {
		c.ID = store.NewID()
	}
	if err := tx.InsertLPRevocation(c); err != nil {
		return err
	}
	if err := tx.InsertLPEvent(&store.LPEvent{RevocationID: c.ID, To: store.LPCandidate, Actor: actor, CreatedAt: now}); err != nil {
		return err
	}
	return tx.Audit(now, actor, "lp.revocation.candidate", ojson.Object{{Key: "id", Value: c.ID}, {Key: "principal", Value: c.Principal},
		{Key: "policy_arn", Value: c.PolicyARN}, {Key: "kind", Value: c.Kind}, {Key: "confidence", Value: c.Confidence},
		{Key: "eligibility", Value: elig}, {Key: "unused_days", Value: c.UnusedDays}, {Key: "candidate_sha256", Value: c.CandidateSHA256}})
}

// Approve announces candidates: a person approves a batch of auto-eligible ones and, one by one, the items that
// need their own approval (medium confidence, or high with fewer unused days than the auto threshold). The
// owners have announce_days to object. Nothing is announced while the loop is paused, disabled or not staged.
func Approve(tx *store.TenantTx, now time.Time, actor string, batch, items []string, disabled bool, ex Executor) ([]*store.LPRevocation, error) {
	if len(batch)+len(items) == 0 || len(batch)+len(items) > MaxBatch {
		return nil, refuse(422, "invalid_batch", "name 1 to %d revocations", MaxBatch)
	}
	s, err := tx.LPSettings()
	if err != nil {
		return nil, err
	}
	switch {
	case disabled:
		return nil, refuse(409, "disabled", "the operator has disabled the loop (TESSERA_LP_DISABLE)")
	case s.Paused:
		return nil, refuse(409, "paused", "the loop is paused (%s): resuming takes two admins", s.PausedReason)
	case s.Mode != store.LPModeStaged && s.Mode != store.LPModeAuto:
		return nil, refuse(409, "mode_off", "the loop is in mode %s", s.Mode)
	}
	seen := map[string]bool{}
	var out []*store.LPRevocation
	for _, group := range []struct {
		ids  []string
		elig string
	}{{batch, store.LPEligAuto}, {items, store.LPEligItem}} {
		for _, id := range group.ids {
			if seen[id] {
				return nil, refuse(422, "invalid_batch", "%s is named twice", id)
			}
			seen[id] = true
			r, err := tx.LPRevocation(id)
			if errors.Is(err, store.ErrNotFound) {
				return nil, refuse(404, "not_found", "no such revocation")
			} else if err != nil {
				return nil, err
			}
			switch {
			case r.State != store.LPCandidate:
				return nil, refuse(409, "not_a_candidate", "%s is %s, not a candidate", id, r.State)
			case r.Eligibility != group.elig && group.elig == store.LPEligAuto:
				return nil, refuse(422, "item_needs_own_approval", "%s is not eligible for a batch approval: approve it as an item", id)
			case r.Eligibility != group.elig:
				return nil, refuse(422, "not_an_item", "%s is eligible for a batch approval: name it in the batch", id)
			}
			if why, err := Guard(tx, now, r.Principal, r.PolicyARN); err != nil {
				return nil, err
			} else if why != "" {
				return nil, refuse(422, "grant_"+why, "%s: the grant is %s", id, why)
			}
			if err := ex.Ready(tx, r); err != nil {
				return nil, err
			}
			until := now.AddDate(0, 0, s.AnnounceDays)
			r.ApprovedBy, r.ApprovedAt, r.AnnounceUntil = actor, &now, &until
			if err := Move(tx, now, r, store.LPAnnounced, actor, "approved"); err != nil {
				return nil, err
			}
			out = append(out, r)
		}
	}
	return out, nil
}

// Object records an owner's objection: the grant is exempted for 180 days and not proposed again.
func Object(tx *store.TenantTx, now time.Time, actor, id, reason string) (*store.LPRevocation, error) {
	r, err := tx.LPRevocation(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(404, "not_found", "no such revocation")
	} else if err != nil {
		return nil, err
	}
	if r.State != store.LPCandidate && r.State != store.LPAnnounced {
		return nil, refuse(409, "not_objectable", "only a candidate or an announced revocation can be objected to (this one is %s): a revoked grant is restored instead", r.State)
	}
	r.Reason = reason
	if err := Move(tx, now, r, store.LPExempted, actor, "objection: "+reason); err != nil {
		return nil, err
	}
	return r, tx.InsertLPExemption(&store.LPExemption{Principal: r.Principal, PolicyARN: r.PolicyARN, Source: store.LPExemptObjection,
		Reason: reason, RevocationID: r.ID, Until: now.AddDate(0, 0, ExemptionDays), CreatedBy: actor, CreatedAt: now})
}

// Restore puts a revoked grant back from the payload recorded at the revoke. It is open to an owner or an admin
// until the revocation is finalized, needs no second person and is never blocked by a pause or the operator switch.
// The payload is refused when its digest is not the one recorded.
func Restore(tx *store.TenantTx, now time.Time, actor, trigger, id string, ex Executor) (*store.LPRevocation, error) {
	return restore(tx, now, actor, trigger, "restore requested ("+trigger+")", id, ex)
}

// restore is Restore with the detail the transition's event records (a denial names its event there).
func restore(tx *store.TenantTx, now time.Time, actor, trigger, detail, id string, ex Executor) (*store.LPRevocation, error) {
	r, err := tx.LPRevocation(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(404, "not_found", "no such revocation")
	} else if err != nil {
		return nil, err
	}
	switch r.State {
	case store.LPRevoked:
	case store.LPRestoring, store.LPRestored:
		return r, nil // already on its way back
	case store.LPFinalized:
		return nil, refuse(409, "finalized", "the revocation is final: the access comes back through an ordinary access request")
	default:
		return nil, refuse(409, "not_revoked", "only a revoked grant is restored (this one is %s)", r.State)
	}
	if DigestPayload(r.RestorePayload) != r.RestoreSHA256 {
		return nil, refuse(409, "payload_digest_mismatch", "the stored restore payload does not match the digest recorded at the revoke: it is not restored")
	}
	opID, err := ex.EnqueueRestore(tx, now, r)
	if err != nil {
		return nil, err
	}
	r.RestoreOpID, r.RestoreTrigger, r.RestoreRequestedAt = opID, trigger, &now
	return r, Move(tx, now, r, store.LPRestoring, actor, detail)
}

// Recheck is what the API found when it computed the right-size again just before the revoke.
type Recheck struct {
	// OK: the same verified right-size, with no usage since the announcement.
	OK bool
	// Reason says why it is not (the grant vanished, the snapshot moved, a call was used).
	Reason string
}

// Tick is the result of one pass.
type Tick struct {
	Revoking, Revoked, Finalized, Restored, Failed, Superseded, Expired, Held int
	// Holds counts, by reason, the announced revocations that were due and not executed.
	Holds map[string]int
	// Paused is the reason the pass paused the loop, if it did.
	Paused string
}

// Run advances every revocation one step. Verification, finalizing and restores always proceed; new executions
// need an active loop (staged mode, not paused, not disabled) and room under the caps. rechecks holds, per
// revocation id, the right-size computed again just before the revoke: one that is missing is left for the next pass.
func Run(tx *store.TenantTx, now time.Time, ex Executor, disabled bool, rechecks map[string]Recheck) (*Tick, error) {
	t := &Tick{Holds: map[string]int{}}
	s, err := tx.LPSettings()
	if err != nil {
		return nil, err
	}
	pause := func(reason string) error {
		if s.Paused {
			return nil
		}
		ns, err := Pause(tx, now, ActorAuto, reason, ex)
		if err != nil {
			return err
		}
		s, t.Paused = ns, reason
		return nil
	}
	// verification of what is in flight
	revoking, err := tx.LPRevocationsToAdvance(store.LPRevoking, 500)
	if err != nil {
		return nil, err
	}
	for _, r := range revoking {
		st, err := ex.OpStatus(tx, r.OpID)
		if errors.Is(err, store.ErrNotFound) {
			st = opFailed
		} else if err != nil {
			return nil, err
		}
		switch st {
		case opVerified:
			until := now.AddDate(0, 0, s.FinalizeDays)
			r.RevokedAt, r.RestoreUntil = &now, &until
			if err := Move(tx, now, r, store.LPRevoked, ActorTick, "verified by re-reading the target"); err != nil {
				return nil, err
			}
			t.Revoked++
		case opFailed, opMismatch:
			r.Reason = "the revoking operation " + st
			if err := Move(tx, now, r, store.LPFailed, ActorTick, r.Reason); err != nil {
				return nil, err
			}
			t.Failed++
			if err := pause("a revocation failed: " + r.ID); err != nil {
				return nil, err
			}
		case opCancelled:
			r.Reason = "the revoking operation was cancelled"
			if err := Move(tx, now, r, store.LPSuperseded, ActorTick, r.Reason); err != nil {
				return nil, err
			}
			t.Superseded++
		}
	}
	restoring, err := tx.LPRevocationsToAdvance(store.LPRestoring, 500)
	if err != nil {
		return nil, err
	}
	for _, r := range restoring {
		st, err := ex.OpStatus(tx, r.RestoreOpID)
		if errors.Is(err, store.ErrNotFound) {
			st = opFailed
		} else if err != nil {
			return nil, err
		}
		switch st {
		case opVerified:
			r.RestoredAt = &now
			if err := Move(tx, now, r, store.LPRestored, ActorTick, "verified by re-reading the target"); err != nil {
				return nil, err
			}
			// a restored grant was a false positive: it is not proposed again for 180 days
			if err := tx.InsertLPExemption(&store.LPExemption{Principal: r.Principal, PolicyARN: r.PolicyARN, Source: store.LPExemptRestore,
				Reason: "restored (" + r.RestoreTrigger + ")", RevocationID: r.ID, Until: now.AddDate(0, 0, ExemptionDays), CreatedBy: ActorTick, CreatedAt: now}); err != nil {
				return nil, err
			}
			t.Restored++
		case opFailed, opMismatch, opCancelled:
			r.Reason = "the restoring operation " + st
			if err := Move(tx, now, r, store.LPFailed, ActorTick, r.Reason); err != nil {
				return nil, err
			}
			t.Failed++
			if err := pause("a restore failed: " + r.ID); err != nil {
				return nil, err
			}
		}
	}
	revoked, err := tx.LPRevocationsToAdvance(store.LPRevoked, 500)
	if err != nil {
		return nil, err
	}
	for _, r := range revoked {
		if r.RestoreUntil != nil && !r.RestoreUntil.After(now) {
			r.FinalizedAt = &now
			if err := Move(tx, now, r, store.LPFinalized, ActorTick, "no denial or re-request in the finalize period"); err != nil {
				return nil, err
			}
			t.Finalized++
		}
	}
	cands, err := tx.LPRevocationsToAdvance(store.LPCandidate, 500)
	if err != nil {
		return nil, err
	}
	for _, r := range cands {
		if r.CreatedAt.AddDate(0, 0, CandidateTTLDays).Before(now) {
			r.Reason = "not approved in time"
			if err := Move(tx, now, r, store.LPSuperseded, ActorTick, r.Reason); err != nil {
				return nil, err
			}
			t.Expired++
		}
	}
	// the loop's own tripwires
	if !s.Paused && (s.Mode == store.LPModeStaged || s.Mode == store.LPModeAuto) {
		if reason, err := tripwire(tx, now); err != nil {
			return nil, err
		} else if reason != "" {
			if err := pause(reason); err != nil {
				return nil, err
			}
		}
	}
	// new executions
	if disabled || !Active(s) {
		return t, nil
	}
	due, err := tx.LPRevocationsToAdvance(store.LPAnnounced, 500)
	if err != nil {
		return nil, err
	}
	run := 0
	for _, r := range due {
		if r.AnnounceUntil == nil || r.AnnounceUntil.After(now) {
			continue
		}
		if s.Paused { // a failure above paused the loop mid-pass
			break
		}
		rc, ok := rechecks[r.ID]
		if !ok {
			t.Holds["recheck_pending"]++
			continue
		}
		if why, err := Guard(tx, now, r.Principal, r.PolicyARN); err != nil {
			return nil, err
		} else if why != "" {
			rc = Recheck{Reason: "the grant is now " + why}
		}
		if !rc.OK {
			r.Reason = rc.Reason
			if err := Move(tx, now, r, store.LPSuperseded, ActorTick, rc.Reason); err != nil {
				return nil, err
			}
			t.Superseded++
			continue
		}
		hold, err := Hold(tx, now, s, r, run)
		if err != nil {
			return nil, err
		}
		if hold != "" {
			t.Holds[hold]++ // stays announced: held for a later pass, not dropped
			t.Held++
			continue
		}
		if err := ex.Ready(tx, r); err != nil {
			t.Holds["not_ready"]++
			t.Held++
			continue
		}
		opID, err := ex.Enqueue(tx, now, r)
		var refused *Error
		if errors.As(err, &refused) {
			// the write target refuses this change (a document that does not match its digest, a restore-less kind):
			// a failed revocation, which pauses the loop, not an error that would stop every pass
			r.Reason = refused.Msg
			if err := Move(tx, now, r, store.LPFailed, ActorTick, refused.Msg); err != nil {
				return nil, err
			}
			t.Failed++
			if err := pause("a revocation could not be queued: " + r.ID); err != nil {
				return nil, err
			}
			continue
		} else if err != nil {
			return nil, err
		}
		r.OpID, r.ExecutedAt = opID, &now
		if err := Move(tx, now, r, store.LPRevoking, ActorTick, "queued through the AWS write target"); err != nil {
			return nil, err
		}
		run++
		t.Revoking++
	}
	return t, nil
}

// tripwire is the automatic pause: three restores in the last hour (one run), a rolling-7-day restore rate above
// 2 percent, or an evaluator disagreement triaged as an engine bug.
func tripwire(tx *store.TenantTx, now time.Time) (string, error) {
	if n, err := tx.LPRestoredSince(now.Add(-time.Hour)); err != nil {
		return "", err
	} else if n >= RestoresPerRunPause {
		return fmt.Sprintf("%d restores in one run", n), nil
	}
	week := now.AddDate(0, 0, -7)
	restored, err := tx.LPRestoredSince(week)
	if err != nil {
		return "", err
	}
	executed, err := tx.LPExecutedSince(week, "", "")
	if err != nil {
		return "", err
	}
	if restored > 0 && executed > 0 && restored*100 > executed*RestoreRatePausePercent {
		return fmt.Sprintf("%d of %d revocations restored in 7 days", restored, executed), nil
	}
	if cs, err := tx.AWSShadowChecks(store.AWSShadowDisagree, store.AWSTriageEngineBug, 1); err != nil {
		return "", err
	} else if len(cs) > 0 && !cs[0].CheckedAt.Before(now.AddDate(0, 0, -30)) {
		return "an evaluator disagreement is an engine bug", nil
	}
	return "", nil
}
