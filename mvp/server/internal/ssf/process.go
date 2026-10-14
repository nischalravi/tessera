package ssf

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/containment"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Actor is the audit actor of events the receiver and the poller write when
// the caller sets none.
const Actor = "ssf.receiver"

// actions are the kill-switch steps an event runs on the subject's other
// linked accounts.
func actions(eventType string) []string {
	switch eventType {
	case EventSessionRevoked:
		return []string{containment.ActionRevokeSessions}
	case EventCredentialChange, EventAccountDisabled:
		return []string{containment.ActionRevokeSessions, containment.ActionRevokeGrants}
	}
	return nil
}

func terminal(status string) bool {
	return status != store.SSFEventReceived && status != store.SSFEventMatched
}

func (s *Service) containTimeout() time.Duration {
	if s.ContainTimeout > 0 {
		return s.ContainTimeout
	}
	return 20 * time.Second
}

func (s *Service) expect() Expect {
	return Expect{Now: s.now(), Skew: s.Skew, MaxAge: s.MaxAge}
}

// Receive validates one SET delivered by transmitter tr (via push or poll),
// records it and runs the actions it calls for. It returns the event row.
//
// A refusal (bad signature, wrong issuer or audience, a stale iat, ...) is an
// *Error: the SET is audited as rejected, nothing else happens. Any other
// error is ours (the database, the transmitter's key endpoint): the transmitter
// should deliver again. A jti that was seen before is not processed twice; the
// stored row is returned (a row that never finished is resumed).
//
// expectJTI, when set (a poll response names each SET by its jti), must be
// the SET's jti.
func (s *Service) Receive(ctx context.Context, db *store.DB, tenant tenancy.ID, tr *store.SSFTransmitter, via, raw, expectJTI string) (*store.SSFEvent, error) {
	started := time.Now()
	if tr.Status != store.SSFEnabled {
		return nil, &Error{Code: ErrAccessDenied, Msg: "this stream is " + tr.Status}
	}
	ex := s.expect()
	ex.Issuer, ex.Audience = tr.Issuer, tr.Audience
	keys, err := s.keys(ctx, tr, false)
	if err != nil {
		s.noteError(ctx, db, tenant, tr.ID, "the signing keys could not be fetched")
		return nil, err
	}
	set, err := ParseSET(raw, keys, ex)
	var perr *Error
	if errors.As(err, &perr) && perr.Code == ErrInvalidKey && tr.JWKSInline == "" {
		// the transmitter may have rotated its keys: look once more
		if fresh, kerr := s.keys(ctx, tr, true); kerr == nil {
			set, err = ParseSET(raw, fresh, ex)
		}
	}
	if err == nil && expectJTI != "" && set.JTI != expectJTI {
		err = invalid("the SET's jti is not the one it was delivered under")
	}
	if err != nil {
		if errors.As(err, &perr) {
			s.reject(ctx, db, tenant, tr, via, perr)
		}
		return nil, err
	}
	ev := &store.SSFEvent{TransmitterID: tr.ID, JTI: set.JTI, Via: via, EventType: set.EventType,
		SubjectFormat: set.Subject.Format, Subject: set.Subject.Label(), ReceivedAt: s.now(), IATAt: set.IssuedAt}
	var replay bool
	err = db.InTenant(ctx, tenant, func(c *store.TenantTx) error {
		ierr := c.InsertSSFEvent(ev)
		if errors.Is(ierr, store.ErrDuplicate) {
			old, err := c.SSFEventByJTI(tr.ID, set.JTI)
			if err != nil {
				return err
			}
			*ev, replay = *old, true
			if !terminal(ev.Status) {
				return nil // a delivery that never finished: resume it
			}
			return c.Audit(s.now(), Actor, "ssf.event_replayed", ojson.Object{{Key: "event_id", Value: ev.ID},
				{Key: "transmitter_id", Value: tr.ID}, {Key: "jti", Value: set.JTI}, {Key: "via", Value: via},
				{Key: "status", Value: ev.Status}})
		}
		if ierr != nil {
			return ierr
		}
		if err := c.TouchSSFTransmitter(tr.ID, ev.ReceivedAt); err != nil {
			return err
		}
		if err := c.SetSSFTransmitterError(tr.ID, "", ev.ReceivedAt); err != nil {
			return err
		}
		return c.Audit(ev.ReceivedAt, Actor, "ssf.event_received", ojson.Object{{Key: "event_id", Value: ev.ID},
			{Key: "transmitter_id", Value: tr.ID}, {Key: "transmitter", Value: tr.Name}, {Key: "jti", Value: set.JTI},
			{Key: "via", Value: via}, {Key: "event_type", Value: set.EventType}, {Key: "event", Value: EventName(set.EventType)},
			{Key: "subject_format", Value: set.Subject.Format}, {Key: "subject", Value: ev.Subject},
			{Key: "iat", Value: ev.IATAt.UTC().Format(time.RFC3339)}})
	})
	if err != nil {
		return nil, err
	}
	if replay && terminal(ev.Status) {
		return ev, nil
	}
	if err := s.process(ctx, db, tenant, tr, ev, set, started); err != nil {
		return nil, err
	}
	return ev, nil
}

// noteError records a transmitter's last error (best effort).
func (s *Service) noteError(ctx context.Context, db *store.DB, tenant tenancy.ID, id, msg string) {
	_ = db.InTenant(ctx, tenant, func(c *store.TenantTx) error {
		return c.SetSSFTransmitterError(id, msg, s.now())
	})
}

// reject audits a refused SET (its reason, never the token) and records it as
// the transmitter's last error.
func (s *Service) reject(ctx context.Context, db *store.DB, tenant tenancy.ID, tr *store.SSFTransmitter, via string, e *Error) {
	_ = db.InTenant(ctx, tenant, func(c *store.TenantTx) error {
		now := s.now()
		if err := c.SetSSFTransmitterError(tr.ID, "rejected a SET: "+e.Code+": "+e.Msg, now); err != nil {
			return err
		}
		return c.Audit(now, Actor, "ssf.event_rejected", ojson.Object{{Key: "transmitter_id", Value: tr.ID},
			{Key: "transmitter", Value: tr.Name}, {Key: "via", Value: via}, {Key: "error", Value: e.Code},
			{Key: "reason", Value: e.Msg}})
	})
}

// process acts on a recorded event.
func (s *Service) process(ctx context.Context, db *store.DB, tenant tenancy.ID, tr *store.SSFTransmitter, ev *store.SSFEvent, set *SET, started time.Time) error {
	switch {
	case set.EventType == EventVerification:
		return s.finish(ctx, db, tenant, tr, ev, started, store.SSFEventIgnored, "verification event", nil, func(c *store.TenantTx, now time.Time) error {
			state, _ := set.Payload["state"].(string)
			if tr.VerificationState == "" || state != tr.VerificationState {
				return c.Audit(now, Actor, "ssf.verification_received", ojson.Object{{Key: "transmitter_id", Value: tr.ID},
					{Key: "event_id", Value: ev.ID}, {Key: "matched_request", Value: false}})
			}
			if err := c.SetSSFVerified(tr.ID, now); err != nil {
				return err
			}
			return c.Audit(now, Actor, "ssf.verification_received", ojson.Object{{Key: "transmitter_id", Value: tr.ID},
				{Key: "event_id", Value: ev.ID}, {Key: "matched_request", Value: true}})
		})
	case !set.Known:
		return s.finish(ctx, db, tenant, tr, ev, started, store.SSFEventIgnored,
			"unknown event type: acknowledged and ignored", nil, func(c *store.TenantTx, now time.Time) error {
				return c.Audit(now, Actor, "ssf.event_ignored", ojson.Object{{Key: "event_id", Value: ev.ID},
					{Key: "transmitter_id", Value: tr.ID}, {Key: "event_type", Value: set.EventType},
					{Key: "reason", Value: "unknown event type"}})
			})
	}
	var job *containment.Job
	var acct *store.Account
	var ident *store.Identity
	var reason string
	err := db.ReadTenant(ctx, tenant, func(c *store.TenantTx) error {
		var err error
		if acct, ident, reason, err = resolveSubject(c, tr.SubjectSystem, set.Subject); err != nil || reason != "" {
			return err
		}
		specs, err := s.specs(c, tr, ident.ID, set.EventType)
		if err != nil || len(specs) == 0 {
			return err
		}
		if s.Containment == nil {
			return errNoContainment
		}
		job, err = s.Containment.BuildJob(c, ident.ID, "ssf", specs)
		return err
	})
	if errors.Is(err, errNoContainment) {
		return s.finish(ctx, db, tenant, tr, ev, started, store.SSFEventFailed,
			"containment is not configured on this server; nothing was revoked", &match{acct, ident}, s.actionedAudit(ev, tr, set, ident, 0, 0))
	}
	if err != nil {
		return err
	}
	if reason != "" {
		return s.finish(ctx, db, tenant, tr, ev, started, store.SSFEventUnmatched, reason, nil, func(c *store.TenantTx, now time.Time) error {
			return c.Audit(now, Actor, "ssf.event_unmatched", ojson.Object{{Key: "event_id", Value: ev.ID},
				{Key: "transmitter_id", Value: tr.ID}, {Key: "event_type", Value: set.EventType},
				{Key: "subject_format", Value: set.Subject.Format}, {Key: "subject", Value: ev.Subject},
				{Key: "reason", Value: reason}})
		})
	}
	m := &match{acct, ident}
	if job == nil {
		return s.finish(ctx, db, tenant, tr, ev, started, store.SSFEventNoAction,
			"the identity has no other linked account with a kill-switch connection", m, s.actionedAudit(ev, tr, set, ident, 0, 0))
	}
	// matched: recorded before the provider calls, which can take a while
	if err := db.InTenant(ctx, tenant, func(c *store.TenantTx) error {
		ev.IdentityID, ev.AccountID, ev.Status = &ident.ID, &acct.ID, store.SSFEventMatched
		ev.Outcome = fmt.Sprintf("running %d kill-switch step(s)", len(job.Items))
		return c.UpdateSSFEvent(ev)
	}); err != nil {
		return err
	}
	rctx, cancel := context.WithTimeout(ctx, s.containTimeout())
	defer cancel()
	rep := s.Containment.Run(rctx, job)
	return db.InTenant(ctx, tenant, func(c *store.TenantTx) error {
		now := s.now()
		if err := containment.Record(c, now, Actor, rep); err != nil {
			return err
		}
		retries, err := containment.EnqueueRetries(c, now, job, rep)
		if err != nil {
			return err
		}
		failed := len(rep.Failed())
		status := store.SSFEventActioned
		if failed > 0 {
			status = store.SSFEventFailed
		}
		ev.IdentityID, ev.AccountID = &ident.ID, &acct.ID
		ev.Status, ev.Steps, ev.StepsFailed = status, len(rep.Steps), failed
		ev.Outcome = outcomeText(rep, len(retries))
		s.stamp(ev, started, now)
		if err := c.UpdateSSFEvent(ev); err != nil {
			return err
		}
		return s.actionedAudit(ev, tr, set, ident, len(retries), len(rep.Manual))(c, now)
	})
}

var errNoContainment = errors.New("containment is not configured")

type match struct {
	acct  *store.Account
	ident *store.Identity
}

func outcomeText(rep *containment.Report, retries int) string {
	done, manual, failed := 0, 0, 0
	for _, st := range rep.Steps {
		switch st.Outcome {
		case containment.OutcomeDone:
			done++
		case containment.OutcomeManual:
			manual++
		default:
			failed++
		}
	}
	out := fmt.Sprintf("%d step(s) done and verified", done)
	if manual > 0 {
		out += fmt.Sprintf(", %d need a person", manual)
	}
	if failed > 0 {
		out += fmt.Sprintf(", %d failed (%d retry task(s) queued)", failed, retries)
	}
	return out
}

// stamp sets the time of the last action and the two latencies: receipt to
// the last action (measured on the monotonic clock) and the SET's iat to it.
func (s *Service) stamp(ev *store.SSFEvent, started, now time.Time) {
	latency := max(time.Since(started).Milliseconds(), 0)
	iatLatency := max(now.Sub(ev.IATAt).Milliseconds(), 0)
	ev.ActionedAt, ev.LatencyMS, ev.IATLatencyMS = &now, &latency, &iatLatency
}

// actionedAudit audits ssf.event_actioned: what ran, how long it took.
func (s *Service) actionedAudit(ev *store.SSFEvent, tr *store.SSFTransmitter, set *SET, ident *store.Identity, retries, manual int) func(*store.TenantTx, time.Time) error {
	return func(c *store.TenantTx, now time.Time) error {
		d := ojson.Object{{Key: "event_id", Value: ev.ID}, {Key: "transmitter_id", Value: tr.ID},
			{Key: "event_type", Value: set.EventType}, {Key: "event", Value: EventName(set.EventType)},
			{Key: "status", Value: ev.Status}, {Key: "outcome", Value: ev.Outcome}, {Key: "steps", Value: ev.Steps},
			{Key: "steps_failed", Value: ev.StepsFailed}, {Key: "manual_tasks", Value: manual}, {Key: "retries_queued", Value: retries}}
		if ident != nil {
			d = append(d, ojson.KV{Key: "identity_id", Value: ident.ID}, ojson.KV{Key: "identity", Value: ident.Name})
		}
		if ev.LatencyMS != nil {
			d = append(d, ojson.KV{Key: "latency_ms", Value: *ev.LatencyMS}, ojson.KV{Key: "iat_latency_ms", Value: *ev.IATLatencyMS})
		}
		return c.Audit(now, Actor, "ssf.event_actioned", d)
	}
}

// finish records a terminal outcome that ran no provider call: the status, the
// outcome text and, through extra, the audit event.
func (s *Service) finish(ctx context.Context, db *store.DB, tenant tenancy.ID, tr *store.SSFTransmitter, ev *store.SSFEvent,
	started time.Time, status, outcome string, m *match, extra func(*store.TenantTx, time.Time) error) error {
	return db.InTenant(ctx, tenant, func(c *store.TenantTx) error {
		now := s.now()
		ev.Status, ev.Outcome = status, outcome
		if m != nil {
			ev.IdentityID, ev.AccountID = &m.ident.ID, &m.acct.ID
		}
		s.stamp(ev, started, now)
		if err := c.UpdateSSFEvent(ev); err != nil {
			return err
		}
		return extra(c, now)
	})
}

// specs lists the steps an event runs: the event's actions on the identity's
// accounts with a kill-switch connection, except on the transmitter's own
// system (it already acted).
func (s *Service) specs(c *store.TenantTx, tr *store.SSFTransmitter, identityID int64, eventType string) ([]containment.Spec, error) {
	all, err := containment.Steps(c, identityID, true)
	if err != nil {
		return nil, err
	}
	accts, err := c.IdentityAccounts(identityID)
	if err != nil {
		return nil, err
	}
	system := map[int64]string{}
	for _, a := range accts {
		system[a.ID] = a.System
	}
	want := map[string]bool{}
	for _, a := range actions(eventType) {
		want[a] = true
	}
	var out []containment.Spec
	for _, sp := range all {
		if want[sp.Action] && system[sp.AccountID] != tr.SubjectSystem {
			out = append(out, sp)
		}
	}
	return out, nil
}

// resolveSubject resolves a subject to an account of the transmitter's system
// and to the identity the account is linked to. reason says why it did not.
func resolveSubject(c *store.TenantTx, system string, sub Subject) (*store.Account, *store.Identity, string, error) {
	if sub.Format == "complex" && sub.User != nil {
		sub = *sub.User
	}
	if sub.Problem != "" {
		return nil, nil, sub.Problem, nil
	}
	var accts []*store.Account
	var err error
	switch sub.Format {
	case "iss_sub", "opaque":
		accts, err = c.AccountsByExternalID(system, sub.ID)
	case "email", "account":
		if accts, err = c.AccountsByLogin(system, sub.ID); err == nil && len(accts) == 0 {
			accts, err = c.AccountsByExternalID(system, sub.ID)
		}
	default:
		return nil, nil, "unsupported subject format", nil
	}
	if err != nil {
		return nil, nil, "", err
	}
	if len(accts) == 0 {
		return nil, nil, "no " + system + " account matches the subject", nil
	}
	var acct *store.Account
	ids := map[int64]bool{}
	for _, a := range accts {
		if a.IdentityID != nil {
			ids[*a.IdentityID] = true
			if acct == nil {
				acct = a
			}
		}
	}
	switch {
	case len(ids) == 0:
		return nil, nil, "the " + system + " account is not linked to an identity", nil
	case len(ids) > 1:
		return nil, nil, fmt.Sprintf("ambiguous: the subject matches accounts of %d identities", len(ids)), nil
	}
	ident, err := c.Identity(*acct.IdentityID)
	if err != nil {
		return nil, nil, "", err
	}
	return acct, ident, "", nil
}
