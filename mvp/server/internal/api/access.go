package api

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	authnorm "github.com/nischalravi/tessera/mvp/server/internal/auth/normalize"
	"github.com/nischalravi/tessera/mvp/server/internal/condaccess"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Conditional access enforcement (issue #163). The tenant's policies are
// evaluated in two places:
//
//   - at the Tessera sign-in (finishLogin, scope signin): a deny refuses the
//     sign-in, and a step-up refuses it unless this very authentication
//     already meets the policy's ACR (and age);
//   - on privileged actions (authorize and accessCheck, scope privileged): a
//     route that declares a step-up requirement is checked against the
//     policies too. A deny answers 403 conditional_access_denied, and a
//     step-up outcome tightens the route's own requirement, so the existing
//     RFC 9470 challenge (401 step_up_required) is what the client sees.
//
// The inputs are the trusted-proxy client address (clientIP: an
// X-Forwarded-For counts only when the peer is a trusted proxy), the device
// claims the IdP asserted at sign-in, and the user's device-compliance
// signal. Every evaluation that had a policy to check is audited with those
// inputs (access.decision, or the auth.login events of a sign-in). Policies in
// report_only mode are audited with the outcome they would have had and
// change nothing.

const (
	errConditionalAccessDenied = "conditional_access_denied"
	// Sign-in refusal reasons (auth.login.failure detail.reason).
	reasonAccessDenied = "conditional_access_denied"
	reasonAccessStepUp = "conditional_access_step_up_required"
)

// accessDecision evaluates scope's policies for a request. user is the
// user whose device-compliance signal applies (nil: none yet) and claims the
// device posture the IdP asserted for the authentication.
func (s *Server) accessDecision(tx *store.TenantTx, r *http.Request, scope string, user *uuid.UUID,
	claims authnorm.Device) (condaccess.Decision, error) {
	pols, err := tx.AccessPolicies()
	if err != nil {
		return condaccess.Decision{}, err
	}
	ranges, err := tx.NetworkRanges()
	if err != nil {
		return condaccess.Decision{}, err
	}
	var sig *store.DeviceSignal
	if user != nil {
		if sig, err = s.signals.DeviceSignal(tx, *user, s.clock()); err != nil {
			return condaccess.Decision{}, err
		}
	}
	ip, via, resolved := s.accessClientIP(r)
	dec := condaccess.Evaluate(pols, ranges, condaccess.Input{Scope: scope, ClientIP: ip, IPVia: via,
		IPUnresolved: !resolved, Device: condaccess.ResolveDevice(claims, sig)})
	if !resolved && (dec.Evaluated > 0) {
		// also covers report-only policies: the unresolved client is visible in the logs
		s.log.Warn("conditional access: client address unresolved", "scope", scope, "outcome", dec.Outcome,
			"report_only_hits", len(dec.ReportOnly), "path", r.URL.Path)
	}
	return dec, nil
}

// signinAccess evaluates the sign-in policies of a tenant for a sign-in that
// is about to create a session.
func (s *Server) signinAccess(ctx context.Context, tenant tenancy.ID, r *http.Request, user *uuid.UUID,
	res authnorm.Result) (condaccess.Decision, error) {
	var dec condaccess.Decision
	err := s.store.ReadTenant(ctx, tenant, func(tx *store.TenantTx) error {
		var err error
		dec, err = s.accessDecision(tx, r, store.AccessScopeSignin, user, res.Device)
		return err
	})
	return dec, err
}

// signinRefusal is why a sign-in must be refused under dec, or "". A step-up
// outcome is met when the sign-in's own authentication already satisfies the
// policy's ACR and age.
func signinRefusal(dec condaccess.Decision, res authnorm.Result, now time.Time) string {
	switch dec.Outcome {
	case store.AccessDeny:
		return reasonAccessDenied
	case store.AccessStepUp:
		acr, maxAge, _ := dec.StepUp()
		presented := auth.AuthnContext{AAL: res.AAL, PhishingResistant: res.PhishingResistant,
			TesseraACR: auth.ACR(res.TesseraACR), AuthTime: res.AuthTime}
		if !presented.Satisfies(auth.AuthnRequirement{ACR: auth.ACR(acr), MaxAge: time.Duration(maxAge) * time.Second}, now) {
			return reasonAccessStepUp
		}
	}
	return ""
}

// accessCheck is auth.Check for a privileged action plus the tenant's
// privileged-scope policies: the permission is checked first (so a caller
// without it learns nothing of the policies), then a deny refuses with 403
// conditional_access_denied, and a step-up outcome tightens authn. tx is the
// request's write transaction when the caller is inside one, else nil (the
// decision is read and recorded in transactions of its own). label names the
// action in the audit event.
func (s *Server) accessCheck(ctx context.Context, r *http.Request, tx *store.TenantTx, p *auth.Principal,
	perm auth.Permission, authn *auth.AuthnRequirement, label string) (*auth.Denial, error) {
	now := s.clock()
	if d := auth.Check(p, perm, nil, now); d != nil || authn == nil || p.Kind != auth.KindUser || p.Authn == nil {
		return auth.Check(p, perm, authn, now), nil
	}
	dec, err := s.privilegedDecision(ctx, r, tx, p, label)
	if err != nil {
		return nil, err
	}
	switch dec.Outcome {
	case store.AccessDeny:
		return &auth.Denial{Status: http.StatusForbidden, Error: errConditionalAccessDenied, Permission: perm}, nil
	case store.AccessStepUp:
		acr, maxAge, _ := dec.StepUp()
		m := authn.Merge(auth.AuthnRequirement{ACR: auth.ACR(acr), MaxAge: time.Duration(maxAge) * time.Second})
		authn = &m
	}
	return auth.Check(p, perm, authn, now), nil
}

// privilegedDecision evaluates the privileged-scope policies for p and, when
// a policy was checked, records access.decision. The event is not counted as
// the request's own domain event (a mutation still needs that one).
func (s *Server) privilegedDecision(ctx context.Context, r *http.Request, tx *store.TenantTx, p *auth.Principal,
	label string) (condaccess.Decision, error) {
	var dec condaccess.Decision
	var err error
	if tx != nil {
		dec, err = s.accessDecision(tx, r, store.AccessScopePrivileged, p.UserID, p.Authn.Device)
	} else {
		err = s.store.ReadTenant(ctx, p.TenantID, func(rt *store.TenantTx) error {
			var err error
			dec, err = s.accessDecision(rt, r, store.AccessScopePrivileged, p.UserID, p.Authn.Device)
			return err
		})
	}
	if err != nil || dec.Evaluated == 0 {
		return dec, err
	}
	record := func(w *store.TenantTx) error {
		detail := append(ojson.Object{{Key: "action", Value: label}}, dec.Audit()...)
		out := store.OutcomeSuccess
		if dec.Outcome == store.AccessDeny {
			out = store.OutcomeDenied
		}
		_, err := audit.Record(ctx, w, "access.decision", detail, audit.At(s.clock()), audit.Outcome(out))
		return err
	}
	if tx != nil {
		return dec, record(tx)
	}
	ac, _ := store.AuditContextFrom(ctx)
	ac.Committed = nil
	return dec, s.store.InTenant(store.WithAuditContext(ctx, ac), p.TenantID, record)
}

// writeAuditUnavailable answers a request whose access decision could not be
// recorded: nothing is decided without a record.
func writeAuditUnavailable(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusServiceUnavailable, ojson.Object{{Key: "error", Value: "audit_unavailable"},
		{Key: "request_id", Value: audit.RequestID(r.Context())}})
}
