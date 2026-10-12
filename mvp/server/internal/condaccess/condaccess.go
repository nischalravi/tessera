// Package condaccess decides conditional access (issue #163): given where a
// request comes from and what the IdP and admins know about the user's
// device, the tenant's policies answer allow, require step-up or deny.
//
// Policies apply to one scope, the Tessera sign-in or privileged actions, and
// are checked in priority order: the first enforced policy whose conditions
// all hold decides, and no match is allow. A report_only policy is evaluated
// and recorded in the decision but never changes the outcome, so a policy can
// be observed before it is enforced.
//
// The package is pure: no I/O and no clock. Callers supply the client IP
// (the trusted-proxy address, never a raw X-Forwarded-For), the device
// posture and the policies, and audit the Decision, whose Audit method
// lists the inputs that drove it.
package condaccess

import (
	"errors"
	"net/netip"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/auth/normalize"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Compliance states of a device.
const (
	Compliant    = "compliant"
	NotCompliant = "not_compliant"
	Unknown      = "unknown"
)

// Where the compliance verdict came from.
const (
	SourceNone   = "none"
	SourceIdP    = "idp_claim"
	SourceSignal = "signal" // suffixed with the signal's source: signal:manual, signal:caep
)

// DeviceState is the device posture a decision used.
type DeviceState struct {
	Managed          *bool  // nil: the IdP did not say
	Compliance       string // compliant | not_compliant | unknown
	ComplianceSource string
}

// SignalSource supplies the device-compliance signal of a user. The manual
// (admin-set) source is StoreSignals; the CAEP receiver of #114 will write
// device-compliance-change events into the same store, or implement this
// interface itself.
type SignalSource interface {
	// DeviceSignal returns the user's current (unexpired) signal, nil when none.
	DeviceSignal(tx *store.TenantTx, user uuid.UUID, now time.Time) (*store.DeviceSignal, error)
}

// StoreSignals reads the signals kept in device_compliance_signals (set by an
// admin, source manual, or by the future CAEP receiver, source caep).
type StoreSignals struct{}

// DeviceSignal implements SignalSource.
func (StoreSignals) DeviceSignal(tx *store.TenantTx, user uuid.UUID, now time.Time) (*store.DeviceSignal, error) {
	s, err := tx.DeviceSignal(user)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	if s.ExpiresAt != nil && !now.Before(*s.ExpiresAt) {
		return nil, nil
	}
	return s, nil
}

// ResolveDevice combines what the IdP asserted at sign-in with the user's
// signal. Not compliant from either source wins (a fresh "not compliant"
// signal is never overridden by an older "compliant" claim, and a claim is
// not overridden by a manual "compliant" signal); otherwise a compliant
// verdict from either counts; otherwise unknown.
func ResolveDevice(claims normalize.Device, sig *store.DeviceSignal) DeviceState {
	d := DeviceState{Managed: claims.Managed, Compliance: Unknown, ComplianceSource: SourceNone}
	if claims.Compliant != nil {
		d.ComplianceSource = SourceIdP
		d.Compliance = NotCompliant
		if *claims.Compliant {
			d.Compliance = Compliant
		}
	}
	if sig != nil {
		switch {
		case sig.Status == store.DeviceNonCompliant:
			d.Compliance, d.ComplianceSource = NotCompliant, SourceSignal+":"+sig.Source
		case d.Compliance != NotCompliant:
			d.Compliance, d.ComplianceSource = Compliant, SourceSignal+":"+sig.Source
		}
	}
	return d
}

// Input is what a decision is made on.
type Input struct {
	Scope string
	// ClientIP is the trusted-proxy client address; the zero Addr means it
	// could not be determined.
	ClientIP netip.Addr
	// IPVia says how the address was found: peer (the TCP peer) or
	// x_forwarded_for (taken from the header of a trusted proxy).
	IPVia  string
	Device DeviceState
}

// Hit is a policy that matched.
type Hit struct {
	PolicyID     uuid.UUID
	Name         string
	Mode         string
	Outcome      string
	StepUpACR    string
	StepUpMaxAge int // seconds
}

// Decision is the answer for one input.
type Decision struct {
	Scope string
	// Outcome is the enforced result: allow, step_up or deny.
	Outcome string
	// Enforced is the policy that decided; nil when none matched.
	Enforced *Hit
	// ReportOnly are the report_only policies that matched, with the outcome
	// each would have had; they did not change Outcome.
	ReportOnly []Hit
	// Evaluated counts the enabled policies of the scope that were checked.
	Evaluated int
	Input     Input
}

// StepUp reports whether the outcome is a step-up requirement, with it.
func (d Decision) StepUp() (acr string, maxAge int, ok bool) {
	if d.Outcome != store.AccessStepUp || d.Enforced == nil {
		return "", 0, false
	}
	return d.Enforced.StepUpACR, d.Enforced.StepUpMaxAge, true
}

// Evaluate decides in.Scope. policies and ranges are the tenant's; ranges a
// policy names that are missing count as empty (no address is in them).
func Evaluate(policies []*store.AccessPolicy, ranges []*store.NetworkRange, in Input) Decision {
	d := Decision{Scope: in.Scope, Outcome: store.AccessAllow, Input: in}
	byID := map[uuid.UUID]*store.NetworkRange{}
	for _, r := range ranges {
		byID[r.ID] = r
	}
	// evaluation order: priority, then age, then id (the store lists in this
	// order per scope; sorting here keeps Evaluate correct for any input)
	ordered := slices.Clone(policies)
	slices.SortStableFunc(ordered, func(a, b *store.AccessPolicy) int {
		if a.Priority != b.Priority {
			return a.Priority - b.Priority
		}
		if c := a.CreatedAt.Compare(b.CreatedAt); c != 0 {
			return c
		}
		return slices.Compare(a.ID[:], b.ID[:])
	})
	for _, p := range ordered {
		if p.Scope != in.Scope || p.Mode == store.AccessModeDisabled {
			continue
		}
		d.Evaluated++
		if !matches(p, byID, in) {
			continue
		}
		h := hit(p)
		switch {
		case p.Mode == store.AccessModeReportOnly:
			d.ReportOnly = append(d.ReportOnly, h)
		case d.Enforced == nil: // the first enforced match decides
			d.Enforced, d.Outcome = &h, p.Outcome
		}
	}
	return d
}

func hit(p *store.AccessPolicy) Hit {
	h := Hit{PolicyID: p.ID, Name: p.Name, Mode: p.Mode, Outcome: p.Outcome, StepUpMaxAge: p.StepUpMaxAge}
	if p.StepUpACR != nil {
		h.StepUpACR = *p.StepUpACR
	}
	return h
}

// matches reports whether every condition of p holds for in.
func matches(p *store.AccessPolicy, ranges map[uuid.UUID]*store.NetworkRange, in Input) bool {
	switch p.NetworkOp {
	case store.NetworkIn:
		if !inAny(p.NetworkRangeIDs, ranges, in.ClientIP) {
			return false
		}
	case store.NetworkNotIn:
		// an address that is unknown is not in any range
		if inAny(p.NetworkRangeIDs, ranges, in.ClientIP) {
			return false
		}
	}
	switch p.Device {
	case store.DeviceUnmanaged:
		if in.Device.Managed != nil && *in.Device.Managed {
			return false
		}
	case store.DeviceNotCompliant:
		if in.Device.Compliance == Compliant {
			return false
		}
	}
	return true
}

func inAny(ids []uuid.UUID, ranges map[uuid.UUID]*store.NetworkRange, ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	ip = ip.Unmap()
	for _, id := range ids {
		r := ranges[id]
		if r == nil {
			continue
		}
		for _, c := range r.CIDRs {
			if p, err := netip.ParsePrefix(c); err == nil && p.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// Audit is the decision as an audit detail: the outcome, the policy that
// decided, the report-only policies that matched, and the inputs (client
// address and how it was found, device posture) that drove it.
func (d Decision) Audit() ojson.Object {
	ip := ""
	if d.Input.ClientIP.IsValid() {
		ip = d.Input.ClientIP.Unmap().String()
	}
	managed := "unknown"
	if m := d.Input.Device.Managed; m != nil {
		managed = map[bool]string{true: "managed", false: "unmanaged"}[*m]
	}
	out := ojson.Object{{Key: "scope", Value: d.Scope}, {Key: "outcome", Value: d.Outcome},
		{Key: "policies_evaluated", Value: d.Evaluated}}
	if d.Enforced != nil {
		out = append(out, ojson.KV{Key: "decided_by", Value: d.Enforced.audit()})
	}
	if len(d.ReportOnly) > 0 {
		hits := make([]any, len(d.ReportOnly))
		for i, h := range d.ReportOnly {
			hits[i] = h.audit()
		}
		out = append(out, ojson.KV{Key: "report_only", Value: hits})
	}
	return append(out, ojson.KV{Key: "inputs", Value: ojson.Object{
		{Key: "client_ip", Value: ip}, {Key: "client_ip_via", Value: d.Input.IPVia},
		{Key: "device_managed", Value: managed}, {Key: "device_compliance", Value: d.Input.Device.Compliance},
		{Key: "device_compliance_source", Value: d.Input.Device.ComplianceSource}}})
}

func (h Hit) audit() ojson.Object {
	o := ojson.Object{{Key: "policy_id", Value: h.PolicyID.String()}, {Key: "name", Value: h.Name},
		{Key: "mode", Value: h.Mode}, {Key: "outcome", Value: h.Outcome}}
	if h.StepUpACR != "" {
		o = append(o, ojson.KV{Key: "step_up_acr", Value: h.StepUpACR}, ojson.KV{Key: "step_up_max_age", Value: h.StepUpMaxAge})
	}
	return o
}
