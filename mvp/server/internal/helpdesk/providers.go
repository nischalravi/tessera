package helpdesk

import (
	"context"
	"errors"
	"strings"
)

// Verification providers. Push and IDV need a real provider (an IdP push API,
// an IDV vendor); until one is wired in, the simulated providers below record
// an attestation and are refused in production (Service.Simulated).

// PushRequest asks an identity's existing authenticator to approve a reset.
type PushRequest struct {
	CaseID   string
	System   string
	UserID   string // the provider's user id
	Username string
}

// PushResult is the identity's answer.
type PushResult struct {
	Approved          bool
	PhishingResistant bool   // the authenticator is phishing-resistant (FIDO2, passkey, FastPass)
	Authenticator     string // for the record, never a credential
	Ref               string // the provider's challenge reference
}

// PushProvider sends a push to an existing phishing-resistant authenticator.
type PushProvider interface {
	SendPush(ctx context.Context, r PushRequest) (PushResult, error)
}

// IDVRequest asks an identity-verification provider to confirm a person.
type IDVRequest struct {
	CaseID string
	// SessionRef is the IDV vendor's session or report id the help-desk agent
	// received after the person completed the check.
	SessionRef string
}

// IDVResult is the vendor's verdict.
type IDVResult struct {
	Verified bool
	Ref      string
}

// IDVProvider confirms a completed identity verification.
type IDVProvider interface {
	Confirm(ctx context.Context, r IDVRequest) (IDVResult, error)
}

// ErrUnavailable means the verification method has no provider configured.
var ErrUnavailable = errors.New("helpdesk: no provider is configured for this verification method")

// SimulatedPush approves every push to a phishing-resistant authenticator.
// For demos and the shared dev and test instances only.
type SimulatedPush struct{}

// SendPush implements PushProvider.
func (SimulatedPush) SendPush(_ context.Context, r PushRequest) (PushResult, error) {
	return PushResult{Approved: true, PhishingResistant: true, Authenticator: "simulated_fido2", Ref: "sim-push-" + r.CaseID}, nil
}

// SimulatedIDV accepts any non-empty session reference that does not start
// with "fail". For demos only.
type SimulatedIDV struct{}

// Confirm implements IDVProvider.
func (SimulatedIDV) Confirm(_ context.Context, r IDVRequest) (IDVResult, error) {
	ok := strings.TrimSpace(r.SessionRef) != "" && !strings.HasPrefix(strings.ToLower(r.SessionRef), "fail")
	return IDVResult{Verified: ok, Ref: "sim-idv-" + r.CaseID}, nil
}
