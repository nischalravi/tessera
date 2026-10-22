package helpdesk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/containment"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// Error codes of *Error.
const (
	CodeNotFound    = "not_found"
	CodeInvalid     = "invalid"
	CodeConflict    = "conflict"
	CodeForbidden   = "forbidden"
	CodeNotVerified = "not_verified"
	CodeUnavailable = "unavailable"
	CodeIdPFailed   = "idp_failed"
)

// Reasons of CodeForbidden refusals: the stable error code the API returns
// (separation of duties, #358).
const (
	// ReasonOperatorRequired: the act needs a signed-in platform user.
	ReasonOperatorRequired = "operator_required"
	// ReasonSelfReset: the caller is linked to the identity being reset.
	ReasonSelfReset = "self_reset_not_allowed"
	// ReasonActorUnlinked: the caller is a platform user with no linked
	// identity, so "not the subject" cannot be shown (fail closed, #446).
	ReasonActorUnlinked = "actor_unlinked"
	// ReasonRequesterVerify: the requester recorded an attested verification
	// (a call-back) on their own case; a second operator must.
	ReasonRequesterVerify = "requester_cannot_verify"
	// ReasonRequesterExecute: the requester tried to execute their own case;
	// a second operator must.
	ReasonRequesterExecute = "requester_cannot_execute"
)

// Error is a refusal the API renders: Code picks the status, Msg is safe to show.
type Error struct {
	Code string
	// Reason, when set, is the stable error code the API returns instead of
	// the generic one for Code.
	Reason   string
	Msg      string
	Decision *Decision // set with CodeNotVerified
}

func (e *Error) Error() string { return e.Msg }

func fail(code, format string, a ...any) *Error {
	return &Error{Code: code, Msg: fmt.Sprintf(format, a...)}
}

func forbid(reason, msg string) *Error {
	return &Error{Code: CodeForbidden, Reason: reason, Msg: msg}
}

// Service runs the workflow. The zero value works for the policy and the
// attestation methods; resets and push or IDV verification need the fields
// below.
type Service struct {
	// HTTP is the outbound client for the Okta and Entra executors; it must
	// come from internal/safehttp.
	HTTP *http.Client
	// Containment supplies the sealed provider credential of a connection
	// (the same token the kill switch uses). Nil: no live executor.
	Containment *containment.Service
	Clock       timeutil.Clock
	// Simulated allows the simulated executor and the simulated push and IDV
	// providers. It must be false in production.
	Simulated bool
	// Executors overrides the executor of a system (tests).
	Executors map[string]ResetExecutor
	// Push and IDV override the verification providers (tests). With
	// Simulated they default to the simulators.
	Push PushProvider
	IDV  IDVProvider
}

func (s *Service) push() PushProvider {
	if s.Push != nil {
		return s.Push
	}
	if s.Simulated {
		return SimulatedPush{}
	}
	return nil
}

func (s *Service) idv() IDVProvider {
	if s.IDV != nil {
		return s.IDV
	}
	if s.Simulated {
		return SimulatedIDV{}
	}
	return nil
}

// ---------------------------------------------------------------- start

// StartInput starts a case.
type StartInput struct {
	IdentityID int64
	Kind       string
	System     string
	Reason     string
}

func validSystem(s string) bool { return s == SystemOkta || s == SystemEntra || s == SystemSimulated }

// subjectAccount picks the account a reset runs against.
func subjectAccount(c *store.TenantTx, ident *store.Identity, system string) (*Target, error) {
	if system == SystemSimulated {
		return &Target{System: system, UserID: ident.ExternalID, Username: ident.Name}, nil
	}
	accts, err := c.IdentityAccounts(ident.ID)
	if err != nil {
		return nil, err
	}
	for _, a := range accts {
		if a.System == system && a.Status == "active" {
			return &Target{System: system, UserID: a.ExternalID, Username: a.Username}, nil
		}
	}
	return nil, fail(CodeInvalid, "the identity has no active %s account to reset", system)
}

func actorName(by store.UserRef) string {
	if by.Display == "" {
		return "unknown"
	}
	return by.Display
}

func userPtr(by store.UserRef) *uuid.UUID {
	if by.ID == uuid.Nil {
		return nil
	}
	id := by.ID
	return &id
}

// refuseUnlinked fails closed for a platform user with no linked identity: the
// self-reset checks compare linked users, which cannot place such a person
// (#446). A caller with no platform user (a service) passes.
func refuseUnlinked(c *store.TenantTx, by store.UserRef) error {
	if by.ID == uuid.Nil {
		return nil
	}
	u, err := c.PlatformUser(by.ID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if err != nil || u.IdentityID == nil {
		return forbid(ReasonActorUnlinked, "your account is not linked to an identity, so it cannot handle reset cases; ask an administrator to link it")
	}
	return nil
}

// subjectUsers lists the platform users linked to the identity being reset.
func subjectUsers(c *store.TenantTx, identityID int64) ([]uuid.UUID, error) {
	return c.PlatformUserIDsForIdentity(identityID)
}

// requesterUsers lists the other platform users linked to the same identity as
// the requester (none when the requester is not linked or is not a platform
// user), so a verification from the requester's second sign-in is still the
// requester's (#431).
func requesterUsers(c *store.TenantTx, hc *store.HelpdeskCase) ([]uuid.UUID, error) {
	if hc.RequestedByUserID == nil || *hc.RequestedByUserID == uuid.Nil {
		return nil, nil
	}
	u, err := c.PlatformUser(*hc.RequestedByUserID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && u.IdentityID == nil) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return c.PlatformUserIDsForIdentity(*u.IdentityID)
}

// Start opens a reset case for an identity. The requester may not be the
// subject: nobody opens a reset for their own account.
func (s *Service) Start(c *store.TenantTx, in StartInput, by store.UserRef, now time.Time) (*store.HelpdeskCase, error) {
	if in.Kind != KindPassword && in.Kind != KindMFA {
		return nil, fail(CodeInvalid, "kind must be password or mfa")
	}
	if !validSystem(in.System) {
		return nil, fail(CodeInvalid, "system must be okta, entra or simulated")
	}
	if in.System == SystemSimulated && !s.Simulated {
		return nil, fail(CodeInvalid, "the simulated executor is not available in this environment")
	}
	if n := len(strings.TrimSpace(in.Reason)); n < 10 || n > 500 {
		return nil, fail(CodeInvalid, "reason is required: 10 to 500 characters")
	}
	ident, err := c.Identity(in.IdentityID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, fail(CodeNotFound, "identity not found")
	}
	if err != nil {
		return nil, err
	}
	if ident.Status == "terminated" || ident.Status == "merged" {
		return nil, fail(CodeConflict, "the identity is %s; it cannot be reset", ident.Status)
	}
	if _, err := subjectAccount(c, ident, in.System); err != nil {
		return nil, err
	}
	subj, err := subjectUsers(c, ident.ID)
	if err != nil {
		return nil, err
	}
	if err := refuseUnlinked(c, by); err != nil {
		return nil, err
	}
	if isOneOf(userPtr(by), subj...) {
		return nil, forbid(ReasonSelfReset, "you cannot open a reset case for your own identity")
	}
	priv, err := NewChecker(c, now).Privileged(ident.ID)
	if err != nil {
		return nil, err
	}
	hc := &store.HelpdeskCase{IdentityID: ident.ID, Kind: in.Kind, System: in.System, Reason: strings.TrimSpace(in.Reason),
		Privileged: priv, RequestedBy: actorName(by), RequestedByUserID: userPtr(by)}
	if err := c.InsertHelpdeskCase(hc, now); err != nil {
		return nil, err
	}
	if err := c.Audit(now, actorName(by), "helpdesk.case.started", ojson.Object{{Key: "case_id", Value: hc.ID},
		{Key: "identity_id", Value: ident.ID}, {Key: "identity", Value: ident.Name}, {Key: "kind", Value: hc.Kind},
		{Key: "system", Value: hc.System}, {Key: "privileged", Value: priv}}); err != nil {
		return nil, err
	}
	return c.HelpdeskCase(hc.ID)
}

// ---------------------------------------------------------------- view

// VerificationView is a verification as the API shows it.
type VerificationView struct {
	ID                string    `json:"id"`
	Method            string    `json:"method"`
	Outcome           string    `json:"outcome"`
	PhishingResistant bool      `json:"phishing_resistant"`
	VerifiedBy        string    `json:"verified_by"`
	Evidence          string    `json:"evidence"`
	Provider          string    `json:"provider"`
	CreatedAt         time.Time `json:"created_at"`
}

// FindingView is a detection finding as the API shows it.
type FindingView struct {
	ID        string          `json:"id"`
	CaseID    string          `json:"case_id"`
	Identity  int64           `json:"identity_id"`
	Rule      string          `json:"rule"`
	Detail    json.RawMessage `json:"detail"`
	CreatedAt time.Time       `json:"created_at"`
}

// CaseView is a case with its policy decision.
type CaseView struct {
	ID               string             `json:"id"`
	IdentityID       int64              `json:"identity_id"`
	Identity         string             `json:"identity"`
	Kind             string             `json:"kind"`
	System           string             `json:"system"`
	Reason           string             `json:"reason"`
	Status           string             `json:"status"`
	Privileged       bool               `json:"privileged"`
	RequestedBy      string             `json:"requested_by"`
	SecondApprover   *string            `json:"second_approver"`
	SecondApprovedAt *time.Time         `json:"second_approved_at"`
	ExecutedBy       *string            `json:"executed_by"`
	ExecutedAt       *time.Time         `json:"executed_at"`
	Result           []string           `json:"result"`
	Error            string             `json:"error"`
	CreatedAt        time.Time          `json:"created_at"`
	UpdatedAt        time.Time          `json:"updated_at"`
	Policy           Decision           `json:"policy"`
	Verifications    []VerificationView `json:"verifications"`
	Findings         []FindingView      `json:"findings"`
}

// policyInput builds the policy's input for a case from the store, re-reading
// whether the identity is privileged now.
func policyInput(k *Checker, hc *store.HelpdeskCase) (Input, []*store.HelpdeskVerification, error) {
	c := k.c
	priv, err := k.Privileged(hc.IdentityID)
	if err != nil {
		return Input{}, nil, err
	}
	vs, err := c.HelpdeskVerifications(hc.ID)
	if err != nil {
		return Input{}, nil, err
	}
	subj, err := subjectUsers(c, hc.IdentityID)
	if err != nil {
		return Input{}, nil, err
	}
	reqUsers, err := requesterUsers(c, hc)
	if err != nil {
		return Input{}, nil, err
	}
	in := Input{Privileged: priv || hc.Privileged, RequestedBy: hc.RequestedByUserID, SecondApprover: hc.SecondApproverUserID,
		SubjectUsers: subj, RequesterUsers: reqUsers}
	for _, v := range vs {
		in.Verifications = append(in.Verifications, Verification{Method: v.Method, Outcome: v.Outcome,
			PhishingResistant: v.PhishingResistant, By: v.VerifiedByUserID})
	}
	return in, vs, nil
}

// View returns a case with its decision, verifications and findings.
func View(k *Checker, hc *store.HelpdeskCase) (*CaseView, error) {
	c := k.c
	in, vs, err := policyInput(k, hc)
	if err != nil {
		return nil, err
	}
	ident, err := c.Identity(hc.IdentityID)
	if err != nil {
		return nil, err
	}
	fs, err := c.HelpdeskFindingsForCase(hc.ID)
	if err != nil {
		return nil, err
	}
	v := &CaseView{ID: hc.ID, IdentityID: hc.IdentityID, Identity: ident.Name, Kind: hc.Kind, System: hc.System,
		Reason: hc.Reason, Status: hc.Status, Privileged: in.Privileged, RequestedBy: hc.RequestedBy,
		SecondApprover: hc.SecondApprover, SecondApprovedAt: hc.SecondApprovedAt, ExecutedBy: hc.ExecutedBy,
		ExecutedAt: hc.ExecutedAt, Result: []string{}, Error: hc.Error, CreatedAt: hc.CreatedAt, UpdatedAt: hc.UpdatedAt,
		Policy: Evaluate(in), Verifications: []VerificationView{}, Findings: []FindingView{}}
	if hc.Result != "" {
		_ = json.Unmarshal([]byte(hc.Result), &v.Result)
	}
	for _, x := range vs {
		v.Verifications = append(v.Verifications, VerificationView{ID: x.ID, Method: x.Method, Outcome: x.Outcome,
			PhishingResistant: x.PhishingResistant, VerifiedBy: x.VerifiedBy, Evidence: x.Evidence, Provider: x.Provider,
			CreatedAt: x.CreatedAt})
	}
	for _, f := range fs {
		v.Findings = append(v.Findings, ViewFinding(f))
	}
	return v, nil
}

// ViewFinding renders a finding.
func ViewFinding(f *store.HelpdeskFinding) FindingView {
	d := json.RawMessage(f.Detail)
	if !json.Valid(d) {
		d = json.RawMessage(`{}`)
	}
	return FindingView{ID: f.ID, CaseID: f.CaseID, Identity: f.IdentityID, Rule: f.Rule, Detail: d, CreatedAt: f.CreatedAt}
}

func open(c *store.TenantTx, id string) (*store.HelpdeskCase, error) {
	hc, err := c.HelpdeskCase(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, fail(CodeNotFound, "case not found")
	}
	return hc, err
}

func openForWork(c *store.TenantTx, id string) (*store.HelpdeskCase, error) {
	hc, err := open(c, id)
	if err != nil {
		return nil, err
	}
	if hc.Status != store.HelpdeskOpen && hc.Status != store.HelpdeskFailed {
		return nil, fail(CodeConflict, "the case is %s", hc.Status)
	}
	return hc, nil
}

// ---------------------------------------------------------------- verify

// VerifyInput is a verification attempt as submitted.
type VerifyInput struct {
	Method string
	// Evidence is the agent's note: what was checked. Required for callback.
	Evidence string
	// NumberSource must be "hr" for a callback: the number comes from the HR
	// record, never from the caller.
	NumberSource string
	// SessionRef is the IDV vendor's session reference.
	SessionRef string
}

// VerifyPlan is a checked attempt waiting for its provider call.
type VerifyPlan struct {
	CaseID string
	In     VerifyInput
	Target Target
}

// Attestation is the outcome to record.
type Attestation struct {
	Outcome           string
	PhishingResistant bool
	Evidence          string
	Provider          string
}

// PrepareVerify checks an attempt against the case: the method must be
// allowed for this identity, its inputs well formed and, for a manager
// approval, the approver must be the subject's manager. It reads only; the
// provider call (RunVerify) and the record (RecordVerify) follow.
func (s *Service) PrepareVerify(c *store.TenantTx, caseID string, in VerifyInput, by store.UserRef, now time.Time) (*VerifyPlan, error) {
	hc, err := openForWork(c, caseID)
	if err != nil {
		return nil, err
	}
	pin, _, err := policyInput(NewChecker(c, now), hc)
	if err != nil {
		return nil, err
	}
	if !Allowed(in.Method, pin.Privileged) {
		if in.Method == MethodIDV {
			return nil, fail(CodeInvalid, "IDV is only for privileged identities")
		}
		return nil, fail(CodeInvalid, "method must be one of push, callback, manager_approval, idv")
	}
	// nobody verifies their own reset, whatever the method (#358)
	if err := refuseUnlinked(c, by); err != nil {
		return nil, err
	}
	if isOneOf(userPtr(by), pin.SubjectUsers...) {
		return nil, forbid(ReasonSelfReset, "you cannot verify a reset of your own identity")
	}
	in.Evidence = strings.TrimSpace(in.Evidence)
	if len(in.Evidence) > 500 || len(in.SessionRef) > 200 {
		return nil, fail(CodeInvalid, "evidence is at most 500 characters and session_ref at most 200")
	}
	ident, err := c.Identity(hc.IdentityID)
	if err != nil {
		return nil, err
	}
	tgt, err := subjectAccount(c, ident, hc.System)
	if err != nil {
		return nil, err
	}
	switch in.Method {
	case MethodCallback:
		// a call-back is the operator's own word: it never comes from the
		// person who opened the case (#358)
		if by.ID == uuid.Nil {
			return nil, forbid(ReasonOperatorRequired, "a call-back is recorded by a signed-in operator")
		}
		if same, err := requesterIs(c, hc, by.ID); err != nil {
			return nil, err
		} else if same {
			return nil, forbid(ReasonRequesterVerify, "the requester cannot record the call-back; a second operator must make it")
		}
		if in.NumberSource != "hr" {
			return nil, fail(CodeInvalid, "a call-back must use the number taken from HR (number_source \"hr\"), never a number the caller gives")
		}
		if len(in.Evidence) < 10 {
			return nil, fail(CodeInvalid, "evidence is required for a call-back: 10 to 500 characters")
		}
	case MethodPush:
		if s.push() == nil {
			return nil, fail(CodeUnavailable, "no push provider is configured")
		}
	case MethodIDV:
		if s.idv() == nil {
			return nil, fail(CodeUnavailable, "no IDV provider is configured")
		}
		if strings.TrimSpace(in.SessionRef) == "" {
			return nil, fail(CodeInvalid, "session_ref is required for IDV")
		}
	case MethodManagerApproval:
		if by.ID == uuid.Nil {
			return nil, fail(CodeForbidden, "a manager approval needs a signed-in platform user")
		}
		if same, err := requesterIs(c, hc, by.ID); err != nil {
			return nil, err
		} else if same {
			return nil, forbid(ReasonRequesterVerify, "the requester cannot give the manager approval")
		}
		u, err := c.PlatformUser(by.ID)
		if err != nil {
			return nil, err
		}
		if ident.ManagerID == nil || u.IdentityID == nil || *u.IdentityID != *ident.ManagerID {
			return nil, fail(CodeForbidden, "only the identity's manager can give the manager approval")
		}
	}
	return &VerifyPlan{CaseID: caseID, In: in, Target: *tgt}, nil
}

// RunVerify makes the provider call of a plan (none for attestations). Call
// it with no transaction open.
func (s *Service) RunVerify(ctx context.Context, p *VerifyPlan) (Attestation, error) {
	switch p.In.Method {
	case MethodPush:
		r, err := s.push().SendPush(ctx, PushRequest{CaseID: p.CaseID, System: p.Target.System, UserID: p.Target.UserID,
			Username: p.Target.Username})
		if err != nil {
			return Attestation{}, fail(CodeIdPFailed, "the push could not be sent")
		}
		a := Attestation{Outcome: Failed, PhishingResistant: r.PhishingResistant, Provider: r.Ref,
			Evidence: "authenticator " + r.Authenticator}
		if r.Approved && r.PhishingResistant {
			a.Outcome = Passed
		}
		return a, nil
	case MethodIDV:
		r, err := s.idv().Confirm(ctx, IDVRequest{CaseID: p.CaseID, SessionRef: p.In.SessionRef})
		if err != nil {
			return Attestation{}, fail(CodeIdPFailed, "the IDV provider could not confirm")
		}
		a := Attestation{Outcome: Failed, Provider: r.Ref, Evidence: "session " + p.In.SessionRef}
		if r.Verified {
			a.Outcome = Passed
		}
		return a, nil
	case MethodCallback:
		return Attestation{Outcome: Passed, Evidence: p.In.Evidence, Provider: "attestation:hr-callback"}, nil
	}
	return Attestation{Outcome: Passed, Evidence: p.In.Evidence, Provider: "attestation:manager"}, nil
}

// RecordVerify appends the attempt and audits it. The case is re-read: it
// may have closed since PrepareVerify.
func (s *Service) RecordVerify(c *store.TenantTx, p *VerifyPlan, a Attestation, by store.UserRef, now time.Time) (*store.HelpdeskVerification, error) {
	if _, err := openForWork(c, p.CaseID); err != nil {
		return nil, err
	}
	v := &store.HelpdeskVerification{CaseID: p.CaseID, Method: p.In.Method, Outcome: a.Outcome,
		PhishingResistant: a.PhishingResistant, VerifiedBy: actorName(by), VerifiedByUserID: userPtr(by),
		Evidence: a.Evidence, Provider: a.Provider}
	if err := c.InsertHelpdeskVerification(v, now); err != nil {
		return nil, err
	}
	err := c.Audit(now, actorName(by), "helpdesk.case.verification", ojson.Object{{Key: "case_id", Value: p.CaseID},
		{Key: "method", Value: v.Method}, {Key: "outcome", Value: v.Outcome}, {Key: "provider", Value: v.Provider}})
	return v, err
}

// SecondApprove records the second approver of a privileged case. The
// approver may not be the requester or the subject.
func (s *Service) SecondApprove(c *store.TenantTx, caseID string, by store.UserRef, now time.Time) error {
	hc, err := openForWork(c, caseID)
	if err != nil {
		return err
	}
	in, _, err := policyInput(NewChecker(c, now), hc)
	if err != nil {
		return err
	}
	isRequester, err := requesterIs(c, hc, by.ID)
	if err != nil {
		return err
	}
	if err := refuseUnlinked(c, by); err != nil {
		return err
	}
	switch {
	case !in.Privileged:
		return fail(CodeConflict, "the identity is not privileged; no second approver is needed")
	case by.ID == uuid.Nil:
		return fail(CodeForbidden, "a second approval needs a signed-in platform user")
	case isRequester:
		return fail(CodeForbidden, "the second approver cannot be the requester")
	case isOneOf(&by.ID, in.SubjectUsers...):
		return forbid(ReasonSelfReset, "the subject cannot approve their own reset")
	}
	if err := c.SetHelpdeskSecondApproval(caseID, by, now); errors.Is(err, store.ErrNotFound) {
		return fail(CodeConflict, "the case already has a second approver")
	} else if err != nil {
		return err
	}
	return c.Audit(now, actorName(by), "helpdesk.case.second_approval", ojson.Object{{Key: "case_id", Value: caseID},
		{Key: "identity_id", Value: hc.IdentityID}})
}

// Cancel closes an open or failed case.
func (s *Service) Cancel(c *store.TenantTx, caseID string, by store.UserRef, now time.Time) error {
	if _, err := openForWork(c, caseID); err != nil {
		return err
	}
	if err := c.CancelHelpdeskCase(caseID, now); err != nil {
		return err
	}
	return c.Audit(now, actorName(by), "helpdesk.case.cancelled", ojson.Object{{Key: "case_id", Value: caseID}})
}

// ---------------------------------------------------------------- execute

// ExecPlan is a claimed case ready to run.
type ExecPlan struct {
	CaseID     string
	IdentityID int64
	Identity   string
	Target     Target
	exec       ResetExecutor
}

// executorFor resolves the executor of a system: a test override, the
// simulator (non-production only), or the live Okta or Entra adapter with the
// connection's sealed credential.
func (s *Service) executorFor(c *store.TenantTx, system string) (ResetExecutor, error) {
	if e := s.Executors[system]; e != nil {
		return e, nil
	}
	if system == SystemSimulated {
		if !s.Simulated {
			return nil, fail(CodeUnavailable, "the simulated executor is not available in this environment")
		}
		return SimulatedExecutor{}, nil
	}
	if s.Containment == nil || s.HTTP == nil {
		return nil, fail(CodeUnavailable, "no live %s executor: outbound HTTP or the provider credential store is not configured", system)
	}
	cred, why, err := s.Containment.CredentialFor(c, system)
	if err != nil {
		return nil, err
	}
	if cred == nil {
		return nil, fail(CodeUnavailable, "no live %s executor: %s", system, why)
	}
	var e ResetExecutor
	switch system {
	case SystemOkta:
		e, err = NewOkta(s.HTTP, cred.BaseURL, cred.Token)
	case SystemEntra:
		e, err = NewEntra(s.HTTP, cred.BaseURL, cred.Token)
	default:
		err = fmt.Errorf("no executor for %q", system)
	}
	if err != nil {
		return nil, fail(CodeUnavailable, "no live %s executor: %v", system, err)
	}
	return e, nil
}

// Claim is the gate. In one write transaction it evaluates the policy, and
// only when it is satisfied claims the case (open or failed -> executing),
// which makes a second concurrent execute fail. An unverified case returns a
// CodeNotVerified error carrying the decision and nothing runs.
func (s *Service) Claim(c *store.TenantTx, caseID string, by store.UserRef, now time.Time) (*ExecPlan, error) {
	hc, err := openForWork(c, caseID)
	if err != nil {
		return nil, err
	}
	in, _, err := policyInput(NewChecker(c, now), hc)
	if err != nil {
		return nil, err
	}
	// four eyes (#358): the operator who opened the case does not also run
	// it, and nobody runs a reset of their own identity
	isRequester, err := requesterIs(c, hc, by.ID)
	if err != nil {
		return nil, err
	}
	if err := refuseUnlinked(c, by); err != nil {
		return nil, err
	}
	switch {
	case by.ID == uuid.Nil:
		return nil, forbid(ReasonOperatorRequired, "a reset is executed by a signed-in operator")
	case isOneOf(&by.ID, in.SubjectUsers...):
		return nil, forbid(ReasonSelfReset, "you cannot execute a reset of your own identity")
	case isRequester:
		return nil, forbid(ReasonRequesterExecute, "the requester cannot execute their own case; a second operator must")
	}
	if d := Evaluate(in); !d.Satisfied {
		return nil, &Error{Code: CodeNotVerified, Msg: "the verification policy is not satisfied: " + strings.Join(d.Missing, "; "),
			Decision: &d}
	}
	ident, err := c.Identity(hc.IdentityID)
	if err != nil {
		return nil, err
	}
	if ident.Status == "terminated" || ident.Status == "merged" {
		return nil, fail(CodeConflict, "the identity is %s; it cannot be reset", ident.Status)
	}
	tgt, err := subjectAccount(c, ident, hc.System)
	if err != nil {
		return nil, err
	}
	tgt.Kind = hc.Kind
	ex, err := s.executorFor(c, hc.System)
	if err != nil {
		return nil, err
	}
	if err := c.ClaimHelpdeskCase(caseID, actorName(by), now); errors.Is(err, store.ErrNotFound) {
		return nil, fail(CodeConflict, "the case is already being executed")
	} else if err != nil {
		return nil, err
	}
	if err := c.Audit(now, actorName(by), "helpdesk.reset.started", ojson.Object{{Key: "case_id", Value: caseID},
		{Key: "identity_id", Value: ident.ID}, {Key: "identity", Value: ident.Name}, {Key: "kind", Value: hc.Kind},
		{Key: "system", Value: hc.System}, {Key: "privileged", Value: in.Privileged},
		{Key: "verifications", Value: Evaluate(in).Counted}, {Key: "second_approver", Value: deref(hc.SecondApprover)}}); err != nil {
		return nil, err
	}
	return &ExecPlan{CaseID: caseID, IdentityID: ident.ID, Identity: ident.Name, Target: *tgt, exec: ex}, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// Run makes the IdP call. Call it with no transaction open.
func (p *ExecPlan) Run(ctx context.Context) (Result, error) {
	res, err := p.exec.Reset(ctx, p.Target)
	if err != nil {
		return Result{}, err
	}
	return res, nil
}

// Finish records the outcome of a claimed case and audits it. A failed reset
// leaves the case retryable; its error text is the provider call's method,
// path and status only.
func (s *Service) Finish(c *store.TenantTx, p *ExecPlan, res Result, runErr error, by store.UserRef, now time.Time) error {
	if runErr != nil {
		msg := runErr.Error()
		if len(msg) > 300 {
			msg = msg[:300]
		}
		if err := c.FinishHelpdeskCase(p.CaseID, store.HelpdeskFailed, now, "", msg); err != nil {
			return err
		}
		return c.Audit(now, actorName(by), "helpdesk.reset.failed", ojson.Object{{Key: "case_id", Value: p.CaseID},
			{Key: "identity_id", Value: p.IdentityID}, {Key: "system", Value: p.Target.System}, {Key: "error", Value: msg}})
	}
	steps, err := json.Marshal(res.Steps)
	if err != nil {
		return err
	}
	if err := c.FinishHelpdeskCase(p.CaseID, store.HelpdeskExecuted, now, string(steps), ""); err != nil {
		return err
	}
	return c.Audit(now, actorName(by), "helpdesk.reset.executed", ojson.Object{{Key: "case_id", Value: p.CaseID},
		{Key: "identity_id", Value: p.IdentityID}, {Key: "identity", Value: p.Identity},
		{Key: "kind", Value: p.Target.Kind}, {Key: "system", Value: p.Target.System}, {Key: "steps", Value: res.Steps},
		{Key: "temporary_access_pass_issued", Value: res.TemporaryAccessPass != ""}})
}

// ---------------------------------------------------------------- detection

// SignalInput is a post-reset observation as submitted.
type SignalInput struct {
	IdentityID int64
	Kind       string
	Location   string
	Device     string
	Source     string
	OccurredAt time.Time
}

// IngestSignal stores a signal and runs the detection for the identity's
// resets in the 24 hours before it. It returns the findings it created (a
// case raises each rule once). In production the IdP log connectors feed this;
// until they do, POST /api/helpdesk/signals simulates the feed.
func (s *Service) IngestSignal(c *store.TenantTx, in SignalInput, by store.UserRef, now time.Time) ([]*store.HelpdeskFinding, error) {
	if in.Kind != SignalMFADevice && in.Kind != SignalSignIn {
		return nil, fail(CodeInvalid, "kind must be mfa_device_added or sign_in")
	}
	if len(in.Location) > 120 || len(in.Device) > 120 || len(in.Source) > 60 {
		return nil, fail(CodeInvalid, "location and device are at most 120 characters, source at most 60")
	}
	if in.Kind == SignalSignIn && strings.TrimSpace(in.Location) == "" {
		return nil, fail(CodeInvalid, "a sign_in signal needs a location")
	}
	if in.OccurredAt.IsZero() || in.OccurredAt.After(now.Add(5*time.Minute)) {
		return nil, fail(CodeInvalid, "occurred_at is required and cannot be in the future")
	}
	if _, err := c.Identity(in.IdentityID); errors.Is(err, store.ErrNotFound) {
		return nil, fail(CodeNotFound, "identity not found")
	} else if err != nil {
		return nil, err
	}
	g := &store.HelpdeskSignal{IdentityID: in.IdentityID, Kind: in.Kind, Location: strings.TrimSpace(in.Location),
		Device: strings.TrimSpace(in.Device), Source: in.Source, OccurredAt: in.OccurredAt.UTC()}
	if err := c.InsertHelpdeskSignal(g, now); err != nil {
		return nil, err
	}
	return s.detect(c, in.IdentityID, in.OccurredAt, by, now)
}

// detect checks the identity's resets whose window contains t.
func (s *Service) detect(c *store.TenantTx, identityID int64, t time.Time, by store.UserRef, now time.Time) ([]*store.HelpdeskFinding, error) {
	cases, err := c.HelpdeskCasesExecutedSince(identityID, t.Add(-Window))
	if err != nil || len(cases) == 0 {
		return nil, err
	}
	rows, err := c.HelpdeskSignals(identityID)
	if err != nil {
		return nil, err
	}
	sigs := make([]Signal, len(rows))
	for i, r := range rows {
		sigs[i] = Signal{Kind: r.Kind, Location: r.Location, Device: r.Device, At: r.OccurredAt}
	}
	var out []*store.HelpdeskFinding
	for _, hc := range cases {
		if hc.ExecutedAt == nil {
			continue
		}
		hit := Detect(*hc.ExecutedAt, sigs)
		if hit == nil {
			continue
		}
		detail, err := json.Marshal(hit)
		if err != nil {
			return nil, err
		}
		f := &store.HelpdeskFinding{CaseID: hc.ID, IdentityID: identityID, Rule: hit.Rule, Detail: string(detail)}
		created, err := c.InsertHelpdeskFinding(f, now)
		if err != nil {
			return nil, err
		}
		if !created {
			continue
		}
		out = append(out, f)
		if err := c.Audit(now, actorName(by), "helpdesk.detection.fired", ojson.Object{{Key: "rule", Value: hit.Rule},
			{Key: "case_id", Value: hc.ID}, {Key: "identity_id", Value: identityID}, {Key: "device", Value: hit.Device},
			{Key: "location", Value: hit.Location}, {Key: "reset_at", Value: hit.ResetAt}}); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// requesterIs reports whether the platform user by is the person who opened the
// case: the same user, or another user linked to the same identity (#402).
func requesterIs(c *store.TenantTx, hc *store.HelpdeskCase, by uuid.UUID) (bool, error) {
	if hc.RequestedByUserID == nil || by == uuid.Nil {
		return false, nil
	}
	return c.SameActor(hc.RequestedByUserID.String(), by.String())
}
