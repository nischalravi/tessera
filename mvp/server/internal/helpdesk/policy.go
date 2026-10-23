// Package helpdesk is Tessera's verified help-desk reset workflow: a password
// or MFA reset for an identity runs through the IdP only after a verification
// policy is satisfied, and a detection watches for account takeover after it.
//
// The rules:
//
//   - Fail closed. A case executes only when Evaluate says the policy is
//     satisfied, checked again inside the transaction that claims the case.
//   - A person never verifies themselves. The requester cannot be the second
//     approver, the manager approval or the call-back, nor execute the case
//     (#358), and the subject (or anyone signed in
//     as the subject) cannot approve their own reset.
//   - Privileged identities need two distinct verification methods and a
//     second approver. IDV counts only for them.
//   - A recently added authentication method is a takeover signal (#477). When
//     the identity gained a method in the last N days, or a connected IdP
//     reported a suspicious-method risk signal, the case needs the second
//     approver a privileged identity needs (require_approval), or cannot run
//     (block), as the tenant's setting says.
//   - No secret is stored or logged. The one secret a reset can produce, an
//     Entra temporary access pass, is returned once to the caller.
package helpdesk

import (
	"fmt"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Verification methods.
const (
	MethodPush            = "push"             // a push to an existing phishing-resistant authenticator
	MethodCallback        = "callback"         // a call-back to a number taken from HR
	MethodManagerApproval = "manager_approval" // the subject's manager approves
	MethodIDV             = "idv"              // identity document verification (privileged identities only)
)

// Methods lists every verification method.
var Methods = []string{MethodPush, MethodCallback, MethodManagerApproval, MethodIDV}

// Reset kinds.
const (
	KindPassword = "password"
	KindMFA      = "mfa"
)

// Verification outcomes.
const (
	Passed = "passed"
	Failed = "failed"
)

// Allowed reports whether method may count for an identity (IDV only for privileged ones).
func Allowed(method string, privileged bool) bool {
	switch method {
	case MethodPush, MethodCallback, MethodManagerApproval:
		return true
	case MethodIDV:
		return privileged
	}
	return false
}

// Verification is one recorded attempt, as the policy reads it.
type Verification struct {
	Method            string
	Outcome           string
	PhishingResistant bool
	By                *uuid.UUID // the platform user who verified or approved
}

// RecentAuth is what the recent authentication method rule found for an
// identity (see RecentAuthFor). Reasons is empty when nothing was added in the
// window.
type RecentAuth struct {
	Action  string   `json:"action"` // require_approval or block
	Days    int      `json:"days"`
	Reasons []string `json:"reasons"`
}

func (r *RecentAuth) triggered() bool {
	return r != nil && len(r.Reasons) > 0 && (r.Action == store.HelpdeskRecentRequireApproval || r.Action == store.HelpdeskRecentBlock)
}

// Input is everything Evaluate reads.
type Input struct {
	Privileged bool
	// RecentAuth is nil when the rule is off.
	RecentAuth    *RecentAuth
	Verifications []Verification
	// RequestedBy is the platform user who started the case.
	RequestedBy *uuid.UUID
	// RequesterUsers are the platform users linked to the same identity as the
	// requester: one person can hold several sign-in users, so the requester's
	// second user is the requester too (#431, as store.TenantTx.SameActor).
	RequesterUsers []uuid.UUID
	// SecondApprover is the platform user who gave the second approval.
	SecondApprover *uuid.UUID
	// SubjectUsers are the platform users linked to the identity being reset.
	SubjectUsers []uuid.UUID
}

// Decision is the policy's answer for a case.
type Decision struct {
	Satisfied bool `json:"satisfied"`
	// Required is how many distinct verification methods are needed.
	Required int `json:"required_verifications"`
	// Counted lists the methods that count.
	Counted []string `json:"counted_methods"`
	// NeedsSecondApprover is true for a privileged identity, and for an identity
	// that gained an authentication method recently (require_approval).
	NeedsSecondApprover bool `json:"needs_second_approver"`
	SecondApproved      bool `json:"second_approved"`
	// RecentAuthMethod is set when an authentication method was added recently
	// or an IdP reported a risk signal; Blocked is true when the tenant's
	// action is block (the case cannot execute until the window has passed).
	RecentAuthMethod *RecentAuth `json:"recent_auth_method,omitempty"`
	Blocked          bool        `json:"blocked"`
	// Allowed lists the methods that may still be used.
	Allowed []string `json:"allowed_methods"`
	// Missing says, in words, what is still needed.
	Missing []string `json:"missing"`
}

// Required returns the number of distinct methods a case needs.
func Required(privileged bool) int {
	if privileged {
		return 2
	}
	return 1
}

// needsSecond reports whether the case needs a second approver.
func (in Input) needsSecond() bool {
	return in.Privileged || (in.RecentAuth.triggered() && in.RecentAuth.Action == store.HelpdeskRecentRequireApproval)
}

// is reports whether u is set and equals one of ids.
func isOneOf(u *uuid.UUID, ids ...uuid.UUID) bool {
	return u != nil && *u != uuid.Nil && slices.Contains(ids, *u)
}

// isRequester reports whether u is the requester or another user of the same
// person.
func (in Input) isRequester(u *uuid.UUID) bool {
	return in.RequestedBy != nil && u != nil &&
		(*u == *in.RequestedBy || isOneOf(u, in.RequesterUsers...))
}

// Counts reports whether v counts toward the policy.
func (in Input) counts(v Verification) bool {
	if v.Outcome != Passed || !Allowed(v.Method, in.Privileged) {
		return false
	}
	switch v.Method {
	case MethodPush:
		return v.PhishingResistant
	case MethodManagerApproval, MethodCallback:
		// an attestation (a manager approval, or a call-back, which is only
		// the operator's word) from the requester or the subject is no
		// verification (#358)
		if v.By == nil || *v.By == uuid.Nil || isOneOf(v.By, in.SubjectUsers...) {
			return false
		}
		return !in.isRequester(v.By)
	}
	return true
}

// Evaluate decides whether the verification policy is satisfied. It is pure:
// the same input always gives the same decision.
func Evaluate(in Input) Decision {
	d := Decision{Required: Required(in.Privileged), NeedsSecondApprover: in.needsSecond(),
		Counted: []string{}, Allowed: []string{}, Missing: []string{}}
	for _, m := range Methods {
		if Allowed(m, in.Privileged) {
			d.Allowed = append(d.Allowed, m)
		}
	}
	for _, v := range in.Verifications {
		if in.counts(v) && !slices.Contains(d.Counted, v.Method) {
			d.Counted = append(d.Counted, v.Method)
		}
	}
	slices.Sort(d.Counted)
	if n := d.Required - len(d.Counted); n > 0 {
		d.Missing = append(d.Missing, fmt.Sprintf("%d more distinct verification method(s)", n))
	}
	if in.RecentAuth.triggered() {
		d.RecentAuthMethod = in.RecentAuth
		if in.RecentAuth.Action == store.HelpdeskRecentBlock {
			d.Blocked = true
			d.Missing = append(d.Missing, fmt.Sprintf("blocked: an authentication method was added in the last %d days (%s)",
				in.RecentAuth.Days, strings.Join(in.RecentAuth.Reasons, "; ")))
		}
	}
	if d.NeedsSecondApprover {
		d.SecondApproved = in.SecondApprover != nil && *in.SecondApprover != uuid.Nil &&
			!isOneOf(in.SecondApprover, in.SubjectUsers...) &&
			!in.isRequester(in.SecondApprover)
		if !d.SecondApproved {
			d.Missing = append(d.Missing, "a second approver who is not the requester")
		}
	}
	d.Satisfied = len(d.Missing) == 0
	return d
}
