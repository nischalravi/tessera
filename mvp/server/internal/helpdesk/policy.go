// Package helpdesk is Tessera's verified help-desk reset workflow: a password
// or MFA reset for an identity runs through the IdP only after a verification
// policy is satisfied, and a detection watches for account takeover after it.
//
// The rules:
//
//   - Fail closed. A case executes only when Evaluate says the policy is
//     satisfied, checked again inside the transaction that claims the case.
//   - A person never verifies themselves. The requester cannot be the second
//     approver or the manager approval, and the subject (or anyone signed in
//     as the subject) cannot approve their own reset.
//   - Privileged identities need two distinct verification methods and a
//     second approver. IDV counts only for them.
//   - No secret is stored or logged. The one secret a reset can produce, an
//     Entra temporary access pass, is returned once to the caller.
package helpdesk

import (
	"fmt"
	"slices"

	"github.com/google/uuid"
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

// Input is everything Evaluate reads.
type Input struct {
	Privileged    bool
	Verifications []Verification
	// RequestedBy is the platform user who started the case.
	RequestedBy *uuid.UUID
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
	// NeedsSecondApprover is true for a privileged identity.
	NeedsSecondApprover bool `json:"needs_second_approver"`
	SecondApproved      bool `json:"second_approved"`
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

// is reports whether u is set and equals one of ids.
func isOneOf(u *uuid.UUID, ids ...uuid.UUID) bool {
	return u != nil && *u != uuid.Nil && slices.Contains(ids, *u)
}

// Counts reports whether v counts toward the policy.
func (in Input) counts(v Verification) bool {
	if v.Outcome != Passed || !Allowed(v.Method, in.Privileged) {
		return false
	}
	switch v.Method {
	case MethodPush:
		return v.PhishingResistant
	case MethodManagerApproval:
		// a manager approval from the requester or the subject is no approval
		if v.By == nil || *v.By == uuid.Nil || isOneOf(v.By, in.SubjectUsers...) {
			return false
		}
		return in.RequestedBy == nil || *v.By != *in.RequestedBy
	}
	return true
}

// Evaluate decides whether the verification policy is satisfied. It is pure:
// the same input always gives the same decision.
func Evaluate(in Input) Decision {
	d := Decision{Required: Required(in.Privileged), NeedsSecondApprover: in.Privileged,
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
	if in.Privileged {
		d.SecondApproved = in.SecondApprover != nil && *in.SecondApprover != uuid.Nil &&
			!isOneOf(in.SecondApprover, in.SubjectUsers...) &&
			(in.RequestedBy == nil || *in.SecondApprover != *in.RequestedBy)
		if !d.SecondApproved {
			d.Missing = append(d.Missing, "a second approver who is not the requester")
		}
	}
	d.Satisfied = len(d.Missing) == 0
	return d
}
