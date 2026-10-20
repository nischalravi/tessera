package helpdesk

import (
	"slices"
	"testing"

	"github.com/google/uuid"
)

func u() *uuid.UUID { id := uuid.New(); return &id }

func pass(method string, by *uuid.UUID) Verification {
	return Verification{Method: method, Outcome: Passed, PhishingResistant: method == MethodPush, By: by}
}

func TestEvaluate(t *testing.T) {
	requester, other, subject, third := u(), u(), u(), u()
	tests := []struct {
		name string
		in   Input
		want bool
		// counted is the expected set of counted methods
		counted []string
	}{
		{"no verification", Input{RequestedBy: requester}, false, nil},
		{"push to phishing-resistant authenticator", Input{RequestedBy: requester,
			Verifications: []Verification{pass(MethodPush, requester)}}, true, []string{MethodPush}},
		{"push to a non phishing-resistant authenticator does not count", Input{RequestedBy: requester,
			Verifications: []Verification{{Method: MethodPush, Outcome: Passed, PhishingResistant: false}}}, false, nil},
		{"failed push does not count", Input{RequestedBy: requester,
			Verifications: []Verification{{Method: MethodPush, Outcome: Failed, PhishingResistant: true}}}, false, nil},
		{"call-back to the HR number", Input{RequestedBy: requester,
			Verifications: []Verification{pass(MethodCallback, requester)}}, true, []string{MethodCallback}},
		{"manager approval by someone else", Input{RequestedBy: requester,
			Verifications: []Verification{pass(MethodManagerApproval, other)}}, true, []string{MethodManagerApproval}},
		{"manager approval by the requester does not count", Input{RequestedBy: requester,
			Verifications: []Verification{pass(MethodManagerApproval, requester)}}, false, nil},
		{"manager approval by the subject does not count", Input{RequestedBy: requester, SubjectUsers: []uuid.UUID{*subject},
			Verifications: []Verification{pass(MethodManagerApproval, subject)}}, false, nil},
		{"manager approval with no approver does not count", Input{RequestedBy: requester,
			Verifications: []Verification{pass(MethodManagerApproval, nil)}}, false, nil},
		{"IDV does not count for a non-privileged identity", Input{RequestedBy: requester,
			Verifications: []Verification{pass(MethodIDV, requester)}}, false, nil},

		{"privileged: one verification is not enough", Input{Privileged: true, RequestedBy: requester, SecondApprover: other,
			Verifications: []Verification{pass(MethodIDV, requester)}}, false, []string{MethodIDV}},
		{"privileged: two verifications but no second approver", Input{Privileged: true, RequestedBy: requester,
			Verifications: []Verification{pass(MethodIDV, requester), pass(MethodCallback, requester)}}, false,
			[]string{MethodCallback, MethodIDV}},
		{"privileged: the same method twice counts once", Input{Privileged: true, RequestedBy: requester, SecondApprover: other,
			Verifications: []Verification{pass(MethodCallback, requester), pass(MethodCallback, requester)}}, false,
			[]string{MethodCallback}},
		{"privileged: second approver is the requester", Input{Privileged: true, RequestedBy: requester, SecondApprover: requester,
			Verifications: []Verification{pass(MethodIDV, requester), pass(MethodCallback, requester)}}, false,
			[]string{MethodCallback, MethodIDV}},
		{"privileged: second approver is the subject", Input{Privileged: true, RequestedBy: requester, SecondApprover: subject,
			SubjectUsers:  []uuid.UUID{*subject},
			Verifications: []Verification{pass(MethodIDV, requester), pass(MethodCallback, requester)}}, false,
			[]string{MethodCallback, MethodIDV}},
		{"privileged: two methods and a second approver", Input{Privileged: true, RequestedBy: requester, SecondApprover: other,
			Verifications: []Verification{pass(MethodIDV, requester), pass(MethodPush, requester)}}, true,
			[]string{MethodIDV, MethodPush}},
		{"privileged: manager approval and call-back with approver", Input{Privileged: true, RequestedBy: requester, SecondApprover: third,
			Verifications: []Verification{pass(MethodManagerApproval, other), pass(MethodCallback, requester)}}, true,
			[]string{MethodCallback, MethodManagerApproval}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := Evaluate(tt.in)
			if d.Satisfied != tt.want {
				t.Errorf("Satisfied = %v, want %v (missing %v)", d.Satisfied, tt.want, d.Missing)
			}
			if tt.want && len(d.Missing) != 0 {
				t.Errorf("satisfied with missing %v", d.Missing)
			}
			if !tt.want && len(d.Missing) == 0 {
				t.Error("unsatisfied but nothing missing is reported")
			}
			if !slices.Equal(d.Counted, append([]string{}, tt.counted...)) && !(len(d.Counted) == 0 && len(tt.counted) == 0) {
				t.Errorf("Counted = %v, want %v", d.Counted, tt.counted)
			}
			if d.Required != Required(tt.in.Privileged) || d.NeedsSecondApprover != tt.in.Privileged {
				t.Errorf("requirements = %d/%v", d.Required, d.NeedsSecondApprover)
			}
		})
	}
}

func TestAllowed(t *testing.T) {
	for _, tt := range []struct {
		method string
		priv   bool
		want   bool
	}{
		{MethodPush, false, true}, {MethodCallback, false, true}, {MethodManagerApproval, false, true},
		{MethodIDV, false, false}, {MethodIDV, true, true}, {"sms", true, false}, {"", false, false},
	} {
		if got := Allowed(tt.method, tt.priv); got != tt.want {
			t.Errorf("Allowed(%q, %v) = %v, want %v", tt.method, tt.priv, got, tt.want)
		}
	}
}
