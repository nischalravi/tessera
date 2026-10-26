package leastpriv

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Verified right-sizing (issue #659, LP-3; design least-privilege-loop §4, §4.1).
//
// A right-size proposes a narrower default version of one customer-managed
// policy: its Allow statements are replaced by exactly the calls the principal
// was seen to make, its Deny statements are kept as they are. The proposal is
// then verified with the evaluator (VerifyAWS): it is a recommendation only if
// every used call is still allowed at EXACT fidelity and it gives nothing new.
// Nothing here changes anything in AWS.

// maxPolicyChars is IAM's limit on a managed policy document (whitespace not
// counted; the document built here has none).
const maxPolicyChars = 6144

// ErrRightSize is wrapped by every refusal to build a right-sized document.
var ErrRightSize = errors.New("leastpriv: cannot right-size")

type rsStatement struct {
	Effect   string   `json:"Effect"`
	Action   []string `json:"Action"`
	Resource []string `json:"Resource"`
}

// RightSizeDocument builds the candidate policy document from the current one
// and the calls to keep: the current document's Deny statements verbatim, then
// one Allow statement per distinct set of actions, naming the resources they
// were used on. The output is deterministic. It refuses a document whose
// language version is not 2012-10-17 (variables mean something else there), a
// document that does not parse, no calls, and a result over IAM's size limit.
func RightSizeDocument(current []byte, keep []UsedCall) (string, error) {
	if len(keep) == 0 {
		return "", fmt.Errorf("%w: the principal used no call this policy allows; detach the policy instead", ErrRightSize)
	}
	var doc struct {
		Version   string          `json:"Version"`
		Statement json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal(current, &doc); err != nil {
		return "", fmt.Errorf("%w: the current document does not parse", ErrRightSize)
	}
	if doc.Version != "2012-10-17" {
		return "", fmt.Errorf("%w: the current document is not language version 2012-10-17", ErrRightSize)
	}
	var stmts []json.RawMessage
	if err := json.Unmarshal(doc.Statement, &stmts); err != nil {
		var one json.RawMessage
		if err2 := json.Unmarshal(doc.Statement, &one); err2 != nil || len(one) == 0 || one[0] != '{' {
			return "", fmt.Errorf("%w: the current document has no readable statements", ErrRightSize)
		}
		stmts = []json.RawMessage{one}
	}
	out := make([]any, 0, len(stmts)+4)
	for _, raw := range stmts {
		var probe struct {
			Effect string `json:"Effect"`
		}
		if err := json.Unmarshal(raw, &probe); err != nil {
			return "", fmt.Errorf("%w: the current document has an unreadable statement", ErrRightSize)
		}
		if probe.Effect == "Deny" {
			out = append(out, raw)
		}
	}

	byResource := map[string]map[string]bool{}
	for _, c := range keep {
		if byResource[c.Resource] == nil {
			byResource[c.Resource] = map[string]bool{}
		}
		byResource[c.Resource][c.Action] = true
	}
	bySet := map[string][]string{} // joined sorted actions -> resources
	for res, as := range byResource {
		k := strings.Join(sortedKeys(as), ",")
		bySet[k] = append(bySet[k], res)
	}
	keys := make([]string, 0, len(bySet))
	for k := range bySet {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		res := bySet[k]
		sort.Strings(res)
		out = append(out, rsStatement{Effect: "Allow", Action: strings.Split(k, ","), Resource: res})
	}
	b, err := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": out})
	if err != nil {
		return "", err
	}
	if len(b) > maxPolicyChars {
		return "", fmt.Errorf("%w: the right-sized document is %d characters, over IAM's limit of %d", ErrRightSize, len(b), maxPolicyChars)
	}
	return string(b), nil
}

// Verdicts of a verified right-size.
const (
	// VerdictVerified: every used call stays allowed at EXACT fidelity, nothing
	// is added, and everything removed rests on an EXACT, unconditional allow.
	VerdictVerified = "verified"
	// VerdictReview: safe for the used calls but something removed rests on a
	// conditional or approximate evaluation; advice for a person, never an action.
	VerdictReview = "review"
	// VerdictRefused: a used call breaks or is not EXACT after the change, the
	// change gives more than it takes, or it removes nothing.
	VerdictRefused = "refused"
)

// Judge turns the evaluator's verification into a verdict and says why. Only
// EXACT results verify: an APPROXIMATE or UNSUPPORTED decision on a used call is
// a refusal, not a warning.
func Judge(v *Verification) (string, []string) {
	reasons := append([]string{}, v.Reasons...)
	switch {
	case len(v.Broken) > 0, v.Added > 0, len(v.Inexact) > 0:
		if len(v.Inexact) > 0 {
			reasons = append(reasons, fmt.Sprintf("%d used call(s) are not EXACT after the change: only EXACT results are acted on", len(v.Inexact)))
		}
		return VerdictRefused, reasons
	case v.Removed == 0:
		return VerdictRefused, append(reasons, "the change removes nothing from this principal")
	case !v.AutoApplicable:
		return VerdictReview, reasons
	}
	return VerdictVerified, reasons
}

// LowestConfidence is the least trusted of the assessments, with the reasons of
// the ones that set it (at most three, no duplicates). No assessments at all is
// unknown. A right-size is as trustworthy as the least trusted permission it
// removes.
func LowestConfidence(cs []Confidence) Confidence {
	if len(cs) == 0 {
		return Confidence{Level: ConfUnknown, Reasons: []string{"no permission is removed, so there is nothing to assess"}}
	}
	low := cs[0].Level
	for _, c := range cs {
		if rank(c.Level) < rank(low) {
			low = c.Level
		}
	}
	out := Confidence{Level: low, Reasons: []string{}}
	seen := map[string]bool{}
	for _, c := range cs {
		if c.Level != low {
			continue
		}
		for _, r := range c.Reasons {
			if !seen[r] && len(out.Reasons) < 3 {
				seen[r] = true
				out.Reasons = append(out.Reasons, r)
			}
		}
	}
	return out
}
