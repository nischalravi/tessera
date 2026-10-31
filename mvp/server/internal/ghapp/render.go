package ghapp

import (
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/nischalravi/tessera/mvp/server/internal/blast"
)

// CommentMarker opens every comment Tessera posts, so a comment is recognizably ours.
const CommentMarker = "<!-- tessera:policy-check:v1 -->"

// Conclusions of the check run.
const (
	Success = "success"
	Failure = "failure"
	Neutral = "neutral"
)

// TerraformInfo is what a Terraform plan in the preview left open.
type TerraformInfo struct {
	// Conditional: a change is unknown until apply, or unsupported and access relevant, so the preview holds only if
	// it has no effect on access.
	Conditional        bool
	Resources          int
	Unsupported        int
	ConditionalChanges int
	Unresolved         int
	// Findings are listed by address; only the first maxListed are shown.
	Findings []TFFinding
}

// TFFinding is one plan change the preview could not map.
type TFFinding struct {
	Address string
	Type    string
	Status  string
	Reason  string
}

// Preview is the blast-radius preview of one pull request (the answer of POST /api/policy/diff) as the check reads it.
type Preview struct {
	Report       *blast.Report
	BundleSHA256 string
	DiffSHA256   string
	Terraform    *TerraformInfo
	// SoDPolicyIDs are the ids of the effective policies that are separation-of-duties rules; a new finding of one
	// fails the check.
	SoDPolicyIDs map[string]bool
}

// Verdict is the check's conclusion and the reasons for it, in a fixed order.
type Verdict struct {
	Conclusion string
	Reasons    []string
}

// Evaluate decides the conclusion, deterministically from the preview:
//
//   - failure when the change introduces a policy violation: the count of any rule is higher after than before, or a
//     new agent-out-of-scope, agent-exceeds-owner or separation-of-duties finding appears. A finding that rests only
//     on approximate evidence (low fidelity) never fails a check. When the report's lists are cut it cannot tell which
//     rules the new findings belong to, so any new finding fails.
//   - neutral when the answer is conditional: a Terraform change unknown until apply or unsupported but access
//     relevant, results that rest on approximate evaluation, or low-fidelity findings.
//   - success otherwise.
func Evaluate(p Preview) Verdict {
	var fail, neutral []string
	r := p.Report
	if r == nil {
		return Verdict{Conclusion: Neutral, Reasons: []string{"No preview was computed."}}
	}
	v := &r.Violations
	if v.AgentScopeIntroduced > 0 {
		fail = append(fail, fmt.Sprintf("%d new agent scope finding(s) (agent out of scope or exceeding its owner).", v.AgentScopeIntroduced))
	}
	if v.IntroducedOmitted > 0 || v.ResolvedOmitted > 0 {
		if v.IntroducedTotal > 0 && v.AgentScopeIntroduced == 0 {
			fail = append(fail, fmt.Sprintf("%d new policy finding(s); the lists are cut, so none can be ruled out as blocking.", v.IntroducedTotal))
		}
	} else {
		intro, res := map[string]int{}, map[string]int{}
		sod := 0
		low := 0
		for _, x := range v.Introduced {
			if x.LowFidelity {
				low++
				continue
			}
			intro[x.PolicyID]++
			if p.SoDPolicyIDs[x.PolicyID] {
				sod++
			}
		}
		for _, x := range v.Resolved {
			if !x.LowFidelity {
				res[x.PolicyID]++
			}
		}
		if sod > 0 {
			fail = append(fail, fmt.Sprintf("%d new separation-of-duties finding(s).", sod))
		}
		var rules []string
		for id, n := range intro {
			if n > res[id] {
				rules = append(rules, id)
			}
		}
		sort.Strings(rules)
		for _, id := range rules {
			fail = append(fail, fmt.Sprintf("Rule %s has %d more finding(s) after than before (%d introduced, %d resolved).", code(id, 60), intro[id]-res[id], intro[id], res[id]))
		}
		if low > 0 {
			neutral = append(neutral, fmt.Sprintf("%d new finding(s) rest on approximate evidence; they are reported and never block.", low))
		}
	}
	if t := p.Terraform; t != nil && t.Conditional {
		neutral = append(neutral, fmt.Sprintf("The Terraform plan is conditional: %d change(s) unknown until apply or not in the snapshot, %d unsupported but access relevant or unresolved.",
			t.ConditionalChanges, t.Unsupported+t.Unresolved))
	}
	if r.Summary.Approximate > 0 {
		neutral = append(neutral, fmt.Sprintf("%d result(s) rest on conditional or approximate evaluation and are not counted as gains or losses.", r.Summary.Approximate))
	}
	switch {
	case len(fail) > 0:
		return Verdict{Conclusion: Failure, Reasons: append(fail, neutral...)}
	case len(neutral) > 0:
		return Verdict{Conclusion: Neutral, Reasons: neutral}
	}
	return Verdict{Conclusion: Success, Reasons: []string{"The change introduces no policy violation."}}
}

const (
	maxListed  = 10
	maxTextLen = 140
)

// code renders tenant-supplied text as an inline code span cut to n characters: markdown, HTML and @mentions in it do
// nothing (a mention inside a code span notifies no one), and it cannot break out of the span or the line.
func code(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case r == '`':
			return '\''
		case unsafeRune(r):
			return ' '
		}
		return r
	}, s)
	if utf8.RuneCountInString(s) > n {
		s = string([]rune(s)[:n]) + "..."
	}
	return "`" + strings.TrimSpace(s) + "`"
}

// isBidi reports a Unicode bidirectional control: the marks, embeddings, overrides and isolates.
func isBidi(r rune) bool {
	return r == 0x061c || r == 0x200e || r == 0x200f || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069)
}

// unsafeRune reports a rune that is replaced by a space in any text from the estate, whether it ends up in a code span, a
// title or a commit message: control characters, line and paragraph separators, next line, the bidirectional controls (an
// unterminated override would reorder the rest of the line) and the zero-width and format characters that hide text. The
// zero-width joiner (U+200D) is kept in a code span, where it joins emoji; a title or commit message drops it too (plain).
func unsafeRune(r rune) bool {
	return r < 0x20 || r == 0x7f || r == 0x85 || r == 0x2028 || r == 0x2029 || isBidi(r) ||
		(r >= 0x200b && r <= 0x200f && r != 0x200d) || (r >= 0x2060 && r <= 0x2069) || r == 0xfeff
}

// Title is the check run's title.
func Title(p Preview, v Verdict) string {
	n := 0
	if p.Report != nil {
		n = p.Report.Violations.IntroducedTotal
	}
	switch v.Conclusion {
	case Failure:
		return fmt.Sprintf("Policy preview: %d new violation(s)", n)
	case Neutral:
		return "Policy preview: conditional, review needed"
	}
	return "Policy preview: no new violations"
}

// Summary renders the deterministic markdown of the check run and the comment (without the comment marker). The same
// preview always gives the same text: nothing in it is a time or a random value.
func Summary(p Preview, v Verdict, headSHA string) string {
	var b strings.Builder
	label := map[string]string{Success: "SUCCESS", Failure: "FAILURE", Neutral: "NEUTRAL"}[v.Conclusion]
	fmt.Fprintf(&b, "### Tessera policy check: %s\n\n", label)
	for _, r := range v.Reasons {
		fmt.Fprintf(&b, "- %s\n", r)
	}
	if r := p.Report; r != nil {
		writeBlastTable(&b, r)
		if len(r.Violations.Introduced) > 0 {
			b.WriteString("\n**New violations**\n\n")
			for i, x := range r.Violations.Introduced {
				if i == maxListed {
					fmt.Fprintf(&b, "- ... and %d more\n", r.Violations.IntroducedTotal-maxListed)
					break
				}
				fmt.Fprintf(&b, "- %s (%s) %s: %s\n", code(x.PolicyID, 60), code(x.Severity, 20), code(x.IdentityName, 60), code(x.Message, maxTextLen))
			}
		}
		if len(r.ByResource) > 0 {
			b.WriteString("\n**Resources with new access paths**\n\n")
			n := 0
			for _, x := range r.ByResource {
				if x.IdentitiesGaining == 0 {
					continue
				}
				if n == maxListed {
					b.WriteString("- ... and more\n")
					break
				}
				n++
				fmt.Fprintf(&b, "- %s: %d identit(ies) gain a path, %d agent(s)\n", code(x.Resource, maxTextLen), x.IdentitiesGaining, x.AgentsGaining)
			}
		}
	}
	if t := p.Terraform; t != nil && len(t.Findings) > 0 {
		fmt.Fprintf(&b, "\n**Terraform changes not fully evaluated** (%d)\n\n", len(t.Findings))
		for i, f := range t.Findings {
			if i == maxListed {
				fmt.Fprintf(&b, "- ... and %d more\n", len(t.Findings)-maxListed)
				break
			}
			fmt.Fprintf(&b, "- %s (%s, %s): %s\n", code(f.Address, maxTextLen), code(f.Type, 60), code(f.Status, 20), code(f.Reason, maxTextLen))
		}
	}
	b.WriteString("\n_Tessera evaluated the bundle and plan supplied by the caller, not files fetched from this commit. This is an advisory preview, not proof the commit is safe._\n")
	short := func(s string) string {
		if len(s) > 12 {
			return s[:12]
		}
		return s
	}
	fmt.Fprintf(&b, "\n<sub>Commit %s, bundle %s, preview %s.</sub>\n", code(short(headSHA), 12), code(short(p.BundleSHA256), 12), code(short(p.DiffSHA256), 12))
	return b.String()
}

// Comment is the pull request comment: the marker, then the summary.
func Comment(p Preview, v Verdict, headSHA string) string {
	return CommentMarker + "\n" + Summary(p, v, headSHA)
}

// writeBlastTable writes the blast-radius table of a report (shared by the check summary and the right-sizing pull request).
func writeBlastTable(b *strings.Builder, r *blast.Report) {
	s := &r.Summary
	b.WriteString("\n| Blast radius | Count |\n|---|---:|\n")
	fmt.Fprintf(b, "| Identities gaining access | %d |\n| Identities losing access | %d |\n| Agents gaining access | %d |\n| Agents losing access | %d |\n",
		s.IdentitiesGaining, s.IdentitiesLosing, s.AgentsGaining, s.AgentsLosing)
	fmt.Fprintf(b, "| Permissions gained / lost (graph) | %d / %d |\n| AWS paths gained / lost | %d / %d |\n", s.GraphPermissionsGained, s.GraphPermissionsLost, s.AWSPathsGained, s.AWSPathsLost)
	fmt.Fprintf(b, "| Policy violations before / after | %d / %d |\n| Violations introduced / resolved | %d / %d |\n", r.Violations.Before, r.Violations.After, r.Violations.IntroducedTotal, r.Violations.ResolvedTotal)
	if s.UnlinkedPrincipals > 0 {
		fmt.Fprintf(b, "| AWS principals not linked to an identity | %d |\n", s.UnlinkedPrincipals)
	}
}
