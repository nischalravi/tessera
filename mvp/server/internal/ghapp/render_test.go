package ghapp_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/blast"
	"github.com/nischalravi/tessera/mvp/server/internal/ghapp"
)

func ref(policy string, low bool) blast.ViolationRef {
	return blast.ViolationRef{Key: policy + "|1", PolicyID: policy, Severity: "high", IdentityName: "Ada", Message: "Ada holds " + policy, LowFidelity: low}
}

func report(before, after int, intro, res []blast.ViolationRef) *blast.Report {
	r := &blast.Report{Violations: blast.Violations{Before: before, After: after, Introduced: intro, Resolved: res,
		IntroducedTotal: len(intro), ResolvedTotal: len(res)}}
	for _, x := range intro {
		if x.PolicyID == "agent-out-of-scope" || x.PolicyID == "agent-exceeds-owner" {
			r.Violations.AgentScopeIntroduced++
		}
	}
	return r
}

// The conclusion follows the preview: failure for a new violation, neutral for a conditional preview, else success.
func TestEvaluateConclusions(t *testing.T) {
	sod := map[string]bool{"sod-pay": true}
	tfCond := &ghapp.TerraformInfo{Conditional: true, ConditionalChanges: 1}
	cut := report(3, 5, []blast.ViolationRef{ref("p1", false)}, nil)
	cut.Violations.IntroducedTotal, cut.Violations.IntroducedOmitted = 150, 149
	approx := report(2, 2, nil, nil)
	approx.Summary.Approximate = 2

	for _, tc := range []struct {
		name string
		p    ghapp.Preview
		want string
	}{
		{"no change", ghapp.Preview{Report: report(4, 4, nil, nil)}, ghapp.Success},
		{"resolves only", ghapp.Preview{Report: report(4, 3, nil, []blast.ViolationRef{ref("p1", false)})}, ghapp.Success},
		{"new violation of a rule", ghapp.Preview{Report: report(4, 5, []blast.ViolationRef{ref("p1", false)}, nil)}, ghapp.Failure},
		{"one introduced, one resolved of the same rule", ghapp.Preview{Report: report(4, 4, []blast.ViolationRef{ref("p1", false)}, []blast.ViolationRef{ref("p1", false)})}, ghapp.Success},
		{"introduced one rule, resolved another", ghapp.Preview{Report: report(4, 4, []blast.ViolationRef{ref("p1", false)}, []blast.ViolationRef{ref("p2", false)})}, ghapp.Failure},
		{"new agent out of scope", ghapp.Preview{Report: report(4, 4, []blast.ViolationRef{ref("agent-out-of-scope", false)}, []blast.ViolationRef{ref("agent-out-of-scope", false)})}, ghapp.Failure},
		{"new agent exceeds owner", ghapp.Preview{Report: report(0, 1, []blast.ViolationRef{ref("agent-exceeds-owner", false)}, nil)}, ghapp.Failure},
		{"new SoD finding even when another SoD one resolves", ghapp.Preview{SoDPolicyIDs: sod, Report: report(1, 1, []blast.ViolationRef{ref("sod-pay", false)}, []blast.ViolationRef{ref("sod-pay", false)})}, ghapp.Failure},
		{"low fidelity only", ghapp.Preview{Report: report(0, 1, []blast.ViolationRef{ref("inv", true)}, nil)}, ghapp.Neutral},
		{"cut lists with new findings", ghapp.Preview{Report: cut}, ghapp.Failure},
		{"conditional terraform", ghapp.Preview{Report: report(2, 2, nil, nil), Terraform: tfCond}, ghapp.Neutral},
		{"terraform fully mapped", ghapp.Preview{Report: report(2, 2, nil, nil), Terraform: &ghapp.TerraformInfo{Resources: 3}}, ghapp.Success},
		{"approximate results", ghapp.Preview{Report: approx}, ghapp.Neutral},
		{"failure beats conditional", ghapp.Preview{Report: report(0, 1, []blast.ViolationRef{ref("p1", false)}, nil), Terraform: tfCond}, ghapp.Failure},
		{"no report", ghapp.Preview{}, ghapp.Neutral},
	} {
		v := ghapp.Evaluate(tc.p)
		if v.Conclusion != tc.want || len(v.Reasons) == 0 {
			t.Errorf("%s: conclusion = %s (%v), want %s", tc.name, v.Conclusion, v.Reasons, tc.want)
		}
	}
}

func TestSummaryIsDeterministicAndSafe(t *testing.T) {
	evil := ref("p`1", false)
	evil.IdentityName = "@octocat <script>alert(1)</script>\n## injected"
	evil.Message = "ping @everyone [x](http://evil) ```` and more"
	r := report(1, 2, []blast.ViolationRef{evil}, nil)
	r.Summary.IdentitiesGaining = 3
	r.Summary.AgentsGaining = 1
	r.ByResource = []blast.ResourceDelta{{Resource: "arn:aws:s3:::bucket @team", IdentitiesGaining: 3, AgentsGaining: 1}}
	p := ghapp.Preview{Report: r, BundleSHA256: strings.Repeat("ab", 32), DiffSHA256: strings.Repeat("cd", 32),
		Terraform: &ghapp.TerraformInfo{Conditional: true, Findings: []ghapp.TFFinding{{Address: "aws_iam_role.x", Type: "aws_iam_role", Status: "unresolved", Reason: "unknown until apply"}}}}
	v := ghapp.Evaluate(p)
	a, b := ghapp.Comment(p, v, sha1c), ghapp.Comment(p, v, sha1c)
	if a != b {
		t.Error("the comment differs between two renders of the same preview")
	}
	if !strings.HasPrefix(a, ghapp.CommentMarker+"\n") {
		t.Error("the comment does not start with the marker")
	}
	for _, want := range []string{"FAILURE", "| Identities gaining access | 3 |", "| Agents gaining access | 1 |", "1 / 2", "aws_iam_role.x", sha1c[:12], strings.Repeat("ab", 6)} {
		if !strings.Contains(a, want) {
			t.Errorf("comment lacks %q:\n%s", want, a)
		}
	}
	// tenant-supplied text sits inside code spans on one line: a mention, tag or heading in it does nothing
	for _, line := range strings.Split(a, "\n") {
		if strings.Contains(line, "octocat") || strings.Contains(line, "everyone") || strings.Contains(line, "@team") {
			if !strings.Contains(line, "`@octocat") && !strings.Contains(line, "`ping @everyone") && !strings.Contains(line, "`arn:aws:s3:::bucket @team`") {
				t.Errorf("a mention is outside a code span: %q", line)
			}
		}
	}
	if strings.Contains(a, "\n## injected") || strings.Contains(a, "````") {
		t.Errorf("tenant text broke out of its line or span:\n%s", a)
	}
	// size: a huge list stays under GitHub's limit
	var many []blast.ViolationRef
	for i := 0; i < 100; i++ {
		x := ref(fmt.Sprintf("p%d", i), false)
		x.Message = strings.Repeat("m", 500)
		many = append(many, x)
	}
	big := ghapp.Preview{Report: report(0, 100, many, nil)}
	if n := len(ghapp.Comment(big, ghapp.Evaluate(big), sha1c)); n > ghapp.MaxCommentBytes {
		t.Errorf("comment is %d bytes, over %d", n, ghapp.MaxCommentBytes)
	}
}

func TestTitle(t *testing.T) {
	p := ghapp.Preview{Report: report(0, 2, []blast.ViolationRef{ref("a", false), ref("b", false)}, nil)}
	for conclusion, want := range map[string]string{ghapp.Failure: "Policy preview: 2 new violation(s)", ghapp.Neutral: "Policy preview: conditional, review needed", ghapp.Success: "Policy preview: no new violations"} {
		if got := ghapp.Title(p, ghapp.Verdict{Conclusion: conclusion}); got != want {
			t.Errorf("Title(%s) = %q, want %q", conclusion, got, want)
		}
	}
}
