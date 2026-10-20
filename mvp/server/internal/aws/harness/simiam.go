package harness

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/nischalravi/tessera/mvp/server/internal/authz"
)

// simPageSize is the largest MaxItems the simulator accepts (§13.2).
const simPageSize = 1000

// NewIAMClient builds an IAM client for the simulator oracles. httpc is the
// transport: awstest.Replay offline, a safehttp-backed client in PR-9's nightly
// job. It signs nothing (anonymous credentials), so an offline replay needs no
// credentials; the nightly job builds its own signed client and passes it to
// SimCustom and SimPrincipal, which take only the API interfaces. Retries use the SDK's adaptive mode, which adds jitter and a client-side rate
// limit (§13.2: no TPS limit is documented).
func NewIAMClient(httpc aws.HTTPClient, region string, retryer func() aws.Retryer) *iam.Client {
	if retryer == nil {
		retryer = func() aws.Retryer { return retry.NewAdaptiveMode() }
	}
	return iam.New(iam.Options{
		Region:      region,
		HTTPClient:  httpc,
		Credentials: aws.AnonymousCredentials{},
		Retryer:     retryer(),
	})
}

// SimCustom is the SimulateCustomPolicy oracle: the fuzz and cross-account
// path (§13.5).
type SimCustom struct {
	Client  iam.SimulateCustomPolicyAPIClient
	Backoff Backoff
}

// Kind implements Oracle.
func (*SimCustom) Kind() OracleKind { return OracleSimCustom }

// Ask implements Oracle.
func (o *SimCustom) Ask(ctx context.Context, s *RequestSpec) (*Answer, error) {
	if err := s.CheckIngest(); err != nil {
		return nil, err
	}
	in := customInput(s)
	var results []types.EvaluationResult
	attempts := 0
	for {
		var out *iam.SimulateCustomPolicyOutput
		n, err := o.Backoff.Do(ctx, func() (e error) {
			out, e = o.Client.SimulateCustomPolicy(ctx, in)
			return e
		})
		attempts += n
		if err != nil {
			return nil, fmt.Errorf("harness: SimulateCustomPolicy: %w", err)
		}
		results = append(results, out.EvaluationResults...)
		if !out.IsTruncated || out.Marker == nil {
			break
		}
		in.Marker = out.Marker
	}
	a := answerFromResults(OracleSimCustom, s, results)
	a.Attempts = attempts
	return a, nil
}

// SimPrincipal is the SimulatePrincipalPolicy oracle for deployed principals.
type SimPrincipal struct {
	Client  iam.SimulatePrincipalPolicyAPIClient
	Backoff Backoff
}

// Kind implements Oracle.
func (*SimPrincipal) Kind() OracleKind { return OracleSimPrincipal }

// Ask implements Oracle.
func (o *SimPrincipal) Ask(ctx context.Context, s *RequestSpec) (*Answer, error) {
	if s.PolicySourceArn == "" {
		return nil, fmt.Errorf("harness: spec %s has no policy_source_arn for SimulatePrincipalPolicy", s.ID)
	}
	if err := s.CheckIngest(); err != nil {
		return nil, err
	}
	in := principalInput(s)
	var results []types.EvaluationResult
	attempts := 0
	for {
		var out *iam.SimulatePrincipalPolicyOutput
		n, err := o.Backoff.Do(ctx, func() (e error) {
			out, e = o.Client.SimulatePrincipalPolicy(ctx, in)
			return e
		})
		attempts += n
		if err != nil {
			return nil, fmt.Errorf("harness: SimulatePrincipalPolicy: %w", err)
		}
		results = append(results, out.EvaluationResults...)
		if !out.IsTruncated || out.Marker == nil {
			break
		}
		in.Marker = out.Marker
	}
	a := answerFromResults(OracleSimPrincipal, s, results)
	a.Attempts = attempts
	return a, nil
}

func resourceArns(s *RequestSpec) []string {
	if s.Resource == "" {
		return []string{"*"}
	}
	return []string{s.Resource}
}

// simContext is the context passed to the simulator: the same one the engine
// gets (engineContext), so neither side has keys the other lacks (§13.2).
func simContext(s *RequestSpec) []types.ContextEntry {
	merged := map[string]ContextEntry{}
	for k, v := range s.Context {
		merged[k] = v
	}
	if !hasKeyFold(merged, "aws:PrincipalArn") {
		merged["aws:PrincipalArn"] = ContextEntry{Values: []string{s.PrincipalARN}}
	}
	keys := make([]string, 0, len(merged))
	for k := range merged {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]types.ContextEntry, 0, len(keys))
	for _, k := range keys {
		e := merged[k]
		t := e.Type
		if t == "" {
			t = "string"
			if len(e.Values) > 1 {
				t = "stringList"
			}
		}
		out = append(out, types.ContextEntry{ContextKeyName: aws.String(k), ContextKeyType: types.ContextKeyTypeEnum(t), ContextKeyValues: e.Values})
	}
	return out
}

func hasKeyFold(m map[string]ContextEntry, key string) bool {
	for k := range m {
		if strings.EqualFold(k, key) {
			return true
		}
	}
	return false
}

// orderedSCPs maps SCP levels (root to account) to the API's ordered list.
func orderedSCPs(levels [][]string) []types.OrderedOrganizationPolicyType {
	out := make([]types.OrderedOrganizationPolicyType, 0, len(levels))
	for _, lvl := range levels {
		out = append(out, types.OrderedOrganizationPolicyType{ServiceControlPolicyInputList: lvl})
	}
	return out
}

func customInput(s *RequestSpec) *iam.SimulateCustomPolicyInput {
	in := &iam.SimulateCustomPolicyInput{
		PolicyInputList:                    s.Identity,
		PermissionsBoundaryPolicyInputList: s.Boundary,
		OrderedOrganizationPolicyInputList: orderedSCPs(s.SCPLevels),
		ActionNames:                        []string{s.Action},
		ResourceArns:                       resourceArns(s),
		ContextEntries:                     simContext(s),
		MaxItems:                           aws.Int32(simPageSize),
	}
	if len(s.SCPLevels) == 0 {
		in.OrderedOrganizationPolicyInputList = nil
	}
	if s.ResourcePolicy != "" {
		in.ResourcePolicy = aws.String(s.ResourcePolicy)
		in.ResourceOwner = aws.String("arn:aws:iam::" + s.ResourceOwner + ":root")
		in.CallerArn = aws.String(s.PrincipalARN) // a user or role ARN, never a session ARN
	}
	return in
}

func principalInput(s *RequestSpec) *iam.SimulatePrincipalPolicyInput {
	in := &iam.SimulatePrincipalPolicyInput{
		PolicySourceArn: aws.String(s.PolicySourceArn),
		ActionNames:     []string{s.Action},
		ResourceArns:    resourceArns(s),
		ContextEntries:  simContext(s),
		MaxItems:        aws.Int32(simPageSize),
	}
	if s.ResourcePolicy != "" {
		in.ResourcePolicy = aws.String(s.ResourcePolicy)
		in.ResourceOwner = aws.String("arn:aws:iam::" + s.ResourceOwner + ":root")
		in.CallerArn = aws.String(s.PrincipalARN)
	}
	for _, x := range s.Exclusions {
		if strings.HasPrefix(x, "arn:") {
			in.PolicyExclusionList = append(in.PolicyExclusionList, &types.PolicyIdentifierMemberPolicyArn{Value: x})
		} else {
			in.PolicyExclusionList = append(in.PolicyExclusionList, &types.PolicyIdentifierMemberPolicyType{Value: types.PolicyIdentifierPolicyType(x)})
		}
	}
	return in
}

// answerFromResults reduces the simulator's results to one Answer.
//
// The trap (§13.2): each EvaluationResult aggregates its resources to the most
// restrictive decision, so with several resources the top-level EvalDecision is
// the worst of them. Per-resource decisions are read from
// ResourceSpecificResults[].EvalResourceDecision when present. SourcePolicyType
// is a plain string at the SDK layer, so undocumented spellings such as
// "Resource Policy" arrive unchanged and NormalizePolicyType accepts both.
func answerFromResults(kind OracleKind, s *RequestSpec, results []types.EvaluationResult) *Answer {
	a := &Answer{Oracle: kind, Status: AnswerOK}
	invalid := func(format string, args ...any) *Answer {
		a.Status, a.Detail = AnswerInvalid, fmt.Sprintf(format, args...)
		return a
	}
	var mine []types.EvaluationResult
	for _, r := range results {
		if strings.EqualFold(aws.ToString(r.EvalActionName), s.Action) {
			mine = append(mine, r)
		}
	}
	if len(mine) != 1 {
		return invalid("%d evaluation results for %s, want 1", len(mine), s.Action)
	}
	r := mine[0]
	if len(r.MissingContextValues) > 0 {
		a.Missing = append([]string(nil), r.MissingContextValues...)
		sort.Strings(a.Missing)
		return invalid("MissingContextValues: %s", strings.Join(a.Missing, ", "))
	}
	decision, matched := string(r.EvalDecision), r.MatchedStatements
	if len(r.ResourceSpecificResults) > 0 {
		want := s.Resource
		if want == "" {
			want = "*"
		}
		var pick *types.ResourceSpecificResult
		for i := range r.ResourceSpecificResults {
			if aws.ToString(r.ResourceSpecificResults[i].EvalResourceName) == want {
				pick = &r.ResourceSpecificResults[i]
			}
		}
		if pick == nil && len(r.ResourceSpecificResults) == 1 {
			pick = &r.ResourceSpecificResults[0]
		}
		if pick == nil {
			return invalid("no ResourceSpecificResults entry for %s", want)
		}
		a.Missing = append(a.Missing, pick.MissingContextValues...)
		if len(a.Missing) > 0 {
			sort.Strings(a.Missing)
			return invalid("MissingContextValues: %s", strings.Join(a.Missing, ", "))
		}
		decision, matched = string(pick.EvalResourceDecision), pick.MatchedStatements
	}
	switch decision {
	case DecisionAllowed, DecisionExplicitDeny, DecisionImplicitDeny:
		a.Decision = decision
	default:
		return invalid("unknown EvalDecision %q", decision)
	}
	for _, m := range matched {
		ms := MatchedStatement{SourcePolicyID: aws.ToString(m.SourcePolicyId), RawPolicyType: string(m.SourcePolicyType), PolicyType: NormalizePolicyType(string(m.SourcePolicyType))}
		if m.StartPosition != nil {
			ms.Line, ms.Column = int(m.StartPosition.Line), int(m.StartPosition.Column)
		}
		a.Matched = append(a.Matched, ms)
	}
	if a.Decision != DecisionAllowed {
		switch {
		case r.OrganizationsDecisionDetail != nil && !r.OrganizationsDecisionDetail.AllowedByOrganizations:
			a.DeniedStage = authz.StageSCP
		case r.PermissionsBoundaryDecisionDetail != nil && !r.PermissionsBoundaryDecisionDetail.AllowedByPermissionsBoundary:
			a.DeniedStage = authz.StageBoundary
		}
	}
	return a
}
