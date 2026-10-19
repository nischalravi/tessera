package harness

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// The Access Analyzer and probe oracles take narrow client interfaces. PR-9
// supplies the implementations that reach AWS (the accessanalyzer SDK client,
// and probe runners that assume sandbox roles); this PR supplies the
// classification around them and recorded stand-ins for offline replay.

// AACheck is one CheckAccessNotGranted call (§13.5).
type AACheck struct {
	PolicyDocument string
	PolicyType     string // "IDENTITY_POLICY" or "RESOURCE_POLICY"
	Actions        []string
	Resources      []string
}

// AAResult is the check's answer.
type AAResult struct {
	Result  string // "PASS" (access is not granted; trustworthy) or "FAIL" (may be a false positive)
	Reasons []AAReason
}

// AAClient is the slice of Access Analyzer the harness uses.
type AAClient interface {
	CheckAccessNotGranted(ctx context.Context, c AACheck) (*AAResult, error)
}

// AccessAnalyzer is the custom-check oracle for universal claims (§13.3).
type AccessAnalyzer struct {
	Client  AAClient
	Backoff Backoff
}

// Kind implements Oracle.
func (*AccessAnalyzer) Kind() OracleKind { return OracleAccessCheck }

// Ask implements Oracle. A check operates on a single policy with no
// environment, so the spec must hold exactly one identity or resource policy.
func (o *AccessAnalyzer) Ask(ctx context.Context, s *RequestSpec) (*Answer, error) {
	if err := s.CheckIngest(); err != nil {
		return nil, err
	}
	var doc, ptype string
	switch {
	case len(s.Identity) == 1 && s.ResourcePolicy == "" && len(s.Boundary) == 0 && len(s.SCPLevels) == 0:
		doc, ptype = s.Identity[0], "IDENTITY_POLICY"
	case len(s.Identity) == 0 && s.ResourcePolicy != "" && len(s.Boundary) == 0 && len(s.SCPLevels) == 0:
		doc, ptype = s.ResourcePolicy, "RESOURCE_POLICY"
	default:
		return nil, fmt.Errorf("harness: spec %s: Access Analyzer checks take exactly one identity or resource policy and no environment", s.ID)
	}
	resources := resourceArns(s)
	var res *AAResult
	n, err := o.Backoff.Do(ctx, func() (e error) {
		res, e = o.Client.CheckAccessNotGranted(ctx, AACheck{PolicyDocument: doc, PolicyType: ptype, Actions: []string{s.Action}, Resources: resources})
		return e
	})
	if err != nil {
		return nil, fmt.Errorf("harness: CheckAccessNotGranted: %w", err)
	}
	a := &Answer{Oracle: OracleAccessCheck, Status: AnswerOK, Attempts: n, Reasons: res.Reasons}
	switch strings.ToUpper(res.Result) {
	case "PASS":
		a.Decision = DecisionPass
	case "FAIL":
		a.Decision = DecisionFail
	default:
		a.Status, a.Detail = AnswerInvalid, fmt.Sprintf("unknown check result %q", res.Result)
	}
	return a, nil
}

// ProbeResponse is the raw outcome of one live probe: the safe call's result
// (§13.5). The runner that makes the call fills it in; ClassifyProbe reads it.
type ProbeResponse struct {
	// Family names the action family, one of the ProbeFamily constants, or a
	// curated probe_catalog.yaml entry (PR-9) the runner maps to one of them.
	Family    string `json:"family"`
	Success   bool   `json:"success"`
	ErrorCode string `json:"error_code,omitempty"`
	Message   string `json:"message,omitempty"`
}

// Probe families (§13.5 table).
const (
	FamilyEC2DryRun      = "ec2_dry_run"
	FamilyS3             = "s3"
	FamilySQS            = "sqs"
	FamilySNS            = "sns"
	FamilyKMS            = "kms"
	FamilySTS            = "sts"
	FamilySecretsManager = "secretsmanager"
	FamilyIAMOrgRead     = "iam_org_read"
	FamilyNotInCatalog   = "not_in_catalog"
)

// Reasons an answer is inconclusive.
const (
	probeNotInCatalogWhy  = "action is not in probe_catalog.yaml; not probed"
	probeUnrecognizedWhy  = "unrecognized probe response"
	probeSuccessDeniedWhy = "success outside the family's contract"
)

// allowedCodes and deniedCodes classify a failed safe call per family. EC2
// dry-run reports an allowed call as an error (DryRunOperation).
var (
	probeAllowedCodes = map[string]map[string]bool{
		FamilyEC2DryRun: {"DryRunOperation": true},
	}
	probeDeniedCodes = map[string]map[string]bool{
		FamilyEC2DryRun:      {"UnauthorizedOperation": true},
		FamilyS3:             {"AccessDenied": true},
		FamilySQS:            {"AccessDenied": true, "AccessDeniedException": true},
		FamilySNS:            {"AuthorizationError": true, "AccessDenied": true},
		FamilyKMS:            {"AccessDeniedException": true},
		FamilySTS:            {"AccessDenied": true},
		FamilySecretsManager: {"AccessDeniedException": true},
		FamilyIAMOrgRead:     {"AccessDenied": true, "AccessDeniedException": true},
	}
)

// ClassifyProbe maps a probe response to an answer. Any error that is not the
// family's allowed or denied code (throttling, NoSuchEntity, validation) is
// inconclusive and never counted as a deny (§13.5).
func ClassifyProbe(r ProbeResponse) *Answer {
	a := &Answer{Oracle: OracleProbe, Status: AnswerOK}
	inconclusive := func(why string) *Answer { a.Status, a.Detail = AnswerInconclusive, why; return a }
	if r.Family == FamilyNotInCatalog || (probeDeniedCodes[r.Family] == nil && probeAllowedCodes[r.Family] == nil) {
		return inconclusive(probeNotInCatalogWhy)
	}
	switch {
	case r.Success && r.Family == FamilyEC2DryRun:
		// A DryRun call that succeeds outright did not dry-run: do not trust it.
		return inconclusive(probeSuccessDeniedWhy)
	case r.Success:
		a.Decision = DecisionAllowed
	case probeAllowedCodes[r.Family][r.ErrorCode]:
		a.Decision = DecisionAllowed
	case probeDeniedCodes[r.Family][r.ErrorCode]:
		a.Decision = DecisionDenied
		if st, ok := ParseAccessDeniedStage(r.Message); ok {
			a.DeniedStage = st
		}
	default:
		return inconclusive(probeUnrecognizedWhy + ": " + r.ErrorCode)
	}
	return a
}

// ProbeClient makes the safe call for a spec as the manifest's principal and
// returns its raw outcome. It must never change IAM, Organizations, policies or
// grants (§13.5); that is PR-9's contract, enforced by its probe catalog test.
type ProbeClient interface {
	Probe(ctx context.Context, s *RequestSpec) (*ProbeResponse, error)
}

// ProbeOracle is the live-probe oracle.
type ProbeOracle struct {
	Client ProbeClient
	// Backoff retries an inconclusive probe; it is never turned into a deny.
	Backoff Backoff
}

// Kind implements Oracle.
func (*ProbeOracle) Kind() OracleKind { return OracleProbe }

// Ask implements Oracle.
func (o *ProbeOracle) Ask(ctx context.Context, s *RequestSpec) (*Answer, error) {
	var ans *Answer
	n, err := o.Backoff.Do(ctx, func() error {
		resp, err := o.Client.Probe(ctx, s)
		if err != nil {
			return err
		}
		ans = ClassifyProbe(*resp)
		if ans.Status == AnswerInconclusive && ans.Detail != probeNotInCatalogWhy {
			return errInconclusive
		}
		return nil
	})
	switch {
	case err == nil:
	case errors.Is(err, ErrRetriesExhausted) && ans != nil:
		// Keep the last inconclusive answer: it is a result, not a failure.
	default:
		return nil, fmt.Errorf("harness: probe: %w", err)
	}
	ans.Attempts = n
	return ans, nil
}

// RecordedProbe replays probe responses from a list, in order. It is how a
// cassette of probe results is replayed offline.
type RecordedProbe struct {
	Responses []ProbeResponse
	next      int
}

// Probe implements ProbeClient.
func (r *RecordedProbe) Probe(_ context.Context, _ *RequestSpec) (*ProbeResponse, error) {
	if r.next >= len(r.Responses) {
		return nil, errors.New("harness: recorded probe responses exhausted")
	}
	p := r.Responses[r.next]
	r.next++
	return &p, nil
}

// RecordedAA replays Access Analyzer results from a list, in order.
type RecordedAA struct {
	Results []AAResult
	next    int
}

// CheckAccessNotGranted implements AAClient.
func (r *RecordedAA) CheckAccessNotGranted(_ context.Context, _ AACheck) (*AAResult, error) {
	if r.next >= len(r.Results) {
		return nil, errors.New("harness: recorded Access Analyzer results exhausted")
	}
	p := r.Results[r.next]
	r.next++
	return &p, nil
}
