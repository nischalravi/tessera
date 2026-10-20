package harness

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/smithy-go"

	"github.com/nischalravi/tessera/mvp/server/internal/authz"
)

// OracleKind names an oracle (§13.3).
type OracleKind string

// The four oracles.
const (
	OracleSimCustom    OracleKind = "sim_custom"
	OracleSimPrincipal OracleKind = "sim_principal"
	OracleAccessCheck  OracleKind = "access_analyzer"
	OracleProbe        OracleKind = "probe"
)

// AnswerStatus says whether an oracle answer can be compared.
type AnswerStatus string

// Answer statuses.
const (
	// AnswerOK: the answer is usable.
	AnswerOK AnswerStatus = "ok"
	// AnswerInvalid: the check itself is broken (the simulator reported
	// MissingContextValues, or returned an unexpected shape). A harness bug,
	// never a divergence.
	AnswerInvalid AnswerStatus = "invalid"
	// AnswerInconclusive: the probe could not tell (throttling, NoSuchEntity,
	// validation). Never counted as a deny (§13.5).
	AnswerInconclusive AnswerStatus = "inconclusive"
)

// Decision spellings an oracle can give.
const (
	DecisionAllowed      = "allowed"
	DecisionExplicitDeny = "explicitDeny"
	DecisionImplicitDeny = "implicitDeny"
	DecisionDenied       = "denied" // a probe cannot tell explicit from implicit
	DecisionPass         = "pass"   // Access Analyzer: access is not granted
	DecisionFail         = "fail"   // Access Analyzer: access may be granted
)

// MatchedStatement is one entry of the simulator's MatchedStatements.
type MatchedStatement struct {
	SourcePolicyID string `json:"source_policy_id"` // "PolicyInputList.1", "ResourcePolicy", ...
	PolicyType     string `json:"policy_type"`      // normalized: see NormalizePolicyType
	RawPolicyType  string `json:"raw_policy_type"`
	Line           int    `json:"line"`
	Column         int    `json:"column"`
}

// AAReason is one reason statement of a failed Access Analyzer check.
type AAReason struct {
	Description    string `json:"description"`
	StatementIndex int    `json:"statement_index"`
	StatementID    string `json:"statement_id"`
}

// Answer is an oracle's reply, normalized.
type Answer struct {
	Oracle   OracleKind         `json:"oracle"`
	Status   AnswerStatus       `json:"status"`
	Decision string             `json:"decision"`
	Detail   string             `json:"detail,omitempty"`
	Matched  []MatchedStatement `json:"matched,omitempty"`
	// DeniedStage is the pipeline stage the oracle named for a denial, in the
	// engine's authz.Stage vocabulary ("" if it did not say).
	DeniedStage authz.Stage `json:"denied_stage,omitempty"`
	Missing     []string    `json:"missing_context,omitempty"`
	Reasons     []AAReason  `json:"reasons,omitempty"` // Access Analyzer
	Attempts    int         `json:"attempts"`
}

// Oracle answers a spec.
type Oracle interface {
	Kind() OracleKind
	Ask(ctx context.Context, s *RequestSpec) (*Answer, error)
}

// Route picks the primary oracle for a spec (§13.3). The returned oracle is
// authoritative for every policy type the spec touches, so its checks count
// toward the gate; the secondary oracles are recorded but not counted.
func Route(s *RequestSpec) OracleKind {
	switch {
	case s.ProbeOnly():
		return OracleProbe
	case s.ResourcePolicy != "":
		// The simulator takes the resource policy only for a user or role
		// caller, which Validate already guarantees.
		return OracleSimCustom
	case s.PolicySourceArn != "":
		return OracleSimPrincipal
	default:
		return OracleSimCustom
	}
}

// NormalizePolicyType maps a SourcePolicyType string to one of "identity",
// "resource", "boundary", "scp" or "none". The API's enum is "user", "group",
// "role", "aws-managed", "user-managed", "resource" and "none", but the
// service also returns display strings such as "Resource Policy" and
// "IAM Policy" (§13.2); both are accepted. An unknown value is returned as
// "unknown:<raw>", never guessed.
func NormalizePolicyType(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "user", "group", "role", "aws-managed", "user-managed", "iam policy", "managed policy", "inline policy", "identity", "identity policy":
		return "identity"
	case "resource", "resource policy", "resource-based policy":
		return "resource"
	case "permissions boundary", "permissions-boundary", "boundary":
		return "boundary"
	case "scp", "service control policy", "service-control-policy":
		return "scp"
	case "none", "":
		return "none"
	}
	return "unknown:" + raw
}

// ParseAccessDeniedStage reads the policy type an AccessDenied message names
// (§13.2) and maps it to the engine's stage. Only one type is ever named, even
// when several deny, and not every service uses the format; ok is false then.
func ParseAccessDeniedStage(msg string) (authz.Stage, bool) {
	m := strings.ToLower(msg)
	for _, c := range []struct {
		phrase string
		stage  authz.Stage
	}{
		{"service control policy", authz.StageSCP},
		{"resource control policy", authz.StageRCP},
		{"vpc endpoint policy", authz.StageVPCE},
		{"permissions boundary", authz.StageBoundary},
		{"session policy", authz.StageSession},
		{"resource-based policy", authz.StageResourcePolicy},
		{"role trust policy", authz.StageResourcePolicy},
		{"identity-based policy", authz.StageIdentity},
	} {
		if strings.Contains(m, c.phrase) {
			return c.stage, true
		}
	}
	return "", false
}

// Backoff retries a throttled call (§13.2: no TPS limit is documented, so the
// harness backs off adaptively). The delay doubles from Base up to Max and is
// never shorter than the service's own RetryAfter. There is no jitter, so a
// run is reproducible; the SDK client's adaptive retryer adds the jitter and
// the client-side rate limit.
type Backoff struct {
	Base        time.Duration
	Max         time.Duration
	MaxAttempts int // total attempts, including the first; 0 means 5
	// Sleep waits d or returns ctx's error. Tests inject a recorder; the
	// binary injects a timer. Nil means no waiting.
	Sleep func(ctx context.Context, d time.Duration) error
	// RetryAfter extracts a service-supplied delay from an error, for errors
	// the default extractor does not know (PR-9 adds Access Analyzer's
	// ThrottlingException.RetryAfterSeconds field). Optional.
	RetryAfter func(error) (time.Duration, bool)
}

// ErrRetriesExhausted wraps the last error when every attempt failed.
var ErrRetriesExhausted = errors.New("harness: retries exhausted")

// errInconclusive marks a probe answer worth retrying.
var errInconclusive = errors.New("harness: inconclusive")

// Do runs op until it succeeds, fails with a non-retryable error, or the
// attempts are used up. It returns the number of attempts made.
func (b Backoff) Do(ctx context.Context, op func() error) (int, error) {
	max := b.MaxAttempts
	if max <= 0 {
		max = 5
	}
	delay := b.Base
	var err error
	for attempt := 1; attempt <= max; attempt++ {
		if cerr := ctx.Err(); cerr != nil {
			return attempt - 1, cerr
		}
		if err = op(); err == nil {
			return attempt, nil
		}
		if !retryable(err) {
			return attempt, err
		}
		if attempt == max {
			break
		}
		d := delay
		if ra, ok := b.retryAfter(err); ok && ra > d {
			d = ra
		}
		if b.Sleep != nil {
			if serr := b.Sleep(ctx, d); serr != nil {
				return attempt, serr
			}
		}
		delay *= 2
		if b.Max > 0 && delay > b.Max {
			delay = b.Max
		}
	}
	return max, errors.Join(ErrRetriesExhausted, err)
}

func (b Backoff) retryAfter(err error) (time.Duration, bool) {
	if b.RetryAfter != nil {
		if d, ok := b.RetryAfter(err); ok {
			return d, true
		}
	}
	return DefaultRetryAfter(err)
}

// DefaultRetryAfter reads a Retry-After header (seconds) from an SDK HTTP
// error, or a RetryAfterSeconds() method.
func DefaultRetryAfter(err error) (time.Duration, bool) {
	var ra interface{ RetryAfterSeconds() int32 }
	if errors.As(err, &ra) {
		if s := ra.RetryAfterSeconds(); s > 0 {
			return time.Duration(s) * time.Second, true
		}
	}
	var re *awshttp.ResponseError
	if errors.As(err, &re) && re.Response != nil && re.Response.Response != nil {
		if s, perr := strconv.Atoi(re.Response.Header.Get("Retry-After")); perr == nil && s > 0 {
			return time.Duration(s) * time.Second, true
		}
	}
	return 0, false
}

var throttleCodes = map[string]bool{
	"Throttling": true, "ThrottlingException": true, "ThrottledException": true, "RequestLimitExceeded": true,
	"TooManyRequestsException": true, "RequestThrottled": true, "SlowDown": true, "ServiceUnavailable": true,
}

func retryable(err error) bool {
	if errors.Is(err, errInconclusive) {
		return true
	}
	var ae smithy.APIError
	if errors.As(err, &ae) && throttleCodes[ae.ErrorCode()] {
		return true
	}
	var re *awshttp.ResponseError
	if errors.As(err, &re) && (re.HTTPStatusCode() == http.StatusTooManyRequests || re.HTTPStatusCode() == http.StatusServiceUnavailable) {
		return true
	}
	var ra interface{ RetryAfterSeconds() int32 }
	return errors.As(err, &ra)
}
