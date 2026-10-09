// Package authz holds the platform-neutral authorization types shared by the
// cloud evaluators: decisions, deny kinds, fidelity, explanation steps,
// statement references, three-valued results (Tri) and residual predicates.
//
// Nothing in this package is AWS-specific, so the Azure and GCP evaluators can
// reuse it (docs/design/aws-effective-permission-evaluator.md §5, §6.1).
//
// Enums are small integer types with String, MarshalText and UnmarshalText.
// Their text form is the lower-case v1 spelling ("allow", "explicit", ...), and
// the zero value marshals as "" (meaning "none" or "unset").
package authz

import "fmt"

// EnumName returns names[v], or "" when v is out of range.
// names[0] is the spelling of the zero value (normally "").
func EnumName[T ~uint8](v T, names []string) string {
	if int(v) < len(names) {
		return names[v]
	}
	return ""
}

// ParseEnum is the inverse of EnumName. It is case-sensitive.
func ParseEnum[T ~uint8](s string, names []string, typ string) (T, error) {
	for i, n := range names {
		if n == s && i <= 255 {
			return T(uint8(i)), nil // #nosec G115 -- i is bounded by the check above
		}
	}
	return 0, fmt.Errorf("authz: unknown %s %q", typ, s)
}

func marshalEnum[T ~uint8](v T, names []string, typ string) ([]byte, error) {
	if int(v) >= len(names) {
		return nil, fmt.Errorf("authz: invalid %s value %d", typ, uint8(v))
	}
	return []byte(names[v]), nil
}

// Outcome is the three-valued decision (D2).
type Outcome uint8

const (
	Allow       Outcome = iota + 1 // "allow"
	Deny                           // "deny"
	Conditional                    // "conditional"
)

var outcomeNames = []string{"", "allow", "deny", "conditional"}

func (o Outcome) String() string                { return EnumName(o, outcomeNames) }
func (o Outcome) MarshalText() ([]byte, error) { return marshalEnum(o, outcomeNames, "outcome") }
func (o *Outcome) UnmarshalText(b []byte) (err error) {
	*o, err = ParseEnum[Outcome](string(b), outcomeNames, "outcome")
	return err
}

// DenyKind says why a request was denied. The zero value means "no deny kind".
type DenyKind uint8

const (
	Explicit  DenyKind = iota + 1 // a Deny statement matched
	Implicit                      // nothing allowed, or a required layer had no Allow
	Guardrail                     // non-policy control: S3 BPA, KMS cross-account op allowlist
)

var denyKindNames = []string{"", "explicit", "implicit", "guardrail"}

func (k DenyKind) String() string                { return EnumName(k, denyKindNames) }
func (k DenyKind) MarshalText() ([]byte, error) { return marshalEnum(k, denyKindNames, "deny kind") }
func (k *DenyKind) UnmarshalText(b []byte) (err error) {
	*k, err = ParseEnum[DenyKind](string(b), denyKindNames, "deny kind")
	return err
}

// Fidelity says how far a decision can be trusted (§3).
type Fidelity uint8

const (
	Exact       Fidelity = iota + 1 // "exact"
	Approximate                     // "approximate"
	Unsupported                     // "unsupported"
)

var fidelityNames = []string{"", "exact", "approximate", "unsupported"}

func (f Fidelity) String() string                { return EnumName(f, fidelityNames) }
func (f Fidelity) MarshalText() ([]byte, error) { return marshalEnum(f, fidelityNames, "fidelity") }
func (f *Fidelity) UnmarshalText(b []byte) (err error) {
	*f, err = ParseEnum[Fidelity](string(b), fidelityNames, "fidelity")
	return err
}

// FidelityReason explains a fidelity downgrade.
type FidelityReason struct {
	Code             string `json:"code"` // e.g. "AMBIGUITY:A3", "VPCE_POLICY_UNKNOWN"
	Detail           string `json:"detail"`
	OutcomeSensitive bool   `json:"outcome_sensitive"` // true if flipping this assumption could flip the decision
}

// Qualifier is a condition set operator prefix.
type Qualifier uint8

const (
	NoQualifier  Qualifier = iota // ""
	ForAllValues                  // "ForAllValues"
	ForAnyValue                   // "ForAnyValue"
)

var qualifierNames = []string{"", "ForAllValues", "ForAnyValue"}

func (q Qualifier) String() string                { return EnumName(q, qualifierNames) }
func (q Qualifier) MarshalText() ([]byte, error) { return marshalEnum(q, qualifierNames, "qualifier") }
func (q *Qualifier) UnmarshalText(b []byte) (err error) {
	*q, err = ParseEnum[Qualifier](string(b), qualifierNames, "qualifier")
	return err
}

// Span locates a statement in the raw policy bytes. Lines and columns are
// 1-based; columns count Unicode code points; the end position is inclusive
// (it points at the closing brace). A line ends at '\n'.
type Span struct {
	StartLine int `json:"start_line"`
	StartCol  int `json:"start_col"`
	EndLine   int `json:"end_line"`
	EndCol    int `json:"end_col"`
}

// StmtRef identifies a statement precisely enough to find it in the console
// and in Git (§7.11).
type StmtRef struct {
	PolicyID       string   `json:"policy_id"`
	PolicyKind     string   `json:"policy_kind"`
	SourceARN      string   `json:"source_arn"`
	VersionID      string   `json:"version_id"` // "" if none
	StatementIndex int      `json:"statement_index"`
	Sid            string   `json:"sid"`
	Span           *Span    `json:"span"`
	AttachmentPath []string `json:"attachment_path"` // e.g. ["role/Ci", "managed:arn:aws:iam::aws:policy/ReadOnlyAccess"]
	OrgLevel       string   `json:"org_level"`       // "r-abcd" | "ou-…" | account id, for SCPs and RCPs; "" otherwise
}

// CondTrace records how one condition atom evaluated.
type CondTrace struct {
	Atom          Atom     `json:"atom"`
	RequestState  string   `json:"request_state"` // "present" | "absent" | "unknown"
	RequestValues []string `json:"request_values"`
	Result        string   `json:"result"` // "true" | "false" | "unknown"
}

// Stage names a step of the evaluation pipeline.
type Stage string

const (
	StageParse          Stage = "parse"
	StageContext        Stage = "context"
	StageExplicitDeny   Stage = "explicit_deny"
	StageRCP            Stage = "rcp"
	StageSCP            Stage = "scp"
	StageResourcePolicy Stage = "resource_policy"
	StageIdentity       Stage = "identity"
	StageBoundary       Stage = "boundary"
	StageSession        Stage = "session"
	StageKMSGrant       Stage = "kms_grant"
	StageS3ACL          Stage = "s3_acl"
	StageS3BPA          Stage = "s3_bpa"
	StageVPCE           Stage = "vpce"
	StageCrossAccount   Stage = "cross_account"
	StageSpecialRule    Stage = "special_rule"
	StageFinal          Stage = "final"
)

// StepResult is the result recorded for one explanation step.
type StepResult string

const (
	ResultAllow         StepResult = "allow"
	ResultDeny          StepResult = "deny"
	ResultNoMatch       StepResult = "no_match"
	ResultNotApplicable StepResult = "not_applicable"
	ResultPass          StepResult = "pass"
	ResultFail          StepResult = "fail"
	ResultConditional   StepResult = "conditional"
)

// ExplanationStep is one entry of the "why" trace (§7.11).
type ExplanationStep struct {
	Stage          Stage             `json:"stage"`
	Result         StepResult        `json:"result"`
	Statement      *StmtRef          `json:"statement"`  // nil for stage summaries
	MatchedOn      map[string]string `json:"matched_on"` // encoding/json sorts map keys
	ConditionTrace []CondTrace       `json:"condition_trace"`
	Residual       Residual          `json:"residual"` // nil if none
	Note           string            `json:"note"`     // generated from a template, never free text
	Decisive       bool              `json:"decisive"` // part of the minimal justification set
}

// Request is the platform-specific request a Decision answers
// (*eval.EvaluationRequest for AWS).
type Request interface{ Platform() string }

// Decision is the evaluator's answer to one request.
type Decision struct {
	Outcome         Outcome           `json:"outcome"`
	DenyKind        DenyKind          `json:"deny_kind"` // zero unless Outcome == Deny
	Residual        Residual          `json:"residual"`  // Const(true) for Allow, Const(false) for Deny, a formula for Conditional
	Fidelity        Fidelity          `json:"fidelity"`
	FidelityReasons []FidelityReason  `json:"fidelity_reasons"`
	Steps           []ExplanationStep `json:"steps"`
	Decisive        []StmtRef         `json:"decisive"` // minimal set of statements that justify the outcome
	Request         Request           `json:"request"`
	EngineVersion   string            `json:"engine_version"`
	CatalogVersion  string            `json:"catalog_version"`
	SnapshotID      string            `json:"snapshot_id"`
}

// AWSEvalDecision returns the AWS simulator spelling of the decision:
// "allowed", "explicitDeny" or "implicitDeny", or "" for Conditional.
// A Deny with a guardrail deny kind is reported as "implicitDeny", which is how
// AWS reports denials that no Deny statement caused.
func (d *Decision) AWSEvalDecision() string {
	switch d.Outcome {
	case Allow:
		return "allowed"
	case Deny:
		if d.DenyKind == Explicit {
			return "explicitDeny"
		}
		return "implicitDeny"
	default:
		return ""
	}
}
