// Package harness is the offline foundation of the differential test harness
// (design §13): request specs, oracle clients, the comparator and its metrics,
// the Wilson-bound gate, the triage store, the delta-debug minimizer and the
// cassette replay corpus.
//
// It does I/O (files, the AWS SDK), so it lives outside the purity-ruled
// engine packages and is imported only by cmd/tessera-harness (enforced in
// internal/archtest); the server binary never links it. Nothing here needs
// AWS credentials: oracle answers come from recorded cassettes, and the
// clients that would reach AWS take their transport from the caller (PR-9
// supplies a safehttp-backed one for the nightly job).
package harness

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/policy"
)

// Stratum is a sampling stratum (§13.4).
type Stratum string

// The strata of §13.4. S1 to S5 count toward the gate; S6 set checks do not.
const (
	S1GoldenDeployed Stratum = "S1"
	S2GrammarFuzz    Stratum = "S2"
	S3DeployedConfig Stratum = "S3"
	S4Probes         Stratum = "S4"
	S5CloudTrail     Stratum = "S5"
	S6SetChecks      Stratum = "S6"
)

func (s Stratum) valid() bool {
	switch s {
	case S1GoldenDeployed, S2GrammarFuzz, S3DeployedConfig, S4Probes, S5CloudTrail, S6SetChecks:
		return true
	}
	return false
}

// GateEligible reports whether checks of the stratum count toward M1 (§13.4).
func (s Stratum) GateEligible() bool { return s != S6SetChecks }

// Feature flags name the policy types and mechanisms a check touches that the
// simulator cannot decide (§13.2, §13.3). Any of them routes the check to a
// live probe.
const (
	FeatureSessionPolicy = "session_policy"
	FeatureRCP           = "rcp"
	FeatureTrust         = "trust"
	FeatureKMSKeyPolicy  = "kms_key_policy"
	FeatureKMSGrant      = "kms_grant"
	FeatureS3ACL         = "s3_acl"
	FeatureBPA           = "bpa"
	FeatureAccessPoint   = "access_point"
	FeatureVPCE          = "vpce"
	FeatureNotPrincipal  = "not_principal"
	FeatureMgmtAccount   = "management_account"
	FeatureSLR           = "service_linked_role"
	FeatureSessionARN    = "session_arn_grant"
	FeatureAmbiguity     = "ambiguity_probe"
)

var probeOnlyFeatures = map[string]bool{
	FeatureSessionPolicy: true, FeatureRCP: true, FeatureTrust: true, FeatureKMSKeyPolicy: true,
	FeatureKMSGrant: true, FeatureS3ACL: true, FeatureBPA: true, FeatureAccessPoint: true, FeatureVPCE: true,
	FeatureNotPrincipal: true, FeatureMgmtAccount: true, FeatureSLR: true, FeatureSessionARN: true, FeatureAmbiguity: true,
}

// ContextEntry is one simulator context key (iam.types.ContextEntry).
type ContextEntry struct {
	Type   string   `json:"type"` // "string" (default), "stringList", "numeric", "boolean", "ip", ...
	Values []string `json:"values"`
}

// RequestSpec is one harness check, independent of any oracle (§13.1): the
// policy set, the request and the context. The engine and the oracles are both
// built from it, so they see the same inputs.
type RequestSpec struct {
	ID      string  `json:"id"`
	Stratum Stratum `json:"stratum"`
	// FixtureVersion pins the cassette keys and the sandbox fixture.
	FixtureVersion string `json:"fixture_version"`

	// PrincipalARN is the caller: an IAM user or role ARN (never a session
	// ARN; the simulator refuses one).
	PrincipalARN string `json:"principal_arn"`
	// PolicySourceArn, when set, asks SimulatePrincipalPolicy about a deployed
	// principal; the policies below are what is deployed (the engine needs
	// them, the simulator reads them from AWS).
	PolicySourceArn string `json:"policy_source_arn"`
	Action          string `json:"action"`   // concrete: Custom mode takes no wildcards
	Resource        string `json:"resource"` // "" or "*" when the action has no resource-level support

	Identity  []string   `json:"identity"`   // raw identity policy JSON
	Boundary  []string   `json:"boundary"`   // at most one document
	SCPLevels [][]string `json:"scp_levels"` // root to account, at most 7 levels, raw JSON
	// ResourcePolicy and ResourceOwner (an account id) describe the one
	// resource policy the simulator accepts.
	ResourcePolicy string `json:"resource_policy"`
	ResourceOwner  string `json:"resource_owner"`

	Context map[string]ContextEntry `json:"context"`
	// Exclusions are PolicyExclusionList identifiers for ablation runs.
	Exclusions []string `json:"exclusions"`
	// Features routes the check (see the Feature constants).
	Features []string `json:"features"`
}

// Limits on a spec, which comes from files and is untrusted.
const (
	maxSCPLevels   = 7
	maxPolicyBytes = 128 << 10
	maxPolicies    = 64
)

// RefusalError means a check is excluded before any oracle is asked, and is
// counted like UNSUPPORTED (§8.4.3, §13.6).
type RefusalError struct {
	Reason string // "dropped_anomaly" or "unparseable"
	Detail string
}

func (e *RefusalError) Error() string { return "harness: refused (" + e.Reason + "): " + e.Detail }

// Refusal reasons.
const (
	RefusedDroppedAnomaly = "dropped_anomaly"
	RefusedUnparseable    = "unparseable"
)

// ParseSpec decodes a spec strictly and validates it.
func ParseSpec(b []byte) (*RequestSpec, error) {
	var s RequestSpec
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("harness: spec: %w", err)
	}
	if dec.More() {
		return nil, errors.New("harness: spec: trailing data")
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return &s, nil
}

// Validate checks the shape of a spec. It does not parse policy documents
// (see CheckIngest).
func (s *RequestSpec) Validate() error {
	switch {
	case s.ID == "":
		return errors.New("harness: spec has no id")
	case !s.Stratum.valid():
		return fmt.Errorf("harness: spec %s: unknown stratum %q", s.ID, s.Stratum)
	case s.FixtureVersion == "":
		return fmt.Errorf("harness: spec %s: no fixture_version", s.ID)
	case s.Action == "" || strings.ContainsAny(s.Action, "*?"):
		return fmt.Errorf("harness: spec %s: action must be concrete, got %q", s.ID, s.Action)
	case !strings.Contains(s.Action, ":"):
		return fmt.Errorf("harness: spec %s: action %q has no service prefix", s.ID, s.Action)
	case len(s.Boundary) > 1:
		return fmt.Errorf("harness: spec %s: at most one boundary document", s.ID)
	case len(s.SCPLevels) > maxSCPLevels:
		return fmt.Errorf("harness: spec %s: %d SCP levels, the simulator takes at most %d", s.ID, len(s.SCPLevels), maxSCPLevels)
	case s.ResourcePolicy != "" && s.ResourceOwner == "":
		return fmt.Errorf("harness: spec %s: a resource policy needs resource_owner", s.ID)
	case len(s.Identity)+len(s.Boundary)+s.scpCount() > maxPolicies:
		return fmt.Errorf("harness: spec %s: more than %d policies", s.ID, maxPolicies)
	}
	if _, _, err := principalParts(s.PrincipalARN); err != nil {
		return fmt.Errorf("harness: spec %s: %w", s.ID, err)
	}
	if s.PolicySourceArn != "" && s.PolicySourceArn != s.PrincipalARN {
		return fmt.Errorf("harness: spec %s: policy_source_arn must equal principal_arn", s.ID)
	}
	for _, f := range s.Features {
		if _, ok := probeOnlyFeatures[f]; !ok {
			return fmt.Errorf("harness: spec %s: unknown feature %q", s.ID, f)
		}
	}
	for k, e := range s.Context {
		if k == "" || len(e.Values) == 0 {
			return fmt.Errorf("harness: spec %s: context key %q needs a name and values", s.ID, k)
		}
	}
	for _, p := range s.allPolicies() {
		if len(p.Raw) > maxPolicyBytes {
			return fmt.Errorf("harness: spec %s: a policy exceeds %d bytes", s.ID, maxPolicyBytes)
		}
	}
	return nil
}

func (s *RequestSpec) scpCount() int {
	n := 0
	for _, l := range s.SCPLevels {
		n += len(l)
	}
	return n
}

type kindedPolicy struct {
	Kind model.PolicyKind
	Raw  string
}

func (s *RequestSpec) allPolicies() []kindedPolicy {
	var out []kindedPolicy
	for _, p := range s.Identity {
		out = append(out, kindedPolicy{model.PolicyIdentity, p})
	}
	for _, p := range s.Boundary {
		out = append(out, kindedPolicy{model.PolicyBoundary, p})
	}
	for _, l := range s.SCPLevels {
		for _, p := range l {
			out = append(out, kindedPolicy{model.PolicySCP, p})
		}
	}
	if s.ResourcePolicy != "" {
		out = append(out, kindedPolicy{model.PolicyResource, s.ResourcePolicy})
	}
	return out
}

// CheckIngest parses every policy of the spec the way the engine will and
// refuses a document with a parse error or a Dropped ingest anomaly: AWS would
// reject or reinterpret it, so a comparison would be meaningless (§8.4.3).
func (s *RequestSpec) CheckIngest() error {
	for i, p := range s.allPolicies() {
		res, err := policy.Parse([]byte(p.Raw), policy.Options{Kind: p.Kind})
		if err != nil {
			return &RefusalError{Reason: RefusedUnparseable, Detail: fmt.Sprintf("policy %d: %v", i, err)}
		}
		for _, a := range res.Anomalies {
			if a.Dropped {
				return &RefusalError{Reason: RefusedDroppedAnomaly, Detail: fmt.Sprintf("policy %d statement %d: %s", i, a.StatementIndex, a.Code)}
			}
		}
	}
	return nil
}

// HasFeature reports whether the spec carries a feature flag.
func (s *RequestSpec) HasFeature(f string) bool {
	for _, x := range s.Features {
		if x == f {
			return true
		}
	}
	return false
}

// ProbeOnly reports whether a feature flag sends the check to a live probe.
func (s *RequestSpec) ProbeOnly() bool {
	for _, f := range s.Features {
		if probeOnlyFeatures[f] {
			return true
		}
	}
	return false
}

// Hash is a stable digest of the spec (struct field order, sorted map keys),
// for cassette and triage references.
func (s *RequestSpec) Hash() string {
	b, _ := json.Marshal(s) // a RequestSpec always marshals
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Clone returns a deep copy.
func (s *RequestSpec) Clone() *RequestSpec {
	c := *s
	c.Identity = append([]string(nil), s.Identity...)
	c.Boundary = append([]string(nil), s.Boundary...)
	c.Exclusions = append([]string(nil), s.Exclusions...)
	c.Features = append([]string(nil), s.Features...)
	c.SCPLevels = make([][]string, len(s.SCPLevels))
	for i, l := range s.SCPLevels {
		c.SCPLevels[i] = append([]string(nil), l...)
	}
	if s.Context != nil {
		c.Context = make(map[string]ContextEntry, len(s.Context))
		for k, v := range s.Context {
			c.Context[k] = ContextEntry{Type: v.Type, Values: append([]string(nil), v.Values...)}
		}
	}
	return &c
}

// contextKeys returns the sorted context key names.
func (s *RequestSpec) contextKeys() []string {
	keys := make([]string, 0, len(s.Context))
	for k := range s.Context {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// principalParts returns the account and kind ("user" or "role") of an IAM
// user or role ARN.
func principalParts(arn string) (account, kind string, err error) {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[2] != "iam" || parts[4] == "" {
		return "", "", fmt.Errorf("principal %q is not an IAM user or role ARN", arn)
	}
	switch {
	case strings.HasPrefix(parts[5], "user/"):
		return parts[4], "user", nil
	case strings.HasPrefix(parts[5], "role/"):
		return parts[4], "role", nil
	}
	return "", "", fmt.Errorf("principal %q is not an IAM user or role ARN", arn)
}
