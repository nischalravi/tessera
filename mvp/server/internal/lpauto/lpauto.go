// Package lpauto is the tenant's automatic least-privilege policy, kept as code in the access-as-code repository
// (issue #664, LP-8; design docs/design/least-privilege-loop.md sections 3, 4, 10 and 11). The file is
// lp/auto.yaml. It can only narrow what the design allows: it cannot lower the confidence, shorten the unused
// period below 90 days, include break-glass or privileged prod permissions, or name a kind the design never
// revokes automatically. Auto mode is off until a policy is applied (two people) and the mode is set (two people).
package lpauto

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

// File is the path of the policy in the repository.
const File = "lp/auto.yaml"

// Bounds of the design (sections 4 and 11).
const (
	MaxFileBytes   = 16 << 10
	MinUnusedDays  = 90
	MaxUnusedDays  = 365
	MaxPerDayLimit = 100
	MaxAccounts    = 100
	MaxCommit      = 64
	Version        = 1
	ConfidenceHigh = "high"
	PrivilegedProd = "suggest"
)

// Kinds are the change kinds the design lets the loop revoke without a person (section 4.1). The kinds that are
// suggest-only or never (shared-policy right-size, role_trim, IdP group removal, trust policies, ...) are not here.
var Kinds = []string{"aws_detach_policy", "aws_delete_inline_policy", "aws_set_policy_version", "aws_remove_from_group", "aws_delete_assignment"}

var accountRE = regexp.MustCompile(`^[0-9]{12}$`)

// Policy is a validated auto policy. Its JSON form (field order fixed) is what is stored, hashed and audited.
type Policy struct {
	Version int `json:"version"`
	// Confidence is always high: medium is suggested, low and unknown are never acted on.
	Confidence string `json:"confidence"`
	// MinUnusedDays is at least 90 (the tenant's auto_min_days applies too: the stricter of the two wins).
	MinUnusedDays int `json:"min_unused_days"`
	// MaxPerDay bounds the revocations the policy announces in 24 hours, inside the tenant's own caps.
	MaxPerDay int      `json:"max_per_day"`
	Kinds     []string `json:"kinds"`
	// Accounts restricts the policy to these AWS accounts; empty means every account of the tenant.
	Accounts []string `json:"accounts"`
	// ExcludeBreakGlass must be true: break-glass and protected principals are never auto-revoked.
	ExcludeBreakGlass bool `json:"exclude_break_glass"`
	// PrivilegedProd must be "suggest": privileged prod permissions are suggest-only in v1 (decision 3).
	PrivilegedProd string `json:"privileged_prod"`
}

// Error is a refusal of a policy file.
type Error struct{ Msg string }

func (e *Error) Error() string { return "invalid_auto_policy: " + e.Msg }

func bad(format string, args ...any) error { return &Error{Msg: fmt.Sprintf(format, args...)} }

// raw has pointers so that a missing field is told from a zero one.
type raw struct {
	Version           *int     `yaml:"version"`
	Confidence        *string  `yaml:"confidence"`
	MinUnusedDays     *int     `yaml:"min_unused_days"`
	MaxPerDay         *int     `yaml:"max_per_day"`
	Kinds             []string `yaml:"kinds"`
	Accounts          []string `yaml:"accounts"`
	ExcludeBreakGlass *bool    `yaml:"exclude_break_glass"`
	PrivilegedProd    *string  `yaml:"privileged_prod"`
}

// Parse reads and validates lp/auto.yaml. Unknown fields are refused. Fields that may only have the safe value
// (confidence, exclude_break_glass, privileged_prod) may be left out and are then set to it.
func Parse(data []byte) (*Policy, error) {
	if len(data) > MaxFileBytes {
		return nil, bad("%s is %d bytes; at most %d", File, len(data), MaxFileBytes)
	}
	var r raw
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&r); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, bad("%s is empty", File)
		}
		return nil, bad("%s: %v", File, err)
	}
	var extra raw
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, bad("%s holds more than one YAML document", File)
	}
	if r.Version == nil || *r.Version != Version {
		return nil, bad("version must be %d", Version)
	}
	p := &Policy{Version: Version, Confidence: ConfidenceHigh, MinUnusedDays: MinUnusedDays, MaxPerDay: MaxPerDayLimit,
		ExcludeBreakGlass: true, PrivilegedProd: PrivilegedProd}
	if r.Confidence != nil && *r.Confidence != ConfidenceHigh {
		return nil, bad("confidence must be %q: medium is suggested, low and unknown are never acted on", ConfidenceHigh)
	}
	if r.MinUnusedDays != nil {
		if *r.MinUnusedDays < MinUnusedDays || *r.MinUnusedDays > MaxUnusedDays {
			return nil, bad("min_unused_days is %d to %d", MinUnusedDays, MaxUnusedDays)
		}
		p.MinUnusedDays = *r.MinUnusedDays
	}
	if r.MaxPerDay != nil {
		if *r.MaxPerDay < 1 || *r.MaxPerDay > MaxPerDayLimit {
			return nil, bad("max_per_day is 1 to %d", MaxPerDayLimit)
		}
		p.MaxPerDay = *r.MaxPerDay
	}
	if r.ExcludeBreakGlass != nil && !*r.ExcludeBreakGlass {
		return nil, bad("exclude_break_glass cannot be false: break-glass and protected principals are never auto-revoked")
	}
	if r.PrivilegedProd != nil && *r.PrivilegedProd != PrivilegedProd {
		return nil, bad("privileged_prod must be %q: privileged prod permissions are suggest-only", PrivilegedProd)
	}
	if len(r.Kinds) == 0 {
		return nil, bad("kinds is required: name the change kinds the policy may revoke (%s)", strings.Join(Kinds, ", "))
	}
	for _, k := range r.Kinds {
		if !slices.Contains(Kinds, k) {
			return nil, bad("kind %q is not auto-eligible (allowed: %s)", k, strings.Join(Kinds, ", "))
		}
		if slices.Contains(p.Kinds, k) {
			return nil, bad("kind %q is named twice", k)
		}
		p.Kinds = append(p.Kinds, k)
	}
	slices.Sort(p.Kinds)
	if len(r.Accounts) > MaxAccounts {
		return nil, bad("accounts is at most %d", MaxAccounts)
	}
	p.Accounts = []string{}
	for _, a := range r.Accounts {
		if !accountRE.MatchString(a) {
			return nil, bad("account %q is not a 12-digit AWS account id", a)
		}
		if slices.Contains(p.Accounts, a) {
			return nil, bad("account %q is named twice", a)
		}
		p.Accounts = append(p.Accounts, a)
	}
	slices.Sort(p.Accounts)
	return p, nil
}

// Canonical is the stored form of the policy.
func (p *Policy) Canonical() string {
	b, _ := json.Marshal(p) // a struct of strings and numbers cannot fail
	return string(b)
}

// Digest is the SHA-256 of the canonical form: what two people approve and what the audit event carries.
func (p *Policy) Digest() string {
	h := sha256.Sum256([]byte(p.Canonical()))
	return hex.EncodeToString(h[:])
}

// FromJSON reads a stored policy. It checks the same bounds, so a hand-edited row is refused.
func FromJSON(s string) (*Policy, error) {
	var p Policy
	dec := json.NewDecoder(strings.NewReader(s))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, bad("stored policy: %v", err)
	}
	if p.Version != Version || p.Confidence != ConfidenceHigh || p.MinUnusedDays < MinUnusedDays || p.MaxPerDay < 1 ||
		p.MaxPerDay > MaxPerDayLimit || !p.ExcludeBreakGlass || p.PrivilegedProd != PrivilegedProd || len(p.Kinds) == 0 {
		return nil, bad("stored policy is outside the design's bounds")
	}
	for _, k := range p.Kinds {
		if !slices.Contains(Kinds, k) {
			return nil, bad("stored policy names kind %q", k)
		}
	}
	return &p, nil
}

// Candidate is what the policy decides on.
type Candidate struct {
	Kind       string
	Account    string
	Confidence string
	UnusedDays int
}

// Allows says why the policy does not cover a candidate ("" when it does).
func (p *Policy) Allows(c Candidate) string {
	switch {
	case c.Confidence != ConfidenceHigh:
		return "confidence is " + c.Confidence + ", the policy needs high"
	case c.UnusedDays < p.MinUnusedDays:
		return fmt.Sprintf("unused %d days, the policy needs %d", c.UnusedDays, p.MinUnusedDays)
	case !slices.Contains(p.Kinds, c.Kind):
		return "kind " + c.Kind + " is not in the policy"
	case len(p.Accounts) > 0 && !slices.Contains(p.Accounts, c.Account):
		return "account " + c.Account + " is not in the policy"
	}
	return ""
}
