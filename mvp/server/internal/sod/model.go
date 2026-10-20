// Package sod models separation of duties as functions, risks and rulesets
// (issue #298): a function is a reusable set of entitlements, a risk is a
// prioritised conflict between two or more functions, and a ruleset is a named
// group of risks that is enabled or disabled per tenant. An identity violates
// a risk when it effectively holds an entitlement of each of two of the risk's
// functions, by any path in the graph (roles and groups included).
//
// The package holds the model, validation, versioned changes with their audit
// events, the YAML form of a ruleset (access as code) and the detection
// engine. It does not import internal/policy: policy imports it to run risks
// as policies, so every consumer of policies (what-if simulation, reviews,
// leaver plans) sees SoD risks without a second code path.
package sod

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/abac"
)

// Limits on the text and size of a ruleset.
const (
	MaxKey         = 64
	MaxName        = 120
	MaxDescription = 2000
	MaxNote        = 500
	MaxSelectors   = 50
	MaxPattern     = 200
	MaxFunctions   = 10 // per risk
	MaxSubjects    = 10
)

// Priorities of a risk, most severe first.
var Priorities = []string{"critical", "high", "medium", "low"}

// PriorityRank orders priorities (unknown ranks 0).
var PriorityRank = map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}

// Attributes a selector can narrow on, and what each tests on an effective
// permission (the fine-grained "object / field / value" case):
//
//	environment  the environment of the permission's resource (prod, dev…)
//	tag          one of the resource's tags (pii, prod…)
//	resource     the resource name (a pattern)
//	privileged   "true" or "false"
var Attributes = []string{"environment", "tag", "resource", "privileged"}

// Selector picks entitlements: a system plus either a permission id or an
// action name pattern, optionally narrowed by one resource attribute. An empty
// system matches every system. In a pattern `*` matches any run of characters
// and `\` escapes the next one.
type Selector struct {
	System        string `json:"system,omitempty" yaml:"system,omitempty"`
	EntitlementID *int64 `json:"entitlement_id,omitempty" yaml:"entitlement_id,omitempty"`
	NamePattern   string `json:"name_pattern,omitempty" yaml:"name_pattern,omitempty"`
	Attribute     string `json:"attribute,omitempty" yaml:"attribute,omitempty"`
	Value         string `json:"value,omitempty" yaml:"value,omitempty"`
}

// Subjects limits who a risk is checked for. No types means every type, no
// statuses means active identities, and an attribute condition (the JSON
// language of internal/abac) keeps only identities for which it is not false.
type Subjects struct {
	IdentityTypes []string `json:"identity_types,omitempty" yaml:"identity_types,omitempty"`
	Statuses      []string `json:"statuses,omitempty" yaml:"statuses,omitempty"`
	Condition     any      `json:"condition,omitempty" yaml:"condition,omitempty"`
}

// Refusal is a refused change; Code is stable for API clients.
type Refusal struct {
	Status int
	Code   string
	Msg    string
}

func (e *Refusal) Error() string { return e.Msg }

func refuse(status int, code, format string, args ...any) error {
	return &Refusal{Status: status, Code: code, Msg: fmt.Sprintf(format, args...)}
}

var keyRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)

// ValidKey reports whether s can be a key: what YAML files and violations
// name an object by.
func ValidKey(s string) bool { return len(s) <= MaxKey && keyRE.MatchString(s) }

// Slug turns a name into a key (lower case, runs of other characters become "-").
func Slug(name string) string {
	var b strings.Builder
	dash := true
	for _, r := range strings.ToLower(name) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
			dash = false
		} else if !dash {
			b.WriteByte('-')
			dash = true
		}
	}
	s := strings.TrimRight(b.String(), "-")
	if len(s) > MaxKey {
		s = strings.TrimRight(s[:MaxKey], "-")
	}
	return s
}

func checkText(name, desc, note string) error {
	switch {
	case name == "" || len(name) > MaxName:
		return refuse(422, "invalid_name", "a name of 1 to %d characters is required", MaxName)
	case len(desc) > MaxDescription:
		return refuse(422, "invalid_description", "the description is at most %d characters", MaxDescription)
	case len(note) > MaxNote:
		return refuse(422, "invalid_note", "the note is at most %d characters", MaxNote)
	}
	return nil
}

// validateSelectors checks a function's selectors (structure only; the entitlement ids
// are checked against the tenant by the service).
func validateSelectors(sels []Selector) error {
	if len(sels) == 0 || len(sels) > MaxSelectors {
		return refuse(422, "invalid_selectors", "a function needs 1 to %d selectors", MaxSelectors)
	}
	for i, s := range sels {
		at := fmt.Sprintf("selector %d", i+1)
		switch {
		case (s.EntitlementID == nil) == (s.NamePattern == ""):
			return refuse(422, "invalid_selectors", "%s needs exactly one of entitlement_id and name_pattern", at)
		case s.EntitlementID != nil && s.System == "":
			return refuse(422, "invalid_selectors", "%s needs a system with its entitlement_id", at)
		case len(s.NamePattern) > MaxPattern || len(s.System) > MaxName || len(s.Value) > MaxPattern:
			return refuse(422, "invalid_selectors", "%s has a value that is too long", at)
		case (s.Attribute == "") != (s.Value == ""):
			return refuse(422, "invalid_selectors", "%s needs both attribute and value, or neither", at)
		case s.Attribute != "" && !contains(Attributes, s.Attribute):
			return refuse(422, "invalid_selectors", "%s: attribute is one of %s", at, strings.Join(Attributes, ", "))
		case s.Attribute == "privileged" && s.Value != "true" && s.Value != "false":
			return refuse(422, "invalid_selectors", "%s: privileged is true or false", at)
		}
	}
	return nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

var identityTypes = []string{"human", "service", "ai_agent"}
var statusRE = regexp.MustCompile(`^[a-z_]{1,32}$`)

func (s *Subjects) validate() error {
	if len(s.IdentityTypes) > MaxSubjects || len(s.Statuses) > MaxSubjects {
		return refuse(422, "invalid_subjects", "too many identity types or statuses")
	}
	for _, t := range s.IdentityTypes {
		if !contains(identityTypes, t) {
			return refuse(422, "invalid_subjects", "identity type %q is not one of %s", t, strings.Join(identityTypes, ", "))
		}
	}
	for _, t := range s.Statuses {
		if !statusRE.MatchString(t) {
			return refuse(422, "invalid_subjects", "status %q is not a status name", t)
		}
	}
	if s.Condition == nil {
		return nil
	}
	raw, err := jsonOf(s.Condition)
	if err != nil {
		return refuse(422, "invalid_subjects", "the condition cannot be read")
	}
	n, err := abac.Parse(raw)
	if err == nil {
		err = n.Validate()
	}
	if err != nil {
		return refuse(422, "invalid_subjects", "condition: %s", err.Error())
	}
	return nil
}

// Remediation options a risk can offer on a violation: remove an entitlement
// (through the revoke path), cover it with a mitigating control, accept it
// until a date, or send it to the risk owner.
const (
	OptRevoke   = "revoke"
	OptMitigate = "mitigate"
	OptAccept   = "accept"
	OptEscalate = "escalate"
)

// RemediationOptions lists them in display order; a risk offers all of them unless it says otherwise.
var RemediationOptions = []string{OptRevoke, OptMitigate, OptAccept, OptEscalate}

// normalizeOptions validates a risk's explicit options and returns them in
// display order; nil means "all four" (none given, or all given).
func normalizeOptions(in []string) ([]string, error) {
	if len(in) == 0 {
		return nil, nil
	}
	for _, o := range in {
		if !contains(RemediationOptions, o) {
			return nil, refuse(422, "invalid_remediation", "remediation options are %s", strings.Join(RemediationOptions, ", "))
		}
	}
	var out []string
	for _, o := range RemediationOptions {
		if contains(in, o) {
			out = append(out, o)
		}
	}
	if len(out) == len(RemediationOptions) {
		return nil, nil
	}
	return out, nil
}
