// Package tfplan reads a Terraform plan (the JSON of `terraform show -json plan.tfplan`) and maps what it changes
// to the AWS operations of internal/blast (issue #655, AC-9; design docs/design/differentiators-plan.md). The plan
// is untrusted input: Parse bounds its depth and size, refuses anything that is not a Terraform plan, and reads
// nothing from the machine or the network (the package is pure: bytes in, operations out). Map turns the changes
// of IAM policies, policy attachments, roles (trust policies included), S3 bucket policies, SCPs and RCPs into
// blast.Operations against the estate a snapshot holds. A resource it does not map, and a value the plan does not
// know until apply, is reported as a Finding and never dropped or guessed: an unknown value makes the answer
// CONDITIONAL on it, not allow and not deny. Plan values are used to build operations and are never copied into
// the findings, so a sensitive value cannot leave through them.
package tfplan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Limits on a plan. The body of the request is already capped by the server; these bound the work a small, hostile
// plan can cause.
const (
	// MaxDepth is the deepest JSON nesting a plan may have.
	MaxDepth = 128
	// MaxResourceChanges is the most resource changes a plan may list.
	MaxResourceChanges = 5000
	maxAddress         = 512
	maxDocument        = 128 << 10
)

// Error is a plan that cannot be read. Code is stable: not_json, not_terraform_plan, plan_too_deep,
// plan_too_large or invalid_plan.
type Error struct {
	Code string
	Msg  string
}

func (e *Error) Error() string { return e.Msg }

func fail(code, format string, a ...any) *Error {
	return &Error{Code: code, Msg: fmt.Sprintf(format, a...)}
}

// Plan is the part of a Terraform plan the mapping reads.
type Plan struct {
	FormatVersion    string
	TerraformVersion string
	Changes          []*Change
	// refs holds, per resource (module path and type.name, no index), the references of each attribute's
	// expression, from the plan's configuration.
	refs map[string]map[string][]string
}

// Change is one entry of resource_changes.
type Change struct {
	Address       string
	ModuleAddress string
	Mode          string // managed or data
	Type          string
	Name          string
	Actions       []string
	Before        map[string]any // nil when the resource does not exist before
	After         map[string]any // nil when the resource does not exist after
	AfterUnknown  any
	BeforeSens    any
	AfterSens     any
}

type rawPlan struct {
	FormatVersion    string          `json:"format_version"`
	TerraformVersion string          `json:"terraform_version"`
	PlannedValues    json.RawMessage `json:"planned_values"`
	ResourceChanges  *[]rawChange    `json:"resource_changes"`
	Configuration    *rawConfig      `json:"configuration"`
}

type rawChange struct {
	Address       string `json:"address"`
	ModuleAddress string `json:"module_address"`
	Mode          string `json:"mode"`
	Type          string `json:"type"`
	Name          string `json:"name"`
	Change        *struct {
		Actions      []string `json:"actions"`
		Before       any      `json:"before"`
		After        any      `json:"after"`
		AfterUnknown any      `json:"after_unknown"`
		BeforeSens   any      `json:"before_sensitive"`
		AfterSens    any      `json:"after_sensitive"`
	} `json:"change"`
}

type rawConfig struct {
	RootModule *rawModule `json:"root_module"`
}

type rawModule struct {
	Resources   []rawConfigResource `json:"resources"`
	ModuleCalls map[string]rawCall  `json:"module_calls"`
}

type rawCall struct {
	Module *rawModule `json:"module"`
}

type rawConfigResource struct {
	Address     string                     `json:"address"`
	Mode        string                     `json:"mode"`
	Expressions map[string]json.RawMessage `json:"expressions"`
}

var (
	formatRE = regexp.MustCompile(`^1\.[0-9]{1,3}$`)
	typeRE   = regexp.MustCompile(`^[a-z][a-z0-9_]{0,127}$`)
)

// Parse reads a plan. It does not look at the machine or the network, and the plan's strings are only data.
func Parse(raw []byte) (*Plan, error) {
	if err := checkDepth(raw); err != nil {
		return nil, err
	}
	var rp rawPlan
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&rp); err != nil {
		return nil, fail("not_json", "the Terraform plan is not valid JSON")
	}
	if dec.More() {
		return nil, fail("not_json", "the Terraform plan has trailing data")
	}
	if !formatRE.MatchString(rp.FormatVersion) {
		return nil, fail("not_terraform_plan", "this is not a Terraform plan: format_version must be 1.x (the JSON of terraform show -json <plan>)")
	}
	if rp.ResourceChanges == nil && rp.PlannedValues == nil {
		return nil, fail("not_terraform_plan", "this is not a Terraform plan: it has no resource_changes or planned_values (a state file is not a plan)")
	}
	p := &Plan{FormatVersion: rp.FormatVersion, TerraformVersion: clip(rp.TerraformVersion, 40), refs: map[string]map[string][]string{}}
	if rp.ResourceChanges != nil {
		if len(*rp.ResourceChanges) > MaxResourceChanges {
			return nil, fail("plan_too_large", "the plan lists %d resource changes; a preview takes at most %d. Plan a smaller part of the configuration with -target or split the change", len(*rp.ResourceChanges), MaxResourceChanges)
		}
		for i, rc := range *rp.ResourceChanges {
			c, err := convert(i, rc)
			if err != nil {
				return nil, err
			}
			p.Changes = append(p.Changes, c)
		}
	}
	if rp.Configuration != nil {
		collectRefs(p.refs, rp.Configuration.RootModule, "", 0)
	}
	return p, nil
}

func convert(i int, rc rawChange) (*Change, error) {
	bad := func(what string) error { return fail("invalid_plan", "resource_changes[%d]: %s", i, what) }
	for _, s := range []string{rc.Address, rc.ModuleAddress, rc.Name} {
		if len(s) > maxAddress || !utf8.ValidString(s) {
			return nil, bad("an address is too long or not text")
		}
	}
	if rc.Address == "" || !typeRE.MatchString(rc.Type) || rc.Name == "" || (rc.Mode != "managed" && rc.Mode != "data") {
		return nil, bad("address, mode, type and name are required")
	}
	if rc.Change == nil {
		return nil, bad("change is required")
	}
	c := &Change{Address: rc.Address, ModuleAddress: rc.ModuleAddress, Mode: rc.Mode, Type: rc.Type, Name: rc.Name,
		Actions: rc.Change.Actions, AfterUnknown: rc.Change.AfterUnknown, BeforeSens: rc.Change.BeforeSens, AfterSens: rc.Change.AfterSens}
	if len(c.Actions) == 0 || len(c.Actions) > 2 {
		return nil, bad("change.actions must list one or two actions")
	}
	for _, a := range c.Actions {
		switch a {
		case "no-op", "create", "read", "update", "delete", "forget":
		default:
			return nil, bad("an unknown action")
		}
	}
	var ok bool
	if rc.Change.Before != nil {
		if c.Before, ok = rc.Change.Before.(map[string]any); !ok {
			return nil, bad("change.before must be an object or null")
		}
	}
	if rc.Change.After != nil {
		if c.After, ok = rc.Change.After.(map[string]any); !ok {
			return nil, bad("change.after must be an object or null")
		}
	}
	return c, nil
}

// checkDepth refuses JSON nested deeper than MaxDepth without building it.
func checkDepth(raw []byte) error {
	depth, inStr, esc := 0, false, false
	for _, b := range raw {
		switch {
		case inStr:
			switch {
			case esc:
				esc = false
			case b == '\\':
				esc = true
			case b == '"':
				inStr = false
			}
		case b == '"':
			inStr = true
		case b == '{' || b == '[':
			if depth++; depth > MaxDepth {
				return fail("plan_too_deep", "the Terraform plan is nested more than %d levels deep", MaxDepth)
			}
		case b == '}' || b == ']':
			depth--
		}
	}
	return nil
}

// collectRefs records, for every resource of the module tree, the references of each attribute's expression, under
// the resource's address without indexes ("module.net.aws_iam_policy.deploy").
func collectRefs(out map[string]map[string][]string, m *rawModule, prefix string, depth int) {
	if m == nil || depth > MaxDepth {
		return
	}
	for _, r := range m.Resources {
		if r.Mode != "managed" || r.Address == "" || len(r.Address) > maxAddress {
			continue
		}
		attrs := map[string][]string{}
		for name, e := range r.Expressions {
			var x struct {
				References []string `json:"references"`
			}
			if json.Unmarshal(e, &x) == nil && len(x.References) > 0 {
				attrs[name] = x.References
			}
		}
		out[prefix+stripIndex(r.Address)] = attrs
	}
	for name, call := range m.ModuleCalls {
		collectRefs(out, call.Module, prefix+"module."+name+".", depth+1)
	}
}

// stripIndex removes the [..] index parts of an address, however they are quoted.
func stripIndex(a string) string {
	var b strings.Builder
	depth, inStr, esc := 0, false, false
	for i := 0; i < len(a); i++ {
		ch := a[i]
		switch {
		case depth > 0 && inStr:
			switch {
			case esc:
				esc = false
			case ch == '\\':
				esc = true
			case ch == '"':
				inStr = false
			}
		case depth > 0 && ch == '"':
			inStr = true
		case ch == '[':
			depth++
		case ch == ']' && depth > 0:
			depth--
		case depth == 0:
			b.WriteByte(ch)
		}
	}
	return b.String()
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
